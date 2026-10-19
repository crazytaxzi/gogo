using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentionce.MutationFirewall;

internal sealed class Policy
{
    public int PolicyVersion { get; set; } = 1;
    public string AuditLog { get; set; } = @"E:\SentionceRecovery\MutationFirewall\logs\mutation-firewall.jsonl";
    public bool DenyReparsePoints { get; set; } = true;
    public Limits AutoLimits { get; set; } = new();
    public List<string> ProtectedRoots { get; set; } = new();
    public List<string> ProtectedExactPaths { get; set; } = new();
    public Dictionary<string, string> QuarantineRoots { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

internal sealed class Limits
{
    public long MaxFiles { get; set; } = 500;
    public long MaxDirectories { get; set; } = 1000;
    public long MaxBytes { get; set; } = 1L << 30;
}

internal sealed record TreeStats(long Files, long Directories, long Bytes, List<string> ReparsePoints);
internal sealed record PathDecision(
    bool Allowed,
    string InputPath,
    string CanonicalPath,
    string? ExistingAnchor,
    bool Exists,
    string? Type,
    TreeStats? Stats,
    List<string> Reasons);

internal sealed record Finding(string Severity, string Category, string Match, string Explanation);

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static Policy _policy = null!;
    private static string _policyPath = null!;

    public static int Main(string[] args)
    {
        try
        {
            var parsed = ParseArgs(args);
            _policyPath = parsed.Options.TryGetValue("policy", out var supplied)
                ? supplied
                : Path.Combine(AppContext.BaseDirectory, "policy.json");

            if (!File.Exists(_policyPath))
            {
                var fallback = @"E:\SentionceRecovery\MutationFirewall\policy.json";
                if (File.Exists(fallback)) _policyPath = fallback;
            }

            _policy = LoadPolicy(_policyPath);

            return parsed.Command.ToLowerInvariant() switch
            {
                "status" => Status(),
                "evaluate" => EvaluateCommand(parsed.Options),
                "scan-command" => ScanCommand(parsed.Options),
                "quarantine" => QuarantineCommand(parsed.Options),
                "replace" => ReplaceCommand(parsed.Options),
                "move" => MoveCommand(parsed.Options),
                "restore" => RestoreCommand(parsed.Options),
                "selftest" => SelfTest(),
                _ => Usage()
            };
        }
        catch (Exception ex)
        {
            WriteJson(new
            {
                ok = false,
                error = ex.GetType().Name,
                message = ex.Message
            });
            return 1;
        }
    }

    private static int Usage()
    {
        WriteJson(new
        {
            ok = false,
            usage = new[]
            {
                "SentionceMutationFirewall status [--policy PATH]",
                "SentionceMutationFirewall evaluate --path PATH [--policy PATH]",
                "SentionceMutationFirewall scan-command (--command TEXT | --command-file PATH) [--policy PATH]",
                "SentionceMutationFirewall quarantine --path PATH [--reason TEXT] [--policy PATH]",
                "SentionceMutationFirewall replace --target PATH --source STAGED_PATH [--reason TEXT] [--policy PATH]",
                "SentionceMutationFirewall move --source PATH --destination PATH [--reason TEXT] [--policy PATH]",
                "SentionceMutationFirewall restore --manifest MANIFEST_PATH [--replace-existing true] [--policy PATH]",
                "SentionceMutationFirewall selftest [--policy PATH]"
            }
        });
        return 1;
    }

    private static int Status()
    {
        WriteJson(new
        {
            ok = true,
            service = "Sentionce Mutation Firewall",
            mode = "deterministic-prototype",
            policyPath = _policyPath,
            policyVersion = _policy.PolicyVersion,
            denyReparsePoints = _policy.DenyReparsePoints,
            limits = _policy.AutoLimits,
            protectedRoots = _policy.ProtectedRoots,
            protectedExactPaths = _policy.ProtectedExactPaths,
            quarantineRoots = _policy.QuarantineRoots
        });
        return 0;
    }

    private static int EvaluateCommand(Dictionary<string, string> options)
    {
        var path = Require(options, "path");
        var decision = EvaluatePath(path, includeStats: true);
        WriteJson(new { ok = true, decision });
        return decision.Allowed ? 0 : 2;
    }

    private static int ScanCommand(Dictionary<string, string> options)
    {
        var command = options.TryGetValue("command", out var inlineCommand) && !string.IsNullOrWhiteSpace(inlineCommand)
            ? inlineCommand
            : options.TryGetValue("command-file", out var commandFile) && File.Exists(commandFile)
                ? File.ReadAllText(commandFile)
                : throw new ArgumentException("Provide --command or --command-file.");
        var findings = AnalyzeCommand(command);
        var max = MaxSeverity(findings);
        var rawExecutionAllowed = max is "None" or "Low";
        WriteJson(new
        {
            ok = true,
            rawExecutionAllowed,
            requiresBroker = max is "Medium" or "High",
            blocked = max == "Critical",
            maximumSeverity = max,
            findings
        });
        return rawExecutionAllowed ? 0 : 2;
    }

    private static int QuarantineCommand(Dictionary<string, string> options)
    {
        var target = Require(options, "path");
        var reason = options.GetValueOrDefault("reason") ?? "unspecified";

        var decision = EvaluatePath(target, includeStats: true);
        if (!decision.Allowed)
            return Block("quarantine", decision.CanonicalPath, decision.Reasons);

        if (!decision.Exists)
            return Block("quarantine", decision.CanonicalPath, new() { "Target does not exist." });

        var stats = decision.Stats!;
        if (ExceedsLimits(stats))
        {
            return Block("quarantine", decision.CanonicalPath, new()
            {
                $"Blast radius exceeds automatic policy: files={stats.Files}/{_policy.AutoLimits.MaxFiles}, directories={stats.Directories}/{_policy.AutoLimits.MaxDirectories}, bytes={stats.Bytes}/{_policy.AutoLimits.MaxBytes}."
            });
        }

        var hash = File.Exists(decision.CanonicalPath) ? Sha256(decision.CanonicalPath) : null;
        var destination = QuarantinePath(decision.CanonicalPath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);

        if (File.Exists(decision.CanonicalPath))
            File.Move(decision.CanonicalPath, destination);
        else
            Directory.Move(decision.CanonicalPath, destination);

        var record = new
        {
            operation = "quarantine",
            timestampUtc = DateTimeOffset.UtcNow,
            originalPath = decision.CanonicalPath,
            quarantinedPath = destination,
            reason,
            sha256 = hash,
            stats
        };
        WriteManifest(destination, record);
        Audit("quarantine", "allowed", decision.CanonicalPath, destination, reason, stats);

        WriteJson(new { ok = true, recycled = false, quarantined = true, originalPath = decision.CanonicalPath, quarantinePath = destination, stats });
        return 0;
    }

    private static int ReplaceCommand(Dictionary<string, string> options)
    {
        var targetInput = Require(options, "target");
        var sourceInput = Require(options, "source");
        var reason = options.GetValueOrDefault("reason") ?? "unspecified";

        var target = EvaluatePath(targetInput, includeStats: true);
        if (!target.Allowed)
            return Block("replace", target.CanonicalPath, target.Reasons);

        var sourceDecision = EvaluatePath(sourceInput, includeStats: true);
        if (!sourceDecision.Allowed)
            return Block("replace-source", sourceDecision.CanonicalPath, sourceDecision.Reasons);
        if (!sourceDecision.Exists || sourceDecision.Type != "file")
            return Block("replace", target.CanonicalPath, new() { "Staged source file does not exist or is not a regular file." });

        var source = sourceDecision.CanonicalPath;
        if (!SameVolume(source, target.CanonicalPath))
            return Block("replace", target.CanonicalPath, new() { "Staged source and target must be on the same volume for atomic replacement." });

        var sourceInfo = new FileInfo(source);
        if (sourceInfo.Length > _policy.AutoLimits.MaxBytes)
            return Block("replace", target.CanonicalPath, new() { $"Staged source exceeds automatic byte limit: {sourceInfo.Length}." });

        string? previous = null;
        if (target.Exists)
        {
            var result = QuarantineInternal(target.CanonicalPath, reason: "pre-replace checkpoint");
            previous = result;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(target.CanonicalPath)!);
        File.Move(source, target.CanonicalPath);

        var hash = Sha256(target.CanonicalPath);
        Audit("replace", "allowed", target.CanonicalPath, previous, reason, new { sha256 = hash, bytes = sourceInfo.Length });
        WriteJson(new
        {
            ok = true,
            target = target.CanonicalPath,
            previousVersionQuarantined = previous is not null,
            previousVersionPath = previous,
            sha256 = hash
        });
        return 0;
    }

    private static int MoveCommand(Dictionary<string, string> options)
    {
        var sourceInput = Require(options, "source");
        var destinationInput = Require(options, "destination");
        var reason = options.GetValueOrDefault("reason") ?? "unspecified";

        var source = EvaluatePath(sourceInput, includeStats: true);
        if (!source.Allowed)
            return Block("move-source", source.CanonicalPath, source.Reasons);
        if (!source.Exists)
            return Block("move-source", source.CanonicalPath, new() { "Source does not exist." });

        var destination = EvaluatePath(destinationInput, includeStats: true);
        if (!destination.Allowed)
            return Block("move-destination", destination.CanonicalPath, destination.Reasons);

        if (!SameVolume(source.CanonicalPath, destination.CanonicalPath))
            return Block("move", destination.CanonicalPath, new() { "Cross-volume moves are denied by the prototype." });

        var stats = source.Stats!;
        if (ExceedsLimits(stats))
            return Block("move", source.CanonicalPath, new() { "Source exceeds automatic blast-radius limits." });

        string? previous = null;
        if (destination.Exists)
            previous = QuarantineInternal(destination.CanonicalPath, "pre-move destination checkpoint");

        Directory.CreateDirectory(Path.GetDirectoryName(destination.CanonicalPath)!);

        if (File.Exists(source.CanonicalPath))
            File.Move(source.CanonicalPath, destination.CanonicalPath);
        else
            Directory.Move(source.CanonicalPath, destination.CanonicalPath);

        Audit("move", "allowed", source.CanonicalPath, destination.CanonicalPath, reason, new { previousDestination = previous, stats });
        WriteJson(new { ok = true, source = source.CanonicalPath, destination = destination.CanonicalPath, previousDestinationQuarantined = previous is not null, previousDestinationPath = previous });
        return 0;
    }


    private static int RestoreCommand(Dictionary<string, string> options)
    {
        var manifestPath = Normalize(Require(options, "manifest"));
        var manifestDecision = EvaluateQuarantineArtifact(manifestPath);
        if (!manifestDecision.Allowed)
            return Block("restore", manifestPath, manifestDecision.Reasons);
        if (!File.Exists(manifestPath))
            return Block("restore", manifestPath, new() { "Manifest does not exist." });

        using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath));
        var root = doc.RootElement;
        var original = Normalize(root.GetProperty("originalPath").GetString() ?? throw new InvalidOperationException("Manifest missing originalPath."));
        var quarantined = Normalize(root.GetProperty("quarantinedPath").GetString() ?? throw new InvalidOperationException("Manifest missing quarantinedPath."));
        var expectedHash = root.TryGetProperty("sha256", out var hashProp) && hashProp.ValueKind == JsonValueKind.String
            ? hashProp.GetString()
            : null;

        var originalDecision = EvaluatePath(original, includeStats: true);
        if (!originalDecision.Allowed)
            return Block("restore", original, originalDecision.Reasons);

        var qDecision = EvaluateQuarantineArtifact(quarantined);
        if (!qDecision.Allowed)
            return Block("restore", quarantined, qDecision.Reasons);
        if (!File.Exists(quarantined) && !Directory.Exists(quarantined))
            return Block("restore", quarantined, new() { "Quarantined payload is missing." });

        if (!string.IsNullOrWhiteSpace(expectedHash) && File.Exists(quarantined))
        {
            var actualHash = Sha256(quarantined);
            if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                return Block("restore", quarantined, new() { "Quarantined file hash does not match its manifest." });
        }

        var replaceExisting = options.TryGetValue("replace-existing", out var replaceValue)
                              && bool.TryParse(replaceValue, out var replaceBool)
                              && replaceBool;

        string? displaced = null;
        if (File.Exists(original) || Directory.Exists(original))
        {
            if (!replaceExisting)
                return Block("restore", original, new() { "Original path is occupied. Use --replace-existing true to checkpoint it first." });
            displaced = QuarantineInternal(original, "pre-restore checkpoint");
        }

        if (!SameVolume(original, quarantined))
            return Block("restore", original, new() { "Restore must remain on the same volume." });

        Directory.CreateDirectory(Path.GetDirectoryName(original)!);
        if (File.Exists(quarantined))
            File.Move(quarantined, original);
        else
            Directory.Move(quarantined, original);

        Audit("restore", "allowed", original, quarantined, "restore from quarantine manifest", new { displaced });
        WriteJson(new
        {
            ok = true,
            restored = true,
            originalPath = original,
            from = quarantined,
            displacedCurrentVersion = displaced
        });
        return 0;
    }

    private static PathDecision EvaluateQuarantineArtifact(string input)
    {
        var reasons = new List<string>();
        string canonical;
        try { canonical = Normalize(input); }
        catch (Exception ex)
        {
            return new(false, input, input, null, false, null, null, new() { "Path normalization failed: " + ex.Message });
        }

        var insideQuarantine = _policy.QuarantineRoots.Values
            .Select(Normalize)
            .Any(q => IsSameOrChild(canonical, q));

        if (!insideQuarantine)
            reasons.Add("Restore source is not inside an approved quarantine root.");

        var exists = File.Exists(canonical) || Directory.Exists(canonical);
        var type = File.Exists(canonical) ? "file" : Directory.Exists(canonical) ? "directory" : null;
        return new(reasons.Count == 0, input, canonical, NearestExisting(canonical), exists, type, null, reasons);
    }

    private static int SelfTest()
    {
        var failures = new List<string>();
        var passed = new List<string>();

        void Check(bool condition, string name)
        {
            if (condition) passed.Add(name);
            else failures.Add(name);
        }

        Check(Normalize(@"C:\") == @"C:\", "drive-root normalization");
        Check(AnalyzeCommand("nvidia-smi --query-gpu=name --format=csv,noheader").Count == 0, "safe --format does not false-positive");
        Check(MaxSeverity(AnalyzeCommand(@"Remove-Item -LiteralPath C:\Projects\Thing -Recurse -Force")) == "Critical", "Remove-Item is critical");
        Check(MaxSeverity(AnalyzeCommand(@"robocopy C:\src C:\dst /MIR")) == "Critical", "robocopy /MIR is critical");
        Check(MaxSeverity(AnalyzeCommand(@"echo x > C:\Projects\Thing\file.txt")) == "High", "overwrite redirection requires broker");
        Check(!EvaluatePath(@"C:\Windows\System32", false).Allowed, "Windows protected root blocked");
        Check(!EvaluatePath(@"C:\", false).Allowed, "drive root blocked");
        Check(EvaluatePath(@"C:\Projects\SomeProject\file.txt", false).Allowed, "project child path allowed");

        var testRoot = Path.Combine(@"C:\Projects", "_SentionceMutationFirewallSelfTest-" + Environment.ProcessId + "-" + DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss"));
        Directory.CreateDirectory(testRoot);
        var file = Path.Combine(testRoot, "sample.txt");
        File.WriteAllText(file, "selftest-original", Encoding.UTF8);

        try
        {
            var q = QuarantineInternal(file, "selftest");
            Check(!File.Exists(file), "quarantine removes original path");
            Check(File.Exists(q), "quarantine payload exists");
            Check(File.ReadAllText(q, Encoding.UTF8) == "selftest-original", "quarantine preserves content");

            var manifest = q + ".sentionce-quarantine.json";
            Check(File.Exists(manifest), "quarantine manifest exists");

            var restoreOptions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["manifest"] = manifest
            };

            // Inline restore logic without emitting nested JSON.
            using var doc = JsonDocument.Parse(File.ReadAllText(manifest));
            var original = Normalize(doc.RootElement.GetProperty("originalPath").GetString()!);
            var quarantined = Normalize(doc.RootElement.GetProperty("quarantinedPath").GetString()!);
            var expectedHash = doc.RootElement.TryGetProperty("sha256", out var hp) && hp.ValueKind == JsonValueKind.String ? hp.GetString() : null;
            var hashOkay = string.IsNullOrWhiteSpace(expectedHash) || string.Equals(expectedHash, Sha256(quarantined), StringComparison.OrdinalIgnoreCase);
            Check(hashOkay, "quarantine hash verifies");
            if (hashOkay)
            {
                File.Move(quarantined, original);
                Check(File.Exists(original), "restore returns original path");
                Check(File.ReadAllText(original, Encoding.UTF8) == "selftest-original", "restore preserves content");
            }
        }
        finally
        {
            if (Directory.Exists(testRoot))
            {
                try { QuarantineInternal(testRoot, "selftest cleanup"); }
                catch (Exception ex) { failures.Add("selftest cleanup: " + ex.Message); }
            }
        }

        WriteJson(new
        {
            ok = failures.Count == 0,
            passedCount = passed.Count,
            failedCount = failures.Count,
            passed,
            failures
        });
        return failures.Count == 0 ? 0 : 1;
    }

    private static string QuarantineInternal(string canonicalPath, string reason)
    {
        var decision = EvaluatePath(canonicalPath, includeStats: true);
        if (!decision.Allowed || !decision.Exists)
            throw new InvalidOperationException("Internal quarantine refused target: " + canonicalPath);

        var hash = File.Exists(canonicalPath) ? Sha256(canonicalPath) : null;
        var destination = QuarantinePath(canonicalPath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);

        if (File.Exists(canonicalPath))
            File.Move(canonicalPath, destination);
        else
            Directory.Move(canonicalPath, destination);

        var record = new
        {
            operation = "quarantine",
            timestampUtc = DateTimeOffset.UtcNow,
            originalPath = canonicalPath,
            quarantinedPath = destination,
            reason,
            sha256 = hash,
            stats = decision.Stats
        };
        WriteManifest(destination, record);
        Audit("quarantine", "allowed", canonicalPath, destination, reason, decision.Stats);
        return destination;
    }

    private static PathDecision EvaluatePath(string input, bool includeStats)
    {
        var reasons = new List<string>();
        string canonical;
        try { canonical = Normalize(input); }
        catch (Exception ex)
        {
            return new(false, input, input, null, false, null, null, new() { "Path normalization failed: " + ex.Message });
        }

        var root = Path.GetPathRoot(canonical) ?? "";
        if (string.Equals(TrimSep(canonical), TrimSep(root), StringComparison.OrdinalIgnoreCase))
            reasons.Add("Drive roots are immutable.");

        foreach (var exact in _policy.ProtectedExactPaths)
        {
            if (string.Equals(TrimSep(canonical), TrimSep(Normalize(exact)), StringComparison.OrdinalIgnoreCase))
                reasons.Add($"Exact protected path: {Normalize(exact)}");
        }

        foreach (var protectedRoot in _policy.ProtectedRoots)
        {
            var p = Normalize(protectedRoot);
            if (IsSameOrChild(canonical, p))
                reasons.Add($"Inside protected root: {p}");
        }

        foreach (var q in _policy.QuarantineRoots.Values)
        {
            var qp = Normalize(q);
            if (IsSameOrChild(canonical, qp))
                reasons.Add($"Quarantine storage is immutable to agent mutations: {qp}");
        }

        var existingAnchor = NearestExisting(canonical);
        var reparse = ExistingReparseAncestors(canonical);
        if (_policy.DenyReparsePoints && reparse.Count > 0)
            reasons.Add("Path traverses reparse point(s): " + string.Join(", ", reparse));

        var exists = File.Exists(canonical) || Directory.Exists(canonical);
        string? type = File.Exists(canonical) ? "file" : Directory.Exists(canonical) ? "directory" : null;
        TreeStats? stats = null;
        if (includeStats && exists)
        {
            stats = Measure(canonical);
            if (_policy.DenyReparsePoints && stats.ReparsePoints.Count > 0)
                reasons.Add("Target tree contains reparse point(s): " + string.Join(", ", stats.ReparsePoints.Take(10)));
        }

        return new(reasons.Count == 0, input, canonical, existingAnchor, exists, type, stats, reasons);
    }

    private static TreeStats Measure(string path)
    {
        if (File.Exists(path))
        {
            var attrs = File.GetAttributes(path);
            var links = attrs.HasFlag(FileAttributes.ReparsePoint) ? new List<string> { path } : new List<string>();
            return new(1, 0, new FileInfo(path).Length, links);
        }

        long files = 0, dirs = 1, bytes = 0;
        var linksFound = new List<string>();
        var stack = new Stack<string>();
        stack.Push(path);

        while (stack.Count > 0)
        {
            var current = stack.Pop();
            foreach (var entry in Directory.EnumerateFileSystemEntries(current))
            {
                var attrs = File.GetAttributes(entry);
                if (attrs.HasFlag(FileAttributes.ReparsePoint))
                {
                    linksFound.Add(entry);
                    continue;
                }

                if (attrs.HasFlag(FileAttributes.Directory))
                {
                    dirs++;
                    stack.Push(entry);
                }
                else
                {
                    files++;
                    bytes += new FileInfo(entry).Length;
                }

                if (files > _policy.AutoLimits.MaxFiles + 1
                    || dirs > _policy.AutoLimits.MaxDirectories + 1
                    || bytes > _policy.AutoLimits.MaxBytes + 1)
                    return new(files, dirs, bytes, linksFound);
            }
        }

        return new(files, dirs, bytes, linksFound);
    }

    private static List<string> ExistingReparseAncestors(string canonical)
    {
        var found = new List<string>();
        var root = Path.GetPathRoot(canonical);
        if (string.IsNullOrWhiteSpace(root)) return found;

        var relative = canonical[root.Length..];
        var parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Where(x => !string.IsNullOrWhiteSpace(x));

        var current = root;
        foreach (var part in parts)
        {
            current = Path.Combine(current, part);
            if (!File.Exists(current) && !Directory.Exists(current)) break;
            try
            {
                if (File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint))
                    found.Add(current);
            }
            catch { }
        }
        return found;
    }

    private static string? NearestExisting(string canonical)
    {
        var p = canonical;
        while (!string.IsNullOrWhiteSpace(p))
        {
            if (File.Exists(p) || Directory.Exists(p)) return p;
            var parent = Directory.GetParent(p);
            if (parent is null) return Path.GetPathRoot(canonical);
            p = parent.FullName;
        }
        return null;
    }

    private static string QuarantinePath(string canonical)
    {
        var root = Path.GetPathRoot(canonical) ?? throw new InvalidOperationException("Target has no volume root.");
        var qroot = _policy.QuarantineRoots
            .FirstOrDefault(kv => string.Equals(TrimSep(kv.Key), TrimSep(root), StringComparison.OrdinalIgnoreCase))
            .Value;

        if (string.IsNullOrWhiteSpace(qroot))
            qroot = Path.Combine(root, "SentionceQuarantine");

        qroot = Normalize(qroot);
        Directory.CreateDirectory(qroot);

        var relative = canonical[root.Length..].TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmss.fffffffZ");
        var leaf = Path.GetFileName(canonical.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        if (string.IsNullOrWhiteSpace(leaf)) leaf = "root";

        var safeRelParent = Path.GetDirectoryName(relative) ?? "";
        var destinationDir = Path.Combine(qroot, stamp, safeRelParent);
        var destination = Path.Combine(destinationDir, leaf);

        var n = 0;
        while (File.Exists(destination) || Directory.Exists(destination))
            destination = Path.Combine(destinationDir, $"{leaf}.{++n}");

        return destination;
    }

    private static void WriteManifest(string quarantinedPath, object record)
    {
        var manifest = quarantinedPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + ".sentionce-quarantine.json";
        File.WriteAllText(manifest, JsonSerializer.Serialize(record, JsonOptions), Encoding.UTF8);
    }

    private static void Audit(string operation, string outcome, string target, string? related, string reason, object? details)
    {
        var log = Normalize(_policy.AuditLog);
        Directory.CreateDirectory(Path.GetDirectoryName(log)!);
        var record = new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            operation,
            outcome,
            target,
            related,
            reason,
            details,
            pid = Environment.ProcessId,
            user = Environment.UserName,
            machine = Environment.MachineName
        };
        File.AppendAllText(log, JsonSerializer.Serialize(record) + Environment.NewLine, Encoding.UTF8);
    }

    private static int Block(string operation, string target, List<string> reasons)
    {
        Audit(operation, "blocked", target, null, string.Join(" | ", reasons), null);
        WriteJson(new { ok = false, blocked = true, operation, target, reasons });
        return 2;
    }

    private static List<Finding> AnalyzeCommand(string command)
    {
        var findings = new List<Finding>();

        void Add(string severity, string category, string pattern, string explanation, RegexOptions options = RegexOptions.IgnoreCase)
        {
            var m = Regex.Match(command, pattern, options);
            if (m.Success) findings.Add(new(severity, category, m.Value, explanation));
        }

        Add("Critical", "raw-delete", @"(?<![\w-])Remove-Item\b", "PowerShell Remove-Item can permanently remove filesystem objects.");
        Add("Critical", "raw-delete", @"(?:^|[;&|]\s*)(?:del|erase|rd|rmdir|rm|unlink|shred)(?:\.exe)?(?:\s|$)", "Direct shell deletion command.");
        Add("Critical", "disk-destructive", @"(?:^|[;&|]\s*)(?:format(?:\.com)?|diskpart)(?:\s|$)", "Disk/volume destructive executable. Anchored so --format options do not match.");
        Add("Critical", "disk-destructive", @"(?<![\w-])(?:Clear-Disk|Initialize-Disk|Format-Volume|Remove-Partition|Remove-Volume)\b", "PowerShell storage mutation capable of destroying disk/volume state.");
        Add("Critical", "filesystem-api-delete", @"(?:fs\.(?:promises\.)?(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)|shutil\.rmtree|os\.(?:remove|unlink|rmdir)|pathlib\.[^\r\n]*\.(?:unlink|rmdir)\s*\(|Files\.delete(?:IfExists)?\s*\(|remove_dir_all\s*\(|FileSystem\.Delete(?:File|Directory)|System\.IO\.(?:File|Directory)\]?\s*::\s*Delete|\.(?:Delete)\s*\(\s*\))", "Programmatic deletion API.");
        Add("High", "content-destruction", @"(?<![\w-])(?:Clear-Content|Set-Content|Out-File)\b|(?:WriteAllText|WriteAllBytes|writeFileSync|writeFile)\s*\(", "Content operation can empty or overwrite files.");
        Add("High", "redirect-overwrite", @"(?<!>)>(?!>)", "Shell output redirection can truncate an existing file.");
        Add("Critical", "git-clean", @"\bgit\s+clean\b", "Git clean can remove untracked files/directories.");
        Add("High", "git-hard-reset", @"\bgit\s+reset\s+--hard\b", "Git hard reset discards working-tree/index changes.");
        Add("High", "git-restore", @"\bgit\s+(?:checkout|restore)\b", "Git checkout/restore can discard local file content depending on arguments.");
        Add("Critical", "mirror-delete", @"\brobocopy\b[^\r\n]*(?:/MIR|/PURGE)\b", "Robocopy mirror/purge deletes destination entries absent from source.");
        Add("Critical", "sync-delete", @"\brsync\b[^\r\n]*--delete(?:\b|=)", "rsync --delete removes receiver-side files.");
        Add("High", "package-clean", @"\bnpm\s+ci\b", "npm ci removes existing node_modules before reinstalling.");
        Add("Critical", "docker-destructive", @"\bdocker\s+(?:system|container|image|volume|network)\s+prune\b|\bdocker\s+(?:rm|rmi)\b|\bdocker\s+volume\s+rm\b|\bdocker\s+compose\s+down\b[^\r\n]*(?:-v|--volumes)\b", "Docker cleanup may permanently remove containers/images/volumes.");
        Add("Critical", "backup-destruction", @"\bvssadmin\s+delete\s+shadows\b|\bwmic\s+shadowcopy\s+delete\b|(?:^|[;&|]\s*)diskshadow(?:\.exe)?(?:\s|$)", "Command can remove Volume Shadow Copy recovery data.");
        Add("Critical", "virtualized-storage-destruction", @"\bwsl(?:\.exe)?\s+--unregister\b", "WSL unregister permanently removes a distribution and its filesystem.");
        Add("High", "force-overwrite", @"(?<![\w-])(?:Copy-Item|Move-Item|Expand-Archive)\b[^\r\n]*-Force\b|(?:^|[;&|]\s*)(?:cp|mv)(?:\.exe)?\b[^\r\n]*\s-f(?:\s|$)|\bxcopy\b[^\r\n]*/Y\b", "Force-overwrite operation requires destination checkpointing.");
        Add("High", "build-clean", @"\b(?:dotnet\s+clean|cargo\s+clean|mvn(?:\.cmd)?\s+clean|gradle(?:\.bat)?\s+clean|msbuild(?:\.exe)?\b[^\r\n]*/t:Clean)\b", "Build clean removes generated trees and should be constrained to a verified project root.");
        Add("High", "archive-overwrite", @"\b7z(?:\.exe)?\s+x\b[^\r\n]*-aoa\b", "7-Zip overwrite-all extraction can replace existing files.");
        Add("High", "download-overwrite", @"\b(?:curl|wget)(?:\.exe)?\b[^\r\n]*(?:\s-o\s|\s--output(?:=|\s))", "Download command may overwrite destination.");
        Add("Critical", "opaque-script", @"\bpowershell(?:\.exe)?\b[^\r\n]*(?:-EncodedCommand|-enc)\b", "Encoded PowerShell obscures the payload from command inspection.");
        Add("High", "indirect-script", @"(?:^|[;&|]\s*)(?:powershell|pwsh|cmd|python|python3|node|wscript|cscript|bash)(?:\.exe)?\b[^\r\n]*(?:-File\b|/c\b|-c\b|\.(?:ps1|cmd|bat|py|js|vbs)\b)", "Indirect script execution requires payload inspection, not only command-line inspection.");

        return findings
            .GroupBy(f => (f.Category, f.Match), StringTupleComparer.Instance)
            .Select(g => g.First())
            .ToList();
    }

    private static string MaxSeverity(List<Finding> findings)
    {
        if (findings.Count == 0) return "None";
        var rank = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["None"] = 0, ["Low"] = 1, ["Medium"] = 2, ["High"] = 3, ["Critical"] = 4
        };
        return findings.OrderByDescending(f => rank.GetValueOrDefault(f.Severity, 0)).First().Severity;
    }

    private static bool ExceedsLimits(TreeStats stats)
        => stats.Files > _policy.AutoLimits.MaxFiles
           || stats.Directories > _policy.AutoLimits.MaxDirectories
           || stats.Bytes > _policy.AutoLimits.MaxBytes;

    private static string Sha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static bool SameVolume(string a, string b)
        => string.Equals(TrimSep(Path.GetPathRoot(a) ?? ""), TrimSep(Path.GetPathRoot(b) ?? ""), StringComparison.OrdinalIgnoreCase);

    private static bool IsSameOrChild(string candidate, string parent)
    {
        candidate = TrimSep(candidate);
        parent = TrimSep(parent);
        return string.Equals(candidate, parent, StringComparison.OrdinalIgnoreCase)
            || candidate.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) throw new ArgumentException("Path is empty.");
        var expanded = Environment.ExpandEnvironmentVariables(input.Trim().Trim('"'));
        var full = Path.GetFullPath(expanded);
        var root = Path.GetPathRoot(full);
        if (!string.IsNullOrWhiteSpace(root) && string.Equals(full, root, StringComparison.OrdinalIgnoreCase))
            return root;
        return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static string TrimSep(string p)
    {
        var root = Path.GetPathRoot(p);
        if (!string.IsNullOrEmpty(root) && string.Equals(p, root, StringComparison.OrdinalIgnoreCase))
            return root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return p.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static Policy LoadPolicy(string path)
    {
        var json = File.ReadAllText(path);
        var policy = JsonSerializer.Deserialize<Policy>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                     ?? throw new InvalidOperationException("Policy deserialized to null.");
        policy.ProtectedRoots ??= new();
        policy.ProtectedExactPaths ??= new();
        policy.QuarantineRoots = new Dictionary<string, string>(policy.QuarantineRoots ?? new(), StringComparer.OrdinalIgnoreCase);
        policy.AutoLimits ??= new Limits();
        return policy;
    }

    private static string Require(Dictionary<string, string> options, string key)
        => options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException($"Missing --{key}.");

    private sealed record Parsed(string Command, Dictionary<string, string> Options);

    private static Parsed ParseArgs(string[] args)
    {
        if (args.Length == 0) return new("", new(StringComparer.OrdinalIgnoreCase));
        var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 1; i < args.Length; i++)
        {
            var a = args[i];
            if (!a.StartsWith("--")) continue;
            var key = a[2..];
            var value = i + 1 < args.Length && !args[i + 1].StartsWith("--") ? args[++i] : "true";
            options[key] = value;
        }
        return new(args[0], options);
    }

    private static void WriteJson(object value)
        => Console.WriteLine(JsonSerializer.Serialize(value, JsonOptions));

    private sealed class StringTupleComparer : IEqualityComparer<(string Category, string Match)>
    {
        public static readonly StringTupleComparer Instance = new();
        public bool Equals((string Category, string Match) x, (string Category, string Match) y)
            => string.Equals(x.Category, y.Category, StringComparison.OrdinalIgnoreCase)
               && string.Equals(x.Match, y.Match, StringComparison.OrdinalIgnoreCase);
        public int GetHashCode((string Category, string Match) obj)
            => HashCode.Combine(obj.Category.ToLowerInvariant(), obj.Match.ToLowerInvariant());
    }
}
