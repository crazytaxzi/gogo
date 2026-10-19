using System.Diagnostics;
using System.IO.Pipes;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;

namespace Sentionce.MutationFirewall.Service;

internal sealed class BrokerRequest
{
    public string[] Args { get; set; } = Array.Empty<string>();
}

internal sealed class FirewallWindowsService : ServiceBase
{
    private readonly CancellationTokenSource _cts = new();
    private Task? _serverTask;
    private readonly string _root;

    public FirewallWindowsService(string root)
    {
        _root = root;
        ServiceName = "SentionceMutationFirewall";
        CanStop = true;
        CanShutdown = true;
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        _serverTask = Task.Run(() => BrokerServer.RunAsync(_root, _cts.Token));
    }

    protected override void OnStop()
    {
        _cts.Cancel();
        try { _serverTask?.Wait(TimeSpan.FromSeconds(5)); } catch { }
    }

    protected override void OnShutdown() => OnStop();
}

internal static class BrokerServer
{
    private const string PipeName = "SentionceMutationFirewall.v1";
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static async Task RunAsync(string root, CancellationToken token)
    {
        Directory.CreateDirectory(Path.Combine(root, "logs"));
        var log = Path.Combine(root, "logs", "broker-service.jsonl");
        Log(log, new { evt = "broker_start", pipe = PipeName, root, pid = Environment.ProcessId });

        while (!token.IsCancellationRequested)
        {
            var pipe = new NamedPipeServerStream(
                PipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            try
            {
                await pipe.WaitForConnectionAsync(token);
                _ = Task.Run(() => HandleClientAsync(pipe, root, log, token), CancellationToken.None);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                await pipe.DisposeAsync();
                break;
            }
            catch (Exception ex)
            {
                await pipe.DisposeAsync();
                Log(log, new { evt = "accept_error", error = ex.Message });
                try { await Task.Delay(500, token); } catch { }
            }
        }

        Log(log, new { evt = "broker_stop", pid = Environment.ProcessId });
    }

    private static async Task HandleClientAsync(NamedPipeServerStream pipe, string root, string log, CancellationToken token)
    {
        await using (pipe)
        using (var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 65536, leaveOpen: true))
        using (var writer = new StreamWriter(pipe, new UTF8Encoding(false), 65536, leaveOpen: true) { AutoFlush = true })
        {
            try
            {
                var line = await reader.ReadLineAsync(token);
                if (string.IsNullOrWhiteSpace(line))
                {
                    await writer.WriteLineAsync("{\"ok\":false,\"error\":\"empty_request\"}");
                    return;
                }

                var request = JsonSerializer.Deserialize<BrokerRequest>(line, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                }) ?? new BrokerRequest();

                if (request.Args.Length == 0)
                {
                    await writer.WriteLineAsync("{\"ok\":false,\"error\":\"missing_args\"}");
                    return;
                }

                var result = ExecuteCli(root, request.Args);
                Log(log, new
                {
                    evt = "request",
                    command = request.Args[0],
                    exitCode = result.ExitCode,
                    ok = result.ExitCode == 0
                });

                await writer.WriteLineAsync(JsonSerializer.Serialize(new
                {
                    ok = result.ExitCode == 0,
                    exitCode = result.ExitCode,
                    stdout = result.Stdout,
                    stderr = result.Stderr
                }, JsonOptions));
            }
            catch (Exception ex)
            {
                Log(log, new { evt = "request_error", error = ex.Message });
                try
                {
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new
                    {
                        ok = false,
                        error = ex.GetType().Name,
                        message = ex.Message
                    }, JsonOptions));
                }
                catch { }
            }
        }
    }

    private static (int ExitCode, string Stdout, string Stderr) ExecuteCli(string root, string[] requestArgs)
    {
        var exe = Path.Combine(root, "publish", "SentionceMutationFirewall.exe");
        var policy = Path.Combine(root, "policy.json");

        if (!File.Exists(exe))
            return (127, "", "Mutation Firewall executable not found: " + exe);
        if (!File.Exists(policy))
            return (127, "", "Mutation Firewall policy not found: " + policy);

        var args = new List<string>(requestArgs);
        if (!args.Any(x => string.Equals(x, "--policy", StringComparison.OrdinalIgnoreCase)))
        {
            args.Add("--policy");
            args.Add(policy);
        }

        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = root
        };
        foreach (var arg in args) psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start Mutation Firewall CLI.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit(120_000))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            return (124, "", "Mutation Firewall CLI timed out.");
        }

        Task.WaitAll(stdoutTask, stderrTask);
        return (process.ExitCode, Clamp(stdoutTask.Result), Clamp(stderrTask.Result));
    }

    private static string Clamp(string text)
        => text.Length <= 2_000_000 ? text : text[..2_000_000] + "\n...[truncated]";

    private static void Log(string path, object value)
    {
        try
        {
            var row = JsonSerializer.Serialize(new
            {
                timestampUtc = DateTimeOffset.UtcNow,
                machine = Environment.MachineName,
                data = value
            });
            File.AppendAllText(path, row + Environment.NewLine, Encoding.UTF8);
        }
        catch { }
    }

    public static string GetPipeName() => PipeName;
}

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var root = Environment.GetEnvironmentVariable("SENTIONCE_MUTATION_FIREWALL_ROOT")
                   ?? @"E:\SentionceRecovery\MutationFirewall";

        if (args.Any(x => string.Equals(x, "--console", StringComparison.OrdinalIgnoreCase)))
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                ok = true,
                mode = "console",
                pipe = BrokerServer.GetPipeName(),
                root
            }));

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            await BrokerServer.RunAsync(root, cts.Token);
            return 0;
        }

        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Windows service mode requires Windows.");
            return 1;
        }

        ServiceBase.Run(new FirewallWindowsService(root));
        return 0;
    }
}
