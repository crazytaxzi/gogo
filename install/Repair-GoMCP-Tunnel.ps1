param([switch]$NoPause)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Is-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Is-Admin)) {
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $PSCommandPath + '"'))
    if ($NoPause) { $args += '-NoPause' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList ($args -join ' ') -Verb RunAs
    exit
}

$Desktop = [Environment]::GetFolderPath('Desktop')
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Log = Join-Path $Desktop ('GoMCP-TUNNEL-REPAIR-' + $Stamp + '.log')
$Fail = Join-Path $Desktop 'GoMCP-TUNNEL-REPAIR-FAILED.txt'
$Success = Join-Path $Desktop 'GoMCP-TUNNEL-REPAIR-SUCCESS.txt'

function Big([string]$Text,[ConsoleColor]$Color=[ConsoleColor]::White) {
    Write-Host ''
    Write-Host ('=' * 94) -ForegroundColor $Color
    Write-Host ('  ' + $Text) -ForegroundColor $Color
    Write-Host ('=' * 94) -ForegroundColor $Color
    Write-Host ''
}

function Get-LocalHealth {
    try {
        $h = Invoke-RestMethod -UseBasicParsing -Uri 'http://127.0.0.1:8882/health' -TimeoutSec 4
        if ($h.ok -eq $true -and [int]$h.toolCount -eq 56) { return $h }
    } catch {}
    return $null
}

function Get-PublicMetadata {
    try {
        return Invoke-RestMethod -UseBasicParsing -Uri 'https://gamepc-mcp.sentionce.net/.well-known/oauth-protected-resource/mcp' -TimeoutSec 6
    } catch { return $null }
}

function Find-CloudflaredConfig {
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($p in @(
        'C:\ProgramData\SentionceTunnels\gamepc-mcp.yml',
        'C:\ProgramData\SentionceTunnels\gamepc-mcp.yaml',
        'C:\ProgramData\cloudflared\config.yml',
        'C:\ProgramData\cloudflared\config.yaml',
        (Join-Path $env:USERPROFILE '.cloudflared\config.yml'),
        (Join-Path $env:USERPROFILE '.cloudflared\config.yaml')
    )) { if ($p) { $candidates.Add($p) } }

    $procs = @(Get-CimInstance Win32_Process -Filter "Name='cloudflared.exe'" -ErrorAction SilentlyContinue)
    foreach ($p in $procs) {
        $cmd = [string]$p.CommandLine
        if ($cmd -match '--config(?:=|\s+)(?:"([^"]+)"|([^\s]+))') {
            $v = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
            if ($v) { $candidates.Add($v) }
        }
    }

    foreach ($p in ($candidates | Select-Object -Unique)) {
        if (-not (Test-Path $p)) { continue }
        try {
            $raw = Get-Content $p -Raw -ErrorAction Stop
            if ($raw -match '(?im)^\s*-\s*hostname:\s*["'']?gamepc-mcp\.sentionce\.net["'']?\s*$') {
                return [pscustomobject]@{ Path=$p; Raw=$raw; Processes=$procs }
            }
        } catch {}
    }

    $diag = @()
    foreach ($p in $procs) {
        $diag += ('PID ' + $p.ProcessId + ': ' + $p.CommandLine)
    }
    throw ('Could not find a surviving local Cloudflare config containing gamepc-mcp.sentionce.net. Running cloudflared processes: ' + ($diag -join ' | '))
}

function Patch-McpIngress([string]$ConfigPath) {
    $lines = @(Get-Content $ConfigPath -ErrorAction Stop)
    $hostIndex = -1
    for ($i=0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*-\s*hostname:\s*["'']?gamepc-mcp\.sentionce\.net["'']?\s*$') { $hostIndex=$i; break }
    }
    if ($hostIndex -lt 0) { throw 'MCP hostname rule was not found in the selected tunnel config.' }

    $serviceIndex = -1
    for ($j=$hostIndex+1; $j -lt [Math]::Min($lines.Count,$hostIndex+12); $j++) {
        if ($lines[$j] -match '^\s*-\s*(hostname|service):') { break }
        if ($lines[$j] -match '^(\s*)service:\s*') { $serviceIndex=$j; break }
    }
    if ($serviceIndex -lt 0) { throw 'MCP hostname rule has no service line to patch.' }

    $indent = ''
    if ($lines[$serviceIndex] -match '^(\s*)service:') { $indent = $Matches[1] }
    $old = $lines[$serviceIndex]
    $lines[$serviceIndex] = $indent + 'service: http://127.0.0.1:8882'
    [IO.File]::WriteAllLines($ConfigPath,$lines,[Text.UTF8Encoding]::new($false))
    return $old
}

try {
    Start-Transcript -Path $Log -Force | Out-Null
    Clear-Host
    Big 'GOMCP CLOUDFLARE TUNNEL REPAIR' Cyan
    Write-Host 'This will not touch the rebuilt GoMCP runtime.'
    Write-Host 'It will not stop the current tunnel until an updated replica is validated.'
    Write-Host ''

    Write-Host '[1/7] Verifying local GoMCP...'
    $health = Get-LocalHealth
    if (-not $health) { throw 'Local GoMCP is not healthy on 127.0.0.1:8882 with 56 tools.' }
    Write-Host 'Local GoMCP: healthy, 56 tools.' -ForegroundColor Green

    Write-Host '[2/7] Discovering the live Cloudflare tunnel config...'
    $found = Find-CloudflaredConfig
    $Config = $found.Path
    Write-Host ('Config: ' + $Config)

    $Backup = $Config + '.bak-gomcp-' + $Stamp
    Copy-Item $Config $Backup -Force
    Write-Host ('Backup: ' + $Backup)

    Write-Host '[3/7] Patching only gamepc-mcp.sentionce.net to port 8882...'
    $oldService = Patch-McpIngress $Config
    Write-Host ('Previous rule: ' + $oldService.Trim())
    Write-Host 'New rule:      service: http://127.0.0.1:8882' -ForegroundColor Green

    $Cloudflared = $null
    $cfProcs = @(Get-CimInstance Win32_Process -Filter "Name='cloudflared.exe'" -ErrorAction SilentlyContinue)
    foreach ($p in $cfProcs) {
        if ($p.ExecutablePath -and (Test-Path $p.ExecutablePath)) { $Cloudflared=$p.ExecutablePath; break }
    }
    if (-not $Cloudflared) {
        $cmd = Get-Command cloudflared.exe -ErrorAction SilentlyContinue
        if ($cmd) { $Cloudflared=$cmd.Source }
    }
    if (-not $Cloudflared) {
        foreach ($p in @('C:\Program Files\cloudflared\cloudflared.exe','C:\Projects\cloudflare-mcp-server\bin\cloudflared.exe')) {
            if (Test-Path $p) { $Cloudflared=$p; break }
        }
    }
    if (-not $Cloudflared) { Copy-Item $Backup $Config -Force; throw 'cloudflared.exe was not found.' }
    Write-Host ('cloudflared: ' + $Cloudflared)

    Write-Host '[4/7] Validating the patched ingress rules...'
    $validate = & $Cloudflared tunnel --config $Config ingress validate 2>&1
    if ($LASTEXITCODE -ne 0) {
        $validate = & $Cloudflared --config $Config tunnel ingress validate 2>&1
    }
    if ($LASTEXITCODE -ne 0) {
        Copy-Item $Backup $Config -Force
        throw ('cloudflared rejected the patched config: ' + ($validate -join ' '))
    }
    Write-Host 'Ingress config validated.' -ForegroundColor Green

    Write-Host '[5/7] Starting an updated tunnel replica without stopping the existing one...'
    $OldPids = @($cfProcs | ForEach-Object { [int]$_.ProcessId })
    $ReplicaOut = Join-Path $Desktop ('GoMCP-cloudflared-replica-' + $Stamp + '.out.log')
    $ReplicaErr = Join-Path $Desktop ('GoMCP-cloudflared-replica-' + $Stamp + '.err.log')
    $replica = Start-Process -FilePath $Cloudflared -ArgumentList @('tunnel','--config',$Config,'run') -WindowStyle Hidden -RedirectStandardOutput $ReplicaOut -RedirectStandardError $ReplicaErr -PassThru
    Start-Sleep -Seconds 8
    if ($replica.HasExited) {
        Copy-Item $Backup $Config -Force
        $why = if (Test-Path $ReplicaErr) { Get-Content $ReplicaErr -Raw -ErrorAction SilentlyContinue } else { '' }
        throw ('Updated cloudflared replica exited immediately. ' + $why)
    }

    Write-Host '[6/7] Waiting for the public MCP hostname to hit the updated replica...'
    $public = $null
    for ($i=0; $i -lt 30; $i++) {
        $public = Get-PublicMetadata
        if ($public -and $public.resource -eq 'https://gamepc-mcp.sentionce.net/mcp') { break }
        Start-Sleep -Seconds 2
    }
    if (-not $public) {
        try { Stop-Process -Id $replica.Id -Force -ErrorAction SilentlyContinue } catch {}
        Copy-Item $Backup $Config -Force
        throw 'Updated replica connected, but gamepc-mcp.sentionce.net still returned no valid OAuth metadata. Original config was restored and the old tunnel was left running.'
    }
    Write-Host 'Public MCP hostname is answering correctly.' -ForegroundColor Green

    Write-Host '[7/7] Retiring only the old replica for this same tunnel config...'
    $configEsc = [regex]::Escape($Config)
    $tunnelId = $null
    $cfgRaw = Get-Content $Config -Raw
    if ($cfgRaw -match '(?im)^\s*tunnel:\s*["'']?([0-9a-f-]{36})["'']?\s*$') { $tunnelId=$Matches[1] }

    $stopped = @()
    $current = @(Get-CimInstance Win32_Process -Filter "Name='cloudflared.exe'" -ErrorAction SilentlyContinue)
    foreach ($p in $current) {
        if ([int]$p.ProcessId -eq [int]$replica.Id) { continue }
        if ($OldPids -notcontains [int]$p.ProcessId) { continue }
        $cmdline = [string]$p.CommandLine
        $same = $false
        if ($cmdline -match $configEsc) { $same=$true }
        if (-not $same -and $tunnelId -and $cmdline -match [regex]::Escape($tunnelId)) { $same=$true }
        if ($same) {
            try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $stopped += $p.ProcessId } catch {}
        }
    }

    Start-Sleep -Seconds 4
    $final = Get-PublicMetadata
    if (-not $final -or $final.resource -ne 'https://gamepc-mcp.sentionce.net/mcp') {
        throw 'The patched tunnel worked before old-replica retirement, but final public verification failed. Leave the new cloudflared replica running and send Senti the repair log.'
    }

    $summary = @(
        'GoMCP tunnel repair SUCCESS.',
        ('Config: ' + $Config),
        ('Backup: ' + $Backup),
        'Origin: http://127.0.0.1:8882',
        ('New cloudflared PID: ' + $replica.Id),
        ('Old tunnel PIDs stopped: ' + (($stopped | ForEach-Object { [string]$_ }) -join ', ')),
        'Public MCP: https://gamepc-mcp.sentionce.net/mcp'
    ) -join [Environment]::NewLine
    Set-Content -Path $Success -Value $summary -Encoding UTF8
    Clear-Host
    Big 'GOMCP TUNNEL REPAIR SUCCESSFUL' Green
    Write-Host $summary
    Write-Host ''
    Write-Host 'Senti can test GoMCP again now.' -ForegroundColor Yellow
    try { Stop-Transcript | Out-Null } catch {}
    if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }
    exit 0
}
catch {
    $msg = $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    $detail = @(
        'GoMCP tunnel repair FAILED.',
        ('Time: ' + (Get-Date -Format o)),
        ('Computer: ' + $env:COMPUTERNAME),
        ('Error: ' + $msg),
        ('Log: ' + $Log)
    ) -join [Environment]::NewLine
    try { Set-Content -Path $Fail -Value $detail -Encoding UTF8 } catch {}
    Clear-Host
    Big 'GOMCP TUNNEL REPAIR FAILED' Red
    Write-Host $msg -ForegroundColor Red
    Write-Host ''
    Write-Host 'The repair refuses to stop the existing tunnel unless the replacement works.'
    Write-Host 'Send Senti GoMCP-TUNNEL-REPAIR-FAILED.txt and the repair log from the Desktop.'
    Write-Host ''
    if (-not $NoPause) { Read-Host 'Press Enter only if Senti tells you to' | Out-Null }
    exit 1
}
