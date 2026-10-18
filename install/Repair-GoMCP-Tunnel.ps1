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
$ConfigDir = 'C:\ProgramData\SentionceTunnels'
$Config = Join-Path $ConfigDir 'gamepc-mcp.yml'
$Log = Join-Path $Desktop ('GoMCP-TUNNEL-RECOVERY-' + $Stamp + '.log')
$Fail = Join-Path $Desktop 'GoMCP-TUNNEL-REPAIR-FAILED.txt'
$Success = Join-Path $Desktop 'GoMCP-TUNNEL-REPAIR-SUCCESS.txt'
$PublicHost = 'gamepc-mcp.sentionce.net'
$PublicBase = 'https://' + $PublicHost

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
        return Invoke-RestMethod -UseBasicParsing -Uri ($PublicBase + '/.well-known/oauth-protected-resource/mcp') -TimeoutSec 6
    } catch { return $null }
}

function Find-Cloudflared {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name='cloudflared.exe'" -ErrorAction SilentlyContinue)
    foreach ($p in $procs) {
        if ($p.ExecutablePath -and (Test-Path $p.ExecutablePath)) { return $p.ExecutablePath }
    }
    $cmd = Get-Command cloudflared.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @(
        'C:\ProgramData\SentionceTunnels\cloudflared.exe',
        'C:\Projects\cloudflare-mcp-server\bin\cloudflared.exe',
        'C:\Program Files\cloudflared\cloudflared.exe'
    )) { if (Test-Path $p) { return $p } }
    throw 'cloudflared.exe was not found.'
}

function Find-OriginCert {
    if ($env:TUNNEL_ORIGIN_CERT -and (Test-Path $env:TUNNEL_ORIGIN_CERT)) { return $env:TUNNEL_ORIGIN_CERT }
    foreach ($p in @(
        (Join-Path $env:USERPROFILE '.cloudflared\cert.pem'),
        (Join-Path $ConfigDir 'cert.pem'),
        'C:\Projects\cloudflare-mcp-server\cert.pem'
    )) { if ($p -and (Test-Path $p)) { return $p } }
    return $null
}

function Get-TunnelList([string]$Cloudflared,[string]$Cert) {
    $old = $env:TUNNEL_ORIGIN_CERT
    try {
        if ($Cert) { $env:TUNNEL_ORIGIN_CERT = $Cert }
        $raw = & $Cloudflared tunnel list --output json 2>&1
        if ($LASTEXITCODE -ne 0) { return $null }
        $text = ($raw -join [Environment]::NewLine)
        return @($text | ConvertFrom-Json)
    } catch { return $null }
    finally {
        if ($null -eq $old) { Remove-Item Env:TUNNEL_ORIGIN_CERT -ErrorAction SilentlyContinue } else { $env:TUNNEL_ORIGIN_CERT = $old }
    }
}

function Select-GamePcTunnel($List) {
    if (-not $List) { return $null }
    $live = @($List | Where-Object { -not $_.deletedAt })
    $exact = @($live | Where-Object { [string]$_.name -ieq 'gamepc-mcp' })
    if ($exact.Count -eq 1) { return $exact[0] }
    if ($exact.Count -gt 1) {
        return ($exact | Sort-Object createdAt -Descending | Select-Object -First 1)
    }
    $near = @($live | Where-Object { ([string]$_.name -match '(?i)gamepc.*mcp|mcp.*gamepc') })
    if ($near.Count -eq 1) { return $near[0] }
    return $null
}

function Find-Credential([string]$TunnelId) {
    if (-not $TunnelId) { return $null }
    $name = $TunnelId + '.json'
    foreach ($p in @(
        (Join-Path $env:USERPROFILE ('.cloudflared\' + $name)),
        (Join-Path $ConfigDir $name),
        (Join-Path 'C:\Projects\cloudflare-mcp-server' $name)
    )) { if ($p -and (Test-Path $p)) { return $p } }

    foreach ($root in @(
        (Join-Path $env:USERPROFILE '.cloudflared'),
        $ConfigDir,
        'C:\Projects\cloudflare-mcp-server'
    )) {
        if (-not (Test-Path $root)) { continue }
        $hit = Get-ChildItem -Path $root -Filter $name -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

function Write-TunnelConfig([string]$TunnelId,[string]$CredentialFile) {
    New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
    if (Test-Path $Config) { Copy-Item $Config ($Config + '.bak-' + $Stamp) -Force }
    $credYaml = $CredentialFile.Replace("'","''")
    $lines = @(
        ('tunnel: ' + $TunnelId),
        ("credentials-file: '" + $credYaml + "'"),
        '',
        'ingress:',
        ('  - hostname: ' + $PublicHost),
        '    service: http://127.0.0.1:8882',
        '  - service: http_status:404'
    )
    [IO.File]::WriteAllLines($Config,$lines,[Text.UTF8Encoding]::new($false))
}

function Validate-Config([string]$Cloudflared) {
    $out = & $Cloudflared tunnel --config $Config ingress validate 2>&1
    if ($LASTEXITCODE -ne 0) {
        $out = & $Cloudflared --config $Config tunnel ingress validate 2>&1
    }
    if ($LASTEXITCODE -ne 0) { throw ('cloudflared rejected the reconstructed config: ' + ($out -join ' ')) }
}

function Start-TunnelReplica([string]$Cloudflared,[string]$TunnelId) {
    $out = Join-Path $Desktop ('GoMCP-cloudflared-' + $Stamp + '.out.log')
    $err = Join-Path $Desktop ('GoMCP-cloudflared-' + $Stamp + '.err.log')
    $p = Start-Process -FilePath $Cloudflared -ArgumentList @('tunnel','--config',$Config,'run',$TunnelId) -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    Start-Sleep -Seconds 8
    if ($p.HasExited) {
        $why = if (Test-Path $err) { Get-Content $err -Raw -ErrorAction SilentlyContinue } else { '' }
        throw ('cloudflared replica exited immediately. ' + $why)
    }
    return $p
}

function Wait-Public([int]$Seconds = 45) {
    for ($i=0; $i -lt $Seconds; $i++) {
        $m = Get-PublicMetadata
        if ($m -and $m.resource -eq ($PublicBase + '/mcp')) { return $m }
        Start-Sleep -Seconds 1
    }
    return $null
}

function Create-ReplacementTunnel([string]$Cloudflared,[string]$Cert) {
    if (-not $Cert) { throw 'The original tunnel config/credentials are gone, and cert.pem is also missing. Cloudflare account login is required before a new tunnel can be created.' }
    $old = $env:TUNNEL_ORIGIN_CERT
    try {
        $env:TUNNEL_ORIGIN_CERT = $Cert
        $name = 'gamepc-mcp-recovery-' + $Stamp
        Write-Host ('Creating replacement Cloudflare tunnel: ' + $name) -ForegroundColor Yellow
        $create = & $Cloudflared tunnel create $name 2>&1
        if ($LASTEXITCODE -ne 0) { throw ('Tunnel creation failed: ' + ($create -join ' ')) }

        $list = Get-TunnelList $Cloudflared $Cert
        $new = @($list | Where-Object { [string]$_.name -eq $name } | Sort-Object createdAt -Descending | Select-Object -First 1)
        if (-not $new -or -not $new.id) { throw 'Replacement tunnel was created but could not be rediscovered.' }
        $id = [string]$new.id
        $cred = Find-Credential $id
        if (-not $cred) { throw ('Replacement tunnel credential file was not found for tunnel ' + $id) }

        Write-TunnelConfig $id $cred
        Validate-Config $Cloudflared
        $replica = Start-TunnelReplica $Cloudflared $id

        Write-Host ('Repointing only ' + $PublicHost + ' to replacement tunnel ' + $id + ' ...')
        $route = & $Cloudflared tunnel route dns --overwrite-dns $id $PublicHost 2>&1
        if ($LASTEXITCODE -ne 0) {
            try { Stop-Process -Id $replica.Id -Force -ErrorAction SilentlyContinue } catch {}
            throw ('DNS route update failed: ' + ($route -join ' '))
        }

        return [pscustomobject]@{ Id=$id; Name=$name; Credential=$cred; Process=$replica; Recreated=$true }
    } finally {
        if ($null -eq $old) { Remove-Item Env:TUNNEL_ORIGIN_CERT -ErrorAction SilentlyContinue } else { $env:TUNNEL_ORIGIN_CERT = $old }
    }
}

try {
    Start-Transcript -Path $Log -Force | Out-Null
    Clear-Host
    Big 'GOMCP CLOUDFLARE TUNNEL RECOVERY' Cyan
    Write-Host 'This recovery does not touch the rebuilt GoMCP runtime or any other named tunnel.'
    Write-Host ''

    Write-Host '[1/6] Verifying local GoMCP...'
    $health = Get-LocalHealth
    if (-not $health) { throw 'Local GoMCP is not healthy on 127.0.0.1:8882 with 56 tools.' }
    Write-Host 'Local GoMCP: healthy, 56 tools.' -ForegroundColor Green

    $already = Get-PublicMetadata
    if ($already -and $already.resource -eq ($PublicBase + '/mcp')) {
        Set-Content -Path $Success -Value 'GoMCP public tunnel was already healthy.' -Encoding UTF8
        Big 'GOMCP TUNNEL ALREADY HEALTHY' Green
        if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }
        exit 0
    }

    Write-Host '[2/6] Locating cloudflared and Cloudflare account credentials...'
    $Cloudflared = Find-Cloudflared
    $Cert = Find-OriginCert
    Write-Host ('cloudflared: ' + $Cloudflared)
    if ($Cert) { Write-Host ('cert.pem: ' + $Cert) } else { Write-Host 'cert.pem: not found' -ForegroundColor Yellow }

    Write-Host '[3/6] Rediscovering the original GamePC MCP tunnel...'
    $list = Get-TunnelList $Cloudflared $Cert
    $tunnel = Select-GamePcTunnel $list
    $result = $null

    if ($tunnel -and $tunnel.id) {
        $id = [string]$tunnel.id
        $cred = Find-Credential $id
        Write-Host ('Found tunnel: ' + $tunnel.name + ' [' + $id + ']') -ForegroundColor Green
        if ($cred) {
            Write-Host ('Credential: ' + $cred)
            Write-Host '[4/6] Rebuilding the missing gamepc-mcp.yml from surviving tunnel credentials...'
            Write-TunnelConfig $id $cred
            Validate-Config $Cloudflared
            $replica = Start-TunnelReplica $Cloudflared $id
            $result = [pscustomobject]@{ Id=$id; Name=[string]$tunnel.name; Credential=$cred; Process=$replica; Recreated=$false }
        } else {
            Write-Host 'Original tunnel exists, but its tunnel credential JSON is gone.' -ForegroundColor Yellow
        }
    } else {
        Write-Host 'No surviving Cloudflare tunnel object named gamepc-mcp was found.' -ForegroundColor Yellow
    }

    if (-not $result) {
        Write-Host '[4/6] Creating a fresh replacement tunnel because the original cannot be run locally...'
        $result = Create-ReplacementTunnel $Cloudflared $Cert
    }

    Write-Host '[5/6] Verifying public OAuth metadata through Cloudflare...'
    $public = Wait-Public 50
    if (-not $public) {
        throw ('Tunnel process is running, but ' + $PublicHost + ' still did not return valid GoMCP metadata. New tunnel/config were left intact for diagnosis; unrelated tunnels were untouched.')
    }

    Write-Host '[6/6] Writing recovery summary...'
    $summary = @(
        'GoMCP Cloudflare tunnel recovery SUCCESS.',
        ('Tunnel name: ' + $result.Name),
        ('Tunnel ID: ' + $result.Id),
        ('Recreated tunnel: ' + $result.Recreated),
        ('Config: ' + $Config),
        ('Credential: ' + $result.Credential),
        ('cloudflared PID: ' + $result.Process.Id),
        'Origin: http://127.0.0.1:8882',
        ('Public MCP: ' + $PublicBase + '/mcp'),
        '',
        'No other tunnel process was stopped or modified.'
    ) -join [Environment]::NewLine
    Set-Content -Path $Success -Value $summary -Encoding UTF8

    Clear-Host
    Big 'GOMCP TUNNEL RECOVERY SUCCESSFUL' Green
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
        'GoMCP tunnel recovery FAILED.',
        ('Time: ' + (Get-Date -Format o)),
        ('Computer: ' + $env:COMPUTERNAME),
        ('Error: ' + $msg),
        ('Log: ' + $Log),
        '',
        'No unrelated Cloudflare tunnel was intentionally stopped or modified.'
    ) -join [Environment]::NewLine
    try { Set-Content -Path $Fail -Value $detail -Encoding UTF8 } catch {}
    Clear-Host
    Big 'GOMCP TUNNEL RECOVERY FAILED' Red
    Write-Host $msg -ForegroundColor Red
    Write-Host ''
    Write-Host 'Send Senti GoMCP-TUNNEL-REPAIR-FAILED.txt and the recovery log from the Desktop.'
    Write-Host ''
    if (-not $NoPause) { Read-Host 'Press Enter only if Senti tells you to' | Out-Null }
    exit 1
}
