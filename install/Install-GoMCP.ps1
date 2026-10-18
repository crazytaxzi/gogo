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

$Root = 'C:\actions-runner\GoMCP'
$State = Join-Path $Root 'state'
$Logs = Join-Path $Root 'logs'
$Desktop = [Environment]::GetFolderPath('Desktop')
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Stage = Join-Path $env:TEMP ('GoMCP-install-' + $Stamp)
$ValidationMarkerUrl = 'https://raw.githubusercontent.com/crazytaxzi/gogo/main/ci/gomcp-rebuilt-validated.txt'
$ValidationMarker = (Invoke-WebRequest -UseBasicParsing -Uri $ValidationMarkerUrl -TimeoutSec 30).Content
if ($ValidationMarker -notmatch '(?m)^source_sha=([0-9a-f]{40})\s*
$FailureFile = Join-Path $Desktop 'GoMCP-INSTALL-FAILED.txt'
$OwnerFile = Join-Path $Desktop 'GoMCP-OWNER-KEY.txt'
$SuccessFile = Join-Path $Desktop 'GoMCP-INSTALL-SUCCESS.txt'
$Transcript = Join-Path $Desktop ('GoMCP-INSTALL-' + $Stamp + '.log')

function Big([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::White) {
    Write-Host ''
    Write-Host ('=' * 94) -ForegroundColor $Color
    Write-Host ('  ' + $Text) -ForegroundColor $Color
    Write-Host ('=' * 94) -ForegroundColor $Color
    Write-Host ''
}

function Download([string]$Name) {
    $url = $RepoBase + '/' + $Name
    $dest = Join-Path $Stage $Name
    Write-Host ('Downloading ' + $Name + ' ...')
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $dest -TimeoutSec 60
    if (-not (Test-Path $dest) -or (Get-Item $dest).Length -lt 1) { throw ('Download failed: ' + $Name) }
    return $dest
}

function Wait-Health([int]$Seconds = 40) {
    for ($i = 0; $i -lt $Seconds; $i++) {
        try {
            $h = Invoke-RestMethod -UseBasicParsing -Uri 'http://127.0.0.1:8882/health' -TimeoutSec 3
            if ($h.ok -eq $true -and [int]$h.toolCount -eq 56 -and $h.oauth -eq $true) { return $h }
        } catch {}
        Start-Sleep -Seconds 1
    }
    return $null
}

function Wait-Public([int]$Seconds = 45) {
    for ($i = 0; $i -lt $Seconds; $i++) {
        try {
            $m = Invoke-RestMethod -UseBasicParsing -Uri 'https://gamepc-mcp.sentionce.net/.well-known/oauth-protected-resource/mcp' -TimeoutSec 5
            if ($m.resource -eq 'https://gamepc-mcp.sentionce.net/mcp') { return $m }
        } catch {}
        Start-Sleep -Seconds 1
    }
    return $null
}

try {
    Start-Transcript -Path $Transcript -Force | Out-Null
    Clear-Host
    Big 'GOMCP ONE-CLICK REBUILD / RECOVERY' Cyan
    Write-Host 'Do not close this window. No typing is required.'
    Write-Host ''

    New-Item -ItemType Directory -Force -Path $Stage | Out-Null

    Write-Host '[1/8] Checking Node.js...'
    $nodeCmd = Get-Command node.exe -ErrorAction SilentlyContinue
    if (-not $nodeCmd) {
        $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        if (-not $winget) { throw 'Node.js is missing and winget is unavailable.' }
        Write-Host 'Node.js not found. Installing Node.js LTS with winget...'
        & $winget.Source install --id OpenJS.NodeJS.LTS --exact --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) { throw ('Node.js installation failed with exit code ' + $LASTEXITCODE) }
        $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
        $nodeCmd = Get-Command node.exe -ErrorAction SilentlyContinue
        if (-not $nodeCmd) { throw 'Node.js installed but node.exe is still not available.' }
    }
    $Node = $nodeCmd.Source
    Write-Host ('Node: ' + $Node)

    Write-Host ('[2/8] Downloading CI-validated GoMCP package ' + $ValidatedSha.Substring(0,12) + ' from GitHub...')
    $Names = @('gomcp.js','oauth.js','drive.js','remote.js','supervisor.js','Start-GoMCP-UserAdmin.ps1','remote-targets.default.json','selftest.js')
    foreach ($name in $Names) { Download $name | Out-Null }

    Write-Host '[3/8] Syntax-checking package before touching the installed runtime...'
    foreach ($name in @('gomcp.js','oauth.js','drive.js','remote.js','supervisor.js','selftest.js')) {
        & $Node --check (Join-Path $Stage $name)
        if ($LASTEXITCODE -ne 0) { throw ('Syntax validation failed: ' + $name) }
    }
    Write-Host 'Package syntax is clean.' -ForegroundColor Green

    Write-Host '[4/8] Preserving any surviving GoMCP state/config...'
    $BackupRoot = if (Test-Path 'E:\') { 'E:\SentionceRecovery\GoMCP' } else { Join-Path $Desktop 'GoMCP-Recovery' }
    $Backup = Join-Path $BackupRoot ('preinstall-' + $Stamp)
    New-Item -ItemType Directory -Force -Path $Backup | Out-Null
    if (Test-Path $Root) {
        foreach ($item in @('state','remote-targets.json','gomcp.js','oauth.js','drive.js','remote.js','supervisor.js','Start-GoMCP-UserAdmin.ps1')) {
            $src = Join-Path $Root $item
            if (Test-Path $src) { Copy-Item $src (Join-Path $Backup $item) -Recurse -Force }
        }
    }
    Write-Host ('Backup: ' + $Backup)

    Write-Host '[5/8] Installing rebuilt GoMCP runtime...'
    try { Stop-ScheduledTask -TaskName 'GoMCP User Admin' -ErrorAction SilentlyContinue } catch {}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -eq 'node.exe' -and $_.CommandLine -and $_.CommandLine -match 'C:\\actions-runner\\GoMCP\\(gomcp|supervisor)\.js'
    } | ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }

    New-Item -ItemType Directory -Force -Path $Root,$State,$Logs,'E:\GoMCPdrive\Up','E:\GoMCPdrive\Down' | Out-Null
    foreach ($name in @('gomcp.js','oauth.js','drive.js','remote.js','supervisor.js','Start-GoMCP-UserAdmin.ps1')) {
        Copy-Item (Join-Path $Stage $name) (Join-Path $Root $name) -Force
    }
    $RemoteConfig = Join-Path $Root 'remote-targets.json'
    if (-not (Test-Path $RemoteConfig)) { Copy-Item (Join-Path $Stage 'remote-targets.default.json') $RemoteConfig -Force }
    Remove-Item (Join-Path $State 'supervisor.pid') -Force -ErrorAction SilentlyContinue

    Write-Host '[6/8] Recreating the GoMCP User Admin scheduled task...'
    $UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + (Join-Path $Root 'Start-GoMCP-UserAdmin.ps1') + '"')
    $Trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
    $Principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'GoMCP User Admin' -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
    Start-ScheduledTask -TaskName 'GoMCP User Admin'

    Write-Host '[7/8] Verifying local 56-tool MCP...'
    $health = Wait-Health 20
    if (-not $health) {
        Write-Host 'Scheduled task did not produce a healthy listener yet; launching directly once...'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'Start-GoMCP-UserAdmin.ps1')
        $health = Wait-Health 25
    }
    if (-not $health) { throw 'GoMCP did not become healthy on 127.0.0.1:8882 with 56 tools.' }
    Write-Host ('Local GoMCP healthy: ' + $health.toolCount + ' tools') -ForegroundColor Green

    Write-Host '[8/8] Verifying public Cloudflare route...'
    $public = Wait-Public 45
    if (-not $public) { throw 'Local GoMCP is healthy, but gamepc-mcp.sentionce.net did not recover through the existing tunnel.' }
    Write-Host 'Public GoMCP metadata is reachable.' -ForegroundColor Green

    $OwnerKeyPath = Join-Path $State 'owner.key'
    if (-not (Test-Path $OwnerKeyPath)) { throw 'OAuth owner key was not generated.' }
    $OwnerKey = (Get-Content $OwnerKeyPath -Raw).Trim()
    $RemoteToken = 'C:\Projects\cloudflare-mcp-server\data\streamingpc-token.txt'
    $RemoteNote = if (Test-Path $RemoteToken) { 'StreamingPC token file: PRESENT' } else { 'StreamingPC token file: MISSING - remote tools may need repair after reconnection' }

    $OwnerText = @(
        'GoMCP rebuilt successfully on GAMEPC.',
        '',
        'Public MCP: https://gamepc-mcp.sentionce.net/mcp',
        'Local MCP: http://127.0.0.1:8882/mcp',
        'Tools: 56',
        '',
        'OAuth owner key:',
        $OwnerKey,
        '',
        $RemoteNote,
        '',
        'Use the owner key once when reconnecting/authorizing the GoMCP app.'
    ) -join [Environment]::NewLine
    Set-Content -Path $OwnerFile -Value $OwnerText -Encoding UTF8
    Set-Content -Path $SuccessFile -Value ($OwnerText + [Environment]::NewLine + [Environment]::NewLine + 'Backup: ' + $Backup) -Encoding UTF8
    try { Set-Clipboard -Value $OwnerKey } catch {}

    Clear-Host
    Big 'GOMCP REBUILD SUCCESSFUL' Green
    Write-Host 'GAMEPC GoMCP is back on port 8882 with 56 tools.' -ForegroundColor Green
    Write-Host 'Public metadata is reachable through gamepc-mcp.sentionce.net.' -ForegroundColor Green
    Write-Host ''
    Write-Host 'SEND THIS OWNER KEY TO SENTI:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host $OwnerKey -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'The same key is saved on the Desktop as GoMCP-OWNER-KEY.txt.'
    Write-Host 'It was also copied to the clipboard.'
    Write-Host ''
    Write-Host $RemoteNote
    Write-Host ''
    Write-Host 'This window may now be closed.'
    Stop-Transcript | Out-Null
    if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }
    exit 0
}
catch {
    $msg = $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    $detail = @(
        'GoMCP one-click rebuild FAILED.',
        ('Time: ' + (Get-Date -Format o)),
        ('Computer: ' + $env:COMPUTERNAME),
        ('Error: ' + $msg),
        ('Transcript: ' + $Transcript),
        ('Install root: ' + $Root)
    ) -join [Environment]::NewLine
    try { Set-Content -Path $FailureFile -Value $detail -Encoding UTF8 } catch {}
    Clear-Host
    Big 'GOMCP REBUILD FAILED' Red
    Write-Host $msg -ForegroundColor Red
    Write-Host ''
    Write-Host 'Leave the computer powered on.'
    Write-Host 'Send Senti the Desktop file GoMCP-INSTALL-FAILED.txt and the install log.'
    Write-Host ''
    if (-not $NoPause) { Read-Host 'Press Enter only if Senti tells you to' | Out-Null }
    exit 1
}
) { throw 'GitHub has no valid CI-approved GoMCP revision marker.' }
$ValidatedSha = $Matches[1]
$RepoBase = 'https://raw.githubusercontent.com/crazytaxzi/gogo/' + $ValidatedSha + '/mcp/rebuilt'
$FailureFile = Join-Path $Desktop 'GoMCP-INSTALL-FAILED.txt'
$OwnerFile = Join-Path $Desktop 'GoMCP-OWNER-KEY.txt'
$SuccessFile = Join-Path $Desktop 'GoMCP-INSTALL-SUCCESS.txt'
$Transcript = Join-Path $Desktop ('GoMCP-INSTALL-' + $Stamp + '.log')

function Big([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::White) {
    Write-Host ''
    Write-Host ('=' * 94) -ForegroundColor $Color
    Write-Host ('  ' + $Text) -ForegroundColor $Color
    Write-Host ('=' * 94) -ForegroundColor $Color
    Write-Host ''
}

function Download([string]$Name) {
    $url = $RepoBase + '/' + $Name
    $dest = Join-Path $Stage $Name
    Write-Host ('Downloading ' + $Name + ' ...')
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $dest -TimeoutSec 60
    if (-not (Test-Path $dest) -or (Get-Item $dest).Length -lt 1) { throw ('Download failed: ' + $Name) }
    return $dest
}

function Wait-Health([int]$Seconds = 40) {
    for ($i = 0; $i -lt $Seconds; $i++) {
        try {
            $h = Invoke-RestMethod -UseBasicParsing -Uri 'http://127.0.0.1:8882/health' -TimeoutSec 3
            if ($h.ok -eq $true -and [int]$h.toolCount -eq 56 -and $h.oauth -eq $true) { return $h }
        } catch {}
        Start-Sleep -Seconds 1
    }
    return $null
}

function Wait-Public([int]$Seconds = 45) {
    for ($i = 0; $i -lt $Seconds; $i++) {
        try {
            $m = Invoke-RestMethod -UseBasicParsing -Uri 'https://gamepc-mcp.sentionce.net/.well-known/oauth-protected-resource/mcp' -TimeoutSec 5
            if ($m.resource -eq 'https://gamepc-mcp.sentionce.net/mcp') { return $m }
        } catch {}
        Start-Sleep -Seconds 1
    }
    return $null
}

try {
    Start-Transcript -Path $Transcript -Force | Out-Null
    Clear-Host
    Big 'GOMCP ONE-CLICK REBUILD / RECOVERY' Cyan
    Write-Host 'Do not close this window. No typing is required.'
    Write-Host ''

    New-Item -ItemType Directory -Force -Path $Stage | Out-Null

    Write-Host '[1/8] Checking Node.js...'
    $nodeCmd = Get-Command node.exe -ErrorAction SilentlyContinue
    if (-not $nodeCmd) {
        $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        if (-not $winget) { throw 'Node.js is missing and winget is unavailable.' }
        Write-Host 'Node.js not found. Installing Node.js LTS with winget...'
        & $winget.Source install --id OpenJS.NodeJS.LTS --exact --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) { throw ('Node.js installation failed with exit code ' + $LASTEXITCODE) }
        $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
        $nodeCmd = Get-Command node.exe -ErrorAction SilentlyContinue
        if (-not $nodeCmd) { throw 'Node.js installed but node.exe is still not available.' }
    }
    $Node = $nodeCmd.Source
    Write-Host ('Node: ' + $Node)

    Write-Host '[2/8] Downloading canonical GoMCP package from GitHub...'
    $Names = @('gomcp.js','oauth.js','drive.js','remote.js','supervisor.js','Start-GoMCP-UserAdmin.ps1','remote-targets.default.json','selftest.js')
    foreach ($name in $Names) { Download $name | Out-Null }

    Write-Host '[3/8] Syntax-checking package before touching the installed runtime...'
    foreach ($name in @('gomcp.js','oauth.js','drive.js','remote.js','supervisor.js','selftest.js')) {
        & $Node --check (Join-Path $Stage $name)
        if ($LASTEXITCODE -ne 0) { throw ('Syntax validation failed: ' + $name) }
    }
    Write-Host 'Package syntax is clean.' -ForegroundColor Green

    Write-Host '[4/8] Preserving any surviving GoMCP state/config...'
    $BackupRoot = if (Test-Path 'E:\') { 'E:\SentionceRecovery\GoMCP' } else { Join-Path $Desktop 'GoMCP-Recovery' }
    $Backup = Join-Path $BackupRoot ('preinstall-' + $Stamp)
    New-Item -ItemType Directory -Force -Path $Backup | Out-Null
    if (Test-Path $Root) {
        foreach ($item in @('state','remote-targets.json','gomcp.js','oauth.js','drive.js','remote.js','supervisor.js','Start-GoMCP-UserAdmin.ps1')) {
            $src = Join-Path $Root $item
            if (Test-Path $src) { Copy-Item $src (Join-Path $Backup $item) -Recurse -Force }
        }
    }
    Write-Host ('Backup: ' + $Backup)

    Write-Host '[5/8] Installing rebuilt GoMCP runtime...'
    try { Stop-ScheduledTask -TaskName 'GoMCP User Admin' -ErrorAction SilentlyContinue } catch {}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -eq 'node.exe' -and $_.CommandLine -and $_.CommandLine -match 'C:\\actions-runner\\GoMCP\\(gomcp|supervisor)\.js'
    } | ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }

    New-Item -ItemType Directory -Force -Path $Root,$State,$Logs,'E:\GoMCPdrive\Up','E:\GoMCPdrive\Down' | Out-Null
    foreach ($name in @('gomcp.js','oauth.js','drive.js','remote.js','supervisor.js','Start-GoMCP-UserAdmin.ps1')) {
        Copy-Item (Join-Path $Stage $name) (Join-Path $Root $name) -Force
    }
    $RemoteConfig = Join-Path $Root 'remote-targets.json'
    if (-not (Test-Path $RemoteConfig)) { Copy-Item (Join-Path $Stage 'remote-targets.default.json') $RemoteConfig -Force }
    Remove-Item (Join-Path $State 'supervisor.pid') -Force -ErrorAction SilentlyContinue

    Write-Host '[6/8] Recreating the GoMCP User Admin scheduled task...'
    $UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + (Join-Path $Root 'Start-GoMCP-UserAdmin.ps1') + '"')
    $Trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
    $Principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'GoMCP User Admin' -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
    Start-ScheduledTask -TaskName 'GoMCP User Admin'

    Write-Host '[7/8] Verifying local 56-tool MCP...'
    $health = Wait-Health 20
    if (-not $health) {
        Write-Host 'Scheduled task did not produce a healthy listener yet; launching directly once...'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'Start-GoMCP-UserAdmin.ps1')
        $health = Wait-Health 25
    }
    if (-not $health) { throw 'GoMCP did not become healthy on 127.0.0.1:8882 with 56 tools.' }
    Write-Host ('Local GoMCP healthy: ' + $health.toolCount + ' tools') -ForegroundColor Green

    Write-Host '[8/8] Verifying public Cloudflare route...'
    $public = Wait-Public 45
    if (-not $public) { throw 'Local GoMCP is healthy, but gamepc-mcp.sentionce.net did not recover through the existing tunnel.' }
    Write-Host 'Public GoMCP metadata is reachable.' -ForegroundColor Green

    $OwnerKeyPath = Join-Path $State 'owner.key'
    if (-not (Test-Path $OwnerKeyPath)) { throw 'OAuth owner key was not generated.' }
    $OwnerKey = (Get-Content $OwnerKeyPath -Raw).Trim()
    $RemoteToken = 'C:\Projects\cloudflare-mcp-server\data\streamingpc-token.txt'
    $RemoteNote = if (Test-Path $RemoteToken) { 'StreamingPC token file: PRESENT' } else { 'StreamingPC token file: MISSING - remote tools may need repair after reconnection' }

    $OwnerText = @(
        'GoMCP rebuilt successfully on GAMEPC.',
        '',
        'Public MCP: https://gamepc-mcp.sentionce.net/mcp',
        'Local MCP: http://127.0.0.1:8882/mcp',
        'Tools: 56',
        '',
        'OAuth owner key:',
        $OwnerKey,
        '',
        $RemoteNote,
        '',
        'Use the owner key once when reconnecting/authorizing the GoMCP app.'
    ) -join [Environment]::NewLine
    Set-Content -Path $OwnerFile -Value $OwnerText -Encoding UTF8
    Set-Content -Path $SuccessFile -Value ($OwnerText + [Environment]::NewLine + [Environment]::NewLine + 'Backup: ' + $Backup) -Encoding UTF8
    try { Set-Clipboard -Value $OwnerKey } catch {}

    Clear-Host
    Big 'GOMCP REBUILD SUCCESSFUL' Green
    Write-Host 'GAMEPC GoMCP is back on port 8882 with 56 tools.' -ForegroundColor Green
    Write-Host 'Public metadata is reachable through gamepc-mcp.sentionce.net.' -ForegroundColor Green
    Write-Host ''
    Write-Host 'SEND THIS OWNER KEY TO SENTI:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host $OwnerKey -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'The same key is saved on the Desktop as GoMCP-OWNER-KEY.txt.'
    Write-Host 'It was also copied to the clipboard.'
    Write-Host ''
    Write-Host $RemoteNote
    Write-Host ''
    Write-Host 'This window may now be closed.'
    Stop-Transcript | Out-Null
    if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }
    exit 0
}
catch {
    $msg = $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    $detail = @(
        'GoMCP one-click rebuild FAILED.',
        ('Time: ' + (Get-Date -Format o)),
        ('Computer: ' + $env:COMPUTERNAME),
        ('Error: ' + $msg),
        ('Transcript: ' + $Transcript),
        ('Install root: ' + $Root)
    ) -join [Environment]::NewLine
    try { Set-Content -Path $FailureFile -Value $detail -Encoding UTF8 } catch {}
    Clear-Host
    Big 'GOMCP REBUILD FAILED' Red
    Write-Host $msg -ForegroundColor Red
    Write-Host ''
    Write-Host 'Leave the computer powered on.'
    Write-Host 'Send Senti the Desktop file GoMCP-INSTALL-FAILED.txt and the install log.'
    Write-Host ''
    if (-not $NoPause) { Read-Host 'Press Enter only if Senti tells you to' | Out-Null }
    exit 1
}
