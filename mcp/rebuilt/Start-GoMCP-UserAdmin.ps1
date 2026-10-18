$ErrorActionPreference = 'Stop'

$Root = 'C:\actions-runner\GoMCP'
$State = Join-Path $Root 'state'
$Logs = Join-Path $Root 'logs'
$Supervisor = Join-Path $Root 'supervisor.js'
$PidFile = Join-Path $State 'supervisor.pid'

New-Item -ItemType Directory -Force -Path $State,$Logs | Out-Null
if (-not (Test-Path $Supervisor)) { throw "GoMCP supervisor missing: $Supervisor" }

if (Test-Path $PidFile) {
    try {
        $oldPid = [int](Get-Content $PidFile -Raw).Trim()
        if ($oldPid -gt 0 -and (Get-Process -Id $oldPid -ErrorAction SilentlyContinue)) { exit 0 }
    } catch {}
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

$node = (Get-Command node.exe -ErrorAction Stop).Source
$env:GOMCP_HOME = $Root
$env:GOMCP_STATE = $State
$env:GOMCP_PORT = '8882'
$env:GOMCP_PUBLIC_BASE = 'https://gamepc-mcp.sentionce.net'
$out = Join-Path $Logs 'launcher-supervisor.log'
$err = Join-Path $Logs 'launcher-supervisor-error.log'

$p = Start-Process -FilePath $node -ArgumentList @($Supervisor) -WorkingDirectory $Root -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
Start-Sleep -Seconds 2
if ($p.HasExited) { throw "GoMCP supervisor exited immediately. See $err" }
