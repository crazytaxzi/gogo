param(
    [string]$Root = 'E:\SentionceRecovery\MutationFirewall'
)

$ErrorActionPreference = 'Stop'
$serviceName = 'SentionceMutationFirewall'
$exe = Join-Path $Root 'service-publish\SentionceMutationFirewallService.exe'

if (-not (Test-Path -LiteralPath $exe)) {
    throw "Service executable not found: $exe"
}

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "$serviceName already exists. Installer will not overwrite it."
    exit 0
}

$binPath = '"' + $exe + '"'
& sc.exe create $serviceName binPath= $binPath start= auto DisplayName= "Sentionce Mutation Firewall"
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE" }

& sc.exe description $serviceName "Deterministic local mutation broker for AI-operated development tools."
if ($LASTEXITCODE -ne 0) { throw "sc.exe description failed with exit code $LASTEXITCODE" }

Write-Host "Created $serviceName. Service was NOT started automatically by this installer invocation."
