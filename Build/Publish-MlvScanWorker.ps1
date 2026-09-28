param(
    [Parameter(Mandatory = $true)][string]$Destination,
    [ValidateSet('both', 'x86', 'x64')][string]$Architecture = 'both',
    [string]$Configuration = 'Release'
)
$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot '../Extensions/dnSpy.SecurityAnalysis.MlvScanWorker/dnSpy.SecurityAnalysis.MlvScanWorker.csproj'
$architectures = if ($Architecture -eq 'both') { @('x86', 'x64') } else { @($Architecture) }
foreach ($workerArchitecture in $architectures) {
    $rid = "win-$workerArchitecture"
    $output = Join-Path $Destination "mlvscan/$rid"
    dotnet publish $project -c $Configuration -r $rid --self-contained true -o $output -v:minimal
    if ($LASTEXITCODE) { throw "MLVScan worker publish failed for $rid" }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../Extensions/dnSpy.SecurityAnalysis.MlvScanWorker/THIRD-PARTY-NOTICES.txt') -Destination (Join-Path $output 'MLVSCAN-NOTICES.txt')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../LICENSE.txt') -Destination (Join-Path $output 'GPL-3.0.txt')
}
