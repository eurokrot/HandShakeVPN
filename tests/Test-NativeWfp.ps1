[CmdletBinding()]
param([switch]$RunIntegration)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskOutput = Join-Path $taskRoot '.local\wfp-test'
New-Item -ItemType Directory -Path $taskOutput -Force | Out-Null
$taskFramework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$taskSources = @(
    'shared\HandShake.Release.cs', 'shared\HandShake.UpdateTrust.cs', 'shared\HandShake.ReleaseSecurity.cs', 'shared\HandShake.WfpCleanup.cs',
    'services\Common\ServiceCommon.cs', 'services\Common\FirewallPolicy.cs',
    'services\Common\ServiceIpcHost.cs', 'shared\HandShake.ServiceProtocol.cs',
    'services\Common\NativeWfp.cs', 'tests\NativeWfpIntegration.cs'
) | ForEach-Object { Join-Path $taskRoot $_ }
$taskReferences = @('System.dll', 'System.Core.dll', 'System.Web.Extensions.dll', 'System.Security.dll') |
    ForEach-Object { '/reference:' + (Join-Path $taskFramework $_) }
$taskBinary = Join-Path $taskOutput 'NativeWfpIntegration.exe'
& (Join-Path $taskFramework 'csc.exe') /nologo /platform:x64 /target:exe /warn:4 /warnaserror+ /codepage:65001 ('/out:' + $taskBinary) $taskReferences $taskSources
if ($LASTEXITCODE -ne 0) { throw 'Native WFP integration test compilation failed.' }
if ($RunIntegration) {
    # The test only blocks its own high loopback port, never internet traffic.
    $taskProcess = Start-Process -FilePath $taskBinary -Verb RunAs -WindowStyle Hidden -PassThru
    if (!$taskProcess.WaitForExit(45000)) { throw 'Scoped WFP test exceeded its deadline.' }
    Get-Content -LiteralPath (Join-Path $taskOutput 'native-wfp-integration.txt')
    if ($taskProcess.ExitCode -ne 0) { throw 'Native WFP integration test failed.' }
}
