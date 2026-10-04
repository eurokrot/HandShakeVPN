# Public export builds VPN Service only; Node Service is a closed component.
[CmdletBinding()]
param(
    [string]$OutputDirectory = 'bin'
)

$ErrorActionPreference = 'Stop'
$serviceRoot = $PSScriptRoot
$projectRoot = Split-Path -Parent $serviceRoot
$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$compiler = Join-Path $framework 'csc.exe'

if (-not (Test-Path -LiteralPath $compiler)) {
    throw '.NET Framework 4.x x64 compiler was not found.'
}

$output = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory
} else {
    Join-Path $serviceRoot $OutputDirectory
}
New-Item -ItemType Directory -Path $output -Force | Out-Null

$references = @(
    'System.dll',
    'System.Core.dll',
    'System.Security.dll',
    'System.ServiceProcess.dll',
    'System.Web.Extensions.dll'
) | ForEach-Object { '/reference:' + (Join-Path $framework $_) }

$releaseSources = @('HandShake.Release.cs', 'HandShake.UpdateTrust.cs', 'HandShake.ReleaseSecurity.cs', 'HandShake.WfpCleanup.cs') | ForEach-Object { Join-Path $projectRoot ('shared\' + $_) }
$common = Join-Path $serviceRoot 'Common\ServiceCommon.cs'
$firewallCommon = Join-Path $serviceRoot 'Common\FirewallPolicy.cs'
$ipcCommon = Join-Path $serviceRoot 'Common\ServiceIpcHost.cs'
$serviceProtocol = Join-Path $projectRoot 'shared\HandShake.ServiceProtocol.cs'
$firewallHelper = Join-Path $serviceRoot 'Firewall-Policy.ps1'
$vpnSource = Join-Path $serviceRoot 'HandShakeVpnService.cs'
$nativeWfp = Join-Path $serviceRoot 'Common\NativeWfp.cs'
$recovery = Join-Path $serviceRoot 'Common\NetworkRecovery.cs'
$recoveryReference = '/reference:' + (Join-Path $framework 'System.Windows.Forms.dll')
$recoveryResource = '/resource:' + $firewallHelper + ',network-recovery-firewall.ps1'
$vpnBinary = Join-Path $output 'HandShakeVpnService.exe'

& $compiler /nologo /target:exe /platform:x64 /optimize+ /warn:4 /warnaserror+ /codepage:65001 `
    /main:HandShake.Services.VpnProgram ('/out:' + $vpnBinary) $references $recoveryReference $recoveryResource $releaseSources $serviceProtocol $common $firewallCommon $ipcCommon $nativeWfp $recovery $vpnSource
if ($LASTEXITCODE -ne 0) { throw 'HandShakeVpnService compilation failed.' }

& $compiler /nologo /target:winexe /platform:x64 /optimize+ /warn:4 /warnaserror+ /codepage:65001 `
    /main:HandShake.Services.NetworkRecoveryProgram ('/win32manifest:' + (Join-Path $projectRoot 'installer\setup.manifest')) `
    ('/out:' + (Join-Path $output 'HandShake Network Recovery.exe')) $references $recoveryReference $recoveryResource `
    $releaseSources $serviceProtocol $common $firewallCommon $ipcCommon $nativeWfp $recovery $vpnSource
if ($LASTEXITCODE -ne 0) { throw 'Network recovery compilation failed.' }


& $vpnBinary --self-test
if ($LASTEXITCODE -ne 0) { throw 'HandShakeVpnService self-test failed.' }

& $firewallHelper -Operation SelfTest
if ($LASTEXITCODE -ne 0) { throw 'Firewall policy offline self-test failed.' }
Copy-Item -LiteralPath $firewallHelper -Destination (Join-Path $output 'Firewall-Policy.ps1') -Force

Write-Host ('Built and verified: ' + $vpnBinary)

