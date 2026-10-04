$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskOutput = Join-Path $taskRoot ('.local\vpn-recovery-tests\' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskOutput -Force | Out-Null
$taskFramework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$taskRefs = @('System.dll','System.Core.dll','System.Security.dll','System.ServiceProcess.dll',
    'System.Web.Extensions.dll','System.Windows.Forms.dll') | ForEach-Object { '/reference:' + (Join-Path $taskFramework $_) }
$taskSources = @('services\Common\ServiceCommon.cs','services\Common\FirewallPolicy.cs',
    'services\Common\ServiceIpcHost.cs','services\Common\NativeWfp.cs','services\Common\NetworkRecovery.cs',
    'services\HandShakeVpnService.cs','shared\HandShake.ServiceProtocol.cs','shared\HandShake.Release.cs',
    'shared\HandShake.ReleaseSecurity.cs','shared\HandShake.UpdateTrust.cs','shared\HandShake.WfpCleanup.cs',
    'tests\VpnRecoveryTests.cs') | ForEach-Object { Join-Path $taskRoot $_ }
$taskExe = Join-Path $taskOutput 'VpnRecoveryTests.exe'
& (Join-Path $taskFramework 'csc.exe') /nologo /target:exe /platform:x64 /main:VpnRecoveryTests /warn:4 /warnaserror+ /codepage:65001 ('/out:' + $taskExe) $taskRefs $taskSources
if ($LASTEXITCODE -ne 0) { throw 'VPN recovery tests did not compile.' }
# This executable calls only the disconnect completion component with injected
# actions. It never starts services, Xray, WFP, firewall helpers or live TUN.
& $taskExe
if ($LASTEXITCODE -ne 0) { throw 'VPN recovery tests failed.' }
