$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskScratch = Join-Path $taskRoot ('.local\pipe-integrity\' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskScratch -Force | Out-Null
$taskFramework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$taskRefs = @('System.dll','System.Core.dll','System.Security.dll','System.ServiceProcess.dll','System.Web.Extensions.dll') |
    ForEach-Object { '/reference:' + (Join-Path $taskFramework $_) }
$taskSources = @('services\Common\ServiceCommon.cs','services\Common\FirewallPolicy.cs','services\Common\ServiceIpcHost.cs',
    'shared\HandShake.ServiceProtocol.cs','shared\HandShake.Release.cs','shared\HandShake.ReleaseSecurity.cs',
    'shared\HandShake.UpdateTrust.cs','shared\HandShake.WfpCleanup.cs','tests\PipeIntegrityTests.cs') |
    ForEach-Object { Join-Path $taskRoot $_ }
$taskBinary = Join-Path $taskScratch 'PipeIntegrityTests.exe'
$taskReport = Join-Path $taskScratch 'result.txt'
& (Join-Path $taskFramework 'csc.exe') /nologo /target:exe /platform:x64 /warn:4 /warnaserror+ ('/out:' + $taskBinary) $taskRefs $taskSources
if ($LASTEXITCODE -ne 0) { throw 'Pipe integrity test compilation failed' }
& $taskBinary $taskReport
$taskExit = $LASTEXITCODE
Get-Content -LiteralPath $taskReport
if ($taskExit -ne 0) { throw 'Pipe integrity test failed' }
