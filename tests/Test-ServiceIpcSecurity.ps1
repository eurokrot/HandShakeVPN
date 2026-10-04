$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskScratch = Join-Path $taskRoot ('.local\ipc-security-tests\' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskScratch -Force | Out-Null
# The copy redirects ONLY protected owner-record storage for an isolated host.
# Live service names, ProgramData owner records, services/firewall remain untouched.
$taskSource = [IO.File]::ReadAllText((Join-Path $taskRoot 'services\Common\ServiceIpcHost.cs'))
$taskSource = $taskSource.Replace('Path.Combine(ProductInfo.ProgramDataRoot, "broker")', ('Path.Combine(@"' + $taskScratch + '", "broker")'))
$taskSource = $taskSource.Replace('ProtectedStorage.EnsureDirectory(OwnerDirectory);', 'Directory.CreateDirectory(OwnerDirectory);')
$taskSource = $taskSource.Replace('AccessControlGuard.RequireSystemAndAdministratorsOnly(OwnerPath, false);', '// Test-only redirected owner storage; no production ACL is changed.')
# Keep the real factory and mandatory label. Skipping label application hid the
# missing server-handle WRITE_OWNER failure in earlier tests.
$taskCopy = Join-Path $taskScratch 'ServiceIpcHost.cs'
[IO.File]::WriteAllText($taskCopy, $taskSource, [Text.UTF8Encoding]::new($false))
$taskFramework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$taskRefs = @('System.dll','System.Core.dll','System.Security.dll','System.ServiceProcess.dll','System.Web.Extensions.dll') | ForEach-Object { '/reference:' + (Join-Path $taskFramework $_) }
$taskSources = @('services\Common\ServiceCommon.cs','services\Common\FirewallPolicy.cs','shared\HandShake.ServiceProtocol.cs','shared\HandShake.Release.cs','shared\HandShake.ReleaseSecurity.cs','shared\HandShake.UpdateTrust.cs','shared\HandShake.WfpCleanup.cs','tests\ServiceIpcDeadlineTests.cs') | ForEach-Object { Join-Path $taskRoot $_ }
$taskExe = Join-Path $taskScratch 'ServiceIpcDeadlineTests.exe'
& (Join-Path $taskFramework 'csc.exe') /nologo /target:exe /platform:x64 /warn:4 /warnaserror+ /codepage:65001 ('/out:' + $taskExe) $taskRefs $taskSources $taskCopy
if ($LASTEXITCODE -ne 0) { throw 'IPC security test build failed.' }
& $taskExe $taskScratch
if ($LASTEXITCODE -ne 0) { throw 'IPC security checks failed.' }
