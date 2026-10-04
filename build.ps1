param([string]$OutputDirectory = 'dist')
$ErrorActionPreference = 'Stop'
# Public export: bootstrap a placeholder config; real deployment config is excluded.
$publicConfig = Join-Path $PSScriptRoot 'src/client.config'
if (!(Test-Path -LiteralPath $publicConfig)) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'src/client.config.example') -Destination $publicConfig
}

$projectRoot = $PSScriptRoot
$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$compiler = Join-Path $framework 'csc.exe'
if (!(Test-Path $compiler)) { throw '.NET Framework 4.x compiler was not found.' }
$output = Join-Path $projectRoot $OutputDirectory
New-Item -ItemType Directory -Path $output -Force | Out-Null
$references = @('System.Web.Extensions.dll', 'System.dll', 'System.Core.dll', 'System.Xaml.dll', 'System.Drawing.dll', 'System.Windows.Forms.dll', 'System.Net.Http.dll', 'System.Security.dll', 'System.Management.dll') | ForEach-Object { '/reference:' + (Join-Path $framework $_) }
$references += @('WindowsBase.dll', 'PresentationCore.dll', 'PresentationFramework.dll') | ForEach-Object { '/reference:' + (Join-Path (Join-Path $framework 'WPF') $_) }
$releaseSource = Join-Path $projectRoot 'shared\HandShake.Release.cs'
$serviceProtocol = Join-Path $projectRoot 'shared\HandShake.ServiceProtocol.cs'
$serviceBridge = Join-Path $projectRoot 'src\HandShake.ServiceBridge.cs'
$applicationIcon = Join-Path $projectRoot 'assets\handshake.ico'
if (!(Test-Path -LiteralPath $applicationIcon -PathType Leaf)) { throw 'Application icon was not found.' }

$flagResources = Get-ChildItem -LiteralPath (Join-Path $projectRoot 'assets\flags') -Filter '*.png' | Sort-Object Name | ForEach-Object { '/resource:' + $_.FullName + ',flags.' + $_.Name }
$clientCompilerArguments = @(& { $args } /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 ('/win32icon:' + $applicationIcon) ('/out:' + (Join-Path $output 'HandShake VPN.exe')) $references $flagResources ('/resource:' + $applicationIcon + ',handshake.ico') ('/resource:' + (Join-Path $projectRoot 'src\MainWindow.xaml') + ',MainWindow.xaml') ('/resource:' + (Join-Path $projectRoot 'src\MapWindow.xaml') + ',MapWindow.xaml') ('/resource:' + (Join-Path $projectRoot 'assets\countries.geojson') + ',countries.geojson') (Join-Path $projectRoot 'src\HandShake.Flags.cs') (Join-Path $projectRoot 'src\HandShake.Core.cs') (Join-Path $projectRoot 'src\HandShake.ControlPlane.cs') $releaseSource $serviceProtocol $serviceBridge (Join-Path $projectRoot 'src\HandShake.App.cs'))
$responseFile = Join-Path $output 'gui-build.rsp'
$responseLines = foreach ($argumentGroup in $clientCompilerArguments) {
    foreach ($argument in $argumentGroup) { '"' + $argument + '"' }
}
[IO.File]::WriteAllLines($responseFile, [string[]]$responseLines, (New-Object Text.UTF8Encoding($false)))
try { & $compiler ('@' + $responseFile) }
finally { Remove-Item -LiteralPath $responseFile -Force }

if ($LASTEXITCODE -ne 0) { throw 'Application compilation failed.' }
Copy-Item -LiteralPath (Join-Path $projectRoot 'src\client.config') -Destination (Join-Path $output 'client.config') -Force
Copy-Item -LiteralPath (Join-Path $projectRoot 'src\client.config.example') -Destination (Join-Path $output 'client.config.example') -Force
& $compiler /nologo /target:exe /codepage:65001 ('/out:' + (Join-Path $output 'CoreTests.exe')) $references (Join-Path $projectRoot 'src\HandShake.Flags.cs') (Join-Path $projectRoot 'src\HandShake.Core.cs') (Join-Path $projectRoot 'src\HandShake.ControlPlane.cs') $releaseSource $serviceProtocol $serviceBridge (Join-Path $projectRoot 'tests\CoreTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Test compilation failed.' }
& (Join-Path $output 'CoreTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'Core tests failed.' }
Write-Host ('Built: ' + (Join-Path $output 'HandShake VPN.exe'))
