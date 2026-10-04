[CmdletBinding()]
param(
    [string]$ClientDirectory,
    [string]$ServicesDirectory,
    [string]$XrayDirectory,
    [string]$OutputDirectory,
    [string]$ProductVersion = '0.7-preview.11',
    [string]$XrayVersion = '26.9.30',
    [string]$CertificateThumbprint,
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$CertificateStore = 'CurrentUser',
    [uri]$TimestampServer,
    [string]$SignToolPath,
    [string]$UpdateSigningKeyPath,
    [switch]$UnsignedDevelopmentBuild,
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$installerRoot = $PSScriptRoot
$projectRoot = Split-Path -Parent $installerRoot
if ([string]::IsNullOrWhiteSpace($ClientDirectory)) { $ClientDirectory = Join-Path $projectRoot 'dist' }
if ([string]::IsNullOrWhiteSpace($ServicesDirectory)) { $ServicesDirectory = Join-Path $projectRoot 'services\bin' }
if ([string]::IsNullOrWhiteSpace($XrayDirectory)) { $XrayDirectory = Join-Path $projectRoot '.local\xray-26.9.30\extracted' }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $installerRoot 'dist' }

$releaseSource = Join-Path $projectRoot 'shared\HandShake.Release.cs'
$releaseIdentity = [IO.File]::ReadAllText($releaseSource)
if ($releaseIdentity -notmatch ('Version = "' + [Regex]::Escape($ProductVersion) + '"')) { throw 'Build version must match shared/HandShake.Release.cs.' }
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path -LiteralPath $compiler -PathType Leaf)) { throw '.NET Framework 4.x x64 compiler was not found.' }
if ($XrayVersion -ne '26.9.30') { throw 'This build script is pinned to the verified official Xray 26.9.30 runtime.' }

$pinnedXrayFiles = @(
    [pscustomobject]@{ Name = 'xray.exe'; Length = 37369344L; Sha256 = '43fa465275a8a64ddce4a27c3317ae3e99f0c264fec1962e04c3fadda83adc79' },
    [pscustomobject]@{ Name = 'geoip.dat'; Length = 16635240L; Sha256 = '3cf2236c19063c1c80803368cca5ff589c5033129fdf9ba154230c689b81fc2a' },
    [pscustomobject]@{ Name = 'geosite.dat'; Length = 10973728L; Sha256 = '51211fde21696bbde05d1102f47f586261e98987a3cae23f7dd1cd742c62c2d2' },
    [pscustomobject]@{ Name = 'wintun.dll'; Length = 427552L; Sha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce' },
    [pscustomobject]@{ Name = 'LICENSE'; Length = 16725L; Sha256 = '1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5' },
    [pscustomobject]@{ Name = 'LICENSE-wintun.txt'; Length = 5431L; Sha256 = '183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2' },
    [pscustomobject]@{ Name = 'README.md'; Length = 12666L; Sha256 = '0d098928cf19c756a8c956c0b5ca736b75f9eaff0765fd71c26a3dcb413a3dde' }
)
$pinnedXrayBySource = @{}
foreach ($expected in $pinnedXrayFiles) {
    $source = Join-Path $XrayDirectory $expected.Name
    if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw "Pinned Xray file is missing: $source" }
    $actualLength = (Get-Item -LiteralPath $source).Length
    $actualHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualLength -ne $expected.Length -or $actualHash -ne $expected.Sha256) {
        throw "Pinned Xray file verification failed: $($expected.Name)"
    }
    $pinnedXrayBySource[[IO.Path]::GetFullPath($source)] = $expected
}

$payload = @(
    [pscustomobject]@{ Source = (Join-Path $ClientDirectory 'HandShake VPN.exe'); Destination = 'HandShake VPN.exe'; Component = 'client' },
    [pscustomobject]@{ Source = (Join-Path $ClientDirectory 'client.config'); Destination = 'client.config'; Component = 'client' },
    [pscustomobject]@{ Source = (Join-Path $ServicesDirectory 'HandShakeVpnService.exe'); Destination = 'HandShakeVpnService.exe'; Component = 'vpn-service' },
    [pscustomobject]@{ Source = (Join-Path $ServicesDirectory 'HandShakeNodeService.exe'); Destination = 'HandShakeNodeService.exe'; Component = 'node-service' },
    [pscustomobject]@{ Source = (Join-Path $ServicesDirectory 'Firewall-Policy.ps1'); Destination = 'Firewall-Policy.ps1'; Component = 'firewall-policy' },
    [pscustomobject]@{ Source = (Join-Path $XrayDirectory 'xray.exe'); Destination = 'runtime\vpn\xray.exe'; Component = 'xray-vpn' },
    [pscustomobject]@{ Source = (Join-Path $XrayDirectory 'geoip.dat'); Destination = 'runtime\vpn\geoip.dat'; Component = 'xray-vpn' },
    [pscustomobject]@{ Source = (Join-Path $XrayDirectory 'geosite.dat'); Destination = 'runtime\vpn\geosite.dat'; Component = 'xray-vpn' },
    [pscustomobject]@{ Source = (Join-Path $XrayDirectory 'wintun.dll'); Destination = 'runtime\vpn\wintun.dll'; Component = 'wintun-vpn' },
    [pscustomobject]@{ Source = (Join-Path $XrayDirectory 'xray.exe'); Destination = 'runtime\node\xray.exe'; Component = 'xray-node' },
    [pscustomobject]@{ Source = (Join-Path $XrayDirectory 'geoip.dat'); Destination = 'runtime\node\geoip.dat'; Component = 'xray-node' },
    [pscustomobject]@{ Source = (Join-Path $XrayDirectory 'geosite.dat'); Destination = 'runtime\node\geosite.dat'; Component = 'xray-node' },
    [pscustomobject]@{ Source = (Join-Path $XrayDirectory 'LICENSE'); Destination = 'licenses\Xray-core-LICENSE.txt'; Component = 'licenses' },
    [pscustomobject]@{ Source = (Join-Path $XrayDirectory 'LICENSE-wintun.txt'); Destination = 'licenses\Wintun-LICENSE.txt'; Component = 'licenses' },
    [pscustomobject]@{ Source = (Join-Path $XrayDirectory 'README.md'); Destination = 'licenses\Xray-core-README.md'; Component = 'licenses' }
)

$allowedDestinations = @(
    'HandShake VPN.exe',
    'client.config',
    'HandShakeVpnService.exe',
    'HandShakeNodeService.exe',
    'Firewall-Policy.ps1',
    'runtime\vpn\xray.exe',
    'runtime\vpn\geoip.dat',
    'runtime\vpn\geosite.dat',
    'runtime\vpn\wintun.dll',
    'runtime\node\xray.exe',
    'runtime\node\geoip.dat',
    'runtime\node\geosite.dat',
    'licenses\Xray-core-LICENSE.txt',
    'licenses\Wintun-LICENSE.txt',
    'licenses\Xray-core-README.md'
)
$duplicates = @($payload.Destination | Group-Object { $_.ToLowerInvariant() } | Where-Object Count -ne 1)
$missingDestinations = @($allowedDestinations | Where-Object { $payload.Destination -notcontains $_ })
$unexpectedDestinations = @($payload.Destination | Where-Object { $allowedDestinations -notcontains $_ })
if ($duplicates.Count -ne 0 -or $missingDestinations.Count -ne 0 -or $unexpectedDestinations.Count -ne 0) {
    throw 'Installer payload destinations do not exactly match the fixed allowlist.'
}

$missing = @($payload | Where-Object { !(Test-Path -LiteralPath $_.Source -PathType Leaf) })
if ($missing.Count -gt 0) {
    $details = ($missing | ForEach-Object { ' - ' + $_.Source }) -join [Environment]::NewLine
    throw "Installer payload is incomplete:$([Environment]::NewLine)$details"
}

if ($payload.Destination | Where-Object { $_ -match '(?i)(windows-client|windows-exit-node|server\.relay|token\.txt|device-token\.bin|session\.json|xray-client\.json|xray-exit\.json)' }) {
    throw 'A device/session-specific secret or generated relay configuration was selected for the installer.'
}

$codeSigningRequested = ![string]::IsNullOrWhiteSpace($CertificateThumbprint)
$signingArguments = @{}
if ($codeSigningRequested) {
    if ($null -eq $TimestampServer) { throw 'A trusted RFC3161 HTTPS TimestampServer is required with CertificateThumbprint.' }
    $signingArguments = @{Thumbprint=$CertificateThumbprint; CertificateStore=$CertificateStore; TimestampServer=$TimestampServer}
    if (![string]::IsNullOrWhiteSpace($SignToolPath)) { $signingArguments.SignToolPath = $SignToolPath }
    $ownedFiles = @($payload | Where-Object {$_.Destination -in @('HandShake VPN.exe','HandShakeVpnService.exe','HandShakeNodeService.exe','Firewall-Policy.ps1')} | ForEach-Object {$_.Source})
    & (Join-Path $projectRoot 'scripts\Sign-Release.ps1') @signingArguments -LiteralPath $ownedFiles -CheckOnly:$PlanOnly
}

$plan = [ordered]@{
    product = 'HandShake VPN'
    productVersion = $ProductVersion
    xrayVersion = $XrayVersion
    architecture = 'x64'
    installRoot = '%ProgramFiles%\HandShake VPN'
    dataRoot = '%ProgramData%\HandShake VPN'
    stagingRoot = '%ProgramData%\HandShake VPN Installer Staging'
    services = @('HandShakeVpnService', 'HandShakeNodeService')
    requiresAdministrator = $true
    singleFile = $true
    signed = $false
    payload = @($payload | ForEach-Object {
        [ordered]@{
            source = [IO.Path]::GetFullPath($_.Source)
            destination = $_.Destination
            component = $_.Component
            length = (Get-Item -LiteralPath $_.Source).Length
            sha256 = (Get-FileHash -LiteralPath $_.Source -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    })
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$planPath = Join-Path $OutputDirectory 'build-plan.json'
$plan | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $planPath -Encoding UTF8
Write-Host "Build plan: $planPath"

if ($PlanOnly) {
    Write-Host 'Plan-only completed. No Setup.exe was created and nothing was installed.'
    return
}

$setupPath = Join-Path $OutputDirectory 'HandShake VPN Setup.exe'
$sumsPath = Join-Path $OutputDirectory 'SHA256SUMS.txt'
foreach ($staleArtifact in @($setupPath, $sumsPath)) {
    if (Test-Path -LiteralPath $staleArtifact) { Remove-Item -LiteralPath $staleArtifact -Force }
}

$buildRoot = Join-Path $installerRoot '.build'
$payloadRoot = Join-Path $buildRoot 'payload'
$payloadFiles = Join-Path $payloadRoot 'files'
$payloadZip = Join-Path $buildRoot 'payload.zip'
if (Test-Path -LiteralPath $buildRoot) {
    $resolvedBuild = [IO.Path]::GetFullPath($buildRoot).TrimEnd('\')
    $expectedBuild = [IO.Path]::GetFullPath((Join-Path $installerRoot '.build')).TrimEnd('\')
    if ($resolvedBuild -ne $expectedBuild) { throw 'Unexpected build directory; refusing cleanup.' }
    if (((Get-Item -LiteralPath $buildRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installer build directory is a reparse point; refusing cleanup.'
    }
    Remove-Item -LiteralPath $buildRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $payloadFiles -Force | Out-Null

$manifestFiles = @()
foreach ($item in $payload) {
    $sourceLength = (Get-Item -LiteralPath $item.Source).Length
    $sourceHash = (Get-FileHash -LiteralPath $item.Source -Algorithm SHA256).Hash.ToLowerInvariant()
    $sourceFullPath = [IO.Path]::GetFullPath($item.Source)
    if ($pinnedXrayBySource.ContainsKey($sourceFullPath)) {
        $pinned = $pinnedXrayBySource[$sourceFullPath]
        if ($sourceLength -ne $pinned.Length -or $sourceHash -ne $pinned.Sha256) {
            throw "Pinned Xray source changed before payload copy: $($pinned.Name)"
        }
    }
    $destination = Join-Path $payloadFiles $item.Destination
    $parent = Split-Path -Parent $destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Copy-Item -LiteralPath $item.Source -Destination $destination -Force
    $copied = Get-Item -LiteralPath $destination
    $copiedHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($copied.Length -ne $sourceLength -or $copiedHash -ne $sourceHash) {
        throw "Payload copy verification failed: $($item.Destination)"
    }
    if ($pinnedXrayBySource.ContainsKey($sourceFullPath) -and
        ($copied.Length -ne $pinned.Length -or $copiedHash -ne $pinned.Sha256)) {
        throw "Pinned Xray destination verification failed: $($item.Destination)"
    }
    $manifestFiles += [ordered]@{
        path = $item.Destination
        sha256 = $copiedHash
        length = $copied.Length
        component = $item.Component
    }
}

$plan.payload = @($payload | ForEach-Object {
    $destinationName = $_.Destination
    $snapshot = @($manifestFiles | Where-Object { $_.path -eq $destinationName })
    if ($snapshot.Count -ne 1) { throw "Could not reconcile build plan payload: $destinationName" }
    [ordered]@{
        source = [IO.Path]::GetFullPath($_.Source)
        destination = $destinationName
        component = $_.Component
        length = $snapshot[0].length
        sha256 = $snapshot[0].sha256
    }
})
$plan | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $planPath -Encoding UTF8

$manifest = [ordered]@{
    productVersion = $ProductVersion
    xrayVersion = $XrayVersion
    createdUtc = [DateTime]::UtcNow.ToString('o')
    files = $manifestFiles
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $payloadRoot 'payload-manifest.json') -Encoding UTF8

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
if (Test-Path -LiteralPath $payloadZip) { Remove-Item -LiteralPath $payloadZip -Force }
$zipStream = [IO.File]::Open($payloadZip, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
$zipArchive = $null
try {
    $zipArchive = [IO.Compression.ZipArchive]::new($zipStream, [IO.Compression.ZipArchiveMode]::Create, $true)
    $payloadRootFull = [IO.Path]::GetFullPath($payloadRoot).TrimEnd('\') + '\'
    foreach ($sourceFile in @(Get-ChildItem -LiteralPath $payloadRoot -File -Recurse | Sort-Object FullName)) {
        $sourceFull = [IO.Path]::GetFullPath($sourceFile.FullName)
        if (!$sourceFull.StartsWith($payloadRootFull, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Payload file escaped the build root: $sourceFull"
        }
        # ZIP entry names are portable paths and must always use forward slashes.
        $entryName = $sourceFull.Substring($payloadRootFull.Length).Replace('\', '/')
        $entry = $zipArchive.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
        $input = [IO.File]::OpenRead($sourceFull)
        $output = $entry.Open()
        try { $input.CopyTo($output) }
        finally { $output.Dispose(); $input.Dispose() }
    }
}
finally {
    if ($null -ne $zipArchive) { $zipArchive.Dispose() }
    $zipStream.Dispose()
}

$assemblyInfo = Join-Path $buildRoot 'AssemblyInfo.cs'
$numericVersion = ($ProductVersion -replace '[^0-9\.]', '').Trim('.')
if ([string]::IsNullOrWhiteSpace($numericVersion)) { $numericVersion = '0.1.0' }
$parts = @($numericVersion.Split('.') | ForEach-Object { [int]$_ })
while ($parts.Count -lt 4) { $parts += 0 }
$assemblyVersion = ($parts[0..3] -join '.')
@"
using System.Reflection;
[assembly: AssemblyTitle("HandShake VPN Setup")]
[assembly: AssemblyProduct("HandShake VPN")]
[assembly: AssemblyCompany("HandShake VPN")]
[assembly: AssemblyVersion("$assemblyVersion")]
[assembly: AssemblyFileVersion("$assemblyVersion")]
"@ | Set-Content -LiteralPath $assemblyInfo -Encoding UTF8

$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$references = @(
    'System.dll',
    'System.Core.dll',
    'System.Security.dll',
    'System.Drawing.dll',
    'System.Windows.Forms.dll',
    'System.Web.Extensions.dll',
    'System.ServiceProcess.dll',
    'System.IO.Compression.dll',
    'System.IO.Compression.FileSystem.dll'
) | ForEach-Object { '/reference:' + (Join-Path $framework $_) }

$compiledSetupPath = Join-Path $buildRoot 'setup-output.exe'
$setupIcon = Join-Path $projectRoot 'assets\handshake.ico'
if (!(Test-Path -LiteralPath $setupIcon -PathType Leaf)) { throw 'Installer icon was not found.' }
$arguments = @(
    '/nologo',
    '/target:winexe',
    '/platform:x64',
    '/optimize+',
    '/warn:4',
    '/warnaserror+',
    '/codepage:65001',
    ('/win32icon:' + $setupIcon),
    ('/out:' + $compiledSetupPath),
    ('/win32manifest:' + (Join-Path $installerRoot 'setup.manifest')),
    ('/resource:' + $payloadZip + ',HandShake.Payload.zip')
) + $references + @((Join-Path $installerRoot 'Installer.cs'), $assemblyInfo, $releaseSource, (Join-Path $projectRoot 'shared\HandShake.UpdateTrust.cs'), (Join-Path $projectRoot 'shared\HandShake.ReleaseSecurity.cs'), (Join-Path $projectRoot 'shared\HandShake.WfpCleanup.cs'))

& $compiler $arguments
if ($LASTEXITCODE -ne 0) { throw 'Installer compilation failed.' }

if ($codeSigningRequested) {
    & (Join-Path $projectRoot 'scripts\Sign-Release.ps1') @signingArguments -LiteralPath @($compiledSetupPath)
    $plan.signed = $true
    $plan | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $planPath -Encoding UTF8
}

$hash = (Get-FileHash -LiteralPath $compiledSetupPath -Algorithm SHA256).Hash.ToLowerInvariant()
Move-Item -LiteralPath $compiledSetupPath -Destination $setupPath -Force
if ((Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) {
    throw 'Final Setup copy verification failed.'
}
"$hash  HandShake VPN Setup.exe" | Set-Content -LiteralPath $sumsPath -Encoding ASCII
# Public export: no publisher private key is shipped or implicitly loaded.
if ($UnsignedDevelopmentBuild) {
    Remove-Item -LiteralPath $buildRoot -Recurse -Force
    Write-Warning 'Development Setup built without signed update metadata. The official updater will not accept it.'
    Write-Host ('Built development installer only: ' + $setupPath)
    return
}
if ([string]::IsNullOrWhiteSpace($UpdateSigningKeyPath)) {
    throw 'Supply your own UpdateSigningKeyPath outside this repository, or use UnsignedDevelopmentBuild. Official private keys are not provided.'
}
$privateKey = [IO.Path]::GetFullPath($UpdateSigningKeyPath)
if (!(Test-Path -LiteralPath $privateKey)) { throw 'Release signing key is missing.' }
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
$rsa.PersistKeyInCsp = $false
$rsa.FromXmlString([IO.File]::ReadAllText($privateKey))
$size = (Get-Item -LiteralPath $setupPath).Length
$message = $ProductVersion + "`n" + $hash + "`n" + $size.ToString([Globalization.CultureInfo]::InvariantCulture) + "`n"
$signature = [Convert]::ToBase64String($rsa.SignData([Text.Encoding]::UTF8.GetBytes($message), [Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256')))
$rsa.Dispose()
$releaseManifest = @{version=$ProductVersion;sha256=$hash;sizeBytes=$size;signature=$signature}
$releaseManifest | ConvertTo-Json | Set-Content -LiteralPath ($setupPath + '.update.json') -Encoding UTF8
Remove-Item -LiteralPath $buildRoot -Recurse -Force
Write-Host "Built single-file installer: $setupPath"
if (!$codeSigningRequested) { Write-Warning 'The test installer is not Authenticode-signed. Windows SmartScreen may warn until a trusted code-signing certificate is used.' }
Write-Host 'The installer was built only; it was not launched and nothing was installed.'
