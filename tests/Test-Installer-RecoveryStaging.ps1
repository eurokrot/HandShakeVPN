param([string]$SetupPath = 'installer/dist-runtime-recovery/HandShake VPN Setup.exe')
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Core') {
    # The installer uses .NET Framework's JavaScriptSerializer. Execute these
    # actual resource checks in that runtime instead of PowerShell 7's CLR.
    & (Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $PSCommandPath -SetupPath $SetupPath
    if ($LASTEXITCODE -ne 0) { throw 'Framework installer recovery tests failed.' }
    return
}
$projectRoot = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path $PSScriptRoot ('installer-recovery-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    # Execute the real extraction and failure paths in a disposable workspace.
    # No install/uninstall entry point, services or networking operation is run.
    $framework = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319'
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $references = @('System.dll','System.Core.dll','System.Drawing.dll','System.Windows.Forms.dll','System.Web.Extensions.dll','System.ServiceProcess.dll','System.IO.Compression.dll','System.IO.Compression.FileSystem.dll') | ForEach-Object { '/reference:'+(Join-Path $framework $_) }
    $release = @('HandShake.Release.cs','HandShake.UpdateTrust.cs','HandShake.ReleaseSecurity.cs','HandShake.WfpCleanup.cs') | ForEach-Object { Join-Path $projectRoot ('shared/'+$_) }
    $installerSource = Get-Content -LiteralPath (Join-Path $projectRoot 'installer/Installer.cs') -Raw
    $allowedBlock = [regex]::Match($installerSource, 'AllowedPayloadFiles =\s*\{(.*?)\};', 'Singleline').Groups[1].Value
    $allowedNames = @([regex]::Matches($allowedBlock, '@?"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
    if (!$allowedNames.Count) { throw 'Public installer payload allowlist is missing' }
    $pinBlock = [regex]::Match($installerSource, 'PinnedRuntimeSha256 =.*?\{(.*?)\n\s*\};', 'Singleline').Groups[1].Value
    $pins = @{}
    foreach ($entry in [regex]::Matches($pinBlock, '\{\s*@?"([^"]+)",\s*"([0-9a-f]{64})"\s*\}')) {
        $pins[$entry.Groups[1].Value] = $entry.Groups[2].Value
    }
    if (!$pins.Count) { throw 'Public installer runtime pins are missing' }
    $manifest = [pscustomobject]@{ productVersion = ''; xrayVersion = '26.9.30'; createdUtc = ''; files = @(
        foreach ($name in $allowedNames) {
            $hash = if ($pins.ContainsKey($name)) { $pins[$name] } else { '0'*64 }
            [pscustomobject]@{ path = $name; sha256 = $hash; length = 0; component = 'isolated-fixture' }
        }
    ) }
    $versionSource = Get-Content -LiteralPath (Join-Path $projectRoot 'shared/HandShake.Release.cs') -Raw
    $manifest.productVersion = [regex]::Match($versionSource, 'const string Version = "([^"]+)"').Groups[1].Value
    if (!$manifest.productVersion) { throw 'Current source version was not found' }
    $helperBytes = [IO.File]::ReadAllBytes((Join-Path $projectRoot 'services/Firewall-Policy.ps1'))
    $helperRecord = $manifest.files | Where-Object path -eq 'Firewall-Policy.ps1'
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $helperRecord.sha256 = [BitConverter]::ToString($sha.ComputeHash($helperBytes)).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    $helperRecord.length = $helperBytes.Length
    $newManifestBytes = [Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json -Depth 10 -Compress))
    $source = Get-Content -LiteralPath (Join-Path $projectRoot 'installer/Installer.cs') -Raw
    $literalTestRoot = '"'+$testRoot.Replace('\','\\')+'"'
    $source = $source.Replace('Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)', $literalTestRoot)
    $sourcePath = Join-Path $testRoot 'Installer.cs'
    Set-Content -LiteralPath $sourcePath -Value $source -Encoding utf8
    $checks = 0
    foreach ($kind in @('valid','corrupt','duplicate')) {
        $zipPath = Join-Path $testRoot ($kind+'.zip')
        $zipFile = [IO.File]::Create($zipPath)
        $archive = [IO.Compression.ZipArchive]::new($zipFile, [IO.Compression.ZipArchiveMode]::Create)
        try {
            $entry = $archive.CreateEntry('payload-manifest.json')
            $writer = $entry.Open()
            try { $writer.Write($newManifestBytes,0,$newManifestBytes.Length) } finally { $writer.Dispose() }
            foreach ($file in $manifest.files) {
                $entry = $archive.CreateEntry(('files/'+$file.path.Replace('\','/')))
                $writer = $entry.Open()
                try {
                    if ($file.path -eq 'Firewall-Policy.ps1') {
                        $bytes = if ($kind -eq 'corrupt') { [Text.Encoding]::UTF8.GetBytes('damaged helper') } else { $helperBytes }
                        $writer.Write($bytes,0,$bytes.Length)
                    } else {
                        # Deliberately not executable: cleanup-only extraction
                        # must neither expand nor execute any runtime fixture.
                        $bytes = [Text.Encoding]::UTF8.GetBytes('isolated non-executable fixture')
                        $writer.Write($bytes,0,$bytes.Length)
                    }
                } finally { $writer.Dispose() }
            }
            if ($kind -eq 'duplicate') {
                $entry = $archive.CreateEntry('files/HandShake VPN.exe')
                $writer = $entry.Open(); $writer.Dispose()
            }
        } finally { $archive.Dispose(); $zipFile.Dispose() }
        $binary = Join-Path $testRoot ($kind+'.dll')
        & (Join-Path $framework 'csc.exe') /nologo /target:library /platform:x64 /codepage:65001 ('/out:'+$binary) ('/resource:'+$zipPath+',HandShake.Payload.zip') $references $release $sourcePath
        if ($LASTEXITCODE -ne 0) { throw 'Installer recovery regression compilation failed' }
        $assembly = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($binary))
        $engine = $assembly.GetType('HandShake.Setup.InstallerEngine',$true)
        $flags = [Reflection.BindingFlags]'NonPublic,Static'
        $extract = $engine.GetMethod('ExtractAndValidatePayloadCore',$flags)
        $stage = Join-Path $testRoot ($kind+'-stage')
        New-Item -ItemType Directory -Path $stage | Out-Null
        if ($kind -eq 'valid') {
            $extract.Invoke($null,[object[]]@([string]$stage,[bool]$true)) | Out-Null
            $actualFiles = @(Get-ChildItem -LiteralPath $stage -File -Recurse)
            if ($actualFiles.Count -ne 2 -or !(Test-Path -LiteralPath (Join-Path $stage 'files/Firewall-Policy.ps1'))) { throw 'Cleanup staging expanded runtime files or lost helper' }
            $checks++
            if ((Get-FileHash -LiteralPath (Join-Path $stage 'files/Firewall-Policy.ps1')).Hash.ToLowerInvariant() -ne $helperRecord.sha256) { throw 'Verified helper changed during staging' }
            $checks++
            $cleanup = $engine.GetMethod('CleanupManagedFirewallRole',$flags)
            $safeFailure = $false
            try { $cleanup.Invoke($null,@('HandShakeVpnService.exe','RemoveVpn',$true)) | Out-Null }
            catch { $safeFailure = $_.Exception.InnerException.Message.Contains('Native protection was retained') }
            if (!$safeFailure) { throw 'Missing verified helper did not retain native protection and reject removal' }
            $checks++
            $markerPath = Join-Path $testRoot 'failed-helper-ran.txt'
            $failScript = Join-Path $testRoot 'fail-recovery.ps1'
            $scriptText = "[IO.File]::WriteAllText('" + $markerPath.Replace("'","''") + "','injected recovery failure'); exit 1"
            [IO.File]::WriteAllText($failScript,$scriptText,[Text.UTF8Encoding]::new($false))
            $recordType = $assembly.GetType('HandShake.Setup.PayloadFile',$true)
            $record = [Activator]::CreateInstance($recordType,$true)
            $record.length = (Get-Item -LiteralPath $failScript).Length
            $record.sha256 = (Get-FileHash -LiteralPath $failScript).Hash.ToLowerInvariant()
            $engine.GetField('verifiedCleanupHelper',$flags).SetValue($null,$failScript)
            $engine.GetField('verifiedCleanupManifest',$flags).SetValue($null,$record)
            $safeFailure = $false
            try { $cleanup.Invoke($null,@('HandShakeVpnService.exe','RemoveVpn',$true)) | Out-Null }
            catch { $safeFailure = $_.Exception.InnerException.Message.Contains('Native protection was retained') }
            if (!$safeFailure -or !(Test-Path -LiteralPath $markerPath)) { throw 'Actual failing helper did not run before native protection was retained' }
            $checks++
            Remove-Item -LiteralPath $markerPath
            $record.sha256 = '0'*64
            $rejected = $false
            try { $cleanup.Invoke($null,@('HandShakeVpnService.exe','RemoveVpn',$true)) | Out-Null }
            catch { $rejected = $_.Exception.InnerException -is [IO.InvalidDataException] }
            if (!$rejected -or (Test-Path -LiteralPath $markerPath)) { throw 'Changed helper ran without matching its verified SHA-256' }
            $checks++
            $application = Join-Path $testRoot 'HandShake VPN'
            New-Item -ItemType Directory -Path $application | Out-Null
            $notice = Join-Path $application 'update-installed.json'
            $writeNotice = $engine.GetMethod('WriteInstalledUpdateNotice',$flags)
            $writeNotice.Invoke($null,[object[]]@([string]$manifest.productVersion)) | Out-Null
            $originalNotice = [IO.File]::ReadAllText($notice)
            if (($originalNotice | ConvertFrom-Json).version -ne $manifest.productVersion) { throw 'Installed update notice was not written completely' }
            $checks++
            $locked = [IO.File]::Open($notice,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
            try {
                $rejected = $false
                try { $writeNotice.Invoke($null,[object[]]@([string]'replacement-candidate')) | Out-Null }
                catch { $rejected = $_.Exception.InnerException -is [IO.IOException] }
                if (!$rejected) { throw 'Locked notice write unexpectedly succeeded' }
            } finally { $locked.Dispose() }
            if ([IO.File]::ReadAllText($notice) -ne $originalNotice -or @(Get-ChildItem -LiteralPath $application -Filter '*.new-*').Count -ne 0) { throw 'Failed notice replacement lost previous receipt or left partial file' }
            $checks++
            $writeNotice.Invoke($null,[object[]]@([string]'replacement-candidate')) | Out-Null
            if (([IO.File]::ReadAllText($notice) | ConvertFrom-Json).version -ne 'replacement-candidate') { throw 'Atomic replacement did not commit new receipt' }
            $checks++
        } else {
            $rejected = $false
            try { $extract.Invoke($null,[object[]]@([string]$stage,[bool]$true)) | Out-Null }
            catch { $rejected = $_.Exception.InnerException -is [IO.InvalidDataException] }
            if (!$rejected) { throw "Invalid cleanup payload was accepted: $kind" }
            $checks++
        }
    }
    Write-Output "PASS: $checks real installer checks: minimal verified recovery staging, damaged/duplicate payload rejection, missing/failing/changed helper retains native protection, atomic notice replacement/locked rollback"
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $allowed = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')+'\'
    if (!$resolved.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)) { throw 'Installer recovery test cleanup escaped workspace' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
