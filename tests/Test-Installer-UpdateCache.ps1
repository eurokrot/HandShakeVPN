param([string]$SetupPath)
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path $PSScriptRoot ('installer-cache-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    # Compile the actual installer source with only platform directory getters
    # redirected into this disposable workspace. No install operation is invoked.
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $source = Get-Content -LiteralPath (Join-Path $projectRoot 'installer/Installer.cs') -Raw
    $literalRoot = '"' + $testRoot.Replace('\','\\') + '"'
    $source = $source.Replace('Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)', $literalRoot)
    $sourcePath = Join-Path $testRoot 'Installer.cs'
    Set-Content -LiteralPath $sourcePath -Value $source -Encoding utf8
    $framework = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319'
    $references = @('System.dll','System.Core.dll','System.Drawing.dll','System.Windows.Forms.dll','System.Web.Extensions.dll','System.ServiceProcess.dll','System.IO.Compression.dll','System.IO.Compression.FileSystem.dll') | ForEach-Object { '/reference:'+(Join-Path $framework $_) }
    $release = @('HandShake.Release.cs','HandShake.UpdateTrust.cs','HandShake.ReleaseSecurity.cs','HandShake.WfpCleanup.cs') | ForEach-Object { Join-Path $projectRoot ('shared/'+$_) }
    $binary = Join-Path $testRoot 'cache-regression.dll'
    & (Join-Path $framework 'csc.exe') /nologo /target:library /platform:x64 /codepage:65001 ('/out:'+$binary) $references $release $sourcePath
    if ($LASTEXITCODE -ne 0) { throw 'Could not compile the installer regression harness' }
    $assembly = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($binary))
    $engine = $assembly.GetType('HandShake.Setup.InstallerEngine', $true)
    $flags = [Reflection.BindingFlags]'NonPublic,Static'
    $copy = $engine.GetMethod('CopyDirectory', $flags)
    $remove = $engine.GetMethod('ClearDataForRollback', $flags)
    $state = Join-Path $testRoot 'HandShake VPN'
    $backup = Join-Path $testRoot 'HandShake VPN Installer Staging/backup'
    $cache = Join-Path $state 'updates'
    New-Item -ItemType Directory -Path $cache,(Join-Path $state 'vpn') | Out-Null
    Set-Content -LiteralPath (Join-Path $state 'vpn/session.json') -Value 'original session state'
    $lockedPath = Join-Path $cache 'running-installer.exe'
    $locked = [IO.File]::Open($lockedPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        # Execute the real copy/delete methods against disposable workspace files.
        # The locked installer would break an unfiltered backup or rollback.
        $copy.Invoke($null, [object[]]@([string]$state,[string]$backup,'updates')) | Out-Null
        if (Test-Path -LiteralPath (Join-Path $backup 'updates')) { throw 'Backup included the running updater cache' }
        if (!(Test-Path -LiteralPath (Join-Path $backup 'vpn/session.json'))) { throw 'VPN state was not backed up' }
        $remove.Invoke($null, @()) | Out-Null
        if (!(Test-Path -LiteralPath $lockedPath)) { throw 'Rollback touched the running installer' }
        $copy.Invoke($null, [object[]]@([string]$backup,[string]$state,$null)) | Out-Null
        if ((Get-Content -LiteralPath (Join-Path $state 'vpn/session.json')).Trim() -ne 'original session state') { throw 'Original VPN state was not restored' }
    } finally { $locked.Dispose() }
    Write-Output 'PASS: real backup and rollback preserve an exclusively locked update cache and restore VPN state'
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $allowed = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
    if (!$resolved.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) { throw 'Test cleanup escaped workspace' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
