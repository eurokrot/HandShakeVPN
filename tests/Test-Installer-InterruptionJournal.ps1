$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Core') {
    & (Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $PSCommandPath
    if ($LASTEXITCODE -ne 0) { throw 'Framework installer interruption tests failed.' }
    return
}
$projectRoot = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path $PSScriptRoot ('installer-journal-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    # Execute real durable journal and cleanup code against disposable files.
    # Only platform directory getters are redirected. The filesystem security
    # adapter is faked for phase tests; its real descriptor policy is tested below.
    # No install, uninstall, service, WFP or network operation is invoked.
    $framework = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319'
    $source = Get-Content -LiteralPath (Join-Path $projectRoot 'installer/Installer.cs') -Raw
    $literal = '"'+$testRoot.Replace('\','\\')+'"'
    $source = $source.Replace('Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)',$literal)
    $source = $source.Replace('Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)',$literal)
    $sourcePath = Join-Path $testRoot 'Installer.cs'
    Set-Content -LiteralPath $sourcePath -Value $source -Encoding utf8
    $binary = Join-Path $testRoot 'InstallerJournal.dll'
    $references = @('System.dll','System.Core.dll','System.Drawing.dll','System.Windows.Forms.dll','System.Web.Extensions.dll','System.ServiceProcess.dll','System.IO.Compression.dll','System.IO.Compression.FileSystem.dll') | ForEach-Object { '/reference:'+(Join-Path $framework $_) }
    $release = @('HandShake.Release.cs','HandShake.UpdateTrust.cs','HandShake.ReleaseSecurity.cs','HandShake.WfpCleanup.cs') | ForEach-Object { Join-Path $projectRoot ('shared/'+$_) }
    & (Join-Path $framework 'csc.exe') /nologo /target:library /platform:x64 /codepage:65001 ('/out:'+$binary) $references $release $sourcePath
    if ($LASTEXITCODE -ne 0) { throw 'Installer journal regression compilation failed' }
    $engine = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($binary)).GetType('HandShake.Setup.InstallerEngine',$true)
    $flags = [Reflection.BindingFlags]'NonPublic,Static'
    $write = $engine.GetMethod('WriteOperationJournal',$flags)
    $check = $engine.GetMethod('RejectInterruptedInstallerOperations',$flags)
    $cleanup = $engine.GetMethod('TryDeleteStageDirectoryCore',$flags)
    $descriptorCheck = $engine.GetMethod('ValidateJournalSecurityDescriptor',$flags)
    $staging = Join-Path $testRoot 'HandShake VPN Installer Staging'
    $fakeSecurity = [Action[string,bool]] { param($path,$directory) }
    $checks = 0
    foreach ($phase in @('prepared','services-stopping','backups-ready','files-writing','services-starting','recovery-required')) {
        $stage = Join-Path $staging ([guid]::NewGuid().ToString('N'))
        $backup = Join-Path $stage 'install-backup'
        New-Item -ItemType Directory -Path $backup -Force | Out-Null
        $original = Join-Path $backup 'original-state.txt'
        [IO.File]::WriteAllText($original,'protected original state')
        $write.Invoke($null,[object[]]@([string]$stage,[string]$phase)) | Out-Null
        $blocked = $false
        try { $check.Invoke($null,[object[]]@($fakeSecurity)) | Out-Null }
        catch { $blocked = $_.Exception.InnerException.GetType().Name -eq 'InterruptedInstallationException' }
        if (!$blocked) { throw "Interrupted phase did not block a new transaction: $phase" }
        $checks++
        $cleanup.Invoke($null,[object[]]@([string]$stage,$fakeSecurity)) | Out-Null
        if (!(Test-Path -LiteralPath $original) -or [IO.File]::ReadAllText($original) -ne 'protected original state') { throw "Cleanup removed interrupted backup: $phase" }
        $checks++
        # A completed rollback is the only recovery result simulated here.
        $write.Invoke($null,[object[]]@([string]$stage,[string]'rolled-back')) | Out-Null
        $check.Invoke($null,[object[]]@($fakeSecurity)) | Out-Null
        $cleanup.Invoke($null,[object[]]@([string]$stage,$fakeSecurity)) | Out-Null
        if (Test-Path -LiteralPath $stage) { throw 'Completed rollback stage was not cleared' }
        $checks++
    }
    foreach ($terminal in @('completed','rolled-back')) {
        $stage = Join-Path $staging ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        $write.Invoke($null,[object[]]@([string]$stage,[string]$terminal)) | Out-Null
        $check.Invoke($null,[object[]]@($fakeSecurity)) | Out-Null
        $cleanup.Invoke($null,[object[]]@([string]$stage,$fakeSecurity)) | Out-Null
        if (Test-Path -LiteralPath $stage) { throw 'Terminal journal incorrectly blocked cleanup or next transaction' }
        $checks++
    }
    $stage = Join-Path $staging ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    $write.Invoke($null,[object[]]@([string]$stage,[string]'files-writing')) | Out-Null
    $journal = Join-Path $stage 'operation-journal.json'
    $oldBytes = [IO.File]::ReadAllText($journal)
    $lock = [IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    try {
        $failed = $false
        try { $write.Invoke($null,[object[]]@([string]$stage,[string]'completed')) | Out-Null }
        catch { $failed = $_.Exception.InnerException -is [IO.IOException] }
        if (!$failed) { throw 'Locked checkpoint replacement unexpectedly succeeded' }
    } finally { $lock.Dispose() }
    if ([IO.File]::ReadAllText($journal) -ne $oldBytes -or @(Get-ChildItem -LiteralPath $stage -Filter '*.tmp-*').Count -ne 0) { throw 'Interrupted checkpoint write lost prior marker or retained partial JSON' }
    $checks++
    foreach ($invalid in @('{}','{"schemaVersion":2}',('x'*17000))) {
        [IO.File]::WriteAllText($journal,$invalid)
        $blocked = $false
        try { $check.Invoke($null,[object[]]@($fakeSecurity)) | Out-Null }
        catch { $blocked = $_.Exception.InnerException.GetType().Name -eq 'InterruptedInstallationException' }
        if (!$blocked) { throw 'Malformed/oversized journal was accepted' }
        $cleanup.Invoke($null,[object[]]@([string]$stage,$fakeSecurity)) | Out-Null
        if (!(Test-Path -LiteralPath $journal)) { throw 'Malformed journal was removed instead of retained' }
        $checks++
    }
    [IO.File]::WriteAllText($journal,$oldBytes)
    $refuseSecurity = [Action[string,bool]] { param($path,$directory) throw [UnauthorizedAccessException]::new('Injected untrusted journal ACL') }
    $blocked = $false
    try { $check.Invoke($null,[object[]]@($refuseSecurity)) | Out-Null }
    catch { $blocked = $true }
    if (!$blocked) { throw 'Untrusted ACL adapter did not block transaction inspection' }
    $cleanup.Invoke($null,[object[]]@([string]$stage,$refuseSecurity)) | Out-Null
    if (!(Test-Path -LiteralPath $journal)) { throw 'Untrusted journal was removed' }
    $checks++
    Remove-Item -LiteralPath $stage -Recurse -Force
    # A legacy failure can retain backups before journaling was introduced.
    $stage = Join-Path $staging ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $stage 'data-backup') -Force | Out-Null
    $blocked = $false
    try { $check.Invoke($null,[object[]]@($fakeSecurity)) | Out-Null }
    catch { $blocked = $_.Exception.InnerException.GetType().Name -eq 'InterruptedInstallationException' }
    if (!$blocked) { throw 'Legacy recovery backup was ignored' }
    $cleanup.Invoke($null,[object[]]@([string]$stage,$fakeSecurity)) | Out-Null
    if (!(Test-Path -LiteralPath $stage)) { throw 'Legacy backup was deleted' }
    $checks++
    Remove-Item -LiteralPath $stage -Recurse -Force
    # Security descriptors are constructed in memory. No live Windows ACL changes.
    $administrators = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$null)
    $system = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid,$null)
    $users = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinUsersSid,$null)
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($administrators)
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($system,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($administrators,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
    $descriptorCheck.Invoke($null,[object[]]@($security,[bool]$true)) | Out-Null
    $checks++
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($users,[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow))
    $blocked = $false
    try { $descriptorCheck.Invoke($null,[object[]]@($security,[bool]$true)) | Out-Null } catch { $blocked = $true }
    if (!$blocked) { throw 'Read exposure of protected backup journal was accepted' }
    $checks++
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($users)
    $blocked = $false
    try { $descriptorCheck.Invoke($null,[object[]]@($security,[bool]$true)) | Out-Null } catch { $blocked = $true }
    if (!$blocked) { throw 'Untrusted staging owner was accepted' }
    $checks++
    $escaped = Join-Path $testRoot 'outside-owned-staging'
    New-Item -ItemType Directory -Path $escaped | Out-Null
    $blocked = $false
    try { $write.Invoke($null,[object[]]@([string]$escaped,[string]'prepared')) | Out-Null } catch { $blocked = $true }
    if (!$blocked -or @(Get-ChildItem -LiteralPath $escaped).Count -ne 0) { throw 'Journal writer accepted a path outside its owned GUID stage' }
    $checks++
    Write-Output "PASS: $checks real installer interruption checks: all interrupted phases retain backups, terminal commit/rollback cleanup, atomic checkpoint failure, malformed/untrusted journals, legacy backups and exact path scope"
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $allowed = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')+'\'
    if (!$resolved.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)) { throw 'Installer journal test cleanup escaped workspace' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
