[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$Thumbprint,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$LiteralPath,

    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string]$CertificateStore = 'CurrentUser',

    [Parameter(Mandatory = $true)]
    [uri]$TimestampServer,

    [string]$SignToolPath,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# This script never imports/exports a private key or accepts a PFX password.
# Install a real code-signing certificate using its issuer's supported tooling.
$codeSigningOid = '1.3.6.1.5.5.7.3.3'
$normalizedThumbprint = $Thumbprint.ToUpperInvariant()
if (!$TimestampServer.IsAbsoluteUri -or $TimestampServer.Scheme -ne 'https' -or
    $TimestampServer.Port -ne 443 -or ![string]::IsNullOrEmpty($TimestampServer.UserInfo) -or
    ![string]::IsNullOrEmpty($TimestampServer.Query) -or ![string]::IsNullOrEmpty($TimestampServer.Fragment)) {
    throw 'TimestampServer must be an absolute HTTPS RFC 3161 URL without credentials, a query, or a fragment.'
}

function Assert-NoReparsePoint([string]$FilePath) {
    $current = Get-Item -LiteralPath $FilePath -Force
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Signing through a reparse point is not permitted.'
        }
        $parent = Split-Path -Parent $current.FullName
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current.FullName) { break }
        $current = Get-Item -LiteralPath $parent -Force
    }
}

$files = @()
$seen = @{}
foreach ($candidate in $LiteralPath) {
    $item = Get-Item -LiteralPath $candidate -Force
    if ($item.PSIsContainer -or [IO.Path]::GetExtension($item.Name).ToLowerInvariant() -notin @('.exe', '.dll', '.ps1')) {
        throw 'Only explicit EXE, DLL, or PowerShell files can be signed.'
    }
    if ($item.Name -in @('xray.exe', 'wintun.dll')) {
        throw 'Do not modify the pinned third-party Xray or Wintun runtime.'
    }
    Assert-NoReparsePoint $item.FullName
    if (Test-Path -LiteralPath ($item.FullName + '.update.json')) {
        throw 'This installer already has signed update metadata. Rebuild it and sign before generating final hashes and metadata.'
    }
    $key = $item.FullName.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'A signing target was specified more than once.' }
    $seen[$key] = $true
    $files += [pscustomobject]@{
        Path = $item.FullName
        OriginalHash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        Staged = $null
        Backup = $null
        Committed = $false
    }
}
if ($files.Count -eq 0) { throw 'No signing targets were specified.' }

$certificatePath = 'Cert:\' + $CertificateStore + '\My\' + $normalizedThumbprint
if (!(Test-Path -LiteralPath $certificatePath)) {
    throw 'The requested code-signing certificate is not installed. No file was changed.'
}
$certificate = Get-Item -LiteralPath $certificatePath
if (!$certificate.HasPrivateKey) { throw 'The signing certificate does not have an accessible private key.' }
$now = [DateTime]::UtcNow
if ($certificate.NotBefore.ToUniversalTime() -gt $now -or $certificate.NotAfter.ToUniversalTime() -le $now) {
    throw 'The signing certificate is not currently valid.'
}
if ($certificate.Subject -eq $certificate.Issuer) { throw 'Self-signed code-signing certificates are not accepted.' }
$eku = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
if ($eku.Count -ne 1 -or @($eku[0].EnhancedKeyUsages | Where-Object { $_.Value -eq $codeSigningOid }).Count -ne 1) {
    throw 'The certificate must explicitly permit code signing.'
}

$chain = New-Object Security.Cryptography.X509Certificates.X509Chain
try {
    $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
    $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
    $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(10)
    [void]$chain.ChainPolicy.ApplicationPolicy.Add((New-Object -TypeName Security.Cryptography.Oid -ArgumentList $codeSigningOid))
    if (!$chain.Build($certificate)) {
        throw 'The signing certificate chain or revocation status could not be validated. No file was changed.'
    }
} finally { $chain.Dispose() }

if ([string]::IsNullOrWhiteSpace($SignToolPath)) {
    $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $candidates = @()
    if (Test-Path -LiteralPath $sdk -PathType Container) {
        $candidates = @(Get-ChildItem -LiteralPath $sdk -Directory |
            Where-Object { $_.Name -match '^10\.\d+\.\d+\.\d+$' } |
            Sort-Object { [version]$_.Name } -Descending |
            ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    }
    if ($candidates.Count -eq 0) { throw 'Microsoft SignTool was not found. Provide its Windows SDK path with -SignToolPath.' }
    $SignToolPath = $candidates[0]
}
$tool = Get-Item -LiteralPath $SignToolPath -Force
if ($tool.PSIsContainer -or $tool.Name -ne 'signtool.exe') { throw 'SignToolPath must refer to Microsoft signtool.exe.' }
Assert-NoReparsePoint $tool.FullName
$toolSignature = Get-AuthenticodeSignature -LiteralPath $tool.FullName
if ($toolSignature.Status -ne 'Valid' -or $null -eq $toolSignature.SignerCertificate -or
    $toolSignature.SignerCertificate.Subject -notmatch '(?i)(^|,)\s*O=Microsoft Corporation(,|$)') {
    throw 'Microsoft SignTool itself must have a valid Microsoft Authenticode signature.'
}
$SignToolPath = $tool.FullName

if ($CheckOnly) {
    [pscustomobject]@{
        Status = 'Ready'
        TargetCount = $files.Count
        CertificateThumbprint = $normalizedThumbprint
        CertificateExpiresUtc = $certificate.NotAfter.ToUniversalTime().ToString('o')
        SignToolPath = $SignToolPath
    }
    return
}

function Invoke-CheckedSignTool([string[]]$Arguments, [string]$Operation) {
    # Avoid publishing CSP/provider diagnostics or timestamp URL parameters.
    $null = & $SignToolPath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Microsoft SignTool ' + $Operation + ' failed; no release should be published.') }
}

function Assert-ReleaseSignature([string]$FilePath) {
    $signature = Get-AuthenticodeSignature -LiteralPath $FilePath
    if ($signature.Status -ne 'Valid' -or $signature.SignatureType -ne 'Authenticode' -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $normalizedThumbprint -or
        $null -eq $signature.TimeStamperCertificate) {
        throw 'The release signature, expected publisher, or mandatory timestamp could not be validated.'
    }
    Invoke-CheckedSignTool @('verify', '/pa', '/all', '/tw', '/q', $FilePath) 'verification'
}

$signArguments = @('sign', '/q', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $TimestampServer.AbsoluteUri,
    '/s', 'My', '/sha1', $normalizedThumbprint, '/u', $codeSigningOid)
if ($CertificateStore -eq 'LocalMachine') { $signArguments += '/sm' }

$failure = $null
try {
    # Sign independent copies first; one failure leaves every original unchanged.
    foreach ($file in $files) {
        $parent = Split-Path -Parent $file.Path
        $nonce = [Guid]::NewGuid().ToString('N')
        $file.Staged = Join-Path $parent ('.handshake-sign-' + $nonce + [IO.Path]::GetExtension($file.Path))
        $file.Backup = Join-Path $parent ('.handshake-sign-' + $nonce + '.bak')
        [IO.File]::Copy($file.Path, $file.Staged, $false)
        Invoke-CheckedSignTool ($signArguments + @($file.Staged)) 'signing'
        Assert-ReleaseSignature $file.Staged
    }
    foreach ($file in $files) {
        Assert-NoReparsePoint $file.Path
        if ((Get-FileHash -LiteralPath $file.Path -Algorithm SHA256).Hash -ne $file.OriginalHash) {
            throw 'A signing target changed during signing. Originals were not replaced.'
        }
    }
    foreach ($file in $files) {
        [IO.File]::Replace($file.Staged, $file.Path, $file.Backup)
        $file.Committed = $true
        Assert-ReleaseSignature $file.Path
    }
    foreach ($file in $files) {
        [pscustomobject]@{
            Path = $file.Path
            AuthenticodeStatus = 'Valid'
            CertificateThumbprint = $normalizedThumbprint
            TimestampVerified = $true
            Sha256 = (Get-FileHash -LiteralPath $file.Path -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
} catch {
    $failure = $_
    $rollbackFailed = $false
    for ($i = $files.Count - 1; $i -ge 0; $i--) {
        $file = $files[$i]
        if ($file.Committed) {
            try {
                [IO.File]::Replace($file.Backup, $file.Path, $null)
                $file.Committed = $false
            } catch { $rollbackFailed = $true }
        }
    }
    if ($rollbackFailed) { throw 'Signing failed and an original could not be restored. Preserve .handshake-sign-*.bak files and rebuild the release before publishing.' }
    throw $failure
} finally {
    foreach ($file in $files) {
        if ($null -ne $file.Staged -and (Test-Path -LiteralPath $file.Staged -PathType Leaf)) {
            Remove-Item -LiteralPath $file.Staged -Force
        }
        # Keep the original backup if a rollback failed; otherwise clean our files.
        if (!$file.Committed -or $null -eq $failure) {
            if ($null -ne $file.Backup -and (Test-Path -LiteralPath $file.Backup -PathType Leaf)) {
                Remove-Item -LiteralPath $file.Backup -Force
            }
        }
    }
}
