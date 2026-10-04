[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$script = Join-Path $projectRoot 'scripts\Sign-Release.ps1'
$signTokens = $null
$signParseErrors = $null
[Management.Automation.Language.Parser]::ParseFile($script, [ref]$signTokens, [ref]$signParseErrors) | Out-Null
if ($signParseErrors.Count -ne 0) { throw 'Signing script failed to parse.' }

$scratchRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot '.local\release-signing-tests'))
$scratch = Join-Path $scratchRoot ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$file = Join-Path $scratch 'HandShakeProbe.ps1'
[IO.File]::WriteAllText($file, '# An unsigned local signing preflight test. Never executed.')
$initialHash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
$arguments = @{
    Thumbprint = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
    LiteralPath = @($file)
    TimestampServer = [uri]'https://timestamp.example.invalid/'
    CheckOnly = $true
}

function Assert-Rejected([hashtable]$Parameters, [string]$ExpectedMessage) {
    $rejected = $false
    try { $null = & $script @Parameters }
    catch {
        if ($_.Exception.Message -notlike ('*' + $ExpectedMessage + '*')) {
            throw ('Unexpected signing rejection: ' + $_.Exception.Message)
        }
        $rejected = $true
    }
    if (!$rejected) { throw 'Unsafe signing request was not rejected.' }
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $initialHash) {
        throw 'Signing preflight changed the original file.'
    }
}

try {
    if (Test-Path -LiteralPath ('Cert:\CurrentUser\My\' + $arguments.Thumbprint)) {
        throw 'The test needs an absent certificate thumbprint.'
    }
    Assert-Rejected $arguments 'certificate is not installed'

    foreach ($timestamp in @('http://timestamp.example.invalid/',
            'https://user:password@timestamp.example.invalid/',
            'https://timestamp.example.invalid/?token=forbidden',
            'https://timestamp.example.invalid/#fragment',
            'https://timestamp.example.invalid:8443/')) {
        $invalid = $arguments.Clone()
        $invalid.TimestampServer = [uri]$timestamp
        Assert-Rejected $invalid 'TimestampServer must'
    }

    $duplicate = $arguments.Clone()
    $duplicate.LiteralPath = @($file, $file)
    Assert-Rejected $duplicate 'more than once'

    $runtime = Join-Path $scratch 'xray.exe'
    [IO.File]::WriteAllText($runtime, 'MZ local pinning rejection test; never executed.')
    $pinned = $arguments.Clone()
    $pinned.LiteralPath = @($runtime)
    Assert-Rejected $pinned 'pinned third-party'

    [IO.File]::WriteAllText(($file + '.update.json'), '{}')
    Assert-Rejected $arguments 'already has signed update metadata'
    Remove-Item -LiteralPath ($file + '.update.json')

    $junction = Join-Path $scratch 'linked'
    New-Item -ItemType Junction -Path $junction -Value $scratch | Out-Null
    $linked = $arguments.Clone()
    $linked.LiteralPath = @(Join-Path $junction 'HandShakeProbe.ps1')
    Assert-Rejected $linked 'reparse point'
    [IO.Directory]::Delete($junction)

    if (@(Get-ChildItem -LiteralPath $scratch -Force -Filter '.handshake-sign-*').Count -ne 0) {
        throw 'Rejected signing requests created signing artifacts.'
    }
    Write-Host 'PASS: parse; missing certificate; HTTPS/timestamp validation; duplicate targets; pinned runtime; existing signed metadata; reparse-point rejection; originals unchanged.'
    Write-Host 'No real signature was generated: a trusted code-signing certificate is not installed.'
} finally {
    # One checked test directory, native PowerShell cleanup, no shell handoff.
    $resolvedScratch = [IO.Path]::GetFullPath($scratch)
    if (!$resolvedScratch.StartsWith($scratchRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing cleanup outside the signing-test directory.'
    }
    if (Test-Path -LiteralPath $scratch -PathType Container) {
        foreach ($child in @(Get-ChildItem -LiteralPath $scratch -Force)) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                if ($child.PSIsContainer) { [IO.Directory]::Delete($child.FullName) }
                else { [IO.File]::Delete($child.FullName) }
            }
        }
        Remove-Item -LiteralPath $scratch -Recurse -Force
    }
}
