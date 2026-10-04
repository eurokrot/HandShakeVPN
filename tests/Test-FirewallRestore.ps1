$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskScratch = Join-Path $taskRoot ('.local\firewall-restore-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskScratch | Out-Null
# Evaluate ONLY these source functions. Never execute module imports, switches,
# privilege checks or actual NetSecurity commands from the production helper.
$taskErrors = $null; $taskTokens = $null
$taskAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $taskRoot 'services\Firewall-Policy.ps1'), [ref]$taskTokens, [ref]$taskErrors)
if ($taskErrors.Count) { throw 'Firewall helper parse failed' }
$taskFunctions = @('Assert-ExactProperties','Save-VpnProfileState','Restore-VpnProfileState','Apply-Vpn',
    'Get-OwnedVpnAdapter','Assert-VpnStopped','Assert-VpnRecoveryComplete','Remove-VpnManagedState')
foreach ($taskFunction in $taskFunctions) {
    $taskDefinition = $taskAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        Where-Object Name -eq $taskFunction
    Invoke-Expression $taskDefinition.Extent.Text
}
$script:FirewallStateDirectory = $taskScratch
$script:VpnStatePath = Join-Path $taskScratch 'snapshot.json'
$script:VpnGroup = 'isolated-test'; $script:VpnPrefix = 'isolated-test.'
$script:VpnTunGuid = [Guid]'44eb0814-5448-ac17-9b83-f3224562e575'
$script:defaults = @{ Domain = 'Allow'; Private = 'NotConfigured'; Public = 'Block' }
$script:failPrivateRestore = $true
function Get-NetFirewallProfile { param($PolicyStore)
    foreach ($name in @('Domain','Private','Public')) {
        [pscustomobject]@{ Name = $name; DefaultOutboundAction = $script:defaults[$name]; Enabled = $true }
    }
}
function Set-NetFirewallProfile { param($PolicyStore,$Profile,$DefaultOutboundAction)
    if ($Profile -eq 'Private' -and $DefaultOutboundAction -eq 'NotConfigured' -and $script:failPrivateRestore) {
        throw 'Injected restore failure'
    }
    $script:defaults[$Profile] = $DefaultOutboundAction
}
function Read-Plan { param($Role) [pscustomobject]@{
    tunnelInterfaceAlias = $null; vpnXrayPath = 'C:\fixture\runtime\vpn\xray.exe';
    vpnServicePath = 'C:\fixture\HandShakeVpnService.exe'; nodeServicePath = 'C:\fixture\HandShakeNodeService.exe';
    relayAddress = '198.51.100.2'; relayPort = 8443; apiAddresses = @('198.51.100.2'); apiPort = 443
} }
function Assert-FirewallEnabled { }
function New-ManagedRule { }
function Assert-VpnDefaultBlock { throw 'Injected apply failure after changing defaults' }
function Remove-RuleNames { param($Names) }
function Get-GroupRules { param($Group) $script:ownedRules }
function Remove-ManagedGroup { param($Group) $script:ownedRules = @() }
function Get-NetAdapter { param([switch]$IncludeHidden) $script:adapters }
function Get-NetRoute { param($InterfaceIndex,$PolicyStore) @() }
function Get-DnsClientServerAddress { param($InterfaceIndex) [pscustomobject]@{ ServerAddresses = $script:dns } }
function Get-NetIPAddress { param($InterfaceIndex) @() }
$script:ownedRules = @(); $script:adapters = @(); $script:dns = @()
function Assert-ManagedRules { }
try {
    try { Apply-Vpn $false; throw 'Apply unexpectedly succeeded' } catch {
        if ($_.Exception.Message -ne 'Injected apply failure after changing defaults') { throw }
    }
    if (!(Test-Path -LiteralPath $script:VpnStatePath)) { throw 'Failed rollback discarded the original defaults' }
    $script:failPrivateRestore = $false
    Restore-VpnProfileState
    if ($script:defaults.Domain -ne 'Allow' -or $script:defaults.Private -ne 'NotConfigured' -or $script:defaults.Public -ne 'Block') {
        throw 'Retry did not restore the three original settings'
    }
    # Idempotent retry must preserve an originally blocked profile, not guess Allow.
    Restore-VpnProfileState
    Write-Output 'PASS: failed rollback retains snapshot; retry/idempotency preserve all original profile defaults including Block'
    Remove-Item -LiteralPath $script:VpnStatePath
    try { Assert-VpnRecoveryComplete; throw 'Blocked outbound policy incorrectly confirmed recovery' } catch {
        if ($_.Exception.Message -notlike 'Windows outbound policy still blocks traffic*') { throw }
    }
    $script:ownedRules = @([pscustomobject]@{ Name = 'isolated-test.allow' })
    try { Remove-VpnManagedState; throw 'Missing snapshot caused guessed removal' } catch {
        if ($_.Exception.Message -notlike 'The original firewall snapshot is missing*') { throw }
    }
    if ($script:ownedRules.Count -ne 1 -or $script:defaults.Public -ne 'Block') { throw 'Uncertain firewall state was changed' }
    $script:ownedRules = @(); $script:defaults.Public = 'Allow'
    Assert-VpnRecoveryComplete
    $script:adapters = @([pscustomobject]@{ Name = 'handshake0'; InterfaceDescription = 'HandShake VPN'; ifIndex = 25;
        InterfaceGuid = $script:VpnTunGuid; HardwareInterface = $false; DriverFileName = 'wintun.sys' })
    $script:dns = @('1.1.1.1')
    try { Assert-VpnStopped; throw 'Owned DNS remnants were ignored' } catch {
        if ($_.Exception.Message -notlike 'The managed VPN adapter retains DNS/IP settings*') { throw }
    }
    $script:adapters = @([pscustomobject]@{ Name = 'Ethernet'; InterfaceDescription = 'Physical adapter'; ifIndex = 2;
        InterfaceGuid = [Guid]::NewGuid(); HardwareInterface = $true; DriverFileName = 'ethernet.sys' })
    Assert-VpnRecoveryComplete
    Write-Output 'PASS: lost snapshot/blocked outbound cannot report success or change policy; owned DNS detected; physical adapter untouched'
} finally {
    if (Test-Path -LiteralPath $script:VpnStatePath) { Remove-Item -LiteralPath $script:VpnStatePath }
    Remove-Item -LiteralPath $taskScratch
}
