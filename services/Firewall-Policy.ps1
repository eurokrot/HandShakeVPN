[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('ApplyVpnBootstrap', 'ApplyVpnTunnel', 'VerifyVpnBootstrap', 'VerifyVpnTunnel',
        'RemoveVpn', 'VerifyVpnStopped', 'VerifyVpnRecovery', 'ApplyNode', 'VerifyNode', 'RemoveNode', 'SelfTest')]
    [string]$Operation,

    [string]$PlanPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:VpnGroup = 'HandShake VPN Managed - VPN Kill Switch'
$script:NodeGroup = 'HandShake VPN Managed - Exit Isolation'
$script:VpnPrefix = 'HandShake.Vpn.'
$script:NodePrefix = 'HandShake.Node.'
$script:FirewallStateDirectory = Join-Path $env:ProgramData 'HandShake VPN\firewall'
$script:VpnStatePath = Join-Path $script:FirewallStateDirectory 'vpn-profile-state.json'

$script:PrivateV4 = @(
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
    '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'
)
$script:PrivateV6 = @(
    # Windows Firewall rejects unspecified, loopback, and multicast IPv6
    # literals as RemoteAddress values. They are non-routable or covered by
    # the separate LocalSubnet block. Keep the routable special ranges here.
    '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64',
    '2001::/23', '2001:db8::/32', '2002::/16', 'fc00::/7', 'fe80::/10'
)

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Windows firewall policy requires an elevated service or administrator process.'
    }
}

function Assert-ExactProperties([object]$Value, [string[]]$Allowed) {
    $present = @($Value.PSObject.Properties.Name)
    foreach ($name in $present) {
        if ($Allowed -notcontains $name) {
            throw "Unknown firewall plan property: $name"
        }
    }
    foreach ($name in $Allowed) {
        if ($present -notcontains $name) {
            throw "Missing firewall plan property: $name"
        }
    }
}

function Assert-ExactPath([string]$Actual, [string]$Expected, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Actual)) { throw "$Label is missing." }
    $actualFull = [IO.Path]::GetFullPath($Actual)
    $expectedFull = [IO.Path]::GetFullPath($Expected)
    if (-not [string]::Equals($actualFull, $expectedFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label does not match its fixed protected path."
    }
}

function ConvertTo-StrictIp([string]$Text, [string]$Label) {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Text, [ref]$parsed)) {
        throw "$Label must be a numeric IP address."
    }
    return $parsed
}

function Test-PublicUnicast([Net.IPAddress]$Address) {
    if ([Net.IPAddress]::IsLoopback($Address) -or $Address.Equals([Net.IPAddress]::Any) -or
        $Address.Equals([Net.IPAddress]::IPv6Any) -or $Address.Equals([Net.IPAddress]::None) -or
        $Address.Equals([Net.IPAddress]::IPv6None)) { return $false }
    $bytes = $Address.GetAddressBytes()
    if ($Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        if ($bytes[0] -in @(0, 10, 127)) { return $false }
        if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) { return $false }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return $false }
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $false }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and $bytes[2] -in @(0, 2)) { return $false }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 88 -and $bytes[2] -eq 99) { return $false }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $false }
        if ($bytes[0] -eq 198 -and $bytes[1] -in @(18, 19)) { return $false }
        if ($bytes[0] -eq 198 -and $bytes[1] -eq 51 -and $bytes[2] -eq 100) { return $false }
        if ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and $bytes[2] -eq 113) { return $false }
        return $bytes[0] -lt 224
    }
    if ($Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($Address.IsIPv6LinkLocal -or $Address.IsIPv6SiteLocal -or $bytes[0] -eq 0xff) { return $false }
        if (($bytes[0] -band 0xfe) -eq 0xfc) { return $false }
        if ($bytes[0] -eq 0x00 -and $bytes[1] -eq 0x64 -and $bytes[2] -eq 0xff -and $bytes[3] -eq 0x9b) { return $false }
        if ($bytes[0] -eq 0x01 -and $bytes[1] -eq 0x00) { return $false }
        if ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and $bytes[2] -le 0x01) { return $false }
        if ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and $bytes[2] -eq 0x0d -and $bytes[3] -eq 0xb8) { return $false }
        if ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x02) { return $false }
        return $true
    }
    return $false
}

function Read-Plan([string]$ExpectedKind) {
    if ([string]::IsNullOrWhiteSpace($PlanPath) -or -not (Test-Path -LiteralPath $PlanPath -PathType Leaf)) {
        throw 'The fixed firewall plan file is missing.'
    }
    $info = Get-Item -LiteralPath $PlanPath
    if ($info.Length -lt 2 -or $info.Length -gt 131072) { throw 'The firewall plan has an invalid size.' }
    $plan = Get-Content -Raw -LiteralPath $PlanPath | ConvertFrom-Json
    $keys = @('schemaVersion', 'kind', 'relayAddress', 'relayPort', 'apiAddresses', 'apiPort',
        'vpnXrayPath', 'nodeXrayPath', 'vpnServicePath', 'nodeServicePath', 'tunnelInterfaceAlias')
    if ($ExpectedKind -eq 'node') { $keys += 'localSubnets' }
    Assert-ExactProperties -Value $plan -Allowed $keys
    if ([int]$plan.schemaVersion -ne 1 -or $plan.kind -ne $ExpectedKind) { throw 'The firewall plan schema or kind is invalid.' }

    $expectedPlanPath = Join-Path $env:ProgramData ('HandShake VPN\' + $ExpectedKind + '\firewall-plan.json')
    Assert-ExactPath $PlanPath $expectedPlanPath 'PlanPath'

    $root = [IO.Path]::GetFullPath($PSScriptRoot)
    Assert-ExactPath $plan.vpnXrayPath (Join-Path $root 'runtime\vpn\xray.exe') 'vpnXrayPath'
    Assert-ExactPath $plan.nodeXrayPath (Join-Path $root 'runtime\node\xray.exe') 'nodeXrayPath'
    Assert-ExactPath $plan.vpnServicePath (Join-Path $root 'HandShakeVpnService.exe') 'vpnServicePath'
    Assert-ExactPath $plan.nodeServicePath (Join-Path $root 'HandShakeNodeService.exe') 'nodeServicePath'
    foreach ($managedFile in @($plan.vpnXrayPath, $plan.nodeXrayPath, $plan.vpnServicePath, $plan.nodeServicePath)) {
        if (-not (Test-Path -LiteralPath $managedFile -PathType Leaf)) {
            throw 'A fixed executable required by firewall policy is missing.'
        }
    }

    $relay = ConvertTo-StrictIp ([string]$plan.relayAddress) 'relayAddress'
    if (-not (Test-PublicUnicast $relay)) { throw 'relayAddress must be public unicast.' }
    $relayPort = [int]$plan.relayPort
    $apiPort = [int]$plan.apiPort
    if ($relayPort -lt 1 -or $relayPort -gt 65535 -or $apiPort -lt 1 -or $apiPort -gt 65535) {
        throw 'A firewall plan port is outside the valid range.'
    }

    $apiAddresses = @($plan.apiAddresses)
    if ($apiAddresses.Count -lt 1 -or $apiAddresses.Count -gt 8) { throw 'apiAddresses must contain between one and eight addresses.' }
    foreach ($address in $apiAddresses) { [void](ConvertTo-StrictIp ([string]$address) 'apiAddresses') }
    if ($ExpectedKind -eq 'node') {
        $subnets = @($plan.localSubnets)
        if ($subnets.Count -lt 1 -or $subnets.Count -gt 64) { throw 'Physical local subnets are missing or excessive.' }
        foreach ($subnet in $subnets) {
            $pieces = ([string]$subnet).Split('/')
            if ($pieces.Count -ne 2) { throw 'Invalid physical local subnet.' }
            $address = ConvertTo-StrictIp $pieces[0] 'localSubnets'
            $prefix = 0
            if (-not [int]::TryParse($pieces[1], [ref]$prefix) -or $prefix -lt 1 -or $prefix -gt ($address.GetAddressBytes().Length * 8)) { throw 'Invalid local subnet prefix.' }
        }
    }

    $alias = [string]$plan.tunnelInterfaceAlias
    if ($alias.Length -gt 0 -and $alias -notmatch '^[\p{L}\p{Nd} ._-]{1,64}$') {
        throw 'The tunnel interface alias is invalid.'
    }
    return $plan
}

function Get-GroupRules([string]$Group) {
    return @(Get-NetFirewallRule -PolicyStore PersistentStore -Group $Group -ErrorAction SilentlyContinue)
}

function Remove-RuleNames([string[]]$Names) {
    foreach ($name in @($Names)) {
        Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction Stop
    }
}

function Remove-ManagedGroup([string]$Group) {
    Get-GroupRules $Group | Remove-NetFirewallRule -ErrorAction Stop
}

function New-ManagedRule {
    param(
        [string]$Name,
        [string]$DisplayName,
        [string]$Group,
        [ValidateSet('Allow', 'Block')][string]$Action,
        [string]$Program,
        [string[]]$RemoteAddress,
        [ValidateSet('Any', 'TCP', 'UDP')][string]$Protocol = 'Any',
        [string]$RemotePort,
        [string]$InterfaceAlias
    )
    $parameters = @{
        Name = $Name
        DisplayName = $DisplayName
        Group = $Group
        Direction = 'Outbound'
        Action = $Action
        Enabled = 'True'
        Profile = 'Any'
        PolicyStore = 'PersistentStore'
        Protocol = $Protocol
    }
    if (-not [string]::IsNullOrWhiteSpace($Program)) { $parameters.Program = $Program }
    if ($RemoteAddress -and $RemoteAddress.Count -gt 0) { $parameters.RemoteAddress = $RemoteAddress }
    if (-not [string]::IsNullOrWhiteSpace($RemotePort)) { $parameters.RemotePort = $RemotePort }
    if (-not [string]::IsNullOrWhiteSpace($InterfaceAlias)) { $parameters.InterfaceAlias = $InterfaceAlias }
    New-NetFirewallRule @parameters | Out-Null
}

function Assert-FirewallEnabled {
    $disabled = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { -not $_.Enabled })
    if ($disabled.Count -gt 0) { throw 'Windows Defender Firewall must be enabled for every profile.' }
}

function Save-VpnProfileState {
    if (Test-Path -LiteralPath $script:VpnStatePath) { return $false }
    if (-not (Test-Path -LiteralPath $script:FirewallStateDirectory -PathType Container)) {
        throw 'The protected firewall state directory is missing.'
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore | ForEach-Object {
        [ordered]@{ name = [string]$_.Name; defaultOutboundAction = [string]$_.DefaultOutboundAction }
    })
    if ($profiles.Count -ne 3) { throw 'Could not snapshot all Windows Firewall profiles.' }
    $state = [ordered]@{ schemaVersion = 1; profiles = $profiles }
    $temporary = $script:VpnStatePath + '.tmp-' + [Guid]::NewGuid().ToString('N')
    $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $script:VpnStatePath -Force
    return $true
}

function Restore-VpnProfileState {
    if (-not (Test-Path -LiteralPath $script:VpnStatePath -PathType Leaf)) { return }
    $state = Get-Content -Raw -LiteralPath $script:VpnStatePath | ConvertFrom-Json
    Assert-ExactProperties $state @('schemaVersion', 'profiles')
    if ([int]$state.schemaVersion -ne 1 -or @($state.profiles).Count -ne 3 -or
        @($state.profiles | Select-Object -ExpandProperty name -Unique).Count -ne 3) {
        throw 'The saved Windows Firewall profile state is invalid; refusing an unsafe guessed restore.'
    }
    foreach ($profile in @($state.profiles)) {
        Assert-ExactProperties $profile @('name', 'defaultOutboundAction')
        if ($profile.name -notin @('Domain', 'Private', 'Public')) { throw 'Saved firewall profile name is invalid.' }
        if ($profile.defaultOutboundAction -notin @('Allow', 'Block', 'NotConfigured')) {
            throw 'Saved firewall outbound action is invalid.'
        }
    }
    foreach ($profile in @($state.profiles)) {
        Set-NetFirewallProfile -PolicyStore PersistentStore -Profile $profile.name `
            -DefaultOutboundAction $profile.defaultOutboundAction
    }
    $restored = @(Get-NetFirewallProfile -PolicyStore PersistentStore)
    foreach ($profile in @($state.profiles)) {
        $current = @($restored | Where-Object { [string]$_.Name -eq [string]$profile.name })
        if ($current.Count -ne 1 -or [string]$current[0].DefaultOutboundAction -ne [string]$profile.defaultOutboundAction) {
            throw 'Saved firewall defaults could not be confirmed; retaining the restore snapshot.'
        }
    }
}

function Assert-VpnDefaultBlock {
    Assert-FirewallEnabled
    $notBlocked = @(Get-NetFirewallProfile -PolicyStore ActiveStore |
        Where-Object { [string]$_.DefaultOutboundAction -ne 'Block' })
    if ($notBlocked.Count -gt 0) { throw 'Effective outbound firewall policy is not fail-closed for every profile.' }
}

function Assert-VpnStopped {
    if (@(Get-GroupRules $script:VpnGroup).Count -ne 0 -or (Test-Path -LiteralPath $script:VpnStatePath)) {
        throw 'Managed VPN firewall cleanup is incomplete.'
    }
    $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object {
        $_.Name -eq 'handshake0' -or $_.InterfaceDescription -eq 'HandShake VPN'
    })
    foreach ($adapter in $adapters) {
        if (@(Get-NetRoute -InterfaceIndex $adapter.ifIndex -PolicyStore ActiveStore -ErrorAction Stop).Count -gt 0) {
            throw 'The managed VPN adapter still has routes. Restoration is not confirmed.'
        }
        $dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop |
            Where-Object { @($_.ServerAddresses).Count -gt 0 })
        $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop | Where-Object {
            $_.IPAddress -like '10.253.0.*' -or $_.IPAddress -like 'fd7a:115c:a1e0:*'
        })
        if ($dns.Count -gt 0 -or $addresses.Count -gt 0) {
            throw 'The managed VPN adapter retains DNS/IP settings. Restoration is not confirmed.'
        }
    }
}

function Remove-VpnManagedState {
    if (!(Test-Path -LiteralPath $script:VpnStatePath) -and @(Get-GroupRules $script:VpnGroup).Count -gt 0 -and
        @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { [string]$_.DefaultOutboundAction -eq 'Block' }).Count -gt 0) {
        throw 'The original firewall snapshot is missing. Retaining managed allow rules instead of guessing a restore.'
    }
    Restore-VpnProfileState
    Remove-ManagedGroup $script:VpnGroup
    if (Test-Path -LiteralPath $script:VpnStatePath) { Remove-Item -LiteralPath $script:VpnStatePath -Force }
}

function Assert-VpnRecoveryComplete {
    Assert-VpnStopped
    if (@(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object {
        [string]$_.DefaultOutboundAction -eq 'Block'
    }).Count -gt 0) {
        # May be an old lost snapshot OR intentional corporate policy. We cannot
        # distinguish these safely or guess Allow; report incomplete restoration.
        throw 'Windows outbound policy still blocks traffic. Original defaults cannot be inferred; no global reset was performed.'
    }
}

function Assert-ManagedRules([string]$Group, [int]$MinimumCount, [string]$Prefix) {
    $rules = Get-GroupRules $Group
    if ($rules.Count -lt $MinimumCount) { throw "Managed firewall group $Group is incomplete." }
    foreach ($rule in $rules) {
        if (-not ([string]$rule.Name).StartsWith($Prefix, [StringComparison]::Ordinal) -or -not $rule.Enabled) {
            throw "Managed firewall group $Group contains an invalid or disabled rule."
        }
    }
}

function Apply-Vpn([bool]$IncludeTunnel) {
    $plan = Read-Plan 'vpn'
    if ($IncludeTunnel -and [string]::IsNullOrWhiteSpace([string]$plan.tunnelInterfaceAlias)) {
        throw 'The managed TUN interface must exist before tunnel access is enabled.'
    }
    if (-not $IncludeTunnel -and -not [string]::IsNullOrWhiteSpace([string]$plan.tunnelInterfaceAlias)) {
        throw 'Bootstrap policy must not include a TUN interface.'
    }
    Assert-FirewallEnabled
    $newSnapshot = Save-VpnProfileState
    $generation = [Guid]::NewGuid().ToString('N')
    $base = $script:VpnPrefix + $generation + '.'
    $created = [Collections.Generic.List[string]]::new()
    try {
        $name = $base + 'AllowVpnXrayRelay'; $created.Add($name)
        New-ManagedRule -Name $name -DisplayName 'HandShake VPN - VPN transport to relay' `
            -Group $script:VpnGroup -Action Allow -Program $plan.vpnXrayPath `
            -RemoteAddress @([string]$plan.relayAddress) -Protocol TCP -RemotePort ([string]$plan.relayPort)

        $name = $base + 'AllowVpnServiceApi'; $created.Add($name)
        New-ManagedRule -Name $name -DisplayName 'HandShake VPN - VPN service control plane' `
            -Group $script:VpnGroup -Action Allow -Program $plan.vpnServicePath `
            -RemoteAddress @($plan.apiAddresses | ForEach-Object { [string]$_ }) -Protocol TCP -RemotePort ([string]$plan.apiPort)

        # The API address is deliberately outside the TUN. Permit only these
        # owned clients to contact it physically while the default policy blocks.
        $name = $base + 'AllowGuiApi'; $created.Add($name)
        $guiPath = Join-Path (Split-Path -Parent $plan.vpnServicePath) 'HandShake VPN.exe'
        New-ManagedRule -Name $name -DisplayName 'HandShake VPN - application control plane' `
            -Group $script:VpnGroup -Action Allow -Program $guiPath `
            -RemoteAddress @($plan.apiAddresses | ForEach-Object { [string]$_ }) -Protocol TCP -RemotePort ([string]$plan.apiPort)

        $name = $base + 'AllowIndependentNodeServiceApi'; $created.Add($name)
        New-ManagedRule -Name $name -DisplayName 'HandShake VPN - independent Node service control plane' `
            -Group $script:VpnGroup -Action Allow -Program $plan.nodeServicePath `
            -RemoteAddress @($plan.apiAddresses | ForEach-Object { [string]$_ }) -Protocol TCP -RemotePort ([string]$plan.apiPort)

        if ($IncludeTunnel) {
            $name = $base + 'AllowManagedTun'; $created.Add($name)
            New-ManagedRule -Name $name -DisplayName 'HandShake VPN - managed TUN traffic' `
                -Group $script:VpnGroup -Action Allow -RemoteAddress @('Any') -Protocol Any `
                -InterfaceAlias ([string]$plan.tunnelInterfaceAlias)
        }

        foreach ($profile in @('Domain', 'Private', 'Public')) {
            Set-NetFirewallProfile -PolicyStore PersistentStore -Profile $profile -DefaultOutboundAction Block
        }
        Assert-VpnDefaultBlock
        foreach ($rule in Get-GroupRules $script:VpnGroup) {
            if ($created -notcontains [string]$rule.Name) { $rule | Remove-NetFirewallRule -ErrorAction Stop }
        }
        Assert-ManagedRules $script:VpnGroup ($(if ($IncludeTunnel) { 5 } else { 4 })) $script:VpnPrefix
    }
    catch {
        Remove-RuleNames $created.ToArray()
        if ($newSnapshot) {
            # Preserve the original defaults if restore fails; cleanup can retry.
            try {
                Restore-VpnProfileState
                Remove-Item -LiteralPath $script:VpnStatePath -Force
            } catch { }
        }
        throw
    }
}

function Apply-Node {
    $plan = Read-Plan 'node'
    Assert-FirewallEnabled
    $generation = [Guid]::NewGuid().ToString('N')
    $base = $script:NodePrefix + $generation + '.'
    $created = [Collections.Generic.List[string]]::new()
    try {
        $name = $base + 'BlockNonPublicV4'; $created.Add($name)
        New-ManagedRule -Name $name -DisplayName 'HandShake Node - block private and special IPv4' `
            -Group $script:NodeGroup -Action Block -Program $plan.nodeXrayPath -RemoteAddress $script:PrivateV4

        $name = $base + 'BlockNonPublicV6'; $created.Add($name)
        New-ManagedRule -Name $name -DisplayName 'HandShake Node - block private and special IPv6' `
            -Group $script:NodeGroup -Action Block -Program $plan.nodeXrayPath -RemoteAddress $script:PrivateV6

        $name = $base + 'BlockLocalSubnet'; $created.Add($name)
        New-ManagedRule -Name $name -DisplayName 'HandShake Node - block active local subnets' `
            -Group $script:NodeGroup -Action Block -Program $plan.nodeXrayPath -RemoteAddress @($plan.localSubnets)

        # Explicit block rules take precedence over this allow. It is needed when the VPN service
        # has changed the Windows Firewall profile default outbound action to Block.
        $name = $base + 'AllowNodeXrayPublic'; $created.Add($name)
        New-ManagedRule -Name $name -DisplayName 'HandShake Node - allow public exit traffic' `
            -Group $script:NodeGroup -Action Allow -Program $plan.nodeXrayPath -RemoteAddress @('Any')

        $name = $base + 'AllowNodeServiceApi'; $created.Add($name)
        New-ManagedRule -Name $name -DisplayName 'HandShake Node - control plane heartbeat' `
            -Group $script:NodeGroup -Action Allow -Program $plan.nodeServicePath `
            -RemoteAddress @($plan.apiAddresses | ForEach-Object { [string]$_ }) -Protocol TCP -RemotePort ([string]$plan.apiPort)

        foreach ($rule in Get-GroupRules $script:NodeGroup) {
            if ($created -notcontains [string]$rule.Name) { $rule | Remove-NetFirewallRule -ErrorAction Stop }
        }
        Assert-ManagedRules $script:NodeGroup 5 $script:NodePrefix
    }
    catch {
        Remove-RuleNames $created.ToArray()
        throw
    }
}

function Invoke-SelfTest {
    if ($script:VpnGroup -eq $script:NodeGroup -or -not $script:VpnPrefix.StartsWith('HandShake.Vpn.') -or
        -not $script:NodePrefix.StartsWith('HandShake.Node.')) {
        throw 'Managed firewall ownership constants are invalid.'
    }
    foreach ($required in @('10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4')) {
        if ($script:PrivateV4 -notcontains $required) { throw "Missing IPv4 isolation range: $required" }
    }
    foreach ($required in @('::ffff:0:0/96', '64:ff9b::/96', 'fc00::/7', 'fe80::/10')) {
        if ($script:PrivateV6 -notcontains $required) { throw "Missing IPv6 isolation range: $required" }
    }
    foreach ($unsupported in @('::/128', '::1/128', 'ff00::/8')) {
        if ($script:PrivateV6 -contains $unsupported) { throw "Windows Firewall rejects IPv6 RemoteAddress: $unsupported" }
    }
    $public = ConvertTo-StrictIp '203.0.114.10' 'self-test public'
    $private = ConvertTo-StrictIp '192.168.1.5' 'self-test private'
    if (-not (Test-PublicUnicast $public) -or (Test-PublicUnicast $private)) {
        throw 'Public-address classifier self-test failed.'
    }
    $source = Get-Content -Raw -LiteralPath $PSCommandPath
    foreach ($banned in @(('Invoke' + '-Expression'), ('i' + 'ex '), ('net' + 'sh.exe'),
        ('net' + 'sh advfirewall'), ('Remove-NetFirewallRule ' + '-All'),
        ('Set-NetFirewallProfile ' + '-Enabled False'))) {
        if ($source.IndexOf($banned, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "Firewall helper contains a banned broad operation: $banned"
        }
    }
    Write-Output 'Firewall policy offline self-test passed.'
}

if ($Operation -eq 'SelfTest') {
    Invoke-SelfTest
    exit 0
}

Assert-Administrator
Import-Module NetSecurity -ErrorAction Stop

switch ($Operation) {
    'ApplyVpnBootstrap' { Apply-Vpn $false }
    'ApplyVpnTunnel' { Apply-Vpn $true }
    'VerifyVpnBootstrap' { Assert-VpnDefaultBlock; Assert-ManagedRules $script:VpnGroup 4 $script:VpnPrefix }
    'VerifyVpnTunnel' { Assert-VpnDefaultBlock; Assert-ManagedRules $script:VpnGroup 5 $script:VpnPrefix }
    'RemoveVpn' {
        Remove-VpnManagedState
    }
    'VerifyVpnStopped' { Assert-VpnStopped }
    'VerifyVpnRecovery' { Assert-VpnRecoveryComplete }
    'ApplyNode' { Apply-Node }
    'VerifyNode' { Assert-FirewallEnabled; Assert-ManagedRules $script:NodeGroup 5 $script:NodePrefix }
    'RemoveNode' { Remove-ManagedGroup $script:NodeGroup }
    default { throw 'Unsupported firewall operation.' }
}

Write-Output ('Windows firewall operation completed: ' + $Operation)
