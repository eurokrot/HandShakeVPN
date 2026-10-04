$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskErrors = $null; $taskTokens = $null
$taskAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $taskRoot 'services\Firewall-Policy.ps1'),
    [ref]$taskTokens, [ref]$taskErrors)
if ($taskErrors.Count) { throw 'Firewall recovery helper parse failed.' }
# Only load the fixed production recovery functions. Every process, adapter,
# DNS, route, address and firewall API below is an isolated in-memory fixture.
$taskFunctions = @('Get-OwnedVpnAdapter','Assert-PersonalXrayStopped','Clear-VpnTunState',
    'Assert-VpnStopped','Recover-VpnManagedState')
foreach ($taskFunction in $taskFunctions) {
    $taskDefinition = @($taskAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        Where-Object Name -eq $taskFunction)
    if ($taskDefinition.Count -ne 1) { throw 'Production recovery function is missing or ambiguous.' }
    . ([ScriptBlock]::Create($taskDefinition[0].Extent.Text))
}
$script:VpnTunGuid = [Guid]'44eb0814-5448-ac17-9b83-f3224562e575'
$script:VpnGroup = 'isolated-vpn-test'
$script:VpnStatePath = Join-Path $taskRoot ('.local\nonexistent-snapshot-' + [Guid]::NewGuid().ToString('N'))
$script:checks = 0
function Check([bool]$Value, [string]$Message) {
    if (-not $Value) { throw $Message }
    $script:checks++
}
function New-Adapter([string]$Name, [int]$Index, [Guid]$Guid, [bool]$Hardware, [string]$Driver) {
    [pscustomobject]@{ Name = $Name; ifIndex = $Index; InterfaceGuid = $Guid;
        HardwareInterface = $Hardware; DriverFileName = $Driver; InterfaceDescription = 'fixture' }
}
function Reset-Fixture {
    $script:adapters = @((New-Adapter 'Ethernet' 2 ([Guid]::NewGuid()) $true 'ethernet.sys'),
        (New-Adapter 'handshake0' 25 $script:VpnTunGuid $false 'wintun.sys'),
        (New-Adapter 'Another VPN' 26 ([Guid]::NewGuid()) $false 'wintun.sys'))
    $script:routes = @([pscustomobject]@{ InterfaceIndex = 2; DestinationPrefix = '0.0.0.0/0' },
        [pscustomobject]@{ InterfaceIndex = 25; DestinationPrefix = '0.0.0.0/1' },
        [pscustomobject]@{ InterfaceIndex = 25; DestinationPrefix = '::/0' },
        [pscustomobject]@{ InterfaceIndex = 26; DestinationPrefix = '128.0.0.0/1' })
    $script:addresses = @([pscustomobject]@{ InterfaceIndex = 2; IPAddress = '192.168.1.5' },
        [pscustomobject]@{ InterfaceIndex = 25; IPAddress = '10.253.0.1' },
        [pscustomobject]@{ InterfaceIndex = 25; IPAddress = 'fd7a:115c:a1e0::1' },
        [pscustomobject]@{ InterfaceIndex = 26; IPAddress = '10.7.0.1' })
    $script:dns = @{ 2 = @('192.168.1.1'); 25 = @('1.1.1.1','1.0.0.1'); 26 = @('9.9.9.9') }
    $script:processes = @([pscustomobject]@{ HasExited = $false;
        MainModule = [pscustomobject]@{ FileName = (Join-Path $env:ProgramFiles 'HandShake VPN\runtime\node\xray.exe') } })
    $script:mutations = [Collections.Generic.List[string]]::new()
    $script:adapterReads = 0
    $script:replaceIndex = $false
    $script:failDns = $false
    $script:failRoute = $false
    $script:firewallRemoved = $false
}
function Get-Process { param($Name) $script:processes }
function Get-NetAdapter { param([switch]$IncludeHidden)
    $script:adapterReads++
    if ($script:replaceIndex -and $script:adapterReads -gt 1) { $script:adapters[1].ifIndex = 99 }
    $script:adapters
}
function Get-NetRoute { param($InterfaceIndex,$PolicyStore)
    Check ($PolicyStore -eq 'ActiveStore') 'Recovery attempted to read an unexpected route store.'
    $script:routes | Where-Object InterfaceIndex -eq $InterfaceIndex
}
function Get-NetIPAddress { param($InterfaceIndex,$PolicyStore)
    $script:addresses | Where-Object InterfaceIndex -eq $InterfaceIndex
}
function Get-DnsClientServerAddress { param($InterfaceIndex)
    [pscustomobject]@{ ServerAddresses = $script:dns[[int]$InterfaceIndex] }
}
function Set-DnsClientServerAddress { param($InterfaceIndex,[switch]$ResetServerAddresses)
    Check ($InterfaceIndex -eq 25 -and $ResetServerAddresses) 'Recovery changed DNS on an unrelated adapter.'
    if ($script:failDns) { throw 'Injected DNS restore failure' }
    $script:mutations.Add('dns')
    $script:dns[25] = @()
}
function Remove-NetRoute { param($InputObject,$Confirm)
    Check ($InputObject.InterfaceIndex -eq 25 -and $Confirm -eq $false) 'Recovery removed an unrelated route.'
    if ($script:failRoute) { throw 'Injected route cleanup failure' }
    $script:mutations.Add('route')
    $script:routes = @($script:routes | Where-Object { $_ -ne $InputObject })
}
function Remove-NetIPAddress { param($InputObject,$Confirm)
    Check ($InputObject.InterfaceIndex -eq 25 -and $Confirm -eq $false) 'Recovery removed an unrelated IP address.'
    $script:mutations.Add('ip')
    $script:addresses = @($script:addresses | Where-Object { $_ -ne $InputObject })
}
function Remove-VpnManagedState { $script:firewallRemoved = $true; $script:mutations.Add('firewall') }
function Get-GroupRules { param($Group) @() }
function Expect-Failure([ScriptBlock]$Action, [string]$Prefix) {
    $caught = $null
    try { & $Action } catch { $caught = $_.Exception.Message }
    Check ($caught -like ($Prefix + '*')) ('Expected safe failure: ' + $Prefix + '; got: ' + $caught)
    Check (-not $script:firewallRemoved) 'Recovery removed firewall state after incomplete TUN cleanup.'
}

Reset-Fixture
Recover-VpnManagedState
Check ($script:mutations[$script:mutations.Count - 1] -eq 'firewall') 'Protection cleanup ran before TUN cleanup.'
Check ($script:routes.Count -eq 2 -and $script:addresses.Count -eq 2) 'Owned residual TUN routes or addresses remain.'
Check ($script:dns[2][0] -eq '192.168.1.1' -and $script:dns[26][0] -eq '9.9.9.9') 'Unrelated DNS was changed.'
$taskMutations = $script:mutations.Count
Recover-VpnManagedState
Check ($script:mutations.Count -eq $taskMutations + 1) 'Repeated recovery repeated adapter changes.'

Reset-Fixture
$script:adapters[1].InterfaceGuid = [Guid]::NewGuid()
Expect-Failure { Recover-VpnManagedState } 'Managed VPN adapter identity could not be verified'
Check ($script:mutations.Count -eq 0) 'Name-only adapter was changed.'
Reset-Fixture
$script:adapters[1].HardwareInterface = $true
Expect-Failure { Recover-VpnManagedState } 'Managed VPN adapter identity could not be verified'
Reset-Fixture
$script:adapters += New-Adapter 'handshake0' 27 ([Guid]::NewGuid()) $false 'wintun.sys'
Expect-Failure { Recover-VpnManagedState } 'Managed VPN adapter identity is ambiguous'
Reset-Fixture
$script:replaceIndex = $true
Expect-Failure { Recover-VpnManagedState } 'Managed VPN adapter changed during cleanup'
Check ($script:mutations.Count -eq 0) 'Reused interface index was changed.'

Reset-Fixture
$script:processes[0].MainModule.FileName = Join-Path $env:ProgramFiles 'HandShake VPN\runtime\vpn\xray.exe'
Expect-Failure { Recover-VpnManagedState } 'Personal VPN Xray is still running'
Check ($script:mutations.Count -eq 0) 'A live personal VPN had network settings removed.'
Reset-Fixture
$script:processes[0].MainModule.FileName = ''
Expect-Failure { Recover-VpnManagedState } 'Could not verify an Xray process'
Reset-Fixture
$script:failDns = $true
Expect-Failure { Recover-VpnManagedState } 'Injected DNS restore failure'
Reset-Fixture
$script:failRoute = $true
Expect-Failure { Recover-VpnManagedState } 'Injected route cleanup failure'
$script:failRoute = $false
Recover-VpnManagedState
Check ($script:firewallRemoved -and $script:routes.Count -eq 2) 'A partial cleanup could not be retried.'

Reset-Fixture
$script:adapters = @($script:adapters | Where-Object ifIndex -ne 25)
Recover-VpnManagedState
Check ($script:mutations.Count -eq 1 -and $script:mutations[0] -eq 'firewall') 'Absent owned adapter changed other devices.'
Write-Output ('PASS: ' + $script:checks + ' isolated owned-TUN recovery checks (identity, residues, faults, retry, Node independence).')
