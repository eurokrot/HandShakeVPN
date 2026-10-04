using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace HandShake.Services
{
    internal sealed class RelayEndpoint
    {
        public IPAddress Address { get; private set; }
        public int Port { get; private set; }

        public RelayEndpoint(IPAddress address, int port)
        {
            Address = address;
            Port = port;
        }
    }

    internal sealed class VpnXrayNetworkProfile
    {
        public RelayEndpoint Relay { get; private set; }
        public string[] TunInterfaceCandidates { get; private set; }

        public VpnXrayNetworkProfile(RelayEndpoint relay, string[] tunInterfaceCandidates)
        {
            Relay = relay;
            TunInterfaceCandidates = tunInterfaceCandidates;
        }
    }

    internal static class NetworkAddressPolicy
    {
        public static bool IsPublicRelayAddress(IPAddress address)
        {
            if (address == null || IPAddress.Any.Equals(address) || IPAddress.IPv6Any.Equals(address) ||
                IPAddress.None.Equals(address) || IPAddress.IPv6None.Equals(address) || IPAddress.IsLoopback(address))
            {
                return false;
            }

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] b = address.GetAddressBytes();
                return !(b[0] == 0 || b[0] == 10 || b[0] == 127 ||
                    (b[0] == 100 && b[1] >= 64 && b[1] <= 127) ||
                    (b[0] == 169 && b[1] == 254) ||
                    (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                    (b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2)) ||
                    (b[0] == 192 && b[1] == 88 && b[2] == 99) ||
                    (b[0] == 192 && b[1] == 168) ||
                    (b[0] == 198 && (b[1] == 18 || b[1] == 19 || b[1] == 51) &&
                        (b[1] != 51 || b[2] == 100)) ||
                    (b[0] == 203 && b[1] == 0 && b[2] == 113) ||
                    (b[0] >= 224));
            }

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (address.IsIPv4MappedToIPv6)
                {
                    return IsPublicRelayAddress(address.MapToIPv4());
                }
                byte[] b = address.GetAddressBytes();
                bool uniqueLocal = (b[0] & 0xfe) == 0xfc;
                bool multicast = b[0] == 0xff;
                bool unspecified = true;
                for (int i = 0; i < b.Length; i++) { if (b[i] != 0) { unspecified = false; break; } }
                bool nat64 = b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b;
                bool discardOnly = b[0] == 0x01 && b[1] == 0x00;
                bool ietfSpecial = b[0] == 0x20 && b[1] == 0x01 && b[2] <= 0x01;
                bool documentation = b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8;
                bool sixToFour = b[0] == 0x20 && b[1] == 0x02;
                return !unspecified && !address.IsIPv6LinkLocal && !address.IsIPv6SiteLocal && !uniqueLocal &&
                    !multicast && !nat64 && !discardOnly && !ietfSpecial && !documentation && !sixToFour;
            }
            return false;
        }
    }

    internal static class XrayNetworkInspector
    {
        public static RelayEndpoint InspectExitRelay(string path)
        {
            IDictionary<string, object> root = ReadRoot(path);
            return ReadSingleRealityRelay(root);
        }

        public static VpnXrayNetworkProfile InspectVpn(string path)
        {
            IDictionary<string, object> root = ReadRoot(path);
            RelayEndpoint relay = ReadSingleRealityRelay(root);
            List<string> candidates = new List<string>();
            foreach (IDictionary<string, object> inbound in Dictionaries(Get(root, "inbounds")))
            {
                if (!EqualsText(Get(inbound, "protocol"), "tun")) { continue; }
                IDictionary<string, object> settings = Get(inbound, "settings") as IDictionary<string, object>;
                Validation.Require(settings != null, "The TUN inbound settings are missing.");
                AddInterfaceCandidate(candidates, Get(settings, "name") as string);
                AddInterfaceCandidate(candidates, Get(settings, "desc") as string);
            }
            Validation.Require(candidates.Count > 0, "The TUN profile must declare a fixed interface name or description.");
            return new VpnXrayNetworkProfile(relay, candidates.ToArray());
        }

        private static RelayEndpoint ReadSingleRealityRelay(IDictionary<string, object> root)
        {
            RelayEndpoint result = null;
            foreach (IDictionary<string, object> outbound in Dictionaries(Get(root, "outbounds")))
            {
                if (!EqualsText(Get(outbound, "protocol"), "vless")) { continue; }
                IDictionary<string, object> stream = Get(outbound, "streamSettings") as IDictionary<string, object>;
                if (stream == null || !EqualsText(Get(stream, "security"), "reality")) { continue; }
                Validation.Require(result == null, "The profile contains more than one REALITY relay outbound.");
                Validation.Require(EqualsText(Get(stream, "network"), "raw"),
                    "The REALITY relay transport must use Xray raw/TCP framing.");

                IDictionary<string, object> settings = Get(outbound, "settings") as IDictionary<string, object>;
                Validation.Require(settings != null, "The REALITY relay settings are missing.");
                Validation.Require(EqualsText(Get(settings, "encryption"), "none") &&
                    (EqualsText(Get(settings, "flow"), "xtls-rprx-vision") || EqualsText(Get(settings, "flow"), "xtls-rprx-vision-udp443")),
                    "The VLESS REALITY relay must use encryption=none with xtls-rprx-vision.");
                Guid credential;
                Validation.Require(Guid.TryParse(Get(settings, "id") as string, out credential),
                    "The VLESS REALITY relay credential is not a UUID.");
                IDictionary<string, object> reality = Get(stream, "realitySettings") as IDictionary<string, object>;
                Validation.Require(reality != null && IsSafeRealityText(Get(reality, "serverName") as string, 253) &&
                    IsSafeRealityText(Get(reality, "password") as string, 128) &&
                    IsHex(Get(reality, "shortId") as string, 16) &&
                    IsSafeRealityText(Get(reality, "fingerprint") as string, 32),
                    "The REALITY transport settings are incomplete or invalid.");
                string addressText = Get(settings, "address") as string;
                object portValue = Get(settings, "port");

                if (string.IsNullOrWhiteSpace(addressText))
                {
                    foreach (IDictionary<string, object> vnext in Dictionaries(Get(settings, "vnext")))
                    {
                        addressText = Get(vnext, "address") as string;
                        portValue = Get(vnext, "port");
                        break;
                    }
                }

                IPAddress address;
                Validation.Require(IPAddress.TryParse(addressText, out address),
                    "The REALITY relay address must be a numeric IP address for fail-closed firewall policy.");
                Validation.Require(NetworkAddressPolicy.IsPublicRelayAddress(address),
                    "The REALITY relay must use a public unicast IP address.");
                int port = ToPort(portValue);
                result = new RelayEndpoint(address, port);
            }
            Validation.Require(result != null, "The profile must contain exactly one VLESS REALITY relay outbound.");
            return result;
        }

        private static IDictionary<string, object> ReadRoot(string path)
        {
            if (!File.Exists(path)) { throw new ServiceConfigurationException("Provisioned Xray configuration is missing."); }
            FileInfo info = new FileInfo(path);
            Validation.Require(info.Length > 1 && info.Length <= 4 * 1024 * 1024,
                "Provisioned Xray configuration has an invalid size.");
            object parsed = JsonFile.ParseObject(File.ReadAllText(path, Encoding.UTF8));
            IDictionary<string, object> root = parsed as IDictionary<string, object>;
            Validation.Require(root != null, "The Xray configuration root must be an object.");
            return root;
        }

        private static IEnumerable<IDictionary<string, object>> Dictionaries(object value)
        {
            IEnumerable values = value as IEnumerable;
            if (values == null || value is string) { yield break; }
            foreach (object item in values)
            {
                IDictionary<string, object> dictionary = item as IDictionary<string, object>;
                if (dictionary != null) { yield return dictionary; }
            }
        }

        private static object Get(IDictionary<string, object> dictionary, string key)
        {
            object value;
            return dictionary != null && dictionary.TryGetValue(key, out value) ? value : null;
        }

        private static bool EqualsText(object value, string expected)
        {
            return string.Equals(value as string, expected, StringComparison.Ordinal);
        }

        private static int ToPort(object value)
        {
            int port;
            try { port = Convert.ToInt32(value, CultureInfo.InvariantCulture); }
            catch { throw new ServiceConfigurationException("The REALITY relay port is invalid."); }
            Validation.Require(port >= 1 && port <= 65535, "The REALITY relay port is outside the valid range.");
            return port;
        }

        private static void AddInterfaceCandidate(List<string> target, string value)
        {
            if (string.IsNullOrWhiteSpace(value)) { return; }
            value = value.Trim();
            Validation.Require(value.Length <= 64, "The TUN interface name is too long.");
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                Validation.Require(char.IsLetterOrDigit(c) || c == ' ' || c == '-' || c == '_' || c == '.',
                    "The TUN interface name contains an unsupported character.");
            }
            if (!target.Contains(value)) { target.Add(value); }
        }

        private static bool IsSafeRealityText(string value, int maximumLength)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength) { return false; }
            for (int i = 0; i < value.Length; i++)
            {
                if (char.IsWhiteSpace(value[i]) || char.IsControl(value[i])) { return false; }
            }
            return true;
        }

        private static bool IsHex(string value, int maximumLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length > maximumLength || value.Length % 2 != 0) { return false; }
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) { return false; }
            }
            return true;
        }
    }

    internal static class FirewallPlanFactory
    {
        public static Dictionary<string, object> Create(
            string kind,
            RelayEndpoint relay,
            IEnumerable<IPAddress> apiAddresses,
            int apiPort,
            string tunnelInterfaceAlias)
        {
            if (!string.IsNullOrEmpty(tunnelInterfaceAlias))
            {
                Validation.Require(tunnelInterfaceAlias.Length <= 64, "The active TUN interface alias is too long.");
                for (int i = 0; i < tunnelInterfaceAlias.Length; i++)
                {
                    char c = tunnelInterfaceAlias[i];
                    Validation.Require(char.IsLetterOrDigit(c) || c == ' ' || c == '-' || c == '_' || c == '.',
                        "The active TUN interface alias contains an unsupported character.");
                }
            }
            List<string> api = new List<string>();
            foreach (IPAddress address in apiAddresses)
            {
                if (address != null && !api.Contains(address.ToString())) { api.Add(address.ToString()); }
            }
            Validation.Require(api.Count > 0, "At least one numeric control-plane address is required.");

            Dictionary<string, object> plan = new Dictionary<string, object>(StringComparer.Ordinal);
            plan["schemaVersion"] = 1;
            plan["kind"] = kind;
            plan["relayAddress"] = relay.Address.ToString();
            plan["relayPort"] = relay.Port;
            plan["apiAddresses"] = api.ToArray();
            Validation.Require(apiPort >= 1 && apiPort <= 65535, "The control-plane port is invalid.");
            plan["apiPort"] = apiPort;
            plan["vpnXrayPath"] = ProductInfo.VpnXrayExecutablePath;
            plan["nodeXrayPath"] = ProductInfo.NodeXrayExecutablePath;
            plan["vpnServicePath"] = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "HandShakeVpnService.exe");
            plan["nodeServicePath"] = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "HandShakeNodeService.exe");
            plan["tunnelInterfaceAlias"] = tunnelInterfaceAlias;
            if (kind == "node") plan["localSubnets"] = PhysicalLocalSubnets();
            return plan;
        }

        public static string[] PhysicalLocalSubnets()
        {
            var result = new SortedSet<string>(StringComparer.Ordinal);
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces()) {
                if (adapter.OperationalStatus != OperationalStatus.Up || adapter.NetworkInterfaceType == NetworkInterfaceType.Tunnel ||
                    adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback || adapter.Name.StartsWith("HandShake", StringComparison.OrdinalIgnoreCase) ||
                    adapter.Description.IndexOf("HandShake", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                foreach (UnicastIPAddressInformation address in adapter.GetIPProperties().UnicastAddresses) {
                    if (IPAddress.IsLoopback(address.Address)) continue;
                    int prefix = address.PrefixLength;
                    byte[] bytes = address.Address.GetAddressBytes();
                    if (prefix < 1 || prefix > bytes.Length * 8) continue;
                    for (int i = 0; i < bytes.Length; i++) {
                        int remaining = prefix - i * 8;
                        bytes[i] = (byte)(bytes[i] & (remaining >= 8 ? 255 : remaining <= 0 ? 0 : 255 << (8 - remaining)));
                    }
                    result.Add(new IPAddress(bytes).ToString() + "/" + prefix.ToString(CultureInfo.InvariantCulture));
                }
            }
            if (result.Count > 64) throw new ServiceConfigurationException("Too many physical local subnets.");
            if (result.Count == 0) result.Add("127.0.0.0/8");
            return new List<string>(result).ToArray();
        }

        public static IPAddress[] ResolveApiAddress(Uri uri, bool allowLoopback)
        {
            IPAddress address;
            Validation.Require(IPAddress.TryParse(uri.Host, out address),
                "The control-plane host must be a numeric IP address for deterministic firewall policy.");
            Validation.Require(NetworkAddressPolicy.IsPublicRelayAddress(address) || (allowLoopback && IPAddress.IsLoopback(address)),
                "The control-plane address is not permitted by firewall policy.");
            return new[] { address };
        }
    }

    internal abstract class FirewallControllerBase
    {
        private readonly string _planPath;
        private readonly ServiceLog _log;
        private DateTime _nextVerificationUtc = DateTime.MinValue;

        protected FirewallControllerBase(string planPath, ServiceLog log)
        {
            _planPath = planPath;
            _log = log;
        }

        protected void WritePlan(Dictionary<string, object> plan)
        {
            string directory = Path.GetDirectoryName(_planPath);
            Directory.CreateDirectory(directory);
            AccessControlGuard.RequireSystemAndAdministratorsOnly(directory, true);
            Validation.RequireFixedFileUnder(_planPath, directory);
            JsonFile.WriteAtomic(_planPath, plan);
            AccessControlGuard.RequireSystemAndAdministratorsOnly(_planPath, false);
        }

        protected void RunHelper(string operation)
        {
            if (operation.StartsWith("Apply", StringComparison.Ordinal) || operation.StartsWith("Verify", StringComparison.Ordinal))
            {
                string stateDirectory = Path.Combine(ProductInfo.ProgramDataRoot, "firewall");
                if (!Directory.Exists(stateDirectory))
                {
                    throw new ServiceConfigurationException("The protected Windows firewall state directory is missing.");
                }
                AccessControlGuard.RequireSystemAndAdministratorsOnly(stateDirectory, true);
            }
            string helper = ProductInfo.FirewallHelperPath;
            if (!File.Exists(helper))
            {
                throw new ServiceConfigurationException("The fixed Windows firewall helper is missing.");
            }
            string powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe");
            if (!File.Exists(powershell))
            {
                throw new ServiceConfigurationException("Windows PowerShell is unavailable for firewall policy.");
            }
            if (operation.IndexOfAny(new[] { ' ', '\"', '\'', '\t', '\r', '\n' }) >= 0)
            {
                throw new InvalidOperationException("Invalid internal firewall operation.");
            }

            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = powershell;
            start.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " + Quote(helper) +
                " -Operation " + operation + " -PlanPath " + Quote(_planPath);
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            using (Process process = Process.Start(start))
            {
                if (process == null) { throw new ServiceConfigurationException("Windows did not start the firewall helper."); }
                Task<string> outputRead = process.StandardOutput.ReadToEndAsync();
                Task<string> errorRead = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(30000))
                {
                    try { process.Kill(); } catch { }
                    throw new ServiceConfigurationException("The Windows firewall helper timed out.");
                }
                if (!Task.WaitAll(new Task[] { outputRead, errorRead }, 5000))
                {
                    throw new ServiceConfigurationException("The Windows firewall helper output did not close cleanly.");
                }
                string output = outputRead.Result;
                string error = errorRead.Result;
                if (process.ExitCode != 0)
                {
                    string category = string.IsNullOrWhiteSpace(error) ? "policy-error" : FirstSafeLine(error);
                    throw new ServiceConfigurationException("Windows firewall operation " + operation + " failed: " + category);
                }
                if (output.Length > 64 * 1024)
                {
                    throw new ServiceConfigurationException("The Windows firewall helper returned excessive output.");
                }
            }
        }

        protected bool VerificationIsDue()
        {
            return DateTime.UtcNow >= _nextVerificationUtc;
        }

        protected void VerificationCompleted()
        {
            _nextVerificationUtc = DateTime.UtcNow.AddSeconds(10);
        }

        protected void LogApplied(string message)
        {
            _log.Info(message);
        }

        private static string Quote(string value)
        {
            if (value.IndexOf('\"') >= 0) { throw new ServiceConfigurationException("A fixed firewall path contains a quote."); }
            return "\"" + value + "\"";
        }

        private static string FirstSafeLine(string value)
        {
            string line = value.Replace('\r', '\n').Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries)[0].Trim();
            if (line.Length > 180) { line = line.Substring(0, 180); }
            StringBuilder safe = new StringBuilder();
            foreach (char c in line)
            {
                if (!char.IsControl(c)) { safe.Append(c); }
            }
            return safe.Length == 0 ? "policy-error" : safe.ToString();
        }
    }

    internal sealed class VpnFirewallController : FirewallControllerBase
    {
        private string _signature;
        private string _tunnelAlias;
        private bool _cleanupChecked;

        public VpnFirewallController(string planPath, ServiceLog log) : base(planPath, log) { }

        public void EnsureBootstrap(VpnXrayNetworkProfile profile)
        {
            string signature = profile.Relay.Address + ":" + profile.Relay.Port.ToString(CultureInfo.InvariantCulture);
            Dictionary<string, object> plan = FirewallPlanFactory.Create("vpn", profile.Relay,
                new[] { profile.Relay.Address }, 443, null);
            WritePlan(plan);
            if (!string.Equals(_signature, signature, StringComparison.Ordinal))
            {
                RunHelper("ApplyVpnBootstrap");
                _signature = signature;
                _tunnelAlias = null;
                _cleanupChecked = false;
                LogApplied("Applied the fail-closed Windows Firewall bootstrap policy.");
            }
            else if (VerificationIsDue())
            {
                RunHelper(_tunnelAlias == null ? "VerifyVpnBootstrap" : "VerifyVpnTunnel");
                VerificationCompleted();
            }
        }

        public bool TryAttachTunnel(VpnXrayNetworkProfile profile)
        {
            string found = FindActiveInterface(profile.TunInterfaceCandidates);
            if (found == null) { return false; }
            Dictionary<string, object> plan = FirewallPlanFactory.Create("vpn", profile.Relay,
                new[] { profile.Relay.Address }, 443, found);
            WritePlan(plan);
            if (!string.Equals(_tunnelAlias, found, StringComparison.OrdinalIgnoreCase))
            {
                RunHelper("ApplyVpnTunnel");
                RunHelper("VerifyVpnTunnel");
                _tunnelAlias = found;
                VerificationCompleted();
                LogApplied("Bound the fail-closed policy to the managed TUN interface.");
            }
            return true;
        }

        public bool IsTunnelActive(VpnXrayNetworkProfile profile)
        {
            if (profile == null) { throw new ArgumentNullException("profile"); }
            return FindActiveInterface(profile.TunInterfaceCandidates) != null;
        }

        public void Remove()
        {
            if (_cleanupChecked) { return; }
            RunHelper("RemoveVpn");
            _signature = null;
            _tunnelAlias = null;
            _cleanupChecked = true;
            LogApplied("Removed the managed VPN firewall policy and restored its saved profile defaults.");
        }

        public void VerifyStopped() { RunHelper("VerifyVpnStopped"); }

        private static string FindActiveInterface(IEnumerable<string> candidates)
        {
            foreach (NetworkInterface network in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (network.OperationalStatus != OperationalStatus.Up) { continue; }
                foreach (string candidate in candidates)
                {
                    if (string.Equals(network.Name, candidate, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(network.Description, candidate, StringComparison.OrdinalIgnoreCase))
                    {
                        return network.Name;
                    }
                }
            }
            return null;
        }
    }

    internal sealed class NodeFirewallController : FirewallControllerBase
    {
        private string _signature;
        private bool _cleanupChecked;

        public NodeFirewallController(string planPath, ServiceLog log) : base(planPath, log) { }

        public void Ensure(RelayEndpoint relay, Uri apiBase, bool allowLoopback)
        {
            IPAddress[] api = FirewallPlanFactory.ResolveApiAddress(apiBase, allowLoopback);
            string signature = relay.Address + ":" + relay.Port.ToString(CultureInfo.InvariantCulture) + "|" + api[0] +
                ":" + apiBase.Port.ToString(CultureInfo.InvariantCulture);
            Dictionary<string, object> plan = FirewallPlanFactory.Create("node", relay, api, apiBase.Port, null);
            signature += "|" + String.Join(",", (string[])plan["localSubnets"]);
            WritePlan(plan);
            if (!string.Equals(_signature, signature, StringComparison.Ordinal))
            {
                RunHelper("ApplyNode");
                RunHelper("VerifyNode");
                _signature = signature;
                _cleanupChecked = false;
                VerificationCompleted();
                LogApplied("Applied the managed exit-node LAN isolation policy.");
            }
            else if (VerificationIsDue())
            {
                RunHelper("VerifyNode");
                VerificationCompleted();
            }
        }

        public void Remove()
        {
            if (_cleanupChecked) { return; }
            RunHelper("RemoveNode");
            _signature = null;
            _cleanupChecked = true;
            LogApplied("Removed the managed exit-node firewall policy.");
        }
    }
}
