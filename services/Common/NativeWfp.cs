using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Text;

namespace HandShake.Services
{
    // Uses the built-in Base Filtering Engine. No custom kernel driver or global
    // Windows Firewall profile changes are needed. Persistent filters survive
    // an abrupt service termination; only an explicit disconnect removes them.
    internal sealed class NativeWfp : IDisposable
    {
        internal static readonly Guid ProviderKey = HandShake.Release.WfpCleanup.ProviderKey;
        internal static readonly Guid SublayerKey = new Guid("78cdc152-b810-47ef-a72b-8fa9fa1e29c5");
        internal static readonly Guid Connect4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        internal static readonly Guid Connect6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        internal static readonly Guid AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        internal static readonly Guid UserId = new Guid("af043a0a-b34d-4f86-979c-c90371af6e66");
        internal static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        internal static readonly Guid RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
        internal static readonly Guid LocalPort = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b");
        internal static readonly Guid Protocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
        internal static readonly Guid Flags = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");
        internal static readonly Guid NextHop = new Guid("93ae8f5b-7f6f-4719-98c8-14e97429ef04");
        private IntPtr engine;
        private readonly Guid providerKey, sublayerKey;
        private string installedSignature;
        private DateTime nextVerificationUtc;
        private Dictionary<Guid, ulong> installedFilters;
        private Dictionary<Guid, ulong> pendingFilters;
        private const uint AlreadyExists = 0x80320009;
        internal NativeWfp() : this(false) { }
        internal NativeWfp(bool integrationTest)
        {
            providerKey = integrationTest ? new Guid("cd3f6626-9097-4447-bacc-988287b7ab9b") : ProviderKey;
            sublayerKey = integrationTest ? new Guid("c93b264a-41c6-4b0b-9515-c9ca9c2c0eee") : SublayerKey;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct Display { public string name; public string description; }
        [StructLayout(LayoutKind.Sequential)]
        internal struct Blob { public uint size; public IntPtr data; }
        [StructLayout(LayoutKind.Explicit, Size = 16)]
        internal struct Value
        {
            [FieldOffset(0)] public uint type;
            [FieldOffset(8)] public uint number;
            [FieldOffset(8)] public IntPtr pointer;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct Condition { public Guid field; public uint match; public Value value; }
        [StructLayout(LayoutKind.Sequential)]
        internal struct Provider { public Guid key; public Display display; public uint flags; public Blob data; public IntPtr service; }
        [StructLayout(LayoutKind.Sequential)]
        internal struct Sublayer { public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob data; public ushort weight; }
        [StructLayout(LayoutKind.Explicit, Size = 200)]
        internal struct Filter
        {
            [FieldOffset(0)] public Guid key;
            [FieldOffset(16)] public Display display;
            [FieldOffset(32)] public uint flags;
            [FieldOffset(40)] public IntPtr provider;
            [FieldOffset(48)] public Blob data;
            [FieldOffset(64)] public Guid layer;
            [FieldOffset(80)] public Guid sublayer;
            [FieldOffset(96)] public Value weight;
            [FieldOffset(112)] public uint count;
            [FieldOffset(120)] public IntPtr conditions;
            [FieldOffset(128)] public uint action;
            [FieldOffset(132)] public Guid callout;
            [FieldOffset(152)] public Guid context;
            [FieldOffset(168)] public IntPtr reserved;
            [FieldOffset(176)] public ulong id;
            [FieldOffset(184)] public Value effectiveWeight;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct Enumeration { public IntPtr provider; public Guid layer; public uint kind; public uint flags; public IntPtr context; public uint count; public IntPtr conditions; public uint actionMask; public IntPtr callout; }
        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] private static extern uint FwpmEngineOpen0(string server, uint authentication, IntPtr identity, IntPtr session, out IntPtr handle);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmEngineClose0(IntPtr handle);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionBegin0(IntPtr handle, uint flags);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionCommit0(IntPtr handle);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionAbort0(IntPtr handle);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmProviderAdd0(IntPtr handle, ref Provider provider, IntPtr descriptor);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmSubLayerAdd0(IntPtr handle, ref Sublayer sublayer, IntPtr descriptor);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterAdd0(IntPtr handle, ref Filter filter, IntPtr descriptor, out ulong id);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterDeleteByKey0(IntPtr handle, ref Guid key);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterCreateEnumHandle0(IntPtr handle, IntPtr template, out IntPtr enumeration);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterEnum0(IntPtr handle, IntPtr enumeration, uint requested, out IntPtr entries, out uint count);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterDestroyEnumHandle0(IntPtr handle, IntPtr enumeration);
        [DllImport("fwpuclnt.dll")] private static extern void FwpmFreeMemory0(ref IntPtr pointer);
        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] internal static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);
        [DllImport("iphlpapi.dll", CharSet = CharSet.Unicode)] private static extern uint ConvertInterfaceAliasToLuid(string alias, out ulong luid);

        internal sealed class Memory : IDisposable
        {
            private readonly List<IntPtr> owned = new List<IntPtr>();
            private readonly List<IntPtr> wfp = new List<IntPtr>();
            public IntPtr Structure<T>(T value) where T : struct
            { IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T))); owned.Add(p); Marshal.StructureToPtr(value, p, false); return p; }
            public IntPtr Bytes(byte[] bytes)
            { IntPtr p = Marshal.AllocHGlobal(bytes.Length); owned.Add(p); Marshal.Copy(bytes, 0, p, bytes.Length); return p; }
            public Condition Numeric(Guid field, uint type, uint value, uint match)
            { return new Condition { field = field, match = match, value = new Value { type = type, number = value } }; }
            public Condition Number64(Guid field, ulong value)
            { return new Condition { field = field, value = new Value { type = 4, pointer = Structure(value) } }; }
            public Condition Application(string path)
            { IntPtr p; Check(FwpmGetAppIdFromFileName0(Path.GetFullPath(path), out p), "app-id"); wfp.Add(p); return new Condition { field = AppId, value = new Value { type = 12, pointer = p } }; }
            public Condition SystemAccount()
            {
                RawSecurityDescriptor descriptor = new RawSecurityDescriptor("D:(A;;0x1;;;SY)");
                byte[] bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
                Blob blob = new Blob { size = (uint)bytes.Length, data = Bytes(bytes) };
                return new Condition { field = UserId, value = new Value { type = 14, pointer = Structure(blob) } };
            }
            public Condition Address(string cidr)
            {
                string[] parts = cidr.Split('/'); IPAddress ip = IPAddress.Parse(parts[0]);
                byte[] bytes = ip.GetAddressBytes();
                int prefix = parts.Length == 1 ? bytes.Length * 8 : int.Parse(parts[1]);
                if (prefix < 0 || prefix > bytes.Length * 8) throw new ArgumentException("Invalid WFP network prefix.");
                if (bytes.Length == 4)
                {
                    uint address = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
                    uint mask = prefix == 0 ? 0 : UInt32.MaxValue << (32 - prefix);
                    return new Condition { field = RemoteAddress, value = new Value { type = 256, pointer = Bytes(BitConverter.GetBytes(address & mask).ConcatBytes(BitConverter.GetBytes(mask))) } };
                }
                byte[] network = new byte[17]; Array.Copy(bytes, network, 16); network[16] = (byte)prefix;
                return new Condition { field = RemoteAddress, value = new Value { type = 257, pointer = Bytes(network) } };
            }
            public IntPtr Conditions(Condition[] values)
            {
                if (values.Length == 0) return IntPtr.Zero;
                int size = Marshal.SizeOf(typeof(Condition)); IntPtr p = Marshal.AllocHGlobal(size * values.Length); owned.Add(p);
                for (int i = 0; i < values.Length; i++) Marshal.StructureToPtr(values[i], IntPtr.Add(p, i * size), false);
                return p;
            }
            public void Dispose()
            { foreach (IntPtr p in wfp) { IntPtr x = p; FwpmFreeMemory0(ref x); } foreach (IntPtr p in owned) Marshal.FreeHGlobal(p); }
        }

        private static void Check(uint code, string operation)
        { if (code != 0) throw new ServiceConfigurationException("Windows Filtering Platform " + operation + " failed (0x" + code.ToString("X8") + ")."); }
        private void Open()
        { if (engine == IntPtr.Zero) Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out engine), "open"); }

        internal static Guid RuleKey(string name)
        {
            using (SHA256 sha = SHA256.Create())
            { byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes("HandShake.native-wfp.v1:" + name)); byte[] key = new byte[16]; Array.Copy(digest, key, 16); return new Guid(key); }
        }
        internal void Add(Guid layer, string name, byte weight, bool block, bool persistent, Memory memory, params Condition[] conditions)
        {
            Filter filter = new Filter { key = RuleKey(providerKey + ":" + name), display = new Display { name = "HandShake " + name },
                flags = persistent ? 1U : 0U, provider = memory.Structure(providerKey), layer = layer, sublayer = sublayerKey,
                weight = new Value { type = 4, pointer = memory.Structure((ulong)weight << 56) }, count = (uint)conditions.Length,
                conditions = memory.Conditions(conditions), action = block ? 0x1001U : 0x1002U };
            ulong id; Check(FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out id), "add");
            if (pendingFilters != null) pendingFilters.Add(filter.key, id);
        }
        private List<Filter> OwnedFilters()
        {
            using (Memory memory = new Memory())
            {
                IntPtr enumeration;
                uint code = FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out enumeration);
                if (code == 0x80320004) return new List<Filter>(); // provider absent on a clean installation
                Check(code, "enumerate");
                try
                {
                    List<Filter> result = new List<Filter>(); uint count; IntPtr entries;
                    do
                    {
                        Check(FwpmFilterEnum0(engine, enumeration, 256, out entries, out count), "read");
                        try {
                            for (int i = 0; i < count; i++) {
                                Filter filter = (Filter)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries, i * IntPtr.Size), typeof(Filter));
                                if (filter.provider != IntPtr.Zero && (Guid)Marshal.PtrToStructure(filter.provider, typeof(Guid)) == providerKey)
                                    result.Add(filter);
                            }
                        }
                        finally { FwpmFreeMemory0(ref entries); }
                    } while (count != 0);
                    return result;
                }
                finally { FwpmFilterDestroyEnumHandle0(engine, enumeration); }
            }
        }
        private void DeleteOwned()
        { foreach (Filter filter in OwnedFilters()) { Guid key = filter.key; Check(FwpmFilterDeleteByKey0(engine, ref key), "remove"); } }
        private void EnsureObjects(Memory memory)
        {
            Provider provider = new Provider { key = providerKey, display = new Display { name = "HandShake VPN" }, flags = 1 };
            uint code = FwpmProviderAdd0(engine, ref provider, IntPtr.Zero); if (code != AlreadyExists) Check(code, "provider");
            Sublayer sublayer = new Sublayer { key = sublayerKey, display = new Display { name = "HandShake VPN egress" },
                flags = 1, provider = memory.Structure(providerKey), weight = UInt16.MaxValue };
            code = FwpmSubLayerAdd0(engine, ref sublayer, IntPtr.Zero); if (code != AlreadyExists) Check(code, "sublayer");
        }
        internal void Replace(Action<Memory> rules)
        {
            Open(); Check(FwpmTransactionBegin0(engine, 0), "begin");
            pendingFilters = new Dictionary<Guid, ulong>();
            try
            {
                using (Memory memory = new Memory()) { EnsureObjects(memory); DeleteOwned(); rules(memory); Check(FwpmTransactionCommit0(engine), "commit"); }
                installedFilters = pendingFilters;
            }
            catch { FwpmTransactionAbort0(engine); throw; }
            finally { pendingFilters = null; }
        }
        // Filter objects are immutable. Replacing an object changes its ID even
        // when its key is reused; checking key + ID detects removal/replacement
        // without provoking ALE reauthorization on healthy live connections.
        internal static bool SameFilters(IDictionary<Guid, ulong> expected, IDictionary<Guid, ulong> actual)
        {
            if (expected == null || actual == null || expected.Count != actual.Count) return false;
            foreach (KeyValuePair<Guid, ulong> item in expected) {
                ulong id;
                if (!actual.TryGetValue(item.Key, out id) || id != item.Value) return false;
            }
            return true;
        }
        internal bool InstalledFiltersPresent()
        {
            Dictionary<Guid, ulong> actual = new Dictionary<Guid, ulong>();
            foreach (Filter filter in OwnedFilters()) actual.Add(filter.key, filter.id);
            return SameFilters(installedFilters, actual);
        }
        internal ulong FindTunnel(string[] candidates)
        {
            foreach (NetworkInterface network in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (network.OperationalStatus != OperationalStatus.Up) continue;
                foreach (string candidate in candidates)
                    if (String.Equals(network.Name, candidate, StringComparison.OrdinalIgnoreCase) ||
                        String.Equals(network.Description, candidate, StringComparison.OrdinalIgnoreCase))
                    { ulong luid; Check(ConvertInterfaceAliasToLuid(network.Name, out luid), "interface"); return luid; }
            }
            return 0;
        }
        internal void Ensure(VpnXrayNetworkProfile profile, ulong tunnel)
        {
            string signature = profile.Relay.Address + ":" + profile.Relay.Port + ":" + tunnel;
            // A periodic health check must not mutate a healthy ALE policy.
            // Rebuild atomically only on endpoint/interface change or lost filters.
            if (signature == installedSignature) {
                if (DateTime.UtcNow < nextVerificationUtc) return;
                if (InstalledFiltersPresent()) {
                    nextVerificationUtc = DateTime.UtcNow.AddSeconds(30);
                    return;
                }
            }
            var control = ServiceEnvironmentPolicy.ReadControlPlaneConfiguration();
            IPAddress apiAddress;
            if (control.ApiBaseUri.Scheme != Uri.UriSchemeHttps || control.ApiBaseUri.Port != 443 ||
                !IPAddress.TryParse(control.ApiBaseUri.Host, out apiAddress) || !NetworkAddressPolicy.IsPublicRelayAddress(apiAddress))
                throw new ServiceConfigurationException("Native WFP requires the protected numeric HTTPS control-plane endpoint.");
            Replace(delegate(Memory m)
            {
                foreach (Guid layer in new[] { Connect4, Connect6 })
                {
                    bool v4 = layer == Connect4; string family = v4 ? "v4" : "v6";
                    // Local applications remain usable. A local proxy still cannot
                    // reach the physical internet unless it is an explicit exception.
                    Add(layer, family + "-loopback", 200, false, true, m, m.Numeric(Flags, 3, 1, 6));
                    Condition node = m.Application(ProductInfo.NodeXrayExecutablePath);
                    string[] privateRanges = v4 ? new[] { "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4" }
                        : new[] { "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96", "64:ff9b:1::/48" };
                    for (int i = 0; i < privateRanges.Length; i++) Add(layer, family + "-node-private-" + i, 250, true, true, m, node, m.Address(privateRanges[i]));
                    foreach (uint port in new uint[] { 22, 25, 465, 587 })
                        Add(layer, family + "-node-port-" + port, 250, true, true, m, node, m.Numeric(RemotePort, 2, port, 0));
                    Add(layer, family + "-node-egress", 220, false, true, m, node, m.SystemAccount());
                    // Current exits guarantee IPv4 only. Letting TUN accept IPv6 TCP
                    // makes the local handshake succeed before an IPv4-only exit
                    // closes TLS: Chromium then cannot use its IPv4 fallback.
                    // Reject IPv6 at connect authorization instead. Keep its routes
                    // captured and its block persistent; Node's independent SYSTEM
                    // exception and IPv6 loopback remain unchanged.
                    if (v4 && tunnel != 0) Add(layer, family + "-tun", 180, false, true, m, m.Number64(NextHop, tunnel));
                    if (v4 == (profile.Relay.Address.AddressFamily == AddressFamily.InterNetwork))
                    {
                        Condition address = m.Address(profile.Relay.Address.ToString());
                        Condition tcp = m.Numeric(Protocol, 1, 6, 0);
                        Add(layer, family + "-vpn-relay", 230, false, true, m, m.Application(ProductInfo.VpnXrayExecutablePath), m.SystemAccount(), address, tcp,
                            m.Numeric(RemotePort, 2, (uint)profile.Relay.Port, 0));
                    }
                    if (v4 == (apiAddress.AddressFamily == AddressFamily.InterNetwork))
                        foreach (string app in new[] { "HandShake VPN.exe", "HandShakeVpnService.exe", "HandShakeNodeService.exe" })
                            Add(layer, family + "-control-" + app, 230, false, true, m, m.Application(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, app)),
                                m.Address(apiAddress.ToString()), m.Numeric(Protocol, 1, 6, 0), m.Numeric(RemotePort, 2, 443, 0));
                    // Minimal address-renewal exceptions; no general svchost/DNS
                    // exemption. Name resolution must travel through the TUN.
                    Add(layer, family + "-dhcp", 210, false, true, m,
                        m.Application(Path.Combine(Environment.SystemDirectory, "svchost.exe")), m.Numeric(Protocol, 1, 17, 0),
                        m.Numeric(LocalPort, 2, v4 ? 68U : 546U, 0),
                        m.Numeric(RemotePort, 2, v4 ? 67U : 547U, 0));
                    Add(layer, family + "-block", 1, true, true, m);
                }
            });
            installedSignature = signature;
            nextVerificationUtc = DateTime.UtcNow.AddSeconds(30);
        }
        internal void Remove()
        {
            HandShake.Release.WfpCleanup.RemoveOwned(providerKey);
            installedSignature = null;
            installedFilters = null;
        }
        internal bool HasFilters() { Open(); return OwnedFilters().Count != 0; }
        internal void BlockTunnel()
        {
            Open(); Check(FwpmTransactionBegin0(engine, 0), "begin-block");
            try {
                foreach (string name in new[] { "v4-tun", "v6-tun" }) {
                    Guid key = RuleKey(providerKey + ":" + name);
                    uint code = FwpmFilterDeleteByKey0(engine, ref key);
                    if (code != 0x80320003) Check(code, "block-tunnel");
                }
                Check(FwpmTransactionCommit0(engine), "commit-block");
                installedSignature = null;
            } catch { FwpmTransactionAbort0(engine); throw; }
        }
        internal static void OfflineCheck()
        {
            Guid key = Guid.NewGuid();
            Dictionary<Guid, ulong> expected = new Dictionary<Guid, ulong> { { key, 1 } };
            if (!SameFilters(expected, new Dictionary<Guid, ulong> { { key, 1 } }) ||
                SameFilters(expected, new Dictionary<Guid, ulong> { { key, 2 } }) ||
                SameFilters(expected, new Dictionary<Guid, ulong>()) ||
                SameFilters(expected, new Dictionary<Guid, ulong> { { key, 1 }, { Guid.NewGuid(), 3 } }))
                throw new Exception("Native WFP readonly filter verification mismatch.");
            if (IntPtr.Size != 8 || Marshal.SizeOf(typeof(Filter)) != 200 || Marshal.SizeOf(typeof(Condition)) != 40 ||
                Marshal.SizeOf(typeof(Sublayer)) != 72 || Marshal.SizeOf(typeof(Provider)) != 64)
                throw new Exception("Native WFP x64 layout mismatch.");
        }
        public void Dispose() { if (engine != IntPtr.Zero) { FwpmEngineClose0(engine); engine = IntPtr.Zero; } }
    }
    internal static class WfpBytes
    {
        internal static byte[] ConcatBytes(this byte[] left, byte[] right)
        { byte[] result = new byte[left.Length + right.Length]; Array.Copy(left, result, left.Length); Array.Copy(right, 0, result, left.Length, right.Length); return result; }
    }
}
