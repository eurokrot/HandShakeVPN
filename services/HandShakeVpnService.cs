using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using HandShake.ServiceIntegration;

namespace HandShake.Services
{
    internal sealed class VpnSessionConfig
    {
        public bool enabled { get; set; }
        public string sessionId { get; set; }
        public string expiresAtUtc { get; set; }
        public bool requireKillSwitch { get; set; }
        public bool allowUnsafeLabMode { get; set; }
        public string xrayProfileVersion { get; set; }
        public string xrayExecutableSha256 { get; set; }
        public string telemetryToken { get; set; }

        public DateTime ValidateAndGetExpiry()
        {
            Validation.Require(!string.IsNullOrWhiteSpace(sessionId) && sessionId.Length <= 128,
                "sessionId is required and must be at most 128 characters.");
            DateTime expiry = Validation.ParseUtc(expiresAtUtc, "expiresAtUtc");
            Validation.Require(string.IsNullOrWhiteSpace(xrayExecutableSha256) || Validation.IsSha256(xrayExecutableSha256),
                "xrayExecutableSha256 must be a SHA-256 hex value when provided.");
            Guid token;
            Validation.Require(!enabled || Guid.TryParseExact(telemetryToken, "D", out token),
                "telemetryToken must be the active per-session UUID.");
            return expiry;
        }
    }

    internal static class VpnServiceProfile
    {
        public static string Build(VpnProvisionPayload request)
        {
            IPAddress address;
            Guid credential;
            if (request == null || !IPAddress.TryParse(request.relayAddress, out address) ||
                !NetworkAddressPolicy.IsPublicRelayAddress(address) || request.relayPort < 1 || request.relayPort > 65535 ||
                !Guid.TryParseExact(request.vlessId, "D", out credential) ||
                !string.Equals(request.flow, "xtls-rprx-vision", StringComparison.Ordinal) ||
                !Base64Url(request.realityPublicKey, 43, 44) || !Hex(request.realityShortId, 16) ||
                !DnsName(request.realityServerName))
                throw new ServiceCommandException("invalid_profile", "The typed VPN transport is invalid.");
            object[] privateNetworks = new object[] {
                "geoip:private", "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
                "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
                "::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32",
                "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"
            };
            Dictionary<string, object> root = new Dictionary<string, object>(StringComparer.Ordinal) {
                { "log", new Dictionary<string, object> { { "access", "" }, { "error", "" }, { "loglevel", "none" } } },
                { "inbounds", new object[] {
                    new Dictionary<string, object> {
                        { "tag", "client-tun" }, { "protocol", "tun" },
                        { "settings", new Dictionary<string, object> {
                            { "name", "handshake0" }, { "desc", "HandShake VPN" }, { "mtu", 1400 },
                            { "gateway", new[] { "10.253.0.1/30", "fd7a:115c:a1e0::1/126" } },
                            { "dns", new[] { "1.1.1.1", "1.0.0.1" } }, { "userLevel", 0 },
                            // Keep the relay/control-plane address on the physical route. The Node Service
                            // must retain its independent heartbeat and reverse tunnel while the personal
                            // VPN is connecting, failing, or disconnecting.
                            { "autoSystemRoutingTable", SystemRoutesExcluding(address) },
                            { "autoOutboundsInterface", "auto" }
                        } },
                        { "sniffing", new Dictionary<string, object> {
                            { "enabled", true }, { "destOverride", new[] { "http", "tls", "quic" } }, { "routeOnly", true }
                        } }
                    }
                } },
                { "outbounds", new object[] {
                    new Dictionary<string, object> { { "tag", "blocked" }, { "protocol", "blackhole" }, { "settings", new Dictionary<string, object>() } },
                    new Dictionary<string, object> {
                        { "tag", "to-relay" }, { "protocol", "vless" },
                        { "settings", new Dictionary<string, object> {
                            { "address", address.ToString() }, { "port", request.relayPort }, { "id", credential.ToString("D") },
                            { "encryption", "none" }, { "flow", "xtls-rprx-vision-udp443" }
                        } },
                        { "streamSettings", new Dictionary<string, object> {
                            { "network", "raw" }, { "security", "reality" },
                            { "realitySettings", new Dictionary<string, object> {
                                { "show", false }, { "serverName", request.realityServerName.ToLowerInvariant() }, { "fingerprint", "chrome" },
                                { "password", request.realityPublicKey }, { "shortId", request.realityShortId.ToLowerInvariant() }, { "spiderX", "/" }
                            } }
                        } }
                    }
                } },
                { "routing", new Dictionary<string, object> { { "domainStrategy", "IPIfNonMatch" },
                    { "rules", new object[] {
                        new Dictionary<string, object> { { "type", "field" }, { "inboundTag", new[] { "client-tun" } },
                            { "domain", new[] { "geosite:private" } }, { "outboundTag", "blocked" } },
                        new Dictionary<string, object> { { "type", "field" }, { "inboundTag", new[] { "client-tun" } },
                            { "ip", privateNetworks }, { "outboundTag", "blocked" } },
                        new Dictionary<string, object> { { "type", "field" }, { "inboundTag", new[] { "client-tun" } },
                            { "outboundTag", "to-relay" } }
                    } }
                } }
            };
            string json = JsonFile.Serialize(root);
            if (Encoding.UTF8.GetByteCount(json) > 128 * 1024)
                throw new ServiceCommandException("invalid_profile", "The generated VPN profile is too large.");
            return json;
        }

        internal static string[] SystemRoutesExcluding(IPAddress excluded)
        {
            if (excluded == null || excluded.AddressFamily != AddressFamily.InterNetwork)
                return new[] { "0.0.0.0/0", "::/0" };
            byte[] bytes = excluded.GetAddressBytes();
            ulong value = ((ulong)bytes[0] << 24) | ((ulong)bytes[1] << 16) | ((ulong)bytes[2] << 8) | bytes[3];
            List<string> routes = new List<string>();
            if (value > 0) AddIpv4Range(routes, 0, value - 1);
            if (value < UInt32.MaxValue) AddIpv4Range(routes, value + 1, UInt32.MaxValue);
            routes.Add("::/0");
            return routes.ToArray();
        }

        private static void AddIpv4Range(List<string> routes, ulong first, ulong last)
        {
            while (first <= last)
            {
                ulong block = first == 0 ? (1UL << 32) : (first & (~first + 1));
                ulong remaining = last - first + 1;
                while (block > remaining) block >>= 1;
                int hostBits = 0; ulong size = block;
                while (size > 1) { size >>= 1; hostBits++; }
                byte[] bytes = new[] { (byte)(first >> 24), (byte)(first >> 16), (byte)(first >> 8), (byte)first };
                routes.Add(new IPAddress(bytes) + "/" + (32 - hostBits).ToString(CultureInfo.InvariantCulture));
                first += block;
                if (first > UInt32.MaxValue) break;
            }
        }

        private static bool Base64Url(string value, int minimum, int maximum)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length < minimum || value.Length > maximum) return false;
            foreach (char c in value) if (!(char.IsLetterOrDigit(c) || c == '-' || c == '_')) return false;
            return true;
        }
        private static bool Hex(string value, int maximum)
        {
            if (string.IsNullOrEmpty(value) || value.Length > maximum || value.Length % 2 != 0) return false;
            foreach (char c in value) if (!Uri.IsHexDigit(c)) return false;
            return true;
        }
        private static bool DnsName(string value)
        {
            IPAddress ignored;
            return !string.IsNullOrWhiteSpace(value) && value.Length <= 253 && value.IndexOf('/') < 0 && value.IndexOf(':') < 0 &&
                value.IndexOfAny(new[] { '\r', '\n', '\t', ' ' }) < 0 && !IPAddress.TryParse(value, out ignored) &&
                Uri.CheckHostName(value) == UriHostNameType.Dns;
        }
    }

    internal static class FailClosedProfileCommit
    {
        public static void Execute(Action stopActiveProcess, Action commitProfile, Action commitSession, Action failClosedCleanup)
        {
            try
            {
                stopActiveProcess();
                commitProfile();
                commitSession();
            }
            catch
            {
                try { failClosedCleanup(); }
                catch { }
                throw;
            }
        }
    }

    internal static class VpnPaths
    {
        public static readonly string DirectoryPath = Path.Combine(ProductInfo.ProgramDataRoot, "vpn");
        public static readonly string SessionPath = Path.Combine(DirectoryPath, "session.json");
        public static readonly string XrayConfigPath = Path.Combine(DirectoryPath, "xray-client.json");
        public static readonly string StatePath = Path.Combine(DirectoryPath, "state.json");
        public static readonly string LogPath = Path.Combine(DirectoryPath, "vpn-service.log");
        public static readonly string FirewallPlanPath = Path.Combine(DirectoryPath, "firewall-plan.json");

        public static readonly string[] SessionKeys = new[]
        {
            "enabled", "sessionId", "expiresAtUtc", "requireKillSwitch", "allowUnsafeLabMode",
            "xrayProfileVersion", "xrayExecutableSha256", "telemetryToken"
        };

        public static void ValidateFixedPaths()
        {
            Validation.RequireFixedFileUnder(SessionPath, DirectoryPath);
            Validation.RequireFixedFileUnder(XrayConfigPath, DirectoryPath);
            Validation.RequireFixedFileUnder(StatePath, DirectoryPath);
            Validation.RequireFixedFileUnder(FirewallPlanPath, DirectoryPath);
        }
    }

    internal static class VpnSafetyPolicy
    {
        public static readonly bool KillSwitchImplemented = true;

        public static string Evaluate(VpnSessionConfig session, DateTime utcNow)
        {
            DateTime expiry = session.ValidateAndGetExpiry();
            if (!session.enabled) { return "session-disabled"; }
            if (expiry <= utcNow) { return "session-expired"; }
            if (!session.requireKillSwitch) { return "blocked-session-does-not-require-kill-switch"; }
            return "native-wfp";
        }
    }

    internal sealed class LiveDestinationReporter
    {
        private static readonly Regex Destination = new Regex(
            @"\b(?<protocol>tcp|udp):(?<domain>(?=.{1,253}(?::|\s|$))(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?):(?<port>\d{1,5})\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        private readonly object _sync = new object();
        private readonly Dictionary<string, DateTime> _recent = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

        public void TryReport(string sessionId, string token, string line)
        {
            if (string.IsNullOrWhiteSpace(line) || line.Length > 4096 || string.IsNullOrWhiteSpace(token)) return;
            Match match = Destination.Match(line);
            int port;
            if (!match.Success || !int.TryParse(match.Groups["port"].Value, NumberStyles.None,
                CultureInfo.InvariantCulture, out port) || port < 1 || port > 65535) return;
            string domain = match.Groups["domain"].Value.TrimEnd('.').ToLowerInvariant();
            string protocol = match.Groups["protocol"].Value.ToLowerInvariant();
            string key = domain + ":" + port.ToString(CultureInfo.InvariantCulture) + ":" + protocol;
            DateTime now = DateTime.UtcNow;
            lock (_sync)
            {
                DateTime seen;
                if (_recent.TryGetValue(key, out seen) && now - seen < TimeSpan.FromSeconds(5)) return;
                _recent[key] = now;
                if (_recent.Count > 512)
                {
                    foreach (string expired in _recent.Where(item => now - item.Value > TimeSpan.FromMinutes(2)).Select(item => item.Key).ToArray())
                        _recent.Remove(expired);
                }
            }
            ThreadPool.QueueUserWorkItem(delegate { Send(sessionId, token, domain, protocol, port); });
        }

        private static void Send(string sessionId, string token, string domain, string protocol, int port)
        {
            try
            {
                ServiceEnvironmentPolicy.ControlPlaneConfiguration configuration =
                    ServiceEnvironmentPolicy.ReadControlPlaneConfiguration();
                Uri endpoint = new Uri(configuration.ApiBaseUri, "api/v1/traffic/live");
                Dictionary<string, object> payload = new Dictionary<string, object>(StringComparer.Ordinal) {
                    { "sessionId", sessionId }, { "domain", domain }, { "protocol", protocol }, { "port", port }
                };
                byte[] body = Encoding.UTF8.GetBytes(JsonFile.Serialize(payload));
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(endpoint);
                request.Method = "POST";
                request.ContentType = "application/json";
                request.Headers[HttpRequestHeader.Authorization] = "Bearer " + token;
                request.Timeout = 3000;
                request.ReadWriteTimeout = 3000;
                request.ContentLength = body.Length;
                using (Stream stream = request.GetRequestStream()) stream.Write(body, 0, body.Length);
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse()) { }
            }
            catch
            {
                // Live telemetry is optional and never affects tunnel availability.
            }
        }
    }

    internal sealed class VpnWorker : IDisposable
    {
        private readonly object _sync = new object();
        private readonly object _configurationSync = new object();
        private readonly ManualResetEvent _stop = new ManualResetEvent(false);
        private readonly AutoResetEvent _reload = new AutoResetEvent(false);
        private readonly ServiceLog _log = new ServiceLog(VpnPaths.LogPath);
        private readonly XraySupervisor _xray;
        private readonly VpnFirewallController _firewall;
        private readonly NativeWfp _nativeWfp = new NativeWfp();
        private Thread _thread;
        private LocalServicePipeHost _ipc;
        private string _lastError;
        private DateTime? _tunWaitStartedUtc;
        private bool _faulted;
        private bool _disconnectVerified;
        private volatile VpnSessionConfig _activeSession;
        private readonly LiveDestinationReporter _destinationReporter = new LiveDestinationReporter();

        public VpnWorker()
        {
            _xray = new XraySupervisor(_log, ProductInfo.VpnXrayExecutablePath, OnXrayAccessLine);
            _firewall = new VpnFirewallController(VpnPaths.FirewallPlanPath, _log);
        }

        public void Start()
        {
            lock (_sync)
            {
                if (_thread != null) { return; }
                VpnPaths.ValidateFixedPaths();
                Directory.CreateDirectory(VpnPaths.DirectoryPath);
                AccessControlGuard.RequireSystemAndAdministratorsOnly(VpnPaths.DirectoryPath, true);
                _stop.Reset();
                _xray.AllowStarts();
                _thread = new Thread(Run);
                _thread.IsBackground = true;
                _thread.Name = "HandShake VPN Service worker";
                _thread.Start();
                _ipc = new LocalServicePipeHost(ServiceProtocol.VpnPipeName, new string[0], HandleCommand, _log);
                _ipc.Start();
                _log.Info("VPN Service worker started.");
            }
        }

        public void Stop()
        {
            Thread thread;
            LocalServicePipeHost ipc;
            lock (_sync)
            {
                thread = _thread;
                ipc = _ipc;
                _ipc = null;
            }
            if (ipc != null) ipc.Dispose();
            lock (_sync)
            {
                if (thread == null)
                {
                    _xray.Stop();
                    _firewall.Remove();
                    return;
                }
                _stop.Set();
                _reload.Set();
            }
            if (!thread.Join(15000))
            {
                _log.Error("VPN Service worker did not stop within the expected interval.");
                throw new ServiceConfigurationException("VPN Service worker did not stop; firewall policy remains fail-closed.");
            }
            lock (_sync)
            {
                _thread = null;
                // Retain persistent blocking when SCM stops an active session,
                // including shutdown. Disconnect/uninstall is the explicit cleanup.
                bool active = _activeSession != null && _activeSession.enabled;
                try {
                    if (active && File.Exists(VpnPaths.XrayConfigPath))
                        _nativeWfp.Ensure(XrayNetworkInspector.InspectVpn(VpnPaths.XrayConfigPath), 0);
                } finally {
                    _xray.Stop();
                    _firewall.Remove();
                }
                WriteState("stopped", null, null, active ? CurrentProtectionState() : "no-active-tunnel");
                _log.Info("VPN Service worker stopped.");
            }
        }

        public void Dispose()
        {
            Stop();
            _stop.Dispose();
            _reload.Dispose();
            _xray.Dispose();
            _nativeWfp.Dispose();
        }

        private void Run()
        {
            while (!_stop.WaitOne(0))
            {
                // Keep failure handling serialized with provision/disconnect too.
                lock (_configurationSync) {
                VpnSessionConfig session = null;
                try
                {
                    lock (_configurationSync)
                    {
                        _xray.Tick();
                        if (!File.Exists(VpnPaths.SessionPath))
                        {
                            StopXrayForPolicy();
                            _firewall.Remove();
                            bool protectedSessionLost = _nativeWfp.HasFilters();
                            WriteState(protectedSessionLost ? "error" : "stopped", null,
                                protectedSessionLost ? "Session configuration is missing; traffic remains blocked until disconnect." : null,
                                protectedSessionLost ? "native-wfp-blocked" : "no-active-tunnel");
                        }
                        else
                        {
                            AccessControlGuard.RequireSystemAndAdministratorsOnly(VpnPaths.SessionPath, false);
                            session = JsonFile.ReadStrict<VpnSessionConfig>(VpnPaths.SessionPath, VpnPaths.SessionKeys, 128 * 1024);
                            string decision = VpnSafetyPolicy.Evaluate(session, DateTime.UtcNow);
                            bool mayStart = string.Equals(decision, "native-wfp", StringComparison.Ordinal);

                            if (mayStart && !_faulted)
                            {
                                _disconnectVerified = false;
                                AccessControlGuard.RequireSystemAndAdministratorsOnly(VpnPaths.XrayConfigPath, false);
                                XrayPrivacyChecks.RequireEphemeralDestinationStream(VpnPaths.XrayConfigPath);
                                XrayConfigChecks.ValidateVpnClient(VpnPaths.XrayConfigPath);
                                VpnXrayNetworkProfile profile = XrayNetworkInspector.InspectVpn(VpnPaths.XrayConfigPath);
                                _firewall.Remove();
                                ulong tunnel = _xray.IsRunning ? _nativeWfp.FindTunnel(profile.TunInterfaceCandidates) : 0;
                                _nativeWfp.Ensure(profile, tunnel);
                                _xray.EnsureRunning(VpnPaths.XrayConfigPath, session.xrayExecutableSha256);
                                _activeSession = session;
                                tunnel = _xray.IsRunning ? _nativeWfp.FindTunnel(profile.TunInterfaceCandidates) : 0;
                                _nativeWfp.Ensure(profile, tunnel);
                                bool tunnelReady = _xray.IsRunning && tunnel != 0;
                                if (!tunnelReady)
                                {
                                    if (!_tunWaitStartedUtc.HasValue) { _tunWaitStartedUtc = DateTime.UtcNow; }
                                    if (DateTime.UtcNow - _tunWaitStartedUtc.Value > TimeSpan.FromSeconds(ServiceProtocol.VpnTunnelStartupSeconds))
                                        throw new ServiceConfigurationException("The managed TUN interface did not appear; traffic remains blocked.");
                                }
                                else if (tunnelReady) _tunWaitStartedUtc = null;
                                _lastError = null;
                                WriteState(tunnelReady ? "connected" : "starting", session, null,
                                    tunnelReady ? "native-wfp-tunnel" : "native-wfp-blocked");
                            }
                            else if (mayStart)
                            {
                                // A failed profile/TUN must not oscillate between
                                // full start and kill every second. New provision
                                // or explicit disconnect is the recovery boundary.
                            }
                            else
                            {
                                StopXrayForPolicy();
                                _activeSession = null;
                                _firewall.Remove();
                                if (!session.enabled && !_disconnectVerified) {
                                    _firewall.VerifyStopped();
                                    _nativeWfp.Remove();
                                    _disconnectVerified = true;
                                }
                                _tunWaitStartedUtc = null;
                                WriteState(decision, session, null, session.enabled ? "native-wfp-blocked" : "no-active-tunnel");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _faulted = true;
                    try { StopXrayForPolicy(); } catch { }
                    _activeSession = null;
                    try { _firewall.Remove(); } catch { }
                    string safeMessage = SafeError(ex);
                    if (!string.Equals(_lastError, safeMessage, StringComparison.Ordinal))
                    {
                        _log.Error(safeMessage);
                        _lastError = safeMessage;
                    }
                    WriteState("error", session, safeMessage,
                        CurrentProtectionState());
                }
                }
                WaitHandle.WaitAny(new WaitHandle[] { _stop, _reload }, 1000);
            }
            _xray.Stop();
        }

        private ServiceStatus HandleCommand(string command, object payload)
        {
            if (string.Equals(command, ServiceProtocol.GetStatus, StringComparison.Ordinal))
            {
                ServicePayload.RequireEmpty(payload);
                return ServiceStateReader.Read(VpnPaths.StatePath, "starting");
            }
            if (string.Equals(command, ServiceProtocol.ProvisionVpn, StringComparison.Ordinal))
            {
                VpnProvisionPayload request = ServicePayload.ReadStrict<VpnProvisionPayload>(payload, new[] {
                    "sessionId", "expiresAtUtc", "requireKillSwitch", "allowUnsafeLabMode", "xrayProfileVersion",
                    "relayAddress", "relayPort", "vlessId", "flow", "realityPublicKey", "realityShortId", "realityServerName" });
                if (!request.requireKillSwitch)
                    throw new ServiceCommandException("unsafe_profile", "The GUI may provision only a kill-switch-required session.");
                if (request.allowUnsafeLabMode && !ServiceEnvironmentPolicy.AllowExperimentalFirewallLab())
                    throw new ServiceCommandException("unsafe_profile", "Experimental firewall mode is restricted to the HTTPS closed-test build.");
                if (!VpnSafetyPolicy.KillSwitchImplemented && !request.allowUnsafeLabMode)
                    throw new ServiceCommandException("native_wfp_required", "A production-safe native WFP kill switch is not installed.");
                VpnSessionConfig session = new VpnSessionConfig {
                    enabled = true, sessionId = request.sessionId, expiresAtUtc = request.expiresAtUtc,
                    requireKillSwitch = true, allowUnsafeLabMode = request.allowUnsafeLabMode,
                    xrayProfileVersion = request.xrayProfileVersion, telemetryToken = request.vlessId };
                DateTime expiry = session.ValidateAndGetExpiry();
                if (expiry <= DateTime.UtcNow || expiry > DateTime.UtcNow.AddHours(24))
                    throw new ServiceCommandException("invalid_session", "The VPN session expiry is outside the permitted range.");
                if (!string.Equals(request.xrayProfileVersion, "26.9.9-mvp1", StringComparison.Ordinal))
                    throw new ServiceCommandException("invalid_profile", "The VPN profile version is invalid.");
                string generatedProfile = VpnServiceProfile.Build(request);
                lock (_configurationSync)
                {
                    string validationPath = Path.Combine(VpnPaths.DirectoryPath, ".validate-" + Guid.NewGuid().ToString("N") + ".json");
                    try
                    {
                        ProtectedStorage.WriteTextAtomic(validationPath, generatedProfile);
                        XrayPrivacyChecks.RequireEphemeralDestinationStream(validationPath);
                        XrayConfigChecks.ValidateVpnClient(validationPath);
                        XrayNetworkInspector.InspectVpn(validationPath);
                        session.xrayExecutableSha256 = ProtectedStorage.Sha256File(ProductInfo.VpnXrayExecutablePath);
                        FailClosedProfileCommit.Execute(
                            delegate { StopXrayForPolicy(); },
                            delegate { ProtectedStorage.WriteTextAtomic(VpnPaths.XrayConfigPath, generatedProfile); },
                            delegate
                            {
                                JsonFile.WriteAtomic(VpnPaths.SessionPath, session);
                                AccessControlGuard.RequireSystemAndAdministratorsOnly(VpnPaths.SessionPath, false);
                            },
                            FailClosedProvisioningCleanup);
                        _faulted = false;
                        _disconnectVerified = false;
                    }
                    finally { try { if (File.Exists(validationPath)) File.Delete(validationPath); } catch { } }
                }
                _reload.Set();
                return ServiceStateReader.Read(VpnPaths.StatePath, "starting");
            }
            if (string.Equals(command, ServiceProtocol.DisconnectVpn, StringComparison.Ordinal))
            {
                VpnDisconnectPayload request = ServicePayload.ReadStrict<VpnDisconnectPayload>(payload, new[] { "sessionId" });
                lock (_configurationSync)
                {
                    if (!String.IsNullOrWhiteSpace(request.sessionId) && File.Exists(VpnPaths.SessionPath)) {
                        AccessControlGuard.RequireSystemAndAdministratorsOnly(VpnPaths.SessionPath, false);
                        VpnSessionConfig current = JsonFile.ReadStrict<VpnSessionConfig>(VpnPaths.SessionPath, VpnPaths.SessionKeys, 128 * 1024);
                        if (current.enabled && current.sessionId != request.sessionId)
                            throw new ServiceCommandException("stale_session", "A different VPN session is active; refresh before disconnecting.");
                    }
                    VpnSessionConfig disabled = new VpnSessionConfig {
                        enabled = false,
                        sessionId = string.IsNullOrWhiteSpace(request.sessionId) ? "managed-session" : request.sessionId,
                        expiresAtUtc = DateTime.UtcNow.AddMinutes(5).ToString("o", CultureInfo.InvariantCulture),
                        requireKillSwitch = true, allowUnsafeLabMode = false, xrayProfileVersion = "26.9.9-mvp1" };
                    JsonFile.WriteAtomic(VpnPaths.SessionPath, disabled);
                    AccessControlGuard.RequireSystemAndAdministratorsOnly(VpnPaths.SessionPath, false);
                    _faulted = false;
                }
                _reload.Set();
                DateTime deadline = DateTime.UtcNow.AddSeconds(8);
                while (DateTime.UtcNow < deadline)
                {
                    ServiceStatus status = ServiceStateReader.Read(VpnPaths.StatePath, "stopping");
                    if ((string.Equals(status.state, "session-disabled", StringComparison.Ordinal) ||
                        string.Equals(status.state, "stopped", StringComparison.Ordinal)) &&
                        string.Equals(status.trafficSafety, "no-active-tunnel", StringComparison.Ordinal)) return status;
                    Thread.Sleep(100);
                }
                throw new ServiceCommandException("cleanup_unconfirmed", "The service kept traffic fail-closed because network cleanup was not confirmed.");
            }
            throw new ServiceCommandException("unknown_command", "The VPN service does not support this command.");
        }

        private void StopXrayForPolicy()
        {
            try { _nativeWfp.BlockTunnel(); }
            finally {
                _activeSession = null;
                _xray.Stop();
                _xray.AllowStarts();
                _tunWaitStartedUtc = null;
            }
        }

        private string CurrentProtectionState()
        {
            try { return _nativeWfp.HasFilters() ? "native-wfp-blocked" : "protection-unavailable"; }
            catch { return "protection-unavailable"; }
        }

        private void OnXrayAccessLine(string line)
        {
            VpnSessionConfig session = _activeSession;
            if (session == null || !session.enabled) return;
            _destinationReporter.TryReport(session.sessionId, session.telemetryToken, line);
        }

        private static void SafeDelete(string path)
        {
            if (!File.Exists(path)) return;
            AccessControlGuard.RequireSystemAndAdministratorsOnly(path, false);
            File.Delete(path);
        }

        private void FailClosedProvisioningCleanup()
        {
            try { StopXrayForPolicy(); } catch { }
            // Preserve native blocking after failed reprovisioning of a live VPN.
            try { _firewall.Remove(); } catch { }
            try { SafeDelete(VpnPaths.SessionPath); } catch { }
            try { SafeDelete(VpnPaths.XrayConfigPath); } catch { }
            WriteState("error", null, "VPN provisioning failed; disconnect to restore normal networking.", "native-wfp-blocked");
            _reload.Set();
        }

        private void WriteState(string status, VpnSessionConfig session, string error, string trafficSafety)
        {
            try
            {
                Dictionary<string, object> state = new Dictionary<string, object>();
                state["service"] = "HandShakeVpnService";
                state["serviceVersion"] = ProductInfo.Version;
                state["status"] = status;
                state["updatedAtUtc"] = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
                state["sessionId"] = session == null ? null : session.sessionId;
                state["sessionExpiresAtUtc"] = session == null ? null : session.expiresAtUtc;
                state["xrayRunning"] = _xray.IsRunning;
                state["xrayProcessId"] = _xray.ProcessId;
                state["xrayRestartCount"] = _xray.RestartCount;
                state["killSwitchImplemented"] = VpnSafetyPolicy.KillSwitchImplemented;
                state["windowsFirewallLabLayerImplemented"] = true;
                state["nativeWfpDriver"] = false;
                state["nativeWfpFiltering"] = true;
                state["trafficSafety"] = trafficSafety;
                state["error"] = error;
                JsonFile.WriteAtomic(VpnPaths.StatePath, state);
            }
            catch
            {
                // State reporting must not change the safety decision.
            }
        }

        private static string SafeError(Exception ex)
        {
            ServiceConfigurationException configuration = ex as ServiceConfigurationException;
            if (configuration != null)
            {
                return configuration.Message;
            }
            return "Unexpected service error: " + ex.GetType().Name;
        }
    }

    internal sealed class VpnWindowsService : ServiceBase
    {
        private VpnWorker _worker;

        public VpnWindowsService()
        {
            ServiceName = "HandShakeVpnService";
            CanStop = true;
            CanShutdown = true;
            AutoLog = false;
        }

        protected override void OnStart(string[] args)
        {
            _worker = new VpnWorker();
            _worker.Start();
        }

        protected override void OnStop()
        {
            if (_worker != null)
            {
                _worker.Dispose();
                _worker = null;
            }
        }

        protected override void OnShutdown()
        {
            OnStop();
            base.OnShutdown();
        }
    }

    internal static class VpnSelfTest
    {
        public static int Run()
        {
            string temporaryDirectory = Path.Combine(Path.GetTempPath(), "handshake-vpn-selftest-" + Guid.NewGuid().ToString("N"));
            try
            {
                VpnSessionConfig session = new VpnSessionConfig();
                session.enabled = true;
                session.sessionId = "self-test";
                session.expiresAtUtc = DateTime.UtcNow.AddMinutes(10).ToString("o", CultureInfo.InvariantCulture);
                session.requireKillSwitch = true;
                session.allowUnsafeLabMode = false;
                session.telemetryToken = "11111111-1111-4111-8111-111111111111";

                if (ServiceEnvironmentPolicy.IsExperimentalFirewallLabConfiguration("Production", "https://control.example.test") ||
                    ServiceEnvironmentPolicy.IsExperimentalFirewallLabConfiguration("Test", "http://control.example.test") ||
                    !ServiceEnvironmentPolicy.IsExperimentalFirewallLabConfiguration("Test", "https://control.example.test"))
                    throw new Exception("The service experimental-firewall environment gate failed.");

                NativeWfp.OfflineCheck();
                string blocked = VpnSafetyPolicy.Evaluate(session, DateTime.UtcNow);
                if (!string.Equals(blocked, "native-wfp", StringComparison.Ordinal))
                {
                    throw new Exception("A normal session did not require native-WFP filtering.");
                }
                session.allowUnsafeLabMode = true;
                string laboratory = VpnSafetyPolicy.Evaluate(session, DateTime.UtcNow);
                if (!string.Equals(laboratory, "native-wfp", StringComparison.Ordinal))
                {
                    throw new Exception("Legacy laboratory flag bypassed native-WFP filtering.");
                }
                session.requireKillSwitch = false;
                string unprotected = VpnSafetyPolicy.Evaluate(session, DateTime.UtcNow);
                if (!string.Equals(unprotected, "blocked-session-does-not-require-kill-switch", StringComparison.Ordinal))
                {
                    throw new Exception("Laboratory mode bypassed the kill-switch requirement.");
                }
                session.requireKillSwitch = true;
                session.expiresAtUtc = DateTime.UtcNow.AddMinutes(-1).ToString("o", CultureInfo.InvariantCulture);
                string expired = VpnSafetyPolicy.Evaluate(session, DateTime.UtcNow);
                if (!string.Equals(expired, "session-expired", StringComparison.Ordinal))
                {
                    throw new Exception("An expired VPN session was accepted.");
                }
                Directory.CreateDirectory(temporaryDirectory);
                VpnProvisionPayload typed = new VpnProvisionPayload {
                    sessionId = "typed-self-test", expiresAtUtc = DateTime.UtcNow.AddMinutes(10).ToString("o", CultureInfo.InvariantCulture),
                    requireKillSwitch = true, allowUnsafeLabMode = true, xrayProfileVersion = "26.9.9-mvp1",
                    relayAddress = "8.8.8.8", relayPort = 8443, vlessId = "11111111-1111-4111-8111-111111111111",
                    flow = "xtls-rprx-vision", realityPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    realityShortId = "a1b2c3d4", realityServerName = "www.bing.com" };
                string serviceGenerated = VpnServiceProfile.Build(typed);
                if (serviceGenerated.Contains("masterKeyLog") || serviceGenerated.Contains("xrayConfigJson"))
                    throw new Exception("The typed VPN builder emitted a caller-controlled logging field.");
                if (serviceGenerated.Contains("\"0.0.0.0/0\"") || serviceGenerated.Contains("\"8.8.8.8/32\""))
                    throw new Exception("The personal VPN route table captured its own relay/control-plane address.");
                string[] protectedRoutes = VpnServiceProfile.SystemRoutesExcluding(IPAddress.Parse("8.8.8.8"));
                if (protectedRoutes.Length < 2 || protectedRoutes.Contains("8.8.8.8/32") || !protectedRoutes.Contains("::/0"))
                    throw new Exception("The relay/control-plane route exclusion was not generated safely.");
                string typedPath = Path.Combine(temporaryDirectory, "typed-client.json");
                File.WriteAllText(typedPath, serviceGenerated, new UTF8Encoding(false));
                XrayPrivacyChecks.RequireEphemeralDestinationStream(typedPath);
                XrayConfigChecks.ValidateVpnClient(typedPath);
                XrayNetworkInspector.InspectVpn(typedPath);

                string masterKeyLogPath = Path.Combine(temporaryDirectory, "master-key-log.json");
                File.WriteAllText(masterKeyLogPath, serviceGenerated.Replace("\"password\":", "\"masterKeyLog\":\"C:/Windows/Temp/leak.log\",\"password\":"),
                    new UTF8Encoding(false));
                bool masterKeyLogRejected = false;
                try { XrayPrivacyChecks.RequireTrafficLogsDisabled(masterKeyLogPath); }
                catch (ServiceConfigurationException) { masterKeyLogRejected = true; }
                if (!masterKeyLogRejected) throw new Exception("A nested REALITY masterKeyLog path was accepted.");

                bool stopCalled = false;
                bool cleanupCalled = false;
                bool commitFailed = false;
                try
                {
                    FailClosedProfileCommit.Execute(
                        delegate { stopCalled = true; },
                        delegate { },
                        delegate { throw new IOException("Injected session commit failure."); },
                        delegate { cleanupCalled = true; });
                }
                catch (IOException) { commitFailed = true; }
                if (!stopCalled || !cleanupCalled || !commitFailed)
                    throw new Exception("A partial VPN profile commit did not invoke fail-closed cleanup.");

                string xray = Path.Combine(temporaryDirectory, "client.json");
                string privateRanges = "\"geoip:private\",\"0.0.0.0/8\",\"10.0.0.0/8\",\"100.64.0.0/10\",\"127.0.0.0/8\"," +
                    "\"169.254.0.0/16\",\"172.16.0.0/12\",\"192.0.0.0/24\",\"192.0.2.0/24\",\"192.168.0.0/16\"," +
                    "\"198.18.0.0/15\",\"198.51.100.0/24\",\"203.0.113.0/24\",\"224.0.0.0/4\",\"240.0.0.0/4\"," +
                    "\"::/128\",\"::1/128\",\"64:ff9b::/96\",\"64:ff9b:1::/48\",\"100::/64\",\"2001:db8::/32\"," +
                    "\"2002::/16\",\"fc00::/7\",\"fe80::/10\",\"ff00::/8\"";
                File.WriteAllText(xray,
                    "{\"log\":{\"access\":\"\",\"error\":\"\",\"loglevel\":\"none\"},\"inbounds\":[{\"tag\":\"client-tun\",\"protocol\":\"tun\",\"settings\":{\"name\":\"handshake0\",\"desc\":\"HandShake VPN\",\"autoSystemRoutingTable\":[\"0.0.0.0/0\",\"::/0\"]}}]," +
                    "\"outbounds\":[{\"tag\":\"blocked\",\"protocol\":\"blackhole\"}," +
                    "{\"tag\":\"to-relay\",\"protocol\":\"vless\",\"settings\":{\"address\":\"203.0.114.10\",\"port\":8443,\"id\":\"11111111-1111-4111-8111-111111111111\",\"encryption\":\"none\",\"flow\":\"xtls-rprx-vision\"},\"streamSettings\":{\"network\":\"raw\",\"security\":\"reality\",\"realitySettings\":{\"serverName\":\"www.microsoft.com\",\"fingerprint\":\"chrome\",\"password\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"shortId\":\"0123456789abcdef\"}}}]," +
                    "\"routing\":{\"rules\":[" +
                    "{\"type\":\"field\",\"inboundTag\":[\"client-tun\"],\"outboundTag\":\"blocked\",\"domain\":[\"geosite:private\"]}," +
                    "{\"type\":\"field\",\"inboundTag\":[\"client-tun\"],\"outboundTag\":\"blocked\",\"ip\":[" + privateRanges + "]}," +
                    "{\"type\":\"field\",\"inboundTag\":[\"client-tun\"],\"outboundTag\":\"to-relay\"}]}}",
                    new System.Text.UTF8Encoding(false));
                XrayPrivacyChecks.RequireEphemeralDestinationStream(xray);
                XrayConfigChecks.ValidateVpnClient(xray);

                string deceptive = Path.Combine(temporaryDirectory, "deceptive.json");
                File.WriteAllText(deceptive,
                    "{\"comment\":\"tun 0.0.0.0/0 ::/0 geoip:private\",\"inbounds\":[],\"outbounds\":[]}",
                    new System.Text.UTF8Encoding(false));
                bool deceptiveRejected = false;
                try { XrayConfigChecks.ValidateVpnClient(deceptive); }
                catch (ServiceConfigurationException) { deceptiveRejected = true; }
                if (!deceptiveRejected) { throw new Exception("Metadata strings bypassed structural Xray validation."); }

                if (NetworkAddressPolicy.IsPublicRelayAddress(System.Net.IPAddress.Parse("192.168.1.1")) ||
                    !NetworkAddressPolicy.IsPublicRelayAddress(System.Net.IPAddress.Parse("203.0.114.10")))
                {
                    throw new Exception("Firewall endpoint classification failed.");
                }
                IntPtr job = NativeJob.CreateKillOnCloseJob();
                if (job == IntPtr.Zero || !NativeJob.CloseHandle(job))
                {
                    throw new Exception("KILL_ON_JOB_CLOSE Job Object self-test failed.");
                }
                Console.WriteLine("HandShakeVpnService self-test passed.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("HandShakeVpnService self-test failed: " + ex.Message);
                return 1;
            }
            finally
            {
                try { if (Directory.Exists(temporaryDirectory)) { Directory.Delete(temporaryDirectory, true); } }
                catch { }
            }
        }
    }

    internal static class VpnProgram
    {
        public static int Main(string[] args)
        {
            if (args.Length == 1 && args[0] == "--recover-network") {
                try { NetworkRecovery.Execute(); return 0; }
                catch (Exception ex) { Console.Error.WriteLine("Network recovery failed: " + ex.Message); return 1; }
            }
            if (args.Length == 1 && string.Equals(args[0], "--self-test", StringComparison.OrdinalIgnoreCase))
            {
                return VpnSelfTest.Run();
            }
            if (args.Length == 1 && string.Equals(args[0], "--version", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine(ProductInfo.Version);
                return 0;
            }
            if (args.Length == 1 && string.Equals(args[0], "--firewall-cleanup", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    using (NativeWfp native = new NativeWfp()) native.Remove();
                    new VpnFirewallController(VpnPaths.FirewallPlanPath, new ServiceLog(VpnPaths.LogPath)).Remove();
                    Console.WriteLine("HandShake VPN managed firewall cleanup completed.");
                    return 0;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("HandShake VPN managed firewall cleanup failed: " + ex.Message);
                    return 1;
                }
            }
            if (args.Length == 1 && string.Equals(args[0], "--console", StringComparison.OrdinalIgnoreCase))
            {
                VpnWorker worker = new VpnWorker();
                try { return WorkerHost.RunConsole(worker.Start, worker.Stop); }
                finally { worker.Dispose(); }
            }
            if (args.Length != 0)
            {
                Console.Error.WriteLine("Supported arguments: --self-test, --version, --console, --firewall-cleanup");
                return 2;
            }
            ServiceBase.Run(new VpnWindowsService());
            return 0;
        }
    }
}
