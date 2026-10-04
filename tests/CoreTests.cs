using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HandShake;
using HandShake.ServiceIntegration;

class CoreTests
{
    static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
    static void CheckUpdateNotice()
    {
        string directory = Path.Combine(Path.GetTempPath(), "handshake-notice-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "update-installed.json");
        const string version = "0.7-preview.12";
        try
        {
            Assert(InstalledUpdateNotice.ReadCurrentVersion(path, version) == null, "Missing update notice must not block startup");
            File.WriteAllText(path, "{\"version\":\"" + version + "\"}");
            Assert(InstalledUpdateNotice.ReadCurrentVersion(path, version) == version, "Installed version notice was lost");
            using (var locked = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                Assert(InstalledUpdateNotice.ReadCurrentVersion(path, version) == null, "Busy notice must not block startup");
            foreach (string damaged in new[] { "{\"version\":", "null", "[]", "{\"version\":{}}", "{\"version\":\"0.7-preview.11\"}", new string(' ', 4097) })
            {
                File.WriteAllText(path, damaged);
                Assert(InstalledUpdateNotice.ReadCurrentVersion(path, version) == null, "Damaged, oversized or stale notice must not be shown");
            }
        }
        finally { Directory.Delete(directory, true); }
        Console.WriteLine("PASS: interrupted, locked, oversized and stale installed-update notices cannot block startup");
    }
    sealed class FixedAnchor : IDeviceAnchorReader
    {
        readonly RawDeviceAnchor value;
        public FixedAnchor(RawDeviceAnchor value) { this.value = value; }
        public RawDeviceAnchor Read() { return value; }
    }
    sealed class FakeHttpHandler : HttpMessageHandler
    {
        public string LastPath;
        public string LastBody;
        public string LastAuthorization;
        public bool InvalidConsent;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastPath = request.RequestUri.AbsolutePath;
            LastAuthorization = request.Headers.Authorization == null ? null : request.Headers.Authorization.ToString();
            LastBody = request.Content == null ? null : await request.Content.ReadAsStringAsync();
            if (request.Method == HttpMethod.Delete)
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            string json;
            if (LastPath.EndsWith("/activations"))
                json = InvalidConsent
                    ? "{\"deviceId\":\"server-device\",\"deviceToken\":\"secret-token\",\"expiresAtUtc\":\"2099-01-01T00:00:00Z\",\"nodeConsent\":true}"
                    : "{\"deviceId\":\"server-device\",\"deviceToken\":\"secret-token\",\"expiresAtUtc\":\"2099-01-01T00:00:00Z\",\"activationExpiresAtUtc\":\"2099-01-01T00:00:00Z\",\"nodeConsent\":true,\"nodeConsentVersion\":\"exit-node-closed-test-2026-10-01\",\"nodeConsentAtUtc\":\"2026-10-01T00:00:00Z\"}";
            else if (LastPath.EndsWith("/nodes"))
                json = "{\"nodes\":[{\"id\":\"node-1\",\"countryCode\":\"DE\",\"country\":\"Germany\",\"city\":\"Frankfurt\",\"ip\":\"203.0.113.8\",\"latitude\":50.1,\"longitude\":8.6,\"estimatedMbps\":90,\"latencyMs\":12,\"available\":true}]}";
            else if (LastPath.EndsWith("/diagnostics"))
                json = "{\"id\":1,\"accepted\":true}";
            else
                json = "{\"sessionId\":\"session-1\",\"expiresAtUtc\":\"" + DateTime.UtcNow.AddMinutes(10).ToString("o") + "\",\"transport\":{\"protocol\":\"vless\",\"address\":\"8.8.8.8\",\"port\":8443,\"vlessId\":\"11111111-1111-4111-8111-111111111111\",\"flow\":\"xtls-rprx-vision\",\"network\":\"raw\",\"security\":\"reality\",\"reality\":{\"publicKey\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"shortId\":\"a1b2c3d4\",\"serverName\":\"www.bing.com\"}},\"hops\":[{\"position\":1,\"role\":\"exit\",\"nodeId\":\"node-1\",\"countryCode\":\"DE\",\"country\":\"Germany\",\"city\":\"Frankfurt\",\"ip\":\"203.0.113.8\",\"connectionMode\":\"reverse_relay\",\"endpointHost\":\"8.8.8.8\",\"endpointPort\":8443}]}";
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }
    }
    static int Main()
    {
        CheckUpdateNotice();
        var nodes = new DemoNodeCatalog().GetNodes();
        Assert(ConnectionController.Fastest(nodes).Id == "de", "Lowest known latency must win");
        nodes[1].Available = false;
        Assert(ConnectionController.Fastest(nodes).Id == "nl", "Unavailable node must be excluded");
        nodes[1].Available = true;
        var controller = new ConnectionController();
        int cancelled = controller.Begin(nodes[1]);
        controller.Disconnect();
        Assert(!controller.Complete(cancelled, true), "Cancelled connection must not reconnect later");
        int old = controller.Begin(nodes[1]);
        int current = controller.Begin(nodes[2]);
        Assert(!controller.Complete(old, true), "Stale completion must not override a new selection");
        Assert(controller.Complete(current, true), "Current connection completes");
        Assert(controller.State == ConnectionState.Connected && controller.Selected.Id == "fi", "Correct node connected");
        int failed = controller.Begin(nodes[1]);
        controller.Complete(failed, false);
        Assert(controller.State == ConnectionState.Error, "Failure shown");
        controller.Begin(null);
        Assert(controller.State == ConnectionState.Error, "Empty catalog handled");
        controller.Fail();
        Assert(controller.State == ConnectionState.Error, "An external service failure must be representable");

        var prepared = new ConnectionController();
        int preparing = prepared.Begin(nodes[1]);
        Assert(prepared.MarkSessionReady(preparing) && prepared.State == ConnectionState.SessionReady, "Control-plane session must remain distinct from connected VPN");

        var diskIdentity = new DeviceIdentityProvider(
            new FixedAnchor(new RawDeviceAnchor("  ab c-123  ", "disk-sha256", true))).Get();
        var sameDiskIdentity = new DeviceIdentityProvider(
            new FixedAnchor(new RawDeviceAnchor("ABC-123", "disk-sha256", true))).Get();
        Assert(diskIdentity.Id == sameDiskIdentity.Id && diskIdentity.Id.Length == 64, "Disk fingerprint must be stable, normalized SHA-256");
        Assert(diskIdentity.Kind == "disk-sha256" && diskIdentity.IsHardwareBound, "Physical disk identity must be labelled explicitly");
        Assert(diskIdentity.Id.IndexOf("ABC-123", StringComparison.OrdinalIgnoreCase) < 0, "Raw serial must never appear in device id");
        bool missingDiskRejected = false;
        try { new DeviceIdentityProvider(new FixedAnchor(null)).Get(); }
        catch (DeviceIdentityUnavailableException) { missingDiskRejected = true; }
        Assert(missingDiskRejected, "Activation must fail closed when the physical system disk serial is unavailable");

        bool rejectedProductionHttp = false;
        try { ClientConfiguration.Create(ClientEnvironmentKind.Production, "http://example.test", true); }
        catch (ConfigurationException) { rejectedProductionHttp = true; }
        Assert(rejectedProductionHttp, "Production must reject plain HTTP");
        Assert(HandShake.Release.ProductRelease.MayUpgrade("0.7-preview.3", "0.7-preview.4") &&
            !HandShake.Release.ProductRelease.MayUpgrade("0.7-preview.4", "0.7-preview.3") &&
            !HandShake.Release.ProductRelease.MayUpgrade("0.7-preview.4", "0.7-preview.4") &&
            HandShake.Release.ProductRelease.MayUpgrade("0.7-preview.4", "0.7") &&
            !HandShake.Release.ProductRelease.MayUpgrade("0.7", "0.7-preview.4") &&
            !HandShake.Release.ProductRelease.MayUpgrade("0.7-preview.4", "unknown"),
            "Pending updates must not downgrade a newer manual repair or guess unknown versions");
        string configTestPath = Path.Combine(Path.GetTempPath(), "handshake-config-test-" + Guid.NewGuid().ToString("N") + ".config");
        string previousConfigPath = Environment.GetEnvironmentVariable("HANDSHAKE_CLIENT_CONFIG");
        string previousEnvironment = Environment.GetEnvironmentVariable("HANDSHAKE_ENVIRONMENT");
        string previousApi = Environment.GetEnvironmentVariable("HANDSHAKE_API_BASE_URL");
        try
        {
            File.WriteAllText(configTestPath, "");
            Environment.SetEnvironmentVariable("HANDSHAKE_CLIENT_CONFIG", configTestPath);
            Environment.SetEnvironmentVariable("HANDSHAKE_ENVIRONMENT", null);
            Environment.SetEnvironmentVariable("HANDSHAKE_API_BASE_URL", null);
            bool emptyRejected = false, demoRejected = false;
            try { ClientConfiguration.Load(new string[0]); } catch (ConfigurationException) { emptyRejected = true; }
            try { ClientConfiguration.Load(new[] { "--demo" }); } catch (ConfigurationException) { demoRejected = true; }
            Assert(emptyRejected && demoRejected, "Missing configuration and explicit demo must never start the VPN in preview mode");
            Assert(!ClientConfiguration.Unavailable().HasControlPlane && ClientConfiguration.Unavailable().Environment != ClientEnvironmentKind.Demo,
                "Startup failure must remain unavailable rather than becoming a demo");
        }
        finally
        {
            Environment.SetEnvironmentVariable("HANDSHAKE_CLIENT_CONFIG", previousConfigPath);
            Environment.SetEnvironmentVariable("HANDSHAKE_ENVIRONMENT", previousEnvironment);
            Environment.SetEnvironmentVariable("HANDSHAKE_API_BASE_URL", previousApi);
            File.Delete(configTestPath);
        }
        Assert(ClientConfiguration.Create(ClientEnvironmentKind.Test, "http://127.0.0.1", true).HasControlPlane, "Explicit test HTTP configuration should be supported");
        Assert(!ServiceProvisioningPolicy.AllowExperimentalFirewallLab(
            ClientConfiguration.Create(ClientEnvironmentKind.Production, "https://control.example", false)),
            "Production must never enable the experimental Windows Firewall mode");
        Assert(ServiceProvisioningPolicy.AllowExperimentalFirewallLab(
            ClientConfiguration.Create(ClientEnvironmentKind.Test, "https://control.example", false)),
            "An HTTPS closed-test configuration may explicitly use the experimental firewall layer");
        Assert(!ServiceProvisioningPolicy.AllowExperimentalFirewallLab(
            ClientConfiguration.Create(ClientEnvironmentKind.Test, "http://127.0.0.1", true)),
            "Cleartext test configuration must never enable the experimental firewall layer");
        Assert(PipeServerIdentity.IsLocalSystemSid("S-1-5-18") && !PipeServerIdentity.IsLocalSystemSid("S-1-5-21-1000"),
            "Named-pipe clients must accept only the LocalSystem server SID");

        string secretDirectory = Path.Combine(Path.GetTempPath(), "handshake-tests-" + Guid.NewGuid().ToString("N"));
        string secretPath = Path.Combine(secretDirectory, "device-token.bin");
        var store = new DeviceCredentialStore(secretPath, new DpapiSecretProtector());
        var saved = new DeviceCredential { DeviceToken = "token-that-must-not-be-plain", ServerDeviceId = "server-device",
            FingerprintHash = diskIdentity.Id, IdentityKind = diskIdentity.Kind, ExpiresAtUtc = DateTime.UtcNow.AddDays(1) };
        store.Save(saved);
        Assert(Encoding.UTF8.GetString(File.ReadAllBytes(secretPath)).IndexOf(saved.DeviceToken, StringComparison.Ordinal) < 0, "DPAPI file must not contain plaintext token");
        DeviceCredential loaded;
        Assert(store.TryLoad(out loaded) && loaded.DeviceToken == saved.DeviceToken && loaded.FingerprintHash == diskIdentity.Id, "DPAPI token round-trip failed");
        store.Clear();
        Directory.Delete(secretDirectory);

        var handler = new FakeHttpHandler();
        using (var api = new HttpControlPlaneClient(new Uri("https://control.example/"), new HttpClient(handler)))
        {
            DeviceCredential activated = api.ActivateAsync("MONTH-KEY", diskIdentity, CancellationToken.None).Result;
            Assert(handler.LastPath == "/api/v1/activations" && handler.LastBody.Contains("\"activationKey\"") && handler.LastBody.Contains("\"deviceId\""), "Activation API contract mismatch");
            Assert(handler.LastBody.Contains("\"osName\"") && handler.LastBody.Contains("\"osVersion\"") &&
                handler.LastBody.Contains("\"osBuild\"") && handler.LastBody.Contains("\"clientVersion\""),
                "Activation must include bounded operating-system and client metadata");
            Assert(!handler.LastBody.Contains("ABC-123") && activated.DeviceToken == "secret-token", "Activation must send only the disk hash");
            Assert(activated.NodeConsent && activated.NodeConsentAtUtc.HasValue && activated.NodeParticipationEnabled,
                "Server-verified exit-node consent must be retained in the protected GUI credential");
            var catalog = api.GetNodesAsync(activated.DeviceToken, CancellationToken.None).Result;
            Assert(handler.LastAuthorization == "Bearer secret-token" && catalog.Count == 1 && catalog[0].Id == "node-1", "Catalog API contract mismatch");
            SessionLease lease = api.CreateSessionAsync(activated.DeviceToken, "node-1", CancellationToken.None).Result;
            Assert(handler.LastBody.Contains("\"nodeId\":\"node-1\"") && lease.sessionId == "session-1", "Session API contract mismatch");
            Assert(lease.hops.Count == 1 && lease.hops[0].position == 1 && lease.hops[0].endpointHost == "8.8.8.8" && lease.hops[0].endpointPort == 8443,
                "Session hop names must match the server response");
            Assert(lease.transport != null && lease.transport.vlessId == "11111111-1111-4111-8111-111111111111" &&
                lease.transport.reality != null && lease.transport.reality.serverName == "www.bing.com",
                "Session transport credentials must match the server response");
            api.CloseSessionAsync(activated.DeviceToken, lease.sessionId, CancellationToken.None).Wait();
            Assert(handler.LastPath == "/api/v1/sessions/session-1" && handler.LastAuthorization == "Bearer secret-token",
                "Session close API contract mismatch");

            ValidatedSession validated = VpnProfileFactory.Validate(lease);
            string profile = VpnProfileFactory.BuildJson(validated);
            Assert(profile.Contains("\"loglevel\":\"none\"") && profile.Contains("\"protocol\":\"tun\"") && profile.Contains("\"0.0.0.0/0\"") &&
                profile.Contains("\"::/0\"") && profile.Contains("\"geosite:private\"") &&
                profile.Contains("\"port\":\"22,25,465,587\"") && profile.Contains("\"password\":\"AAAAAAAA"),
                "VPN service profile must contain TUN defaults, private-network blocking and the issued REALITY credential");
            Assert(!profile.Contains(activated.DeviceToken), "A VPN profile must not contain the device bearer token");

            api.DisableExitNodeAsync(activated.DeviceToken, CancellationToken.None).Wait();
            Assert(handler.LastPath == "/api/v1/nodes/exit-profile" && handler.LastAuthorization == "Bearer secret-token",
                "Exit deprovisioning API contract mismatch");

            DiagnosticEventRequest diagnostic = DiagnosticEventFactory.Create("vpn_connect_failed");
            Assert(diagnostic.eventCode == "vpn_connect_failed" && diagnostic.component == "vpn-service" &&
                diagnostic.severity == "error" &&
                diagnostic.message == "The VPN service could not establish the protected tunnel.",
                "Client diagnostics must use the fixed privacy-preserving event catalog");
            bool arbitraryDiagnosticRejected = false;
            try { DiagnosticEventFactory.Create("service.start/failed"); }
            catch (ArgumentException) { arbitraryDiagnosticRejected = true; }
            Assert(arbitraryDiagnosticRejected,
                "Client diagnostics must reject arbitrary codes that could carry caller-authored context");
            string[] allowedDiagnosticCodes = new[] {
                "catalog_refresh_failed", "vpn_session_create_failed", "vpn_session_close_failed",
                "vpn_connect_failed", "vpn_kill_switch_failed", "vpn_disconnect_failed",
                "node_sync_failed", "node_apply_failed", "node_deprovision_failed",
                "node_disable_confirm_failed", "node_heartbeat_failed", "node_runtime_error",
                "node_re_enrollment_failed"
            };
            foreach (string allowedCode in allowedDiagnosticCodes)
            {
                DiagnosticEventRequest allowed = DiagnosticEventFactory.Create(allowedCode);
                Assert(allowed.eventCode == allowedCode && allowed.message.Length <= 500 &&
                    (allowed.component == "gui" || allowed.component == "vpn-service" || allowed.component == "node-service") &&
                    (allowed.severity == "error" || allowed.severity == "critical") &&
                    !allowed.message.Contains("://") && !allowed.message.Contains("\\") && !allowed.message.Contains("@"),
                    "Every allowed diagnostic event must remain fixed, bounded, and free of destinations or user paths");
            }
            api.ReportDiagnosticAsync(activated.DeviceToken, diagnostic, CancellationToken.None).Wait();
            Assert(handler.LastPath == "/api/v1/diagnostics" && handler.LastAuthorization == "Bearer secret-token" &&
                handler.LastBody.Contains("\"component\":\"vpn-service\"") &&
                handler.LastBody.Contains("\"eventCode\":\"vpn_connect_failed\"") &&
                !handler.LastBody.Contains("deviceId") && !handler.LastBody.Contains("deviceToken") &&
                !handler.LastBody.Contains("activationKey"),
                "Diagnostics must use the authenticated structured endpoint without identifiers or credentials in the body");

            var request = new ServiceRequest { protocolVersion = ServiceProtocol.Version, requestId = "request-1",
                command = ServiceProtocol.ProvisionVpn, payload = new VpnProvisionPayload { sessionId = lease.sessionId,
                    expiresAtUtc = lease.expiresAtUtc, requireKillSwitch = true, allowUnsafeLabMode = false,
                    xrayProfileVersion = VpnProfileFactory.ProfileVersion, relayAddress = validated.Address,
                    relayPort = validated.Port, vlessId = validated.VlessId, flow = validated.Flow,
                    realityPublicKey = validated.PublicKey, realityShortId = validated.ShortId,
                    realityServerName = validated.ServerName } };
            byte[] encoded = ServiceWireCodec.Encode(request);
            using (var framed = new MemoryStream())
            {
                ServiceWireCodec.WriteFrame(framed, encoded);
                framed.Position = 0;
                byte[] decodedBytes = ServiceWireCodec.ReadFrame(framed);
                ServiceRequest decoded = ServiceWireCodec.Decode<ServiceRequest>(decodedBytes);
                Assert(decoded.protocolVersion == ServiceProtocol.Version && decoded.requestId == request.requestId &&
                    decoded.command == ServiceProtocol.ProvisionVpn, "Local service protocol round-trip failed");
            }
            string vpnProvisionJson = Encoding.UTF8.GetString(ServiceWireCodec.Encode(request));
            Assert(!vpnProvisionJson.Contains("xrayConfigJson") && !vpnProvisionJson.Contains("masterKeyLog") &&
                vpnProvisionJson.Contains("\"realityPublicKey\""),
                "VPN IPC must carry typed transport fields and never caller-authored Xray JSON");

            var nodeBootstrap = new ServiceRequest { protocolVersion = ServiceProtocol.Version, requestId = "request-2",
                command = ServiceProtocol.BootstrapNode, payload = new NodeBootstrapPayload {
                    requestExitParticipation = true, deviceToken = "secret-token-value-123456", available = true } };
            string nodeBootstrapJson = Encoding.UTF8.GetString(ServiceWireCodec.Encode(nodeBootstrap));
            Assert(nodeBootstrapJson.Contains("\"requestExitParticipation\":true") &&
                !nodeBootstrapJson.Contains("apiBaseUrl") && !nodeBootstrapJson.Contains("xrayConfigJson") &&
                !nodeBootstrapJson.Contains("nodeConsent") && !nodeBootstrapJson.Contains("credentialVersion"),
                "Node bootstrap must carry only device credentials and participation intent; the service owns enrollment/profile generation");

            bool privateRelayRejected = false;
            lease.transport.address = "192.168.1.2";
            try { VpnProfileFactory.Validate(lease); }
            catch (ServiceBridgeException ex) { privateRelayRejected = ex.ErrorCode == "invalid_transport"; }
            Assert(privateRelayRejected, "A private relay address must not enter the firewall/bootstrap profile");
        }

        bool malformedServerConsentRejected = false;
        var invalidConsentHandler = new FakeHttpHandler { InvalidConsent = true };
        using (var invalidConsentApi = new HttpControlPlaneClient(new Uri("https://control.example/"), new HttpClient(invalidConsentHandler)))
        {
            try { invalidConsentApi.ActivateAsync("MONTH-KEY", diskIdentity, CancellationToken.None).GetAwaiter().GetResult(); }
            catch (ControlPlaneException ex) { malformedServerConsentRejected = ex.ErrorCode == "invalid_response"; }
        }
        Assert(malformedServerConsentRejected, "A malformed server consent claim must fail closed during activation");

        string instanceDirectory = Path.Combine(Environment.CurrentDirectory, ".local", "instance-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var first = new ApplicationInstanceGuard(instanceDirectory))
            using (var second = new ApplicationInstanceGuard(instanceDirectory))
            {
                Assert(first.Acquired && !second.Acquired, "Two GUI instances acquired the VPN controller concurrently");
                second.RequestOpen();
                Assert(first.ConsumeOpenRequest() && !first.ConsumeOpenRequest(), "Second launch did not request exactly one UI restore");
            }
            using (var restarted = new ApplicationInstanceGuard(instanceDirectory))
                Assert(restarted.Acquired, "The stale lock file blocked recovery after process exit");
        }
        finally
        {
            foreach (string file in new[] { "ui-instance.lock", "open-ui.request" })
            { string path = Path.Combine(instanceDirectory, file); if (File.Exists(path)) File.Delete(path); }
            Directory.Delete(instanceDirectory);
        }
        Console.WriteLine("PASS: selection, session-ready separation, strict disk hash, HTTPS policy, DPAPI token storage, control-plane API contracts, authenticated service IPC framing, service-owned exit enrollment, TUN profile safety, single GUI controller/recovery");
        DateTime healthNow = DateTime.UtcNow;
        ServiceStatus health = new ServiceStatus { state = "connected", sessionId = "health-test",
            trafficSafety = "native-wfp-tunnel", xrayRunning = true,
            updatedAtUtc = healthNow.ToString("o"), sessionExpiresAtUtc = healthNow.AddMinutes(1).ToString("o") };
        Assert(VpnConnectionHealth.IsProtected(health, healthNow), "Fresh protected service status was rejected");
        health.updatedAtUtc = healthNow.AddSeconds(-20).ToString("o");
        Assert(!VpnConnectionHealth.IsProtected(health, healthNow), "Stale connected state was trusted");
        health.updatedAtUtc = healthNow.ToString("o"); health.xrayRunning = false;
        Assert(!VpnConnectionHealth.IsProtected(health, healthNow), "Dead runtime was considered protected");
        health.xrayRunning = true; health.sessionExpiresAtUtc = healthNow.AddSeconds(-1).ToString("o");
        Assert(!VpnConnectionHealth.IsProtected(health, healthNow), "Expired session was considered connected");
        health.state = "error"; health.trafficSafety = "native-wfp-blocked";
        Assert(VpnConnectionHealth.NeedsDisconnect(health), "Blocked state lacks explicit disconnect recovery");
        Assert(!VpnConnectionHealth.IsProtected(null, healthNow), "Unavailable service became connected");
        Console.WriteLine("PASS: fresh VPN health, stale/dead/expired/unavailable rejection, blocked-session recovery");
        return 0;
    }
}
