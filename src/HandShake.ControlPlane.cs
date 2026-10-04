using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace HandShake
{
    public enum ClientEnvironmentKind { Demo, Test, Production }

    public sealed class ClientConfiguration
    {
        public ClientEnvironmentKind Environment { get; private set; }
        public Uri ApiBaseUri { get; private set; }
        public bool AllowInsecureHttp { get; private set; }
        public bool HasControlPlane { get { return Environment != ClientEnvironmentKind.Demo && ApiBaseUri != null; } }

        public static ClientConfiguration Demo()
        {
            return new ClientConfiguration { Environment = ClientEnvironmentKind.Demo };
        }

        public static ClientConfiguration Unavailable()
        {
            return new ClientConfiguration { Environment = ClientEnvironmentKind.Production };
        }

        public static ClientConfiguration Create(ClientEnvironmentKind environment, string apiBaseUrl, bool allowInsecureHttp)
        {
            if (environment == ClientEnvironmentKind.Demo)
                return Demo();

            Uri uri;
            if (!Uri.TryCreate(apiBaseUrl == null ? null : apiBaseUrl.Trim().TrimEnd('/'), UriKind.Absolute, out uri))
                throw new ConfigurationException("ApiBaseUrl must be an absolute URL.");
            if (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
                throw new ConfigurationException("ApiBaseUrl must use HTTPS.");
            if (uri.Scheme == Uri.UriSchemeHttp && (!allowInsecureHttp || environment != ClientEnvironmentKind.Test))
                throw new ConfigurationException("Plain HTTP is allowed only in an explicitly configured test environment.");

            return new ClientConfiguration {
                Environment = environment,
                ApiBaseUri = new Uri(uri.AbsoluteUri.TrimEnd('/') + "/"),
                AllowInsecureHttp = allowInsecureHttp
            };
        }

        public static ClientConfiguration Load(string[] args)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string explicitPath = System.Environment.GetEnvironmentVariable("HANDSHAKE_CLIENT_CONFIG");
            var paths = new List<string>();
            if (!String.IsNullOrWhiteSpace(explicitPath)) paths.Add(explicitPath);
            paths.Add(Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.CommonApplicationData), "HandShake VPN", "client.config"));
            paths.Add(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "client.config"));
            string path = paths.FirstOrDefault(File.Exists);
            if (path != null)
            {
                foreach (string original in File.ReadAllLines(path))
                {
                    string line = original.Trim();
                    if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                    int separator = line.IndexOf('=');
                    if (separator <= 0) continue;
                    values[line.Substring(0, separator).Trim()] = line.Substring(separator + 1).Trim();
                }
            }

            string environmentValue = ReadOverride(values, "Environment", "HANDSHAKE_ENVIRONMENT");
            string baseUrl = ReadOverride(values, "ApiBaseUrl", "HANDSHAKE_API_BASE_URL");
            string insecureValue = ReadOverride(values, "AllowInsecureHttp", "HANDSHAKE_ALLOW_INSECURE_HTTP");
            foreach (string arg in args ?? new string[0])
            {
                if (arg.StartsWith("--environment=", StringComparison.OrdinalIgnoreCase)) environmentValue = arg.Substring(arg.IndexOf('=') + 1);
                else if (arg.StartsWith("--api-base-url=", StringComparison.OrdinalIgnoreCase)) baseUrl = arg.Substring(arg.IndexOf('=') + 1);
                else if (arg.StartsWith("--allow-insecure-http=", StringComparison.OrdinalIgnoreCase)) insecureValue = arg.Substring(arg.IndexOf('=') + 1);
                else if (String.Equals(arg, "--demo", StringComparison.OrdinalIgnoreCase)) environmentValue = "Demo";
            }

            ClientEnvironmentKind environment;
            if (String.IsNullOrWhiteSpace(environmentValue) && String.IsNullOrWhiteSpace(baseUrl))
                throw new ConfigurationException("Client configuration is missing. Reinstall HandShake VPN.");
            if (!Enum.TryParse(environmentValue ?? "Production", true, out environment))
                throw new ConfigurationException("Environment must be Demo, Test, or Production.");
            if (environment == ClientEnvironmentKind.Demo)
                throw new ConfigurationException("Demo mode is not available in the VPN application.");
            bool allowInsecure;
            Boolean.TryParse(insecureValue, out allowInsecure);
            return Create(environment, baseUrl, allowInsecure);
        }

        private static string ReadOverride(IDictionary<string, string> values, string key, string environmentVariable)
        {
            string result;
            values.TryGetValue(key, out result);
            string overrideValue = System.Environment.GetEnvironmentVariable(environmentVariable);
            return String.IsNullOrWhiteSpace(overrideValue) ? result : overrideValue;
        }
    }

    public sealed class ConfigurationException : Exception
    {
        public ConfigurationException(string message) : base(message) { }
    }

    public sealed class DeviceIdentity
    {
        public string Id { get; private set; }
        public string Kind { get; private set; }
        public bool IsHardwareBound { get; private set; }

        public DeviceIdentity(string id, string kind, bool isHardwareBound)
        {
            Id = id;
            Kind = kind;
            IsHardwareBound = isHardwareBound;
        }
    }

    public sealed class RawDeviceAnchor
    {
        public string Value { get; private set; }
        public string Kind { get; private set; }
        public bool IsHardwareBound { get; private set; }

        public RawDeviceAnchor(string value, string kind, bool isHardwareBound)
        {
            Value = value;
            Kind = kind;
            IsHardwareBound = isHardwareBound;
        }
    }

    public sealed class OperatingSystemMetadata
    {
        public string Name { get; private set; }
        public string Version { get; private set; }
        public string Build { get; private set; }

        public OperatingSystemMetadata(string name, string version, string build)
        {
            Name = Normalize(name, 64);
            Version = Normalize(version, 64);
            Build = Normalize(build, 64);
        }

        private static string Normalize(string value, int maxLength)
        {
            if (String.IsNullOrWhiteSpace(value)) return null;
            string normalized = String.Join(" ", value.Split((char[])null, StringSplitOptions.RemoveEmptyEntries));
            return normalized.Length <= maxLength ? normalized : normalized.Substring(0, maxLength);
        }
    }

    public static class WindowsOperatingSystemMetadata
    {
        public static OperatingSystemMetadata Read()
        {
            string name = null;
            string version = null;
            string build = null;
            try
            {
                using (RegistryKey key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                    .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", false))
                {
                    if (key != null)
                    {
                        name = Convert.ToString(key.GetValue("ProductName"), CultureInfo.InvariantCulture);
                        version = Convert.ToString(key.GetValue("DisplayVersion"), CultureInfo.InvariantCulture);
                        if (String.IsNullOrWhiteSpace(version))
                            version = Convert.ToString(key.GetValue("ReleaseId"), CultureInfo.InvariantCulture);
                        string baseBuild = Convert.ToString(key.GetValue("CurrentBuildNumber"), CultureInfo.InvariantCulture);
                        string updateBuild = Convert.ToString(key.GetValue("UBR"), CultureInfo.InvariantCulture);
                        build = String.IsNullOrWhiteSpace(updateBuild) ? baseBuild : baseBuild + "." + updateBuild;

                        int buildNumber;
                        if (Int32.TryParse(baseBuild, NumberStyles.None, CultureInfo.InvariantCulture, out buildNumber) &&
                            buildNumber >= 22000 && !String.IsNullOrWhiteSpace(name) &&
                            name.IndexOf("Windows 10", StringComparison.OrdinalIgnoreCase) >= 0)
                            name = name.Replace("Windows 10", "Windows 11");
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
            catch (IOException) { }

            if (String.IsNullOrWhiteSpace(name)) name = "Windows";
            if (String.IsNullOrWhiteSpace(version)) version = Environment.OSVersion.VersionString;
            if (String.IsNullOrWhiteSpace(build)) build = Environment.OSVersion.Version.ToString();
            return new OperatingSystemMetadata(name, version, build);
        }
    }

    public interface IDeviceAnchorReader { RawDeviceAnchor Read(); }

    public sealed class DeviceIdentityUnavailableException : Exception
    {
        public DeviceIdentityUnavailableException(string message) : base(message) { }
    }

    public sealed class DeviceIdentityProvider
    {
        private readonly IDeviceAnchorReader reader;

        public DeviceIdentityProvider(IDeviceAnchorReader reader)
        {
            this.reader = reader;
        }

        public DeviceIdentity Get()
        {
            RawDeviceAnchor anchor = null;
            try { anchor = reader.Read(); }
            catch (ManagementException) { }
            catch (UnauthorizedAccessException) { }
            catch (COMException) { }
            catch (IOException) { }

            if (anchor == null || String.IsNullOrWhiteSpace(anchor.Value) ||
                !String.Equals(anchor.Kind, "disk-sha256", StringComparison.Ordinal) || !anchor.IsHardwareBound)
                throw new DeviceIdentityUnavailableException("The system disk serial number is unavailable.");
            string normalized = String.Concat(anchor.Value.Where(c => !Char.IsWhiteSpace(c))).ToUpperInvariant();
            return new DeviceIdentity(Hash("handshake-device-v1\0" + normalized), anchor.Kind, anchor.IsHardwareBound);
        }

        public static string Hash(string value)
        {
            using (var sha = SHA256.Create())
                return ToHex(sha.ComputeHash(Encoding.UTF8.GetBytes(value ?? String.Empty)));
        }

        private static string ToHex(byte[] bytes)
        {
            var result = new StringBuilder(bytes.Length * 2);
            foreach (byte value in bytes) result.Append(value.ToString("x2", CultureInfo.InvariantCulture));
            return result.ToString();
        }
    }

    public sealed class WindowsSystemDiskAnchorReader : IDeviceAnchorReader
    {
        private readonly bool allowTestOverride;
        public WindowsSystemDiskAnchorReader(bool allowTestOverride) { this.allowTestOverride = allowTestOverride; }

        public RawDeviceAnchor Read()
        {
            string testValue = Environment.GetEnvironmentVariable("HANDSHAKE_TEST_DEVICE_SERIAL");
            if (allowTestOverride && !String.IsNullOrWhiteSpace(testValue))
                return new RawDeviceAnchor(testValue, "test-override-sha256", false);

            string systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System)).TrimEnd('\\');
            using (var logicalSearch = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DeviceID='" + systemDrive.Replace("'", "''") + "'"))
            {
                foreach (ManagementObject logical in logicalSearch.Get())
                using (logical)
                {
                    foreach (ManagementObject partition in logical.GetRelated("Win32_DiskPartition"))
                    using (partition)
                    {
                        foreach (ManagementObject disk in partition.GetRelated("Win32_DiskDrive"))
                        using (disk)
                        {
                            string serial = Convert.ToString(disk["SerialNumber"], CultureInfo.InvariantCulture);
                            if (!String.IsNullOrWhiteSpace(serial))
                                return new RawDeviceAnchor(serial, "disk-sha256", true);
                        }
                    }
                }
            }

            return null;
        }
    }

    public interface ISecretProtector
    {
        byte[] Protect(byte[] clearText);
        byte[] Unprotect(byte[] protectedText);
    }

    public sealed class DpapiSecretProtector : ISecretProtector
    {
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("HandShake VPN/local-secret/v1");
        public byte[] Protect(byte[] clearText) { return ProtectedData.Protect(clearText, Entropy, DataProtectionScope.CurrentUser); }
        public byte[] Unprotect(byte[] protectedText) { return ProtectedData.Unprotect(protectedText, Entropy, DataProtectionScope.CurrentUser); }
    }

    public sealed class DeviceCredential
    {
        public string DeviceToken { get; set; }
        public string ServerDeviceId { get; set; }
        public string FingerprintHash { get; set; }
        public string IdentityKind { get; set; }
        public DateTime ExpiresAtUtc { get; set; }
        public bool NodeConsent { get; set; }
        public string NodeConsentVersion { get; set; }
        public DateTime? NodeConsentAtUtc { get; set; }
        public bool NodeParticipationEnabled { get; set; }
        public bool IsUsable { get { return !String.IsNullOrWhiteSpace(DeviceToken) && ExpiresAtUtc > DateTime.UtcNow.AddMinutes(1); } }
    }

    public sealed class DeviceCredentialStore
    {
        private readonly string path;
        private readonly ISecretProtector protector;
        private readonly JavaScriptSerializer serializer = new JavaScriptSerializer();

        public DeviceCredentialStore(string path, ISecretProtector protector)
        {
            this.path = path;
            this.protector = protector;
        }

        public void Save(DeviceCredential credential)
        {
            if (credential == null || String.IsNullOrWhiteSpace(credential.DeviceToken)) throw new ArgumentException("A device token is required.");
            byte[] clear = Encoding.UTF8.GetBytes(serializer.Serialize(credential));
            AtomicSecretFile.Write(path, protector.Protect(clear));
            Array.Clear(clear, 0, clear.Length);
        }

        public bool TryLoad(out DeviceCredential credential)
        {
            credential = null;
            try
            {
                if (!File.Exists(path)) return false;
                byte[] clear = protector.Unprotect(File.ReadAllBytes(path));
                try { credential = serializer.Deserialize<DeviceCredential>(Encoding.UTF8.GetString(clear)); }
                finally { Array.Clear(clear, 0, clear.Length); }
                return credential != null;
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
            catch (CryptographicException) { return false; }
            catch (InvalidOperationException) { return false; }
        }

        public void Clear()
        {
            try { if (File.Exists(path)) File.Delete(path); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    internal static class AtomicSecretFile
    {
        public static void Write(string path, byte[] value)
        {
            string directory = Path.GetDirectoryName(path);
            Directory.CreateDirectory(directory);
            string temporary = path + ".new";
            File.WriteAllBytes(temporary, value);
            if (File.Exists(path)) File.Replace(temporary, path, null);
            else File.Move(temporary, path);
        }
    }

    public sealed class ActivationRequest
    {
        public string activationKey { get; set; }
        public string deviceId { get; set; }
        public string identityKind { get; set; }
        public string deviceName { get; set; }
        public string osName { get; set; }
        public string osVersion { get; set; }
        public string osBuild { get; set; }
        public string clientVersion { get; set; }
        public string timeZoneId { get; set; }
        public int utcOffsetMinutes { get; set; }
    }

    public sealed class ActivationResponse
    {
        public string deviceId { get; set; }
        public string deviceToken { get; set; }
        public string expiresAtUtc { get; set; }
        public string activationExpiresAtUtc { get; set; }
        public bool nodeConsent { get; set; }
        public string nodeConsentVersion { get; set; }
        public string nodeConsentAtUtc { get; set; }
    }

    public sealed class DevicePolicyResponse
    {
        public string deviceId { get; set; }
        public string expiresAtUtc { get; set; }
        public string activationExpiresAtUtc { get; set; }
        public bool nodeConsent { get; set; }
        public string nodeConsentVersion { get; set; }
        public string nodeConsentAtUtc { get; set; }
    }

    public sealed class NodeCatalogResponse { public List<NodeApiModel> nodes { get; set; } public NodeApiModel self { get; set; } }
    public sealed class NodeApiModel
    {
        public string id { get; set; }
        public string countryCode { get; set; }
        public string country { get; set; }
        public string city { get; set; }
        public string ip { get; set; }
        public double? latitude { get; set; }
        public double? longitude { get; set; }
        public double? estimatedMbps { get; set; }
        public double? latencyMs { get; set; }
        public bool available { get; set; }

        public Node ToNode()
        {
            string displayCountry = String.IsNullOrWhiteSpace(country) ? countryCode : country;
            return new Node { Id = id, CountryCode = countryCode, Country = displayCountry, City = city, DisplayLabel = displayCountry + " · " + city,
                Ip = ip, Latitude = latitude ?? 0, Longitude = longitude ?? 0,
                HasCoordinates = latitude.HasValue && longitude.HasValue,
                EstimatedMbps = (int)Math.Round(estimatedMbps ?? 0), LatencyMs = (int)Math.Round(latencyMs ?? -1), Available = available };
        }
    }

    public sealed class SessionRequest
    {
        public string nodeId { get; set; }
    }

    public sealed class SessionLease
    {
        public string sessionId { get; set; }
        public string expiresAtUtc { get; set; }
        public SessionTransport transport { get; set; }
        public List<SessionHop> hops { get; set; }
    }

    public sealed class SessionTransport
    {
        public string protocol { get; set; }
        public string address { get; set; }
        public int port { get; set; }
        public string vlessId { get; set; }
        public string flow { get; set; }
        public string network { get; set; }
        public string security { get; set; }
        public SessionReality reality { get; set; }
    }

    public sealed class SessionReality
    {
        public string publicKey { get; set; }
        public string shortId { get; set; }
        public string serverName { get; set; }
    }

    public sealed class SessionHop
    {
        public int position { get; set; }
        public string role { get; set; }
        public string nodeId { get; set; }
        public string countryCode { get; set; }
        public string country { get; set; }
        public string city { get; set; }
        public string ip { get; set; }
        public string connectionMode { get; set; }
        public string endpointHost { get; set; }
        public int? endpointPort { get; set; }
        public string realityPublicKey { get; set; }
        public string realityShortId { get; set; }
        public string realityServerName { get; set; }
        public string xrayProfileVersion { get; set; }
    }

    public sealed class DiagnosticEventRequest
    {
        public string component { get; set; }
        public string severity { get; set; }
        public string eventCode { get; set; }
        public string message { get; set; }
        public string clientTimestampUtc { get; set; }
        public string clientVersion { get; set; }
    }

    public sealed class DiagnosticEventResponse
    {
        public long id { get; set; }
        public bool accepted { get; set; }
    }

    public sealed class UpdateManifest
    {
        public string version { get; set; }
        public string sha256 { get; set; }
        public long sizeBytes { get; set; }
        public string publishedAtUtc { get; set; }
        public string downloadPath { get; set; }
    }

    public static class DiagnosticEventFactory
    {
        private sealed class Definition
        {
            public string Component { get; private set; }
            public string Severity { get; private set; }
            public string Message { get; private set; }

            public Definition(string component, string severity, string message)
            {
                Component = component;
                Severity = severity;
                Message = message;
            }
        }

        // Diagnostic records deliberately contain no caller-authored message or context.
        // This allowlist is the privacy boundary that prevents exception text, paths,
        // identifiers, network destinations, credentials, and traffic details from being
        // uploaded even if a future call site accidentally passes such data.
        private static readonly IDictionary<string, Definition> Definitions =
            new Dictionary<string, Definition>(StringComparer.Ordinal) {
                { "catalog_refresh_failed", new Definition("gui", "error", "The application could not refresh the available node catalog.") },
                { "vpn_session_create_failed", new Definition("gui", "error", "The application could not create or validate a VPN session.") },
                { "vpn_session_close_failed", new Definition("gui", "error", "The application could not close the server session record.") },
                { "vpn_connect_failed", new Definition("vpn-service", "error", "The VPN service could not establish the protected tunnel.") },
                { "vpn_kill_switch_failed", new Definition("vpn-service", "critical", "The VPN service could not apply the required traffic protection.") },
                { "vpn_disconnect_failed", new Definition("vpn-service", "critical", "The VPN service could not restore the disconnected network state safely.") },
                { "node_sync_failed", new Definition("node-service", "error", "Node Service could not synchronize its control-plane state.") },
                { "node_apply_failed", new Definition("node-service", "error", "Node Service could not apply its requested participation state.") },
                { "node_deprovision_failed", new Definition("node-service", "critical", "Node Service could not stop participation safely.") },
                { "node_disable_confirm_failed", new Definition("node-service", "critical", "The server could not confirm that Node Service participation was disabled.") },
                { "node_heartbeat_failed", new Definition("node-service", "error", "Node Service could not synchronize with the control plane.") },
                { "node_runtime_error", new Definition("node-service", "critical", "Node Service entered a protected error state.") },
                { "node_re_enrollment_failed", new Definition("node-service", "error", "Node Service could not refresh its relay enrollment.") }
            };

        public static DiagnosticEventRequest Create(string eventCode)
        {
            Definition definition;
            if (String.IsNullOrWhiteSpace(eventCode) || !Definitions.TryGetValue(eventCode, out definition))
                throw new ArgumentException("Unsupported diagnostic event code.", "eventCode");
            return new DiagnosticEventRequest {
                component = definition.Component,
                severity = definition.Severity,
                eventCode = eventCode,
                message = definition.Message,
                clientTimestampUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture),
                clientVersion = HandShake.Release.ProductRelease.Version
            };
        }
    }

    public interface IControlPlaneClient : IDisposable
    {
        Task<DeviceCredential> ActivateAsync(string activationKey, DeviceIdentity identity, CancellationToken cancellationToken);
        Task<DeviceCredential> RefreshCredentialPolicyAsync(DeviceCredential credential, CancellationToken cancellationToken);
        Task<IList<Node>> GetNodesAsync(string deviceToken, CancellationToken cancellationToken);
        Task<SessionLease> CreateSessionAsync(string deviceToken, string nodeId, CancellationToken cancellationToken);
        Task CloseSessionAsync(string deviceToken, string sessionId, CancellationToken cancellationToken);
        Task DisableExitNodeAsync(string deviceToken, CancellationToken cancellationToken);
        Task ReportDiagnosticAsync(string deviceToken, DiagnosticEventRequest diagnostic, CancellationToken cancellationToken);
        Task<UpdateManifest> GetLatestUpdateAsync(string deviceToken, CancellationToken cancellationToken);
        Task DownloadUpdateAsync(string deviceToken, UpdateManifest manifest, string destinationPath, CancellationToken cancellationToken);
    }

    public sealed class ControlPlaneException : Exception
    {
        public HttpStatusCode? StatusCode { get; private set; }
        public string ErrorCode { get; private set; }
        public ControlPlaneException(string errorCode, string message, HttpStatusCode? statusCode, Exception inner)
            : base(message, inner) { ErrorCode = errorCode; StatusCode = statusCode; }
    }

    public interface IClientLocationSource { Node SelfLocation { get; } }

    public sealed class HttpControlPlaneClient : IControlPlaneClient, IClientLocationSource
    {
        public Node SelfLocation { get; private set; }
        private readonly Uri baseUri;
        private readonly HttpClient http;
        private readonly JavaScriptSerializer serializer = new JavaScriptSerializer();

        public HttpControlPlaneClient(Uri baseUri) : this(baseUri, CreateHttpClient()) { }
        public HttpControlPlaneClient(Uri baseUri, HttpClient httpClient)
        {
            this.baseUri = baseUri;
            http = httpClient;
        }

        private static HttpClient CreateHttpClient()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var client = new HttpClient(new HttpClientHandler {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                AllowAutoRedirect = false,
                UseProxy = false
            });
            // Provisioning is serialized on the relay: a lock wait plus four
            // bounded API operations can exceed 15 seconds even on a healthy WAN.
            client.Timeout = TimeSpan.FromSeconds(45);
            client.MaxResponseContentBufferSize = 2 * 1024 * 1024;
            client.DefaultRequestHeaders.UserAgent.ParseAdd("HandShake-Windows/" + HandShake.Release.ProductRelease.Version);
            return client;
        }

        public async Task<DeviceCredential> ActivateAsync(string activationKey, DeviceIdentity identity, CancellationToken cancellationToken)
        {
            OperatingSystemMetadata operatingSystem = WindowsOperatingSystemMetadata.Read();
            var payload = new ActivationRequest {
                activationKey = activationKey,
                deviceId = identity.Id,
                identityKind = identity.Kind,
                deviceName = Environment.MachineName,
                osName = operatingSystem.Name,
                osVersion = operatingSystem.Version,
                osBuild = operatingSystem.Build,
                clientVersion = HandShake.Release.ProductRelease.Version,
                timeZoneId = TimeZoneInfo.Local.Id,
                utcOffsetMinutes = (int)Math.Round(DateTimeOffset.Now.Offset.TotalMinutes)
            };
            ActivationResponse response = await PostAsync<ActivationRequest, ActivationResponse>("api/v1/activations", payload, null, cancellationToken);
            DateTime expires;
            DateTime consentAt;
            DateTime? parsedConsentAt = !String.IsNullOrWhiteSpace(response == null ? null : response.nodeConsentAtUtc) &&
                DateTime.TryParse(response.nodeConsentAtUtc, CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out consentAt)
                ? (DateTime?)consentAt.ToUniversalTime() : null;
            if (response == null || String.IsNullOrWhiteSpace(response.deviceToken) ||
                !DateTime.TryParse(response.expiresAtUtc, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out expires))
                throw new ControlPlaneException("invalid_response", "The activation server returned an incomplete response.", null, null);
            if (response.nodeConsent && (String.IsNullOrWhiteSpace(response.nodeConsentVersion) ||
                response.nodeConsentVersion.Length > 96 || !parsedConsentAt.HasValue ||
                parsedConsentAt.Value > DateTime.UtcNow.AddMinutes(5)))
                throw new ControlPlaneException("invalid_response", "The activation server returned an invalid exit-node consent record.", null, null);
            return new DeviceCredential { DeviceToken = response.deviceToken, ServerDeviceId = response.deviceId,
                FingerprintHash = identity.Id, IdentityKind = identity.Kind, ExpiresAtUtc = expires.ToUniversalTime(),
                NodeConsent = response.nodeConsent, NodeConsentVersion = response.nodeConsentVersion,
                NodeConsentAtUtc = parsedConsentAt, NodeParticipationEnabled = response.nodeConsent };
        }

        public async Task<DeviceCredential> RefreshCredentialPolicyAsync(DeviceCredential credential, CancellationToken cancellationToken)
        {
            if (credential == null || !credential.IsUsable || String.IsNullOrWhiteSpace(credential.DeviceToken))
                throw new ControlPlaneException("not_authorized", "An active device credential is required.", null, null);
            DevicePolicyResponse response = await PostAsync<Dictionary<string, object>, DevicePolicyResponse>(
                "api/v1/device-policy/refresh", new Dictionary<string, object>(), credential.DeviceToken, cancellationToken);
            DateTime expires;
            DateTime consentAt;
            DateTime? parsedConsentAt = !String.IsNullOrWhiteSpace(response == null ? null : response.nodeConsentAtUtc) &&
                DateTime.TryParse(response.nodeConsentAtUtc, CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out consentAt)
                ? (DateTime?)consentAt.ToUniversalTime() : null;
            if (response == null || !String.Equals(response.deviceId, credential.ServerDeviceId, StringComparison.Ordinal) ||
                !DateTime.TryParse(response.expiresAtUtc, CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out expires))
                throw new ControlPlaneException("invalid_response", "The server returned an invalid device policy.", null, null);
            if (response.nodeConsent && (String.IsNullOrWhiteSpace(response.nodeConsentVersion) ||
                !parsedConsentAt.HasValue || parsedConsentAt.Value > DateTime.UtcNow.AddMinutes(5)))
                throw new ControlPlaneException("invalid_response", "The server returned an invalid participation policy.", null, null);
            credential.ExpiresAtUtc = expires.ToUniversalTime();
            credential.NodeConsent = response.nodeConsent;
            credential.NodeConsentVersion = response.nodeConsentVersion;
            credential.NodeConsentAtUtc = parsedConsentAt;
            credential.NodeParticipationEnabled = response.nodeConsent;
            return credential;
        }

        public async Task<IList<Node>> GetNodesAsync(string deviceToken, CancellationToken cancellationToken)
        {
            NodeCatalogResponse response = await SendAsync<NodeCatalogResponse>(HttpMethod.Get, "api/v1/nodes", null, deviceToken, cancellationToken);
            SelfLocation = response == null || response.self == null ? null : response.self.ToNode();
            return (IList<Node>)((response == null ? null : response.nodes) ?? new List<NodeApiModel>()).Select(x => x.ToNode()).ToList();
        }

        public Task<SessionLease> CreateSessionAsync(string deviceToken, string nodeId, CancellationToken cancellationToken)
        {
            return PostAsync<SessionRequest, SessionLease>("api/v1/sessions",
                new SessionRequest { nodeId = nodeId }, deviceToken, cancellationToken);
        }

        public async Task CloseSessionAsync(string deviceToken, string sessionId, CancellationToken cancellationToken)
        {
            if (String.IsNullOrWhiteSpace(sessionId)) return;
            try
            {
                using (var request = new HttpRequestMessage(HttpMethod.Delete,
                    new Uri(baseUri, "api/v1/sessions/" + Uri.EscapeDataString(sessionId))))
                {
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", deviceToken);
                    using (HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken))
                    {
                        if (!response.IsSuccessStatusCode) throw ForStatus(response.StatusCode);
                    }
                }
            }
            catch (ControlPlaneException) { throw; }
            catch (TaskCanceledException ex) { throw new ControlPlaneException("timeout", "The control server did not respond in time.", null, ex); }
            catch (HttpRequestException ex) { throw new ControlPlaneException("network_error", "The control server is unavailable.", null, ex); }
        }

        public Task DisableExitNodeAsync(string deviceToken, CancellationToken cancellationToken)
        {
            return DeleteAsync("api/v1/nodes/exit-profile", deviceToken, cancellationToken);
        }

        public async Task ReportDiagnosticAsync(string deviceToken, DiagnosticEventRequest diagnostic, CancellationToken cancellationToken)
        {
            if (String.IsNullOrWhiteSpace(deviceToken) || diagnostic == null) return;
            try
            {
                await PostAsync<DiagnosticEventRequest, DiagnosticEventResponse>(
                    "api/v1/diagnostics", diagnostic, deviceToken, cancellationToken);
            }
            catch (ControlPlaneException) { }
            catch (TaskCanceledException) { }
            catch (HttpRequestException) { }
        }

        public async Task<UpdateManifest> GetLatestUpdateAsync(string deviceToken, CancellationToken cancellationToken)
        {
            try
            {
                return await SendAsync<UpdateManifest>(HttpMethod.Get, "api/v1/updates/latest", null, deviceToken, cancellationToken);
            }
            catch (ControlPlaneException ex)
            {
                if (ex.StatusCode == HttpStatusCode.NotFound) return null;
                throw;
            }
        }

        public async Task DownloadUpdateAsync(string deviceToken, UpdateManifest manifest, string destinationPath, CancellationToken cancellationToken)
        {
            if (manifest == null || String.IsNullOrWhiteSpace(manifest.downloadPath) ||
                !Regex.IsMatch(manifest.sha256 ?? String.Empty, "^[0-9a-fA-F]{64}$") ||
                manifest.sizeBytes < 1024 || manifest.sizeBytes > 120L * 1024L * 1024L)
                throw new ControlPlaneException("invalid_response", "The update manifest is invalid.", null, null);
            string temporary = destinationPath + ".download";
            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath));
            try
            {
                using (var request = new HttpRequestMessage(HttpMethod.Get, new Uri(baseUri, manifest.downloadPath)))
                {
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", deviceToken);
                    using (HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken))
                    {
                        if (!response.IsSuccessStatusCode) throw ForStatus(response.StatusCode);
                        long total = 0;
                        using (Stream input = await response.Content.ReadAsStreamAsync())
                        using (FileStream output = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
                        {
                            byte[] buffer = new byte[64 * 1024]; int read;
                            while ((read = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                            {
                                total += read; if (total > 120L * 1024L * 1024L) throw new ControlPlaneException("response_too_large", "The update is too large.", response.StatusCode, null);
                                await output.WriteAsync(buffer, 0, read, cancellationToken);
                            }
                        }
                        if (total != manifest.sizeBytes) throw new ControlPlaneException("invalid_response", "The update size does not match its manifest.", response.StatusCode, null);
                    }
                }
                string actual;
                using (FileStream stream = File.OpenRead(temporary))
                using (SHA256 sha = SHA256.Create()) actual = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", String.Empty).ToLowerInvariant();
                if (!String.Equals(actual, manifest.sha256, StringComparison.OrdinalIgnoreCase))
                    throw new ControlPlaneException("invalid_response", "The update checksum does not match its manifest.", null, null);
                if (File.Exists(destinationPath)) File.Delete(destinationPath);
                File.Move(temporary, destinationPath);
            }
            catch
            {
                try { if (File.Exists(temporary)) File.Delete(temporary); } catch { }
                throw;
            }
        }

        private async Task DeleteAsync(string path, string deviceToken, CancellationToken cancellationToken)
        {
            try
            {
                using (var request = new HttpRequestMessage(HttpMethod.Delete, new Uri(baseUri, path)))
                {
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", deviceToken);
                    using (HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken))
                    {
                        if (!response.IsSuccessStatusCode) throw ForStatus(response.StatusCode);
                    }
                }
            }
            catch (ControlPlaneException) { throw; }
            catch (TaskCanceledException ex) { throw new ControlPlaneException("timeout", "The control server did not respond in time.", null, ex); }
            catch (HttpRequestException ex) { throw new ControlPlaneException("network_error", "The control server is unavailable.", null, ex); }
        }

        private Task<TResponse> PostAsync<TRequest, TResponse>(string path, TRequest payload, string token, CancellationToken cancellationToken)
        {
            return SendAsync<TResponse>(HttpMethod.Post, path, serializer.Serialize(payload), token, cancellationToken);
        }

        private async Task<T> SendAsync<T>(HttpMethod method, string path, string json, string token, CancellationToken cancellationToken)
        {
            try
            {
                using (var request = new HttpRequestMessage(method, new Uri(baseUri, path)))
                {
                    if (json != null) request.Content = new StringContent(json, Encoding.UTF8, "application/json");
                    if (!String.IsNullOrWhiteSpace(token)) request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                    using (HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken))
                    {
                        if (response.Content.Headers.ContentLength.HasValue && response.Content.Headers.ContentLength.Value > 2 * 1024 * 1024)
                            throw new ControlPlaneException("response_too_large", "The server response is too large.", response.StatusCode, null);
                        string body = await response.Content.ReadAsStringAsync();
                        if (body.Length > 2 * 1024 * 1024)
                            throw new ControlPlaneException("response_too_large", "The server response is too large.", response.StatusCode, null);
                        if (!response.IsSuccessStatusCode) throw ForStatus(response.StatusCode);
                        try { return serializer.Deserialize<T>(body); }
                        catch (InvalidOperationException ex) { throw new ControlPlaneException("invalid_response", "The server response could not be read.", response.StatusCode, ex); }
                    }
                }
            }
            catch (ControlPlaneException) { throw; }
            catch (TaskCanceledException ex) { throw new ControlPlaneException("timeout", "The control server did not respond in time.", null, ex); }
            catch (HttpRequestException ex) { throw new ControlPlaneException("network_error", "The control server is unavailable.", null, ex); }
        }

        private static ControlPlaneException ForStatus(HttpStatusCode status)
        {
            if (status == HttpStatusCode.Unauthorized || status == HttpStatusCode.Forbidden)
                return new ControlPlaneException("not_authorized", "The activation key or device token was rejected.", status, null);
            if (status == HttpStatusCode.Conflict)
                return new ControlPlaneException("device_mismatch", "This key is already bound to another device.", status, null);
            if ((int)status == 429)
                return new ControlPlaneException("rate_limited", "Too many requests. Please wait and try again.", status, null);
            if ((int)status >= 500)
                return new ControlPlaneException("server_error", "The control server is temporarily unavailable.", status, null);
            return new ControlPlaneException("request_rejected", "The control server rejected the request.", status, null);
        }

        public void Dispose() { http.Dispose(); }
    }
}
