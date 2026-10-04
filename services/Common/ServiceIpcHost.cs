using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using HandShake.ServiceIntegration;
using Microsoft.Win32.SafeHandles;

namespace HandShake.Services
{
    internal sealed class ServiceCommandException : Exception
    {
        public string ErrorCode { get; private set; }

        public ServiceCommandException(string errorCode, string message) : base(message)
        {
            ErrorCode = errorCode;
        }
    }

    internal delegate ServiceStatus ServiceCommandHandler(string command, object payload);

    internal static class ProvisionalEnrollment
    {
        public static T CompleteAfterValidatedCommand<T>(Func<T> validatedCommand, Action commitOwner)
        {
            T result = validatedCommand();
            commitOwner();
            return result;
        }
    }

    internal static class ServicePayload
    {
        private static readonly JavaScriptSerializer Serializer = new JavaScriptSerializer
        {
            MaxJsonLength = ServiceProtocol.MaximumFrameBytes,
            RecursionLimit = 80
        };

        public static T ReadStrict<T>(object payload, IEnumerable<string> allowedKeys)
        {
            IDictionary<string, object> dictionary = payload as IDictionary<string, object>;
            if (dictionary == null)
                throw new ServiceCommandException("invalid_request", "The command payload must be a JSON object.");
            HashSet<string> allowed = new HashSet<string>(allowedKeys, StringComparer.Ordinal);
            foreach (string key in dictionary.Keys)
                if (!allowed.Contains(key))
                    throw new ServiceCommandException("invalid_request", "The command payload contains an unknown property.");
            try
            {
                T result = Serializer.Deserialize<T>(Serializer.Serialize(payload));
                if (result == null) throw new ServiceCommandException("invalid_request", "The command payload is empty.");
                return result;
            }
            catch (ServiceCommandException) { throw; }
            catch (Exception ex)
            {
                throw new ServiceCommandException("invalid_request", "The command payload is invalid: " + ex.GetType().Name + ".");
            }
        }

        public static void RequireEmpty(object payload)
        {
            IDictionary<string, object> dictionary = payload as IDictionary<string, object>;
            if (dictionary == null || dictionary.Count != 0)
                throw new ServiceCommandException("invalid_request", "This command does not accept payload properties.");
        }
    }

    internal static class ProtectedStorage
    {
        public static void EnsureDirectory(string path)
        {
            Directory.CreateDirectory(path);
            DirectorySecurity security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            SecurityIdentifier system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            security.SetOwner(administrators);
            security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl,
                inheritance, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(administrators, FileSystemRights.FullControl,
                inheritance, PropagationFlags.None, AccessControlType.Allow));
            Directory.SetAccessControl(path, security);
            AccessControlGuard.RequireSystemAndAdministratorsOnly(path, true);
        }

        public static void WriteBytesAtomic(string path, byte[] value)
        {
            if (value == null || value.Length == 0) throw new ArgumentException("A nonempty value is required.", "value");
            string directory = Path.GetDirectoryName(path);
            EnsureDirectory(directory);
            string temporary = Path.Combine(directory, ".ipc-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (FileStream stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    4096, FileOptions.WriteThrough))
                {
                    stream.Write(value, 0, value.Length);
                    stream.Flush(true);
                }
                ApplyFileAcl(temporary);
                if (File.Exists(path)) File.Replace(temporary, path, null, true);
                else File.Move(temporary, path);
                AccessControlGuard.RequireSystemAndAdministratorsOnly(path, false);
            }
            finally
            {
                try { if (File.Exists(temporary)) File.Delete(temporary); }
                catch { }
            }
        }

        public static void WriteTextAtomic(string path, string value)
        {
            byte[] bytes = new UTF8Encoding(false, true).GetBytes(value ?? string.Empty);
            try { WriteBytesAtomic(path, bytes); }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }

        public static string Sha256File(string path)
        {
            using (FileStream stream = File.OpenRead(path))
            using (SHA256 algorithm = SHA256.Create())
            {
                byte[] hash = algorithm.ComputeHash(stream);
                StringBuilder value = new StringBuilder(hash.Length * 2);
                foreach (byte item in hash) value.Append(item.ToString("x2", CultureInfo.InvariantCulture));
                return value.ToString();
            }
        }

        private static void ApplyFileAcl(string path)
        {
            FileSecurity security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            SecurityIdentifier system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            security.SetOwner(administrators);
            security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(administrators, FileSystemRights.FullControl, AccessControlType.Allow));
            File.SetAccessControl(path, security);
        }
    }

    internal static class MachineSecretFile
    {
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("HandShake VPN/node-device-token/v1");

        public static void WriteBearerToken(string path, string token)
        {
            ValidateToken(token);
            byte[] clear = Encoding.UTF8.GetBytes(token);
            byte[] encrypted = null;
            try
            {
                encrypted = ProtectedData.Protect(clear, Entropy, DataProtectionScope.LocalMachine);
                ProtectedStorage.WriteBytesAtomic(path, encrypted);
            }
            finally
            {
                Array.Clear(clear, 0, clear.Length);
                if (encrypted != null) Array.Clear(encrypted, 0, encrypted.Length);
            }
        }

        public static string ReadBearerToken(string path)
        {
            if (!File.Exists(path)) throw new ServiceConfigurationException("Encrypted device token is missing.");
            AccessControlGuard.RequireSystemAndAdministratorsOnly(path, false);
            byte[] encrypted = File.ReadAllBytes(path);
            byte[] clear = null;
            try
            {
                clear = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.LocalMachine);
                string token = new UTF8Encoding(false, true).GetString(clear);
                ValidateToken(token);
                return token;
            }
            catch (CryptographicException ex)
            {
                throw new ServiceConfigurationException("Encrypted device token could not be opened on this machine.", ex);
            }
            finally
            {
                Array.Clear(encrypted, 0, encrypted.Length);
                if (clear != null) Array.Clear(clear, 0, clear.Length);
            }
        }

        private static void ValidateToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token) || token.Length < 20 || token.Length > 512 ||
                token.IndexOfAny(new[] { '\r', '\n', '\t', ' ' }) >= 0)
                throw new ServiceConfigurationException("Device token has an invalid value.");
        }
    }

    internal static class XrayPrivacyChecks
    {
        public static void RequireTrafficLogsDisabled(string path, bool allowExitDns = false)
        {
            if (!File.Exists(path)) throw new ServiceConfigurationException("Provisioned Xray configuration is missing.");
            RequireTrafficLogsDisabledText(File.ReadAllText(path, Encoding.UTF8), allowExitDns);
        }

        public static void RequireTrafficLogsDisabledText(string text, bool allowExitDns = false)
        {
            object parsed = JsonFile.ParseObject(text);
            IDictionary<string, object> root = parsed as IDictionary<string, object>;
            Validation.Require(root != null, "The Xray configuration root must be an object.");
            foreach (string dangerous in new[] { "api", "stats", "metrics", "reverse", "dns", "policy", "observatory", "burstObservatory", "balancers" })
                Validation.Require(!root.ContainsKey(dangerous) || (dangerous == "dns" && allowExitDns), "The Xray configuration contains a forbidden top-level section: " + dangerous + ".");
            if (allowExitDns && root.ContainsKey("dns")) RequireFixedExitDns(root);
            IDictionary<string, object> routing = Get(root, "routing") as IDictionary<string, object>;
            Validation.Require(routing == null || !routing.ContainsKey("balancers"),
                "The Xray configuration cannot define routing balancers.");
            RejectDangerousNestedKeys(root);
            IDictionary<string, object> log = root == null ? null : Get(root, "log") as IDictionary<string, object>;
            Validation.Require(log != null && string.Equals(Get(log, "access") as string, "none", StringComparison.Ordinal) &&
                string.Equals(Get(log, "error") as string, string.Empty, StringComparison.Ordinal) &&
                string.Equals(Get(log, "loglevel") as string, "none", StringComparison.Ordinal),
                "Xray traffic and destination logging must be disabled.");
        }

        public static void RequireEphemeralDestinationStream(string path)
        {
            if (!File.Exists(path)) throw new ServiceConfigurationException("Provisioned Xray configuration is missing.");
            object parsed = JsonFile.ParseObject(File.ReadAllText(path, Encoding.UTF8));
            IDictionary<string, object> root = parsed as IDictionary<string, object>;
            Validation.Require(root != null, "The Xray configuration root must be an object.");
            foreach (string dangerous in new[] { "api", "stats", "metrics", "reverse", "dns", "policy", "observatory", "burstObservatory", "balancers" })
                Validation.Require(!root.ContainsKey(dangerous), "The Xray configuration contains a forbidden top-level section: " + dangerous + ".");
            RejectDangerousNestedKeys(root);
            IDictionary<string, object> log = Get(root, "log") as IDictionary<string, object>;
            Validation.Require(log != null && string.Equals(Get(log, "access") as string, string.Empty, StringComparison.Ordinal) &&
                string.Equals(Get(log, "error") as string, string.Empty, StringComparison.Ordinal) &&
                string.Equals(Get(log, "loglevel") as string, "none", StringComparison.Ordinal),
                "Xray may emit its ephemeral destination stream only to the service-owned standard output pipe.");
        }

        private static void RequireFixedExitDns(IDictionary<string, object> root)
        {
            IDictionary<string, object> dns = Get(root, "dns") as IDictionary<string, object>;
            Validation.Require(dns != null && dns.Count == 3 && Object.Equals(Get(dns, "tag"), "exit-dns") && Object.Equals(Get(dns, "queryStrategy"), "UseIPv4"),
                "The exit DNS configuration must remain fixed and service-owned.");
            IEnumerable servers = Get(dns, "servers") as IEnumerable;
            List<string> addresses = new List<string>();
            if (servers != null) foreach (object server in servers) addresses.Add(server as string);
            Validation.Require(addresses.Count == 2 && addresses[0] == "1.1.1.1" && addresses[1] == "1.0.0.1", "Exit DNS servers cannot be overridden.");
            IDictionary<string, object> routing = Get(root, "routing") as IDictionary<string, object>;
            IEnumerable rules = Get(routing, "rules") as IEnumerable;
            bool found = false;
            if (rules != null) foreach (object value in rules) {
                IDictionary<string, object> rule = value as IDictionary<string, object>;
                IEnumerable tags = Get(rule, "inboundTag") as IEnumerable;
                if (tags == null) continue;
                foreach (object tag in tags) if (Object.Equals(tag, "exit-dns")) {
                    Validation.Require(!found && rule.Count == 3 && Object.Equals(Get(rule, "type"), "field") && Object.Equals(Get(rule, "outboundTag"), "exit-public"),
                        "Exit DNS must use the protected public outbound.");
                    found = true;
                }
            }
            Validation.Require(found, "The exit DNS route is missing.");
        }

        private static object Get(IDictionary<string, object> value, string key)
        {
            object result;
            return value != null && value.TryGetValue(key, out result) ? result : null;
        }

        private static void RejectDangerousNestedKeys(object value)
        {
            IDictionary<string, object> dictionary = value as IDictionary<string, object>;
            if (dictionary != null)
            {
                foreach (KeyValuePair<string, object> item in dictionary)
                {
                    Validation.Require(!string.Equals(item.Key, "masterKeyLog", StringComparison.OrdinalIgnoreCase),
                        "The Xray configuration cannot request TLS/REALITY master-key logging.");
                    RejectDangerousNestedKeys(item.Value);
                }
                return;
            }
            IEnumerable sequence = value as IEnumerable;
            if (sequence == null || value is string) return;
            foreach (object item in sequence) RejectDangerousNestedKeys(item);
        }
    }

    internal static class ServiceStateReader
    {
        public static ServiceStatus Read(string path, string fallbackState)
        {
            if (!File.Exists(path)) return new ServiceStatus { state = fallbackState };
            try
            {
                AccessControlGuard.RequireSystemAndAdministratorsOnly(path, false);
                IDictionary<string, object> value = JsonFile.ParseObject(File.ReadAllText(path, Encoding.UTF8)) as IDictionary<string, object>;
                if (value == null) return new ServiceStatus { state = "unknown" };
                return new ServiceStatus
                {
                    state = Text(value, "status") ?? fallbackState,
                    sessionId = Text(value, "sessionId"),
                    sessionExpiresAtUtc = Text(value, "sessionExpiresAtUtc"),
                    updatedAtUtc = Text(value, "updatedAtUtc"),
                    xrayRunning = Boolean(value, "xrayRunning"),
                    exitConsent = Boolean(value, "exitConsent"),
                    available = Boolean(value, "available"),
                    trafficSafety = Text(value, "trafficSafety"),
                    detail = Text(value, "error")
                };
            }
            catch { return new ServiceStatus { state = "unknown" }; }
        }

        private static string Text(IDictionary<string, object> value, string key)
        {
            object result;
            return value.TryGetValue(key, out result) ? result as string : null;
        }

        private static bool? Boolean(IDictionary<string, object> value, string key)
        {
            object result;
            return value.TryGetValue(key, out result) && result is bool ? (bool?)result : null;
        }
    }

    internal static class ServiceEnvironmentPolicy
    {
        internal sealed class ControlPlaneConfiguration
        {
            public string EnvironmentName;
            public Uri ApiBaseUri;
            public bool AllowInsecureLoopback;
        }

        public static bool AllowExperimentalFirewallLab()
        {
            try
            {
                ControlPlaneConfiguration configuration = ReadControlPlaneConfiguration();
                return IsExperimentalFirewallLabConfiguration(configuration.EnvironmentName,
                    configuration.ApiBaseUri.AbsoluteUri);
            }
            catch { return false; }
        }

        internal static bool IsExperimentalFirewallLabConfiguration(string environment, string apiBaseUrl)
        {
            Uri uri;
            return string.Equals(environment, "Test", StringComparison.OrdinalIgnoreCase) &&
                Uri.TryCreate(apiBaseUrl, UriKind.Absolute, out uri) &&
                string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
                string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment);
        }

        public static ControlPlaneConfiguration ReadControlPlaneConfiguration()
        {
            string path = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "client.config"));
            string expected = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!path.StartsWith(expected, StringComparison.OrdinalIgnoreCase) || !File.Exists(path))
                throw new ServiceConfigurationException("The protected service client.config is missing.");
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new ServiceConfigurationException("The protected service client.config cannot be a reparse point.");
            AccessControlGuard.RequireNoWriteAccessOutsideSystemAndAdministrators(path);
            FileInfo info = new FileInfo(path);
            if (info.Length <= 0 || info.Length > 16 * 1024)
                throw new ServiceConfigurationException("The protected service client.config has an invalid size.");

            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string original in File.ReadAllLines(path, Encoding.UTF8))
            {
                string line = original.Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                int separator = line.IndexOf('=');
                if (separator <= 0 || separator == line.Length - 1)
                    throw new ServiceConfigurationException("The protected service client.config is invalid.");
                string key = line.Substring(0, separator).Trim();
                string value = line.Substring(separator + 1).Trim();
                if (key.Length == 0 || value.Length == 0 || values.ContainsKey(key) ||
                    !(string.Equals(key, "Environment", StringComparison.OrdinalIgnoreCase) ||
                      string.Equals(key, "ApiBaseUrl", StringComparison.OrdinalIgnoreCase) ||
                      string.Equals(key, "AllowInsecureHttp", StringComparison.OrdinalIgnoreCase)))
                    throw new ServiceConfigurationException("The protected service client.config contains an unsupported or duplicate setting.");
                values.Add(key, value);
            }
            string environment;
            string apiBaseUrl;
            string allowInsecureText;
            if (!values.TryGetValue("Environment", out environment) || !values.TryGetValue("ApiBaseUrl", out apiBaseUrl) ||
                !values.TryGetValue("AllowInsecureHttp", out allowInsecureText))
                throw new ServiceConfigurationException("The protected service client.config is incomplete.");
            bool allowInsecure;
            if (!bool.TryParse(allowInsecureText, out allowInsecure))
                throw new ServiceConfigurationException("AllowInsecureHttp must be true or false.");
            if (!(string.Equals(environment, "Test", StringComparison.OrdinalIgnoreCase) ||
                  string.Equals(environment, "Production", StringComparison.OrdinalIgnoreCase)))
                throw new ServiceConfigurationException("Windows services require Test or Production environment configuration.");
            bool loopbackDevelopment = string.Equals(environment, "Test", StringComparison.OrdinalIgnoreCase) && allowInsecure;
            Uri api = Validation.RequireProtectedApiBase(apiBaseUrl, loopbackDevelopment);
            if (loopbackDevelopment && (!api.IsLoopback || !string.Equals(api.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)))
                throw new ServiceConfigurationException("Plain HTTP is allowed only for an explicit Test loopback control plane.");
            if (!loopbackDevelopment && !string.Equals(api.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                throw new ServiceConfigurationException("The configured control plane must use HTTPS.");
            return new ControlPlaneConfiguration {
                EnvironmentName = environment,
                ApiBaseUri = api,
                AllowInsecureLoopback = loopbackDevelopment
            };
        }
    }

    internal sealed class LocalServicePipeHost : IDisposable
    {
        private const int IoTimeoutMilliseconds = 10000;
        private const int MaximumPipeInstances = 4;
        private static readonly string OwnerDirectory = Path.Combine(ProductInfo.ProgramDataRoot, "broker");
        private static readonly string OwnerPath = Path.Combine(OwnerDirectory, "owner.sid");

        private readonly string _pipeName;
        private readonly HashSet<string> _enrollmentCommands;
        private readonly ServiceCommandHandler _handler;
        private readonly ServiceLog _log;
        private readonly ManualResetEvent _stop = new ManualResetEvent(false);
        private readonly object _sync = new object();
        private readonly object _commandSync = new object();
        private readonly HashSet<NamedPipeServerStream> _activePipes = new HashSet<NamedPipeServerStream>();
        private readonly int _ioTimeoutMilliseconds;
        private Thread[] _threads;

        public LocalServicePipeHost(string pipeName, IEnumerable<string> enrollmentCommands, ServiceCommandHandler handler, ServiceLog log)
            : this(pipeName, enrollmentCommands, handler, log, IoTimeoutMilliseconds) { }

        internal LocalServicePipeHost(string pipeName, IEnumerable<string> enrollmentCommands, ServiceCommandHandler handler, ServiceLog log,
            int ioTimeoutMilliseconds)
        {
            if (ioTimeoutMilliseconds <= 0 || ioTimeoutMilliseconds > IoTimeoutMilliseconds)
                throw new ArgumentOutOfRangeException("ioTimeoutMilliseconds");
            _pipeName = pipeName;
            _enrollmentCommands = new HashSet<string>(enrollmentCommands ?? new string[0], StringComparer.Ordinal);
            _handler = handler;
            _log = log;
            _ioTimeoutMilliseconds = ioTimeoutMilliseconds;
        }

        public void Start()
        {
            lock (_sync)
            {
                if (_threads != null) return;
                ProtectedStorage.EnsureDirectory(OwnerDirectory);
                _stop.Reset();
                _threads = new Thread[MaximumPipeInstances];
                for (int index = 0; index < _threads.Length; index++)
                {
                    _threads[index] = new Thread(Run) { IsBackground = true, Name = _pipeName + " IPC " + index };
                    _threads[index].Start();
                }
            }
        }

        public void Stop()
        {
            Thread[] threads;
            lock (_sync)
            {
                threads = _threads;
                if (threads == null) return;
                _stop.Set();
                foreach (NamedPipeServerStream pipe in _activePipes)
                {
                    try { pipe.Dispose(); }
                    catch { }
                }
            }
            Stopwatch deadline = Stopwatch.StartNew();
            foreach (Thread thread in threads)
                if (!thread.Join(Math.Max(0, 12000 - (int)deadline.ElapsedMilliseconds)))
                    throw new ServiceConfigurationException("The protected local service channel did not stop.");
            lock (_sync) { _threads = null; _activePipes.Clear(); }
        }

        private void Run()
        {
            while (!_stop.WaitOne(0))
            {
                NamedPipeServerStream pipe = null;
                try
                {
                    string aclOwner = ReadOwner();
                    pipe = CreatePipe(aclOwner);
                    lock (_sync)
                    {
                        if (_stop.WaitOne(0)) { pipe.Dispose(); break; }
                        _activePipes.Add(pipe);
                    }
                    while (!_stop.WaitOne(0))
                    {
                        if (!WaitForConnection(pipe, aclOwner)) break;
                        try { if (!_stop.WaitOne(0)) Process(pipe); }
                        finally
                        {
                            if (pipe.IsConnected)
                            {
                                pipe.Disconnect();
                            }
                        }
                        if (!string.Equals(aclOwner, ReadOwner(), StringComparison.Ordinal)) break;
                    }
                }
                catch (ObjectDisposedException) { if (!_stop.WaitOne(0)) _log.Error("The protected local service channel was disposed unexpectedly."); }
                catch (IOException ex) { if (!_stop.WaitOne(0)) _log.Error("Protected local channel I/O failed: " + ex.GetType().Name + "."); }
                catch (Win32Exception ex) { if (!_stop.WaitOne(0)) _log.Error("Protected local channel failed: Win32Exception code=" + ex.NativeErrorCode.ToString(CultureInfo.InvariantCulture) + "."); }
                catch (Exception ex) { if (!_stop.WaitOne(0)) _log.Error("Protected local channel failed: " + ex.GetType().Name + "."); }
                finally
                {
                    lock (_sync) { if (pipe != null) _activePipes.Remove(pipe); }
                    if (pipe != null) pipe.Dispose();
                }
                if (!_stop.WaitOne(0)) _stop.WaitOne(1000);
            }
        }

        private void Process(NamedPipeServerStream pipe)
        {
            ServiceRequest request = null;
            ServiceResponse response;
            try
            {
                byte[] frame = ReadFrame(pipe);
                CallerIdentity caller;
                try
                {
                    // The client authenticates the registered service process
                    // before it sends this bounded frame. Reading first avoids
                    // a mutual-authentication race where both peers inspect the
                    // other process while the service can still disconnect.
                    request = ReadRequestStrict(frame);
                    caller = CaptureCaller(pipe);
                    PreAuthorizeConnection(caller);
                }
                finally { Array.Clear(frame, 0, frame.Length); }
                ServiceStatus status;
                // Reception is bounded and concurrent; profile mutation and the
                // owner transition retain the previous sequential semantics.
                lock (_commandSync)
                {
                    if (_stop.WaitOne(0)) return;
                    bool provisionalEnrollment = Authorize(caller, request.command);
                    status = provisionalEnrollment
                        ? ProvisionalEnrollment.CompleteAfterValidatedCommand(
                            delegate { return _handler(request.command, request.payload); },
                            delegate { EnrollOrReplaceOwner(caller.Sid); })
                        : _handler(request.command, request.payload);
                }
                response = new ServiceResponse { protocolVersion = ServiceProtocol.Version, requestId = request.requestId,
                    success = true, status = status };
            }
            catch (ServiceCommandException ex)
            {
                response = new ServiceResponse { protocolVersion = ServiceProtocol.Version,
                    requestId = request == null ? null : request.requestId, success = false,
                    errorCode = ex.ErrorCode, message = ex.Message };
            }
            catch (ServiceConfigurationException ex)
            {
                response = new ServiceResponse { protocolVersion = ServiceProtocol.Version,
                    requestId = request == null ? null : request.requestId, success = false,
                    errorCode = "configuration_error", message = ex.Message };
            }
            catch (UnauthorizedAccessException)
            {
                response = Failure(request, "local_access_denied", "Windows denied a required local service operation.");
            }
            catch (Win32Exception)
            {
                response = Failure(request, "windows_error", "A required Windows service operation failed.");
            }
            catch (IOException)
            {
                response = Failure(request, "local_io_error", "A protected local service file or channel operation failed.");
            }
            catch (CryptographicException)
            {
                response = Failure(request, "secure_storage_error", "Protected local service storage could not be processed.");
            }
            catch (InvalidOperationException)
            {
                response = Failure(request, "local_state_error", "The Windows service encountered an invalid local state.");
            }
            catch (Exception ex)
            {
                response = Failure(request, "internal_error",
                    "The Windows service could not process the request (" + ex.GetType().Name + ").");
            }
            if (!pipe.IsConnected) return;
            byte[] encoded = ServiceWireCodec.Encode(response);
            try { WriteFrame(pipe, encoded); }
            finally { Array.Clear(encoded, 0, encoded.Length); }
        }

        private static ServiceResponse Failure(ServiceRequest request, string errorCode, string message)
        {
            return new ServiceResponse { protocolVersion = ServiceProtocol.Version,
                requestId = request == null ? null : request.requestId, success = false,
                errorCode = errorCode, message = message };
        }

        private static ServiceRequest ReadRequestStrict(byte[] frame)
        {
            object parsed = JsonFile.ParseObject(new UTF8Encoding(false, true).GetString(frame));
            IDictionary<string, object> root = parsed as IDictionary<string, object>;
            if (root == null || root.Count != 4 || !root.ContainsKey("protocolVersion") ||
                !root.ContainsKey("requestId") || !root.ContainsKey("command") || !root.ContainsKey("payload"))
                throw new ServiceCommandException("invalid_request", "The local service request envelope is invalid.");
            ServiceRequest request = ServiceWireCodec.Decode<ServiceRequest>(frame);
            if (request.protocolVersion != ServiceProtocol.Version || !IsRequestId(request.requestId) ||
                string.IsNullOrWhiteSpace(request.command) || request.command.Length > 64 || request.payload == null)
                throw new ServiceCommandException("invalid_request", "The local service request fields are invalid.");
            return request;
        }

        private bool Authorize(CallerIdentity caller, string command)
        {
            if (caller == null || string.IsNullOrWhiteSpace(caller.Sid))
                throw new ServiceCommandException("access_denied", "The local service caller was rejected.");
            string owner = ReadOwner();
            if (caller.IsSystem || caller.IsAdministrator || string.Equals(owner, caller.Sid, StringComparison.Ordinal)) return false;
            // Enrollment is allowed for an authenticated local caller. Remote
            // pipe clients are rejected at creation time and network-logon
            // tokens are rejected above. The command itself must still prove
            // possession of the device token before ownership is changed.
            if (_enrollmentCommands.Contains(command))
                return true;
            throw new ServiceCommandException("access_denied", "This Windows user does not own the HandShake service profile.");
        }

        private static void PreAuthorizeConnection(CallerIdentity caller)
        {
            if (caller == null || string.IsNullOrWhiteSpace(caller.Sid))
                throw new ServiceCommandException("access_denied", "The local service caller was rejected.");
            if (caller.NetworkLogon)
                throw new ServiceCommandException("access_denied", "Remote named-pipe clients are not accepted.");
            string owner = ReadOwner();
            if (caller.IsSystem || caller.IsAdministrator || string.Equals(owner, caller.Sid, StringComparison.Ordinal)) return;
            // An authenticated local caller may present only an enrollment
            // request. Authorize() keeps all other commands owner-only, and the
            // handler validates the server-issued device token before ownership
            // can be replaced.
            return;
        }

        private static string ReadOwner()
        {
            if (!File.Exists(OwnerPath)) return null;
            AccessControlGuard.RequireSystemAndAdministratorsOnly(OwnerPath, false);
            string value = File.ReadAllText(OwnerPath, Encoding.ASCII).Trim();
            try { return new SecurityIdentifier(value).Value; }
            catch { throw new ServiceConfigurationException("The local service owner record is invalid."); }
        }

        private static void EnrollOrReplaceOwner(string sid)
        {
            ProtectedStorage.EnsureDirectory(OwnerDirectory);
            new SecurityIdentifier(sid);
            ProtectedStorage.WriteTextAtomic(OwnerPath, sid + "\n");
        }

        private NamedPipeServerStream CreatePipe(string ownerSid)
        {
            PipeSecurity security = BuildPipeSecurity(ownerSid);
            // Apply the mandatory label atomically at creation. Setting it later
            // requires WRITE_OWNER, whose CreateNamedPipe open-mode bit aliases
            // FILE_FLAG_FIRST_PIPE_INSTANCE and prevents our additional workers.
            RawSecurityDescriptor descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
            descriptor.SystemAcl = new RawSecurityDescriptor("S:(ML;;NW;;;ME)").SystemAcl;
            descriptor.SetFlags(descriptor.ControlFlags | ControlFlags.SystemAclPresent);
            byte[] bytes = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(bytes, 0);
            GCHandle pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try {
                PipeSecurityAttributes attributes = new PipeSecurityAttributes {
                    length = (uint)Marshal.SizeOf(typeof(PipeSecurityAttributes)),
                    descriptor = pinned.AddrOfPinnedObject(), inheritHandle = 0
                };
                SafePipeHandle handle = CreateNamedPipe("\\\\.\\pipe\\" + _pipeName, 0x40000003, 0,
                    MaximumPipeInstances, 64 * 1024, 64 * 1024, 0, ref attributes);
                if (handle.IsInvalid) {
                    int code = Marshal.GetLastWin32Error(); handle.Dispose();
                    throw new Win32Exception(code, "The protected local pipe could not be created.");
                }
                try { return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle); }
                catch { handle.Dispose(); throw; }
            } finally { pinned.Free(); Array.Clear(bytes, 0, bytes.Length); }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PipeSecurityAttributes { public uint length; public IntPtr descriptor; public int inheritHandle; }
        [DllImport("kernel32.dll", EntryPoint = "CreateNamedPipeW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafePipeHandle CreateNamedPipe(string name, uint openMode, uint pipeMode,
            int maximumInstances, int outputBuffer, int inputBuffer, uint timeout, ref PipeSecurityAttributes attributes);

        private static void ApplyMediumIntegrityLabel(SafePipeHandle handle)
        {
            IntPtr descriptor;
            uint descriptorSize;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor("S:(ML;;NW;;;ME)", 1,
                out descriptor, out descriptorSize) || descriptor == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "The pipe integrity descriptor could not be created.");
            try
            {
                bool present;
                bool defaulted;
                IntPtr sacl;
                if (!GetSecurityDescriptorSacl(descriptor, out present, out sacl, out defaulted) ||
                    !present || sacl == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "The pipe integrity label is missing.");
                uint result = SetSecurityInfo(handle.DangerousGetHandle(), 6, 0x00000010,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl);
                if (result != 0)
                    throw new Win32Exception((int)result, "The pipe integrity label could not be applied.");
            }
            finally { LocalFree(descriptor); }
        }

        private static PipeSecurity BuildPipeSecurity(string ownerSid)
        {
            PipeSecurity security = new PipeSecurity();
            SecurityIdentifier system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(administrators, PipeAccessRights.FullControl, AccessControlType.Allow));
            // Authenticated local users need to reach the command-level authorization
            // gate so an active-console user can recover a stale owner record by
            // presenting a valid enrollment credential. Remote pipe clients remain
            // rejected and non-enrollment commands remain owner-only.
            SecurityIdentifier authenticated = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            // NamedPipeClientStream opens a duplex client with GENERIC_READ |
            // GENERIC_WRITE. For named pipes the generic write mapping also contains
            // FILE_CREATE_PIPE_INSTANCE, exposed by .NET as CreateNewInstance.
            PipeAccessRights clientRights = PipeAccessRights.ReadWrite |
                PipeAccessRights.CreateNewInstance | PipeAccessRights.Synchronize;
            security.AddAccessRule(new PipeAccessRule(authenticated, clientRights, AccessControlType.Allow));
            if (!string.IsNullOrEmpty(ownerSid))
            {
                SecurityIdentifier owner = new SecurityIdentifier(ownerSid);
                security.AddAccessRule(new PipeAccessRule(owner, clientRights, AccessControlType.Allow));
            }
            return security;
        }

        private bool WaitForConnection(NamedPipeServerStream pipe, string aclOwner)
        {
            IAsyncResult pending = pipe.BeginWaitForConnection(null, null);
            while (true)
            {
                int signaled = WaitHandle.WaitAny(new[] { _stop, pending.AsyncWaitHandle }, 1000);
                if (signaled == 0) return false;
                if (signaled == 1)
                {
                    pipe.EndWaitForConnection(pending);
                    return true;
                }
                if (!string.Equals(aclOwner, ReadOwner(), StringComparison.Ordinal)) return false;
            }
        }

        private CallerIdentity CaptureCaller(NamedPipeServerStream pipe)
        {
            CallerIdentity result = null;
            pipe.RunAsClient(delegate
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent(true))
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    SecurityIdentifier network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);
                    SecurityIdentifier interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
                    SecurityIdentifier remoteInteractive = new SecurityIdentifier("S-1-5-14");
                    uint sessionId = ReadTokenSessionId(identity.Token);
                    result = new CallerIdentity
                    {
                        Sid = identity.User == null ? null : identity.User.Value,
                        IsSystem = identity.User != null && identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid),
                        IsAdministrator = principal.IsInRole(WindowsBuiltInRole.Administrator),
                        NetworkLogon = identity.Groups != null && identity.Groups.Contains(network),
                        ActiveConsole = sessionId != 0 && sessionId == WTSGetActiveConsoleSessionId(),
                        InteractiveLogon = identity.Groups != null &&
                            (identity.Groups.Contains(interactive) || identity.Groups.Contains(remoteInteractive))
                    };
                }
            });
            return result;
        }

        private byte[] ReadFrame(Stream stream)
        {
            IoDeadline deadline = new IoDeadline(_ioTimeoutMilliseconds);
            byte[] header = ReadExactlyWithinDeadline(stream, 4, deadline);
            int length = BitConverter.ToInt32(header, 0);
            if (length <= 0 || length > ServiceProtocol.MaximumFrameBytes)
                throw new ServiceCommandException("invalid_request", "The local service frame length is invalid.");
            return ReadExactlyWithinDeadline(stream, length, deadline);
        }

        private byte[] ReadExactly(Stream stream, int count)
        {
            return ReadExactlyWithinDeadline(stream, count, new IoDeadline(_ioTimeoutMilliseconds));
        }

        private byte[] ReadExactlyWithinDeadline(Stream stream, int count, IoDeadline deadline)
        {
            byte[] result = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int remaining = deadline.RemainingMilliseconds;
                IAsyncResult operation = stream.BeginRead(result, offset, count - offset, null, null);
                int signaled = WaitHandle.WaitAny(new[] { _stop, operation.AsyncWaitHandle }, remaining);
                if (signaled == WaitHandle.WaitTimeout || signaled == 0)
                {
                    AbortPendingIo(stream, operation, true);
                    if (signaled == 0) throw new ObjectDisposedException(_pipeName);
                    throw new IOException("The local service request timed out.");
                }
                int read;
                try { read = stream.EndRead(operation); }
                finally { operation.AsyncWaitHandle.Close(); }
                if (read <= 0) throw new EndOfStreamException("The local service request ended early.");
                offset += read;
            }
            return result;
        }

        private void WriteFrame(Stream stream, byte[] payload)
        {
            IoDeadline deadline = new IoDeadline(_ioTimeoutMilliseconds);
            byte[] header = BitConverter.GetBytes(payload.Length);
            WriteTimed(stream, header, 0, header.Length, deadline);
            WriteTimed(stream, payload, 0, payload.Length, deadline);
            stream.Flush();
            // PipeStream.Flush does not wait for the peer to consume the buffer.
            // DisconnectNamedPipe discards unread replies, so wait for a bounded
            // receipt acknowledgement (or EOF from an older client) first.
            try
            {
                byte[] acknowledgement = ReadExactlyWithinDeadline(stream, 1, deadline);
                if (acknowledgement[0] != ServiceProtocol.ResponseAcknowledgement)
                    throw new IOException("The local response acknowledgement is invalid.");
            }
            catch (EndOfStreamException) { }
        }

        private void WriteTimed(Stream stream, byte[] value, int offset, int count, IoDeadline deadline)
        {
            int remaining = deadline.RemainingMilliseconds;
            IAsyncResult operation = stream.BeginWrite(value, offset, count, null, null);
            int signaled = WaitHandle.WaitAny(new[] { _stop, operation.AsyncWaitHandle }, remaining);
            if (signaled == WaitHandle.WaitTimeout || signaled == 0)
            {
                AbortPendingIo(stream, operation, false);
                if (signaled == 0) throw new ObjectDisposedException(_pipeName);
                throw new IOException("The local service response timed out.");
            }
            try { stream.EndWrite(operation); }
            finally { operation.AsyncWaitHandle.Close(); }
        }

        private static void AbortPendingIo(Stream stream, IAsyncResult operation, bool reading)
        {
            PipeStream pipe = stream as PipeStream;
            try { if (pipe != null) CancelIoEx(pipe.SafePipeHandle, IntPtr.Zero); }
            catch (ObjectDisposedException) { }
            try { stream.Dispose(); }
            catch (IOException) { }
            // End the APM operation after kernel cancellation. Do not keep the
            // service worker waiting for a peer that stopped sending/reading.
            ThreadPool.RegisterWaitForSingleObject(operation.AsyncWaitHandle, delegate(object state, bool timedOut) {
                try
                {
                    if (reading) stream.EndRead(operation);
                    else stream.EndWrite(operation);
                }
                catch (Exception) { }
                finally { try { operation.AsyncWaitHandle.Close(); } catch (ObjectDisposedException) { } }
            }, null, Timeout.Infinite, true);
        }

        private sealed class IoDeadline
        {
            private readonly Stopwatch _elapsed = Stopwatch.StartNew();
            private readonly int _milliseconds;
            internal IoDeadline(int milliseconds) { _milliseconds = milliseconds; }
            internal int RemainingMilliseconds
            {
                get
                {
                    long remaining = _milliseconds - _elapsed.ElapsedMilliseconds;
                    if (remaining <= 0) throw new IOException("The local service I/O deadline expired.");
                    return (int)remaining;
                }
            }
        }

        private static bool IsRequestId(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length != 32) return false;
            foreach (char c in value)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            return true;
        }

        private static uint ReadTokenSessionId(IntPtr token)
        {
            uint value;
            int returned;
            if (!GetTokenInformation(token, 12, out value, sizeof(uint), out returned))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not read the pipe caller session.");
            return value;
        }

        public void Dispose()
        {
            Stop();
            _stop.Dispose();
        }

        internal static bool NetworkClientRejectionEnabledForSelfTest()
        {
            try
            {
                PreAuthorizeConnection(new CallerIdentity {
                    Sid = "S-1-5-21-111111111-222222222-333333333-1001", NetworkLogon = true
                });
                return false;
            }
            catch (ServiceCommandException ex)
            {
                return string.Equals(ex.ErrorCode, "access_denied", StringComparison.Ordinal);
            }
        }

        internal static bool PipeAclTransitionsToOwnerOnlyForSelfTest()
        {
            SecurityIdentifier authenticated = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            SecurityIdentifier system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            SecurityIdentifier owner = new SecurityIdentifier("S-1-5-21-111111111-222222222-333333333-1001");
            PipeSecurity initial = BuildPipeSecurity(null);
            PipeSecurity enrolled = BuildPipeSecurity(owner.Value);
            return HasPipeRule(initial, authenticated, AccessControlType.Allow) &&
                HasPipeRule(enrolled, authenticated, AccessControlType.Allow) &&
                HasPipeRule(enrolled, owner, AccessControlType.Allow) &&
                HasPipeRule(enrolled, system, AccessControlType.Allow) &&
                HasPipeRule(enrolled, administrators, AccessControlType.Allow);
        }

        private static bool HasPipeRule(PipeSecurity security, SecurityIdentifier sid, AccessControlType type)
        {
            AuthorizationRuleCollection rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier));
            foreach (AuthorizationRule item in rules)
            {
                PipeAccessRule rule = item as PipeAccessRule;
                SecurityIdentifier identity = rule == null ? null : rule.IdentityReference as SecurityIdentifier;
                if (identity != null && identity.Equals(sid) && rule.AccessControlType == type &&
                    (type != AccessControlType.Allow ||
                     (rule.PipeAccessRights & (PipeAccessRights.Synchronize | PipeAccessRights.CreateNewInstance)) ==
                     (PipeAccessRights.Synchronize | PipeAccessRights.CreateNewInstance))) return true;
            }
            return false;
        }

        private sealed class CallerIdentity
        {
            public string Sid;
            public bool IsSystem;
            public bool IsAdministrator;
            public bool NetworkLogon;
            public bool ActiveConsole;
            public bool InteractiveLogon;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass,
            out uint tokenInformation, int tokenInformationLength, out int returnLength);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string stringSecurityDescriptor, uint revision, out IntPtr descriptor, out uint descriptorSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetSecurityDescriptorSacl(IntPtr descriptor, out bool saclPresent,
            out IntPtr sacl, out bool saclDefaulted);

        [DllImport("advapi32.dll")]
        private static extern uint SetSecurityInfo(IntPtr handle, int objectType, uint securityInformation,
            IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CancelIoEx(SafePipeHandle handle, IntPtr overlapped);
    }
}
