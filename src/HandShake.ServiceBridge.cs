using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;
using HandShake.ServiceIntegration;

namespace HandShake
{
    public static class VpnConnectionHealth
    {
        public static bool IsProtected(ServiceStatus status, DateTime now)
        {
            DateTime expiry, updated;
            return status != null && status.state == "connected" &&
                status.trafficSafety == "native-wfp-tunnel" &&
                !String.IsNullOrWhiteSpace(status.sessionId) &&
                status.xrayRunning == true &&
                DateTime.TryParse(status.updatedAtUtc, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out updated) &&
                now.ToUniversalTime() - updated.ToUniversalTime() <= TimeSpan.FromSeconds(15) &&
                updated.ToUniversalTime() - now.ToUniversalTime() <= TimeSpan.FromSeconds(5) &&
                DateTime.TryParse(status.sessionExpiresAtUtc, CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out expiry) && expiry.ToUniversalTime() > now.ToUniversalTime();
        }

        public static bool NeedsDisconnect(ServiceStatus status)
        {
            return status != null && (status.trafficSafety == "native-wfp-blocked" ||
                status.trafficSafety == "native-wfp-tunnel" || status.state == "error" ||
                status.state == "starting" || status.state == "session-expired");
        }
    }

    public interface IServiceBridge : IDisposable
    {
        Task BootstrapNodeAsync(DeviceCredential credential, bool available, CancellationToken cancellationToken);
        Task BootstrapNodeDisabledAsync(CancellationToken cancellationToken);
        Task DeprovisionNodeAsync(CancellationToken cancellationToken);
        Task ProvisionVpnAsync(SessionLease lease, CancellationToken cancellationToken);
        Task DisconnectVpnAsync(string sessionId, CancellationToken cancellationToken);
        Task<ServiceStatus> GetVpnStatusAsync(CancellationToken cancellationToken);
        Task<ServiceStatus> GetNodeStatusAsync(CancellationToken cancellationToken);
        Task SetNodeAvailabilityAsync(bool available, CancellationToken cancellationToken);
    }

    public sealed class ServiceBridgeException : Exception
    {
        public string ErrorCode { get; private set; }

        public ServiceBridgeException(string errorCode, string message) : base(message)
        {
            ErrorCode = errorCode;
        }

        public ServiceBridgeException(string errorCode, string message, Exception inner) : base(message, inner)
        {
            ErrorCode = errorCode;
        }
    }

    public sealed class NamedPipeServiceBridge : IServiceBridge
    {
        private const int ConnectTimeoutMilliseconds = 5000;
        private const int IoTimeoutMilliseconds = 10000;
        private readonly bool allowExperimentalFirewallLab;
        private volatile bool disposed;

        public NamedPipeServiceBridge(bool allowExperimentalFirewallLab)
        {
            this.allowExperimentalFirewallLab = allowExperimentalFirewallLab;
        }

        public Task BootstrapNodeAsync(DeviceCredential credential, bool available, CancellationToken cancellationToken)
        {
            if (credential == null || !credential.IsUsable || string.IsNullOrWhiteSpace(credential.DeviceToken))
                throw new ServiceBridgeException("credential_required", "An active device credential is required.");
            if (!credential.NodeConsent || String.IsNullOrWhiteSpace(credential.NodeConsentVersion) || !credential.NodeConsentAtUtc.HasValue)
                throw new ServiceBridgeException("exit_consent_required", "Server-verified exit-node consent is required.");

            var payload = new NodeBootstrapPayload
            {
                requestExitParticipation = true,
                deviceToken = credential.DeviceToken,
                available = available
            };
            return SendWithoutStatusAsync(ServiceProtocol.NodePipeName, ServiceProtocol.BootstrapNode, payload, cancellationToken);
        }

        public Task BootstrapNodeDisabledAsync(CancellationToken cancellationToken)
        {
            return SendWithoutStatusAsync(ServiceProtocol.NodePipeName, ServiceProtocol.BootstrapNode,
                new NodeBootstrapPayload { requestExitParticipation = false }, cancellationToken);
        }

        public Task DeprovisionNodeAsync(CancellationToken cancellationToken)
        {
            return SendWithoutStatusAsync(ServiceProtocol.NodePipeName, ServiceProtocol.DeprovisionNode,
                new Dictionary<string, object>(), cancellationToken);
        }

        public Task ProvisionVpnAsync(SessionLease lease, CancellationToken cancellationToken)
        {
            ValidatedSession session = VpnProfileFactory.Validate(lease);
            var payload = new VpnProvisionPayload
            {
                sessionId = session.SessionId,
                expiresAtUtc = session.ExpiresAtUtc.ToString("o", CultureInfo.InvariantCulture),
                requireKillSwitch = true,
                allowUnsafeLabMode = allowExperimentalFirewallLab,
                xrayProfileVersion = VpnProfileFactory.ProfileVersion,
                relayAddress = session.Address,
                relayPort = session.Port,
                vlessId = session.VlessId,
                flow = session.Flow,
                realityPublicKey = session.PublicKey,
                realityShortId = session.ShortId,
                realityServerName = session.ServerName
            };
            return SendWithoutStatusAsync(ServiceProtocol.VpnPipeName, ServiceProtocol.ProvisionVpn, payload, cancellationToken);
        }

        public Task DisconnectVpnAsync(string sessionId, CancellationToken cancellationToken)
        {
            return SendWithoutStatusAsync(ServiceProtocol.VpnPipeName, ServiceProtocol.DisconnectVpn,
                new VpnDisconnectPayload { sessionId = sessionId }, cancellationToken);
        }

        public async Task<ServiceStatus> GetVpnStatusAsync(CancellationToken cancellationToken)
        {
            // Only a read may be retried. Provision/disconnect are never replayed
            // after an uncertain response, and authorization failures are final.
            for (int attempt = 0; ; attempt++)
            {
                try { return await SendForStatusAsync(ServiceProtocol.VpnPipeName, cancellationToken).ConfigureAwait(false); }
                catch (ServiceBridgeException ex)
                {
                    if (attempt >= 1 || !String.Equals(ex.ErrorCode, "service_unavailable", StringComparison.Ordinal)) throw;
                }
                await Task.Delay(300, cancellationToken).ConfigureAwait(false);
            }
        }

        public Task<ServiceStatus> GetNodeStatusAsync(CancellationToken cancellationToken)
        {
            return SendForStatusAsync(ServiceProtocol.NodePipeName, cancellationToken);
        }

        public Task SetNodeAvailabilityAsync(bool available, CancellationToken cancellationToken)
        {
            return SendWithoutStatusAsync(ServiceProtocol.NodePipeName, ServiceProtocol.SetNodeAvailability,
                new NodeAvailabilityPayload { available = available }, cancellationToken);
        }

        private async Task SendWithoutStatusAsync(string pipeName, string command, object payload, CancellationToken cancellationToken)
        {
            await SendAsync(pipeName, command, payload, cancellationToken).ConfigureAwait(false);
        }

        private async Task<ServiceStatus> SendForStatusAsync(string pipeName, CancellationToken cancellationToken)
        {
            ServiceResponse response = await SendAsync(pipeName, ServiceProtocol.GetStatus, new Dictionary<string, object>(), cancellationToken)
                .ConfigureAwait(false);
            return response.status ?? new ServiceStatus { state = "unknown" };
        }

        private Task<ServiceResponse> SendAsync(string pipeName, string command, object payload, CancellationToken cancellationToken)
        {
            if (disposed) throw new ObjectDisposedException("NamedPipeServiceBridge");
            cancellationToken.ThrowIfCancellationRequested();
            return Task.Factory.StartNew(delegate
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Send(pipeName, command, payload, cancellationToken);
            }, cancellationToken, TaskCreationOptions.DenyChildAttach, TaskScheduler.Default);
        }

        private ServiceResponse Send(string pipeName, string command, object payload, CancellationToken cancellationToken)
        {
            var request = new ServiceRequest
            {
                protocolVersion = ServiceProtocol.Version,
                requestId = Guid.NewGuid().ToString("N"),
                command = command,
                payload = payload
            };
            byte[] requestBytes = null;
            byte[] responseBytes = null;
            try
            {
                requestBytes = ServiceWireCodec.Encode(request);
                using (var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
                    TokenImpersonationLevel.Impersonation))
                {
                    pipe.Connect(ConnectTimeoutMilliseconds);
                    pipe.ReadMode = PipeTransmissionMode.Byte;
                    PipeServerIdentity.RequireLocalSystem(pipe.SafePipeHandle, pipeName);
                    cancellationToken.ThrowIfCancellationRequested();
                    WriteFrameTimed(pipe, requestBytes, cancellationToken);
                    responseBytes = ReadFrameTimed(pipe, cancellationToken);
                    // The complete response is now consumed; permit the server
                    // to disconnect without dropping buffered response bytes.
                    try { WriteTimed(pipe, new[] { ServiceProtocol.ResponseAcknowledgement }, 0, 1, cancellationToken); }
                    catch (IOException) { } // Old service builds disconnect immediately.
                }
                ServiceResponse response = ServiceWireCodec.Decode<ServiceResponse>(responseBytes);
                if (response.protocolVersion != ServiceProtocol.Version ||
                    !string.Equals(response.requestId, request.requestId, StringComparison.Ordinal))
                    throw new ServiceBridgeException("invalid_service_response", "The Windows service returned a mismatched response.");
                if (!response.success)
                    throw new ServiceBridgeException(string.IsNullOrWhiteSpace(response.errorCode) ? "service_rejected" : response.errorCode,
                        string.IsNullOrWhiteSpace(response.message) ? "The Windows service rejected the request." : response.message);
                return response;
            }
            catch (ServiceBridgeException) { throw; }
            catch (TimeoutException ex)
            {
                throw new ServiceBridgeException("service_unavailable", "The Windows service did not respond in time.", ex);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new ServiceBridgeException("service_access_denied", "Windows denied access to the protected service channel.", ex);
            }
            catch (Win32Exception ex)
            {
                throw new ServiceBridgeException("service_authentication_failed", "The local pipe server could not be authenticated as LocalSystem.", ex);
            }
            catch (IOException ex)
            {
                throw new ServiceBridgeException("service_unavailable", "The Windows service is unavailable.", ex);
            }
            catch (ServiceProtocolException ex)
            {
                throw new ServiceBridgeException(ex.ErrorCode, ex.Message, ex);
            }
            finally
            {
                if (requestBytes != null) Array.Clear(requestBytes, 0, requestBytes.Length);
                if (responseBytes != null) Array.Clear(responseBytes, 0, responseBytes.Length);
            }
        }

        private static void WriteFrameTimed(NamedPipeClientStream pipe, byte[] payload, CancellationToken cancellationToken)
        {
            if (payload == null || payload.Length == 0 || payload.Length > ServiceProtocol.MaximumFrameBytes)
                throw new ServiceProtocolException("invalid_frame", "The local service message has an invalid size.");
            byte[] header = BitConverter.GetBytes(payload.Length);
            try
            {
                WriteTimed(pipe, header, 0, header.Length, cancellationToken);
                WriteTimed(pipe, payload, 0, payload.Length, cancellationToken);
            }
            finally { Array.Clear(header, 0, header.Length); }
        }

        private static byte[] ReadFrameTimed(NamedPipeClientStream pipe, CancellationToken cancellationToken)
        {
            byte[] header = ReadExactlyTimed(pipe, 4, cancellationToken);
            try
            {
                int length = BitConverter.ToInt32(header, 0);
                if (length <= 0 || length > ServiceProtocol.MaximumFrameBytes)
                    throw new ServiceProtocolException("invalid_frame", "The local service frame length is invalid.");
                return ReadExactlyTimed(pipe, length, cancellationToken);
            }
            finally { Array.Clear(header, 0, header.Length); }
        }

        private static byte[] ReadExactlyTimed(NamedPipeClientStream pipe, int count, CancellationToken cancellationToken)
        {
            byte[] value = new byte[count];
            int offset = 0;
            try
            {
                while (offset < count)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    IAsyncResult operation = pipe.BeginRead(value, offset, count - offset, null, null);
                    int read;
                    if (WaitForPipeIo(operation, cancellationToken))
                    {
                        read = pipe.EndRead(operation);
                    }
                    else
                    {
                        AbortRead(pipe, operation);
                        cancellationToken.ThrowIfCancellationRequested();
                        throw new TimeoutException("The Windows service did not respond in time.");
                    }
                    if (read <= 0)
                        throw new EndOfStreamException("The Windows service closed the local channel before the response was complete.");
                    offset += read;
                }
                return value;
            }
            catch
            {
                Array.Clear(value, 0, value.Length);
                throw;
            }
        }

        private static void WriteTimed(NamedPipeClientStream pipe, byte[] value, int offset, int count,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IAsyncResult operation = pipe.BeginWrite(value, offset, count, null, null);
            if (WaitForPipeIo(operation, cancellationToken))
            {
                pipe.EndWrite(operation);
                return;
            }
            AbortWrite(pipe, operation);
            cancellationToken.ThrowIfCancellationRequested();
            throw new TimeoutException("The Windows service did not accept the request in time.");
        }

        private static bool WaitForPipeIo(IAsyncResult operation, CancellationToken cancellationToken)
        {
            if (!cancellationToken.CanBeCanceled)
                return operation.AsyncWaitHandle.WaitOne(IoTimeoutMilliseconds);
            int signaled = WaitHandle.WaitAny(
                new[] { operation.AsyncWaitHandle, cancellationToken.WaitHandle },
                IoTimeoutMilliseconds);
            return signaled == 0;
        }

        private static void AbortRead(NamedPipeClientStream pipe, IAsyncResult operation)
        {
            CancelPendingIo(pipe, operation);
            try { if (operation.IsCompleted) pipe.EndRead(operation); }
            catch { }
        }

        private static void AbortWrite(NamedPipeClientStream pipe, IAsyncResult operation)
        {
            CancelPendingIo(pipe, operation);
            try { if (operation.IsCompleted) pipe.EndWrite(operation); }
            catch { }
        }

        private static void CancelPendingIo(NamedPipeClientStream pipe, IAsyncResult operation)
        {
            try
            {
                if (pipe.SafePipeHandle != null && !pipe.SafePipeHandle.IsInvalid && !pipe.SafePipeHandle.IsClosed)
                    CancelIoEx(pipe.SafePipeHandle, IntPtr.Zero);
                if (!operation.IsCompleted && !operation.AsyncWaitHandle.WaitOne(1000)) pipe.Dispose();
                if (!operation.IsCompleted) operation.AsyncWaitHandle.WaitOne(1000);
            }
            catch { try { pipe.Dispose(); } catch { } }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CancelIoEx(SafePipeHandle handle, IntPtr overlapped);

        public void Dispose() { disposed = true; }
    }

    internal static class PipeServerIdentity
    {
        public static void RequireLocalSystem(SafePipeHandle pipeHandle, string pipeName)
        {
            if (pipeHandle == null || pipeHandle.IsInvalid || pipeHandle.IsClosed)
                throw new Win32Exception(6, "The connected pipe handle is invalid.");
            uint firstPid;
            if (!GetNamedPipeServerProcessId(pipeHandle, out firstPid) || firstPid == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "The named-pipe server process could not be identified.");

            string serviceName = String.Equals(pipeName, ServiceProtocol.NodePipeName, StringComparison.Ordinal)
                ? "HandShakeNodeService"
                : String.Equals(pipeName, ServiceProtocol.VpnPipeName, StringComparison.Ordinal)
                    ? "HandShakeVpnService" : null;
            if (serviceName == null)
                throw new UnauthorizedAccessException("The connected pipe is not a recognized HandShake service channel.");
            uint servicePid = ReadServiceProcessId(serviceName);
            uint secondPid;
            if (!GetNamedPipeServerProcessId(pipeHandle, out secondPid) || secondPid != firstPid || servicePid != firstPid)
                throw new UnauthorizedAccessException("The connected pipe server does not match the registered Windows service.");
            uint finalPid;
            if (!GetNamedPipeServerProcessId(pipeHandle, out finalPid) || finalPid != firstPid ||
                ReadServiceProcessId(serviceName) != firstPid)
                throw new UnauthorizedAccessException("The named-pipe server identity changed during authentication.");
        }

        private static uint ReadServiceProcessId(string serviceName)
        {
            IntPtr manager = OpenSCManager(null, null, 0x0001);
            if (manager == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "The Service Control Manager could not be opened.");
            IntPtr service = IntPtr.Zero;
            try
            {
                service = OpenService(manager, serviceName, 0x0004);
                if (service == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "The HandShake Windows service could not be queried.");
                ServiceStatusProcess status;
                uint needed;
                if (!QueryServiceStatusEx(service, 0, out status, (uint)Marshal.SizeOf(typeof(ServiceStatusProcess)), out needed) ||
                    status.ProcessId == 0 || status.CurrentState != 4)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "The HandShake Windows service is not running.");
                return status.ProcessId;
            }
            finally
            {
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                CloseServiceHandle(manager);
            }
        }

        internal static bool IsLocalSystemSid(string sid)
        {
            return string.Equals(sid, "S-1-5-18", StringComparison.Ordinal);
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceStatusProcess
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
            public uint ProcessId;
            public uint ServiceFlags;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr manager, string serviceName, uint desiredAccess);
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel,
            out ServiceStatusProcess status, uint bufferSize, out uint bytesNeeded);
        [DllImport("advapi32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr serviceHandle);
    }

    public static class ServiceProvisioningPolicy
    {
        public static bool AllowExperimentalFirewallLab(ClientConfiguration configuration)
        {
            return configuration != null && configuration.Environment == ClientEnvironmentKind.Test &&
                configuration.ApiBaseUri != null &&
                string.Equals(configuration.ApiBaseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        }
    }

    public sealed class ValidatedSession
    {
        public string SessionId { get; set; }
        public DateTime ExpiresAtUtc { get; set; }
        public string Address { get; set; }
        public int Port { get; set; }
        public string VlessId { get; set; }
        public string Flow { get; set; }
        public string PublicKey { get; set; }
        public string ShortId { get; set; }
        public string ServerName { get; set; }
    }

    public static class VpnProfileFactory
    {
        public const string ProfileVersion = "26.9.9-mvp1";
        private static readonly JavaScriptSerializer Serializer = new JavaScriptSerializer
        {
            MaxJsonLength = ServiceProtocol.MaximumFrameBytes,
            RecursionLimit = 80
        };

        internal static readonly string[] PrivateNetworks = new[]
        {
            "geoip:private", "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
            "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
            "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
            "::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32",
            "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"
        };

        public static ValidatedSession Validate(SessionLease lease)
        {
            if (lease == null || string.IsNullOrWhiteSpace(lease.sessionId) || lease.sessionId.Length > 128 ||
                lease.sessionId.AnyControlCharacter())
                throw new ServiceBridgeException("invalid_session", "The session identifier is invalid.");
            DateTime expiry;
            if (!DateTime.TryParse(lease.expiresAtUtc, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out expiry))
                throw new ServiceBridgeException("invalid_session", "The session expiry is invalid.");
            expiry = expiry.ToUniversalTime();
            if (expiry <= DateTime.UtcNow || expiry > DateTime.UtcNow.AddHours(24))
                throw new ServiceBridgeException("invalid_session", "The session expiry is outside the permitted range.");
            SessionTransport transport = lease.transport;
            if (transport == null || !string.Equals(transport.protocol, "vless", StringComparison.Ordinal) ||
                !string.Equals(transport.network, "raw", StringComparison.Ordinal) ||
                !string.Equals(transport.security, "reality", StringComparison.Ordinal) ||
                !string.Equals(transport.flow, "xtls-rprx-vision", StringComparison.Ordinal) ||
                transport.port < 1 || transport.port > 65535 || transport.reality == null)
                throw new ServiceBridgeException("invalid_transport", "The server returned an unsupported VPN transport.");

            IPAddress address;
            if (!IPAddress.TryParse(transport.address, out address) || !IsPublicAddress(address))
                throw new ServiceBridgeException("invalid_transport", "The relay address must be a public numeric IP address.");
            Guid vlessId;
            if (!Guid.TryParseExact(transport.vlessId, "D", out vlessId))
                throw new ServiceBridgeException("invalid_transport", "The VLESS identifier is invalid.");
            if (!IsBase64Url(transport.reality.publicKey, 43, 44))
                throw new ServiceBridgeException("invalid_transport", "The REALITY public key is invalid.");
            if (!IsShortId(transport.reality.shortId))
                throw new ServiceBridgeException("invalid_transport", "The REALITY short id is invalid.");
            if (!IsServerName(transport.reality.serverName))
                throw new ServiceBridgeException("invalid_transport", "The REALITY server name is invalid.");

            return new ValidatedSession
            {
                SessionId = lease.sessionId,
                ExpiresAtUtc = expiry,
                Address = address.ToString(),
                Port = transport.port,
                VlessId = vlessId.ToString("D"),
                Flow = transport.flow,
                PublicKey = transport.reality.publicKey,
                ShortId = transport.reality.shortId.ToLowerInvariant(),
                ServerName = transport.reality.serverName.ToLowerInvariant()
            };
        }

        public static string BuildJson(ValidatedSession session)
        {
            if (session == null) throw new ArgumentNullException("session");
            var root = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                { "log", new Dictionary<string, object> { { "access", "none" }, { "error", "" }, { "loglevel", "none" } } },
                { "inbounds", new object[] {
                    new Dictionary<string, object> {
                        { "tag", "client-tun" }, { "protocol", "tun" },
                        { "settings", new Dictionary<string, object> {
                            { "name", "handshake0" }, { "desc", "HandShake VPN" }, { "mtu", 1500 },
                            { "gateway", new[] { "10.253.0.1/30", "fd7a:115c:a1e0::1/126" } },
                            { "dns", new[] { "1.1.1.1", "1.0.0.1" } }, { "userLevel", 0 },
                            { "autoSystemRoutingTable", new[] { "0.0.0.0/0", "::/0" } },
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
                            { "address", session.Address }, { "port", session.Port }, { "id", session.VlessId },
                            { "encryption", "none" }, { "flow", session.Flow }
                        } },
                        { "streamSettings", new Dictionary<string, object> {
                            { "network", "raw" }, { "security", "reality" },
                            { "realitySettings", new Dictionary<string, object> {
                                { "show", false }, { "serverName", session.ServerName }, { "fingerprint", "chrome" },
                                { "password", session.PublicKey }, { "shortId", session.ShortId }, { "spiderX", "/" }
                            } }
                        } }
                    }
                } },
                { "routing", new Dictionary<string, object> {
                    { "domainStrategy", "IPIfNonMatch" },
                    { "rules", new object[] {
                        new Dictionary<string, object> { { "type", "field" }, { "inboundTag", new[] { "client-tun" } },
                            { "domain", new[] { "geosite:private" } }, { "outboundTag", "blocked" } },
                        new Dictionary<string, object> { { "type", "field" }, { "inboundTag", new[] { "client-tun" } },
                            { "ip", PrivateNetworks }, { "outboundTag", "blocked" } },
                        new Dictionary<string, object> { { "type", "field" }, { "inboundTag", new[] { "client-tun" } },
                            { "network", "tcp" }, { "port", "22,25,465,587" }, { "outboundTag", "blocked" } },
                        new Dictionary<string, object> { { "type", "field" }, { "inboundTag", new[] { "client-tun" } },
                            { "outboundTag", "to-relay" } }
                    } }
                } }
            };
            string json = Serializer.Serialize(root);
            if (Encoding.UTF8.GetByteCount(json) > ServiceProtocol.MaximumFrameBytes / 2)
                throw new ServiceBridgeException("profile_too_large", "The generated VPN profile is too large.");
            return json;
        }

        internal static bool IsPublicAddress(IPAddress address)
        {
            if (address == null || IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) ||
                address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.None) || address.Equals(IPAddress.IPv6None))
                return false;
            if (address.IsIPv4MappedToIPv6) return IsPublicAddress(address.MapToIPv4());
            byte[] bytes = address.GetAddressBytes();
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                int a = bytes[0], b = bytes[1];
                return !(a == 0 || a == 10 || a == 127 || a >= 224 ||
                    (a == 100 && b >= 64 && b <= 127) || (a == 169 && b == 254) ||
                    (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
                    (a == 192 && b == 0 && (bytes[2] == 0 || bytes[2] == 2)) ||
                    (a == 192 && b == 88 && bytes[2] == 99) ||
                    (a == 198 && (b == 18 || b == 19)) ||
                    (a == 198 && b == 51 && bytes[2] == 100) ||
                    (a == 203 && b == 0 && bytes[2] == 113));
            }
            if (address.AddressFamily != AddressFamily.InterNetworkV6) return false;
            bool unspecified = true;
            foreach (byte value in bytes) if (value != 0) { unspecified = false; break; }
            return !(unspecified || address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal ||
                (bytes[0] & 0xfe) == 0xfc ||
                (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b) ||
                (bytes[0] == 0x01 && bytes[1] == 0x00) ||
                (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] <= 0x01) ||
                (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8) ||
                (bytes[0] == 0x20 && bytes[1] == 0x02));
        }

        internal static bool IsBase64Url(string value, int minimumLength, int maximumLength)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length < minimumLength || value.Length > maximumLength) return false;
            foreach (char c in value)
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
            return true;
        }

        internal static bool IsShortId(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length > 16 || value.Length % 2 != 0) return false;
            foreach (char c in value)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
            return true;
        }

        internal static bool IsServerName(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length > 253 || value.IndexOf('/') >= 0 || value.IndexOf(':') >= 0) return false;
            IPAddress ignored;
            return !IPAddress.TryParse(value, out ignored) && Uri.CheckHostName(value) == UriHostNameType.Dns;
        }
    }

    internal static class ServiceBridgeTextExtensions
    {
        public static bool AnyControlCharacter(this string value)
        {
            if (value == null) return false;
            foreach (char c in value) if (char.IsControl(c)) return true;
            return false;
        }
    }
}
