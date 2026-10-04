using System;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace HandShake.ServiceIntegration
{
    public static class ServiceProtocol
    {
        public const int Version = 1;
        public const int MaximumFrameBytes = 256 * 1024;
        public const int VpnTunnelStartupSeconds = 60;
        public const byte ResponseAcknowledgement = 0xAC;
        public const string VpnPipeName = "HandShake.VpnService.v1";
        public const string NodePipeName = "HandShake.NodeService.v1";

        public const string BootstrapNode = "node.bootstrap";
        public const string DeprovisionNode = "node.deprovision";
        public const string SetNodeAvailability = "node.set-availability";
        public const string ProvisionVpn = "vpn.provision";
        public const string DisconnectVpn = "vpn.disconnect";
        public const string GetStatus = "status.get";
    }

    public sealed class ServiceRequest
    {
        public int protocolVersion { get; set; }
        public string requestId { get; set; }
        public string command { get; set; }
        public object payload { get; set; }
    }

    public sealed class ServiceResponse
    {
        public int protocolVersion { get; set; }
        public string requestId { get; set; }
        public bool success { get; set; }
        public string errorCode { get; set; }
        public string message { get; set; }
        public ServiceStatus status { get; set; }
    }

    public sealed class ServiceStatus
    {
        public string state { get; set; }
        public string sessionId { get; set; }
        public string sessionExpiresAtUtc { get; set; }
        public string updatedAtUtc { get; set; }
        public bool? xrayRunning { get; set; }
        public bool? exitConsent { get; set; }
        public bool? available { get; set; }
        public string trafficSafety { get; set; }
        public string detail { get; set; }
    }

    public sealed class NodeBootstrapPayload
    {
        public bool requestExitParticipation { get; set; }
        public string deviceToken { get; set; }
        public bool available { get; set; }
    }

    public sealed class NodeAvailabilityPayload
    {
        public bool available { get; set; }
    }

    public sealed class VpnProvisionPayload
    {
        public string sessionId { get; set; }
        public string expiresAtUtc { get; set; }
        public bool requireKillSwitch { get; set; }
        public bool allowUnsafeLabMode { get; set; }
        public string xrayProfileVersion { get; set; }
        public string relayAddress { get; set; }
        public int relayPort { get; set; }
        public string vlessId { get; set; }
        public string flow { get; set; }
        public string realityPublicKey { get; set; }
        public string realityShortId { get; set; }
        public string realityServerName { get; set; }
    }

    public sealed class VpnDisconnectPayload
    {
        public string sessionId { get; set; }
    }

    public sealed class ServiceProtocolException : Exception
    {
        public string ErrorCode { get; private set; }

        public ServiceProtocolException(string errorCode, string message) : base(message)
        {
            ErrorCode = errorCode;
        }

        public ServiceProtocolException(string errorCode, string message, Exception inner) : base(message, inner)
        {
            ErrorCode = errorCode;
        }
    }

    public static class ServiceWireCodec
    {
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        private static readonly JavaScriptSerializer Serializer = new JavaScriptSerializer
        {
            MaxJsonLength = ServiceProtocol.MaximumFrameBytes,
            RecursionLimit = 80
        };

        public static byte[] Encode(object value)
        {
            if (value == null) throw new ArgumentNullException("value");
            byte[] payload = Utf8.GetBytes(Serializer.Serialize(value));
            if (payload.Length == 0 || payload.Length > ServiceProtocol.MaximumFrameBytes)
                throw new ServiceProtocolException("frame_too_large", "The local service message has an invalid size.");
            return payload;
        }

        public static T Decode<T>(byte[] payload)
        {
            if (payload == null || payload.Length == 0 || payload.Length > ServiceProtocol.MaximumFrameBytes)
                throw new ServiceProtocolException("invalid_frame", "The local service message has an invalid size.");
            try
            {
                T value = Serializer.Deserialize<T>(Utf8.GetString(payload));
                if (value == null) throw new ServiceProtocolException("invalid_frame", "The local service message is empty.");
                return value;
            }
            catch (ServiceProtocolException) { throw; }
            catch (Exception ex)
            {
                throw new ServiceProtocolException("invalid_frame", "The local service message is invalid.", ex);
            }
        }

        public static void WriteFrame(Stream stream, byte[] payload)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            if (payload == null || payload.Length == 0 || payload.Length > ServiceProtocol.MaximumFrameBytes)
                throw new ServiceProtocolException("invalid_frame", "The local service message has an invalid size.");
            byte[] header = BitConverter.GetBytes(payload.Length);
            stream.Write(header, 0, header.Length);
            stream.Write(payload, 0, payload.Length);
            stream.Flush();
        }

        public static byte[] ReadFrame(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            byte[] header = ReadExactly(stream, 4);
            int length = BitConverter.ToInt32(header, 0);
            if (length <= 0 || length > ServiceProtocol.MaximumFrameBytes)
                throw new ServiceProtocolException("invalid_frame", "The local service frame length is invalid.");
            return ReadExactly(stream, length);
        }

        private static byte[] ReadExactly(Stream stream, int count)
        {
            byte[] value = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = stream.Read(value, offset, count - offset);
                if (read <= 0) throw new EndOfStreamException("The local service closed the pipe before the message was complete.");
                offset += read;
            }
            return value;
        }
    }
}
