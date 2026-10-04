using System;
using System.Collections.Generic;
using System.Linq;

namespace HandShake
{
    public static class InstalledUpdateNotice
    {
        // An interrupted notice write must not prevent the UI from starting.
        // The installed version is authoritative; an older notice is ignored.
        public static string ReadCurrentVersion(string path, string installedVersion)
        {
            try
            {
                using (var file = new System.IO.FileStream(path, System.IO.FileMode.Open,
                    System.IO.FileAccess.Read, System.IO.FileShare.Read | System.IO.FileShare.Delete))
                {
                    if (file.Length == 0 || file.Length > 4096) return null;
                    using (var reader = new System.IO.StreamReader(file))
                    {
                        var serializer = new System.Web.Script.Serialization.JavaScriptSerializer {
                            MaxJsonLength = 4096, RecursionLimit = 4
                        };
                        var record = serializer.Deserialize<Dictionary<string, object>>(reader.ReadToEnd());
                        object value;
                        return record != null && record.TryGetValue("version", out value) && value is string &&
                            String.Equals((string)value, installedVersion, StringComparison.Ordinal)
                            ? (string)value : null;
                    }
                }
            }
            catch (System.IO.IOException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
            catch (ArgumentException) { return null; }
            catch (InvalidOperationException) { return null; }
        }
    }

    public static class ServiceDocumentLinks
    {
        public static Uri Get(string document, bool english)
        {
            string path;
            switch (document)
            {
                case "terms": path = "terms/current"; break;
                case "privacy": path = "privacy"; break;
                case "licenses": path = "licenses"; break;
                case "data-deletion": path = "data-deletion"; break;
                default: throw new ArgumentException("Unknown service document.", "document");
            }
            return new Uri("https://handshakevpn.tech/" + path + (english ? "?lang=en" : ""));
        }
    }

    // The file handle is the lifetime lock; an old file after a crash never
    // blocks a new instance. The second launch requests the existing UI to open.
    public sealed class ApplicationInstanceGuard : IDisposable
    {
        private System.IO.FileStream handle;
        private readonly string requestPath;
        public bool Acquired { get { return handle != null; } }
        public ApplicationInstanceGuard(string directory)
        {
            System.IO.Directory.CreateDirectory(directory);
            requestPath = System.IO.Path.Combine(directory, "open-ui.request");
            try
            {
                handle = new System.IO.FileStream(System.IO.Path.Combine(directory, "ui-instance.lock"),
                    System.IO.FileMode.OpenOrCreate, System.IO.FileAccess.ReadWrite, System.IO.FileShare.Read);
                if (System.IO.File.Exists(requestPath)) System.IO.File.Delete(requestPath);
            }
            catch (System.IO.IOException ex)
            {
                int code = ex.HResult & 0xffff;
                if (code != 32 && code != 33) throw;
            }
        }
        public void RequestOpen()
        {
            System.IO.File.WriteAllText(requestPath, "open");
        }
        public bool ConsumeOpenRequest()
        {
            if (!Acquired || !System.IO.File.Exists(requestPath)) return false;
            try { System.IO.File.Delete(requestPath); return true; }
            catch (System.IO.IOException) { return false; }
        }
        public void Dispose()
        {
            if (handle != null) { handle.Dispose(); handle = null; }
        }
    }

    public enum ConnectionState { Disconnected, Connecting, SessionReady, Connected, Error }

    public sealed class Node
    {
        public string Id { get; set; }
        public string CountryCode { get; set; }
        public System.Windows.Media.ImageSource FlagImage { get { return CountryFlags.Get(CountryCode); } }
        public string Country { get; set; }
        public string City { get; set; }
        public string Ip { get; set; }
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public bool HasCoordinates { get; set; }
        public int EstimatedMbps { get; set; }
        public int LatencyMs { get; set; }
        public Node() { LatencyMs = -1; }
        public bool Available { get; set; }
        public string DisplayLabel { get; set; }
        public string Label { get { return Country + " · " + City; } }
    }

    // Replace this adapter with the authenticated control-plane API.
    public interface INodeCatalog { IList<Node> GetNodes(); }
    public sealed class DemoNodeCatalog : INodeCatalog
    {
        public IList<Node> GetNodes()
        {
            return new List<Node> {
                Make("nl", "Нидерланды", "Амстердам", "192.0.2.10", 52.37, 4.90, 240, 24),
                Make("de", "Германия", "Франкфурт", "192.0.2.20", 50.11, 8.68, 190, 16),
                Make("fi", "Финляндия", "Хельсинки", "192.0.2.30", 60.17, 24.94, 160, 38),
                Make("gb", "Великобритания", "Лондон", "198.51.100.10", 51.51, -0.13, 210, 31),
                Make("us", "США", "Нью-Йорк", "198.51.100.20", 40.71, -74.01, 180, 95),
                Make("jp", "Япония", "Токио", "203.0.113.10", 35.68, 139.69, 130, 210),
                Make("sg", "Сингапур", "Сингапур", "203.0.113.20", 1.35, 103.82, 150, 175)
            };
        }
        private static Node Make(string id, string country, string city, string ip, double lat, double lon, int speed, int ping)
        {
            return new Node { Id = id, CountryCode = id.ToUpperInvariant(), Country = country, City = city, DisplayLabel = country + " · " + city, Ip = ip,
                Latitude = lat, Longitude = lon, HasCoordinates = true, EstimatedMbps = speed, LatencyMs = ping, Available = true };
        }
    }

    public sealed class ConnectionController
    {
        public ConnectionState State { get; private set; }
        public Node Selected { get; private set; }
        private int generation;
        public static Node Fastest(IEnumerable<Node> nodes)
        {
            return nodes.Where(n => n.Available).OrderBy(n => n.LatencyMs < 0 ? Int32.MaxValue : n.LatencyMs).FirstOrDefault();
        }
        public void SetSelected(Node node) { if (node != null) Selected = node; }
        public int Begin(Node node)
        {
            generation++;
            Selected = node;
            State = node == null || !node.Available ? ConnectionState.Error : ConnectionState.Connecting;
            return generation;
        }
        public bool Complete(int ticket, bool success)
        {
            if (ticket != generation || State != ConnectionState.Connecting) return false;
            State = success ? ConnectionState.Connected : ConnectionState.Error;
            return true;
        }
        public bool MarkSessionReady(int ticket)
        {
            if (ticket != generation || State != ConnectionState.Connecting) return false;
            State = ConnectionState.SessionReady;
            return true;
        }
        public void Disconnect()
        {
            generation++;
            State = ConnectionState.Disconnected;
            Selected = null;
        }
        public void Fail()
        {
            generation++;
            State = ConnectionState.Error;
        }
    }
}
