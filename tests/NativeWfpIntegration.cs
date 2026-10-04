using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using HandShake.Services;

internal static class NativeWfpIntegration
{
    // Keep the isolated listener outside Windows' default ephemeral port range:
    // an active VPN's outbound socket can otherwise reserve this port first.
    private const int Port = 47173;
    private static string Self { get { return System.Reflection.Assembly.GetExecutingAssembly().Location; } }
    private static bool Connect(bool ipv6)
    {
        try
        {
            using (TcpClient client = new TcpClient(ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork))
            { var result = client.BeginConnect(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, Port, null, null);
                if (!result.AsyncWaitHandle.WaitOne(1500)) return false; client.EndConnect(result); return true; }
        }
        catch (SocketException) { return false; }
    }
    private static Process Child(string executable, string args)
    { return Process.Start(new ProcessStartInfo(executable, args) { UseShellExecute = false, CreateNoWindow = true,
        RedirectStandardOutput = true, RedirectStandardError = true }); }
    private static void InstallScopedRules(NativeWfp wfp, string allowed, bool systemOnly = false)
    {
        wfp.Replace(delegate(NativeWfp.Memory m)
        {
            foreach (Guid layer in new[] { NativeWfp.Connect4, NativeWfp.Connect6 })
            {
                string family = layer == NativeWfp.Connect4 ? "v4" : "v6";
                NativeWfp.Condition address = m.Address(layer == NativeWfp.Connect4 ? "127.0.0.1" : "::1");
                NativeWfp.Condition port = m.Numeric(NativeWfp.RemotePort, 2, Port, 0);
                if (systemOnly) wfp.Add(layer, family + "-test-permit", 230, false, true, m, m.Application(allowed), m.SystemAccount(), address, port);
                else wfp.Add(layer, family + "-test-permit", 230, false, true, m, m.Application(allowed), address, port);
                wfp.Add(layer, family + "-test-block", 1, true, true, m, address, port);
            }
        });
    }
    public static int Main(string[] args)
    {
        if (args.Length == 1 && (args[0] == "--client4" || args[0] == "--client6"))
            return Connect(args[0] == "--client6") ? 0 : 7;
        if (args.Length == 2 && args[0] == "--crash-install")
        {
            try {
                using (NativeWfp wfp = new NativeWfp(true)) InstallScopedRules(wfp, args[1]);
                Console.WriteLine("scoped-filters-installed"); Console.Out.Flush();
                Thread.Sleep(20000); return 0;
            } catch (Exception error) { Console.Error.WriteLine(error.ToString()); return 1; }
        }
        string report = Path.Combine(Path.GetDirectoryName(Self), "native-wfp-integration.txt");
        TcpListener v4 = new TcpListener(IPAddress.Loopback, Port);
        TcpListener v6 = new TcpListener(IPAddress.IPv6Loopback, Port);
        string allowed = Path.Combine(Path.GetDirectoryName(Self), "NativeWfpAllowed.exe");
        Process installer = null;
        try
        {
            NativeWfp.OfflineCheck(); File.Copy(Self, allowed, true);
            v4.Start(); v6.Server.DualMode = false; v6.Start();
            using (NativeWfp wfp = new NativeWfp(true))
            {
                wfp.Remove();
                if (!Connect(false) || !Connect(true)) throw new Exception("baseline loopback failed");
                installer = Child(Self, "--crash-install \"" + allowed + "\"");
                bool blocked = false;
                for (int i = 0; i < 30; i++) { if (!Connect(false)) { blocked = true; break; } Thread.Sleep(100); }
                if (!blocked || Connect(true)) throw new Exception("IPv4/IPv6 block failed" +
                    (installer.HasExited ? ": " + installer.StandardError.ReadToEnd() : ""));
                foreach (string family in new[] { "--client4", "--client6" })
                    using (Process process = Child(allowed, family))
                    { if (!process.WaitForExit(4000) || process.ExitCode != 0) throw new Exception("process-specific permit failed " + family); }
                installer.Kill(); installer.WaitForExit(3000);
                if (Connect(false) || Connect(true)) throw new Exception("persistent filters disappeared after crash");
                InstallScopedRules(wfp, allowed, true);
                for (int i = 0; i < 35; i++)
                    if (!wfp.InstalledFiltersPresent()) throw new Exception("Readonly verification changed/missed installed filters");
                foreach (string family in new[] { "--client4", "--client6" })
                    using (Process process = Child(allowed, family))
                    { if (!process.WaitForExit(4000) || process.ExitCode == 0) throw new Exception("ordinary user obtained a SYSTEM-only bypass " + family); }
                // A failed update must leave the previous blocking policy intact.
                try { wfp.Replace(delegate(NativeWfp.Memory m) { throw new InvalidOperationException("injected transaction failure"); }); }
                catch (InvalidOperationException) { }
                if (Connect(false) || Connect(true)) throw new Exception("transaction rollback opened traffic");
                wfp.Remove(); wfp.Remove();
                if (wfp.InstalledFiltersPresent()) throw new Exception("Removed filters were considered intact");
                if (!Connect(false) || !Connect(true)) throw new Exception("cleanup did not restore loopback");
            }
            File.WriteAllText(report, "PASSED: IPv4/IPv6 blocking; separate application permits; SYSTEM-only restriction; persistent filters after abrupt process kill; atomic rollback; idempotent cleanup.\r\n");
            Console.WriteLine("Native WFP integration passed."); return 0;
        }
        catch (Exception ex) { File.WriteAllText(report, "FAILED: " + ex.ToString()); Console.Error.WriteLine(ex.ToString()); return 1; }
        finally
        {
            if (installer != null) { if (!installer.HasExited) installer.Kill(); installer.Dispose(); }
            try { using (NativeWfp cleanup = new NativeWfp(true)) cleanup.Remove(); }
            catch (Exception error) { File.AppendAllText(report, "\r\nCleanup error: " + error.ToString()); }
            v4.Stop(); v6.Stop();
        }
    }
}
