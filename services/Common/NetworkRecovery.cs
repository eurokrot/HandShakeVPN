using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Principal;
using System.ServiceProcess;
using System.Windows.Forms;

namespace HandShake.Services
{
    internal static class NetworkRecovery
    {
        // Explicit administrator action, independent of API/key validity.
        // Never stop Node Service or reset unrelated firewall/network settings.
        internal static void Execute()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new InvalidOperationException("Administrator permission is required to restore the network.");
            RequireNoReparsePath(ProductInfo.ProgramDataRoot);
            if (Directory.Exists(ProductInfo.ProgramDataRoot))
                AccessControlGuard.RequireSystemAndAdministratorsOnly(ProductInfo.ProgramDataRoot, true);
            else ProtectedStorage.EnsureDirectory(ProductInfo.ProgramDataRoot);
            string directory = Path.Combine(ProductInfo.ProgramDataRoot, "network-recovery");
            RequireNoReparsePath(directory);
            ProtectedStorage.EnsureDirectory(directory);
            string path = Path.Combine(directory, "recovery.lock");
            RequireNoReparsePath(path);
            // An OS-held file lock also serializes independent recovery EXEs.
            using (FileStream recoveryLock = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
                ExecuteExclusive();
        }

        private static void ExecuteExclusive()
        {
            ServiceController vpn = null;
            bool restart = false;
            try {
                foreach (ServiceController service in ServiceController.GetServices()) {
                    if (service.ServiceName == "HandShakeVpnService") vpn = service;
                    else service.Dispose();
                }
                if (vpn != null) {
                    restart = vpn.Status != ServiceControllerStatus.Stopped;
                    if (vpn.Status == ServiceControllerStatus.StartPending)
                        vpn.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                    if (vpn.Status != ServiceControllerStatus.Stopped) {
                        if (vpn.Status != ServiceControllerStatus.StopPending) vpn.Stop();
                        vpn.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));
                    }
                    vpn.Refresh();
                    if (vpn.Status != ServiceControllerStatus.Stopped)
                        throw new InvalidOperationException("VPN Service did not stop. Protection has been retained.");
                }
                RequireNoPersonalXray();
                RequireNoReparsePath(ProductInfo.ProgramDataRoot);
                RequireNoReparsePath(VpnPaths.DirectoryPath);
                RequireNoReparsePath(VpnPaths.SessionPath);
                foreach (string directory in new[] { ProductInfo.ProgramDataRoot, VpnPaths.DirectoryPath,
                    Path.Combine(ProductInfo.ProgramDataRoot, "firewall") }) {
                    RequireNoReparsePath(directory);
                    if (Directory.Exists(directory)) AccessControlGuard.RequireSystemAndAdministratorsOnly(directory, true);
                }
                string snapshot = Path.Combine(ProductInfo.ProgramDataRoot, "firewall", "vpn-profile-state.json");
                RequireNoReparsePath(snapshot);
                if (File.Exists(snapshot)) AccessControlGuard.RequireSystemAndAdministratorsOnly(snapshot, false);
                ProtectedStorage.WriteTextAtomic(VpnPaths.SessionPath, JsonFile.Serialize(new VpnSessionConfig {
                    enabled = false, sessionId = "network-recovery",
                    expiresAtUtc = DateTime.UtcNow.AddMinutes(5).ToString("o", CultureInfo.InvariantCulture),
                    requireKillSwitch = true, xrayProfileVersion = "26.9.9-mvp1"
                }));
                // Mark disabled BEFORE removing persistent filters, so the next
                // service boot cannot resurrect the old enabled session.
                using (NativeWfp native = new NativeWfp()) native.Remove();
                RunEmbeddedCleanup();
                if (restart && vpn != null) {
                    vpn.Start();
                    vpn.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                }
            } finally { if (vpn != null) vpn.Dispose(); }
        }

        internal static void RequireNoReparsePath(string path)
        {
            for (string current = Path.GetFullPath(path); !String.IsNullOrEmpty(current); current = Path.GetDirectoryName(current)) {
                if ((Directory.Exists(current) || File.Exists(current)) &&
                    (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("A recovery path is redirected; recovery was stopped.");
            }
        }

        private static void RequireNoPersonalXray()
        {
            string installed = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "HandShake VPN", "runtime", "vpn", "xray.exe");
            foreach (Process process in Process.GetProcessesByName("xray")) {
                using (process) {
                    string path;
                    try { if (process.HasExited) continue; path = process.MainModule.FileName; }
                    catch { throw new InvalidOperationException("Could not verify an Xray process. Protection has been retained."); }
                    if (String.Equals(Path.GetFullPath(path), installed, StringComparison.OrdinalIgnoreCase) ||
                        String.Equals(Path.GetFullPath(path), ProductInfo.VpnXrayExecutablePath, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Personal VPN Xray is still running. Protection has been retained.");
                }
            }
        }

        private static void RunEmbeddedCleanup()
        {
            string directory = Path.Combine(ProductInfo.ProgramDataRoot, "network-recovery");
            RequireNoReparsePath(directory);
            ProtectedStorage.EnsureDirectory(directory);
            string helper = Path.Combine(directory, "cleanup-" + Guid.NewGuid().ToString("N") + ".ps1");
            try {
                using (Stream resource = typeof(NetworkRecovery).Assembly.GetManifestResourceStream("network-recovery-firewall.ps1"))
                using (StreamReader reader = new StreamReader(resource))
                    ProtectedStorage.WriteTextAtomic(helper, reader.ReadToEnd());
                string powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
                foreach (string operation in new[] { "RemoveVpn", "VerifyVpnRecovery" }) {
                    ProcessStartInfo start = new ProcessStartInfo(powershell,
                        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + helper + "\" -Operation " + operation);
                    start.UseShellExecute = false;
                    start.CreateNoWindow = true;
                    using (Process process = Process.Start(start)) {
                        if (!process.WaitForExit(45000)) {
                            try { process.Kill(); process.WaitForExit(5000); } catch { }
                            throw new InvalidOperationException("Network recovery timed out; completion is not confirmed.");
                        }
                        if (process.ExitCode != 0)
                            throw new InvalidOperationException("Network recovery could not confirm cleanup (" + operation + "). No global reset was performed.");
                    }
                }
            } finally { if (File.Exists(helper)) File.Delete(helper); }
        }
    }

    internal static class NetworkRecoveryProgram
    {
        [STAThread]
        public static int Main()
        {
            try {
                NetworkRecovery.Execute();
                MessageBox.Show("HandShake personal VPN was disconnected and its network blocking was removed. Node Service was not changed.",
                    "HandShake Network Recovery", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return 0;
            } catch (Exception error) {
                MessageBox.Show("Network recovery is not confirmed.\n\n" + error.Message,
                    "HandShake Network Recovery", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
        }
    }
}
