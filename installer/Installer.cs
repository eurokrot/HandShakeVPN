using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace HandShake.Setup
{
    internal static class Product
    {
        internal const string Name = "HandShake VPN";
        internal const string Publisher = "HandShake VPN";
        internal const string VpnServiceName = "HandShakeVpnService";
        internal const string VpnServiceDisplayName = "HandShake VPN Service";
        internal const string NodeServiceName = "HandShakeNodeService";
        internal const string NodeServiceDisplayName = "HandShake Node Service";
        internal const string PayloadResource = "HandShake.Payload.zip";
        internal const string UninstallRegistryKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HandShakeVPN";

        internal static string InstallRoot
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Name); }
        }

        internal static string DataRoot
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Name); }
        }

        internal static string StartMenuRoot
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Programs", Name); }
        }

        internal static string DesktopShortcutPath
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), Name + ".lnk"); }
        }

        internal static string StagingRoot
        {
            get
            {
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "HandShake VPN Installer Staging");
            }
        }
    }

    internal sealed class PayloadManifest
    {
        public string productVersion { get; set; }
        public string xrayVersion { get; set; }
        public string createdUtc { get; set; }
        public List<PayloadFile> files { get; set; }
    }

    internal sealed class PayloadFile
    {
        public string path { get; set; }
        public string sha256 { get; set; }
        public long length { get; set; }
        public string component { get; set; }
    }

    internal sealed class ConsentRecord
    {
        public bool exitConsent { get; set; }
        public string acceptedAtUtc { get; set; }
        public string noticeVersion { get; set; }
        public string installerVersion { get; set; }
    }

    internal sealed class ServiceConfigurationSnapshot
    {
        public string BinaryPath { get; set; }
        public uint StartType { get; set; }
        public string DisplayName { get; set; }
        public string[] Dependencies { get; set; }
        public bool DelayedAutoStart { get; set; }
        public string Description { get; set; }
        public uint FailureResetPeriod { get; set; }
        public string FailureRebootMessage { get; set; }
        public string FailureCommand { get; set; }
        public List<ServiceFailureAction> FailureActions { get; set; }
        public bool FailureActionsOnNonCrashFailures { get; set; }
    }

    internal sealed class ServiceFailureAction
    {
        public int Type { get; set; }
        public uint DelayMilliseconds { get; set; }
    }

    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            try
            {
                if (HasArgument(args, "--self-test"))
                {
                    string result = InstallerEngine.SelfTest();
                    MessageBox.Show(result, Product.Name + " — self-test", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return 0;
                }

                if (HasArgument(args, "--plan"))
                {
                    MessageBox.Show(InstallerEngine.DescribePlan(), Product.Name + " — installation plan", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return 0;
                }

                if (HasArgument(args, "--background-update")) return InstallerEngine.BackgroundUpdate();
                bool uninstall = HasArgument(args, "--uninstall");
                Application.Run(new SetupForm(uninstall));
                return 0;
            }
            catch (Exception ex)
            {
                if (HasArgument(args, "--background-update")) return 1;
                MessageBox.Show("The operation could not be completed.\r\n\r\n" + ex.Message, Product.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
        }

        private static bool HasArgument(IEnumerable<string> args, string expected)
        {
            return args.Any(delegate(string value) { return string.Equals(value, expected, StringComparison.OrdinalIgnoreCase); });
        }
    }

    internal sealed class SetupForm : Form
    {
        private readonly bool uninstall;
        private readonly CheckBox consent;
        private readonly Button action;
        private readonly Button cancel;
        private readonly ProgressBar progress;
        private readonly Label status;

        internal SetupForm(bool uninstallMode)
        {
            uninstall = uninstallMode;
            Text = uninstall ? "Uninstall HandShake VPN" : "Install HandShake VPN";
            Font = new Font("Segoe UI", 9F);
            BackColor = Color.FromArgb(238, 247, 255);
            ForeColor = Color.FromArgb(12, 44, 75);
            ClientSize = new Size(570, uninstall ? 330 : 480);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);

            Label title = new Label();
            title.Text = uninstall ? "Uninstall HandShake VPN" : "Install HandShake VPN";
            title.Font = new Font("Segoe UI Semibold", 18F, FontStyle.Bold);
            title.AutoSize = true;
            title.Location = new Point(28, 25);
            Controls.Add(title);

            Label description = new Label();
            description.AutoSize = false;
            description.Location = new Point(31, 72);
            description.Size = new Size(510, uninstall ? 95 : 115);
            description.Text = uninstall
                ? "The two HandShake services, the application, its shortcuts, configuration, and ProgramData logs will be removed. The uninstaller does not remove system files or files owned by other applications."
                : "HandShake VPN and two independent Windows services will be installed. The services start with Windows. Closing the application window does not stop Node Service.";
            Controls.Add(description);

            consent = new CheckBox();
            consent.AutoSize = false;
            consent.Location = new Point(31, 184);
            consent.Size = new Size(510, 126);
            consent.Text = "I have read and accept the terms of the free P2P version: HandShake VPN and two automatically starting services will be installed, and Node Service may relay other participants' traffic through my public IP, including while the VPN window is closed.";
            consent.CheckedChanged += delegate { action.Enabled = consent.Checked; };
            consent.Visible = !uninstall;
            Controls.Add(consent);

            status = new Label();
            status.AutoSize = false;
            status.Location = new Point(31, uninstall ? 178 : 325);
            status.Size = new Size(510, 43);
            status.Text = uninstall ? "Select Uninstall to continue." : "Personal network credentials are obtained after activation and are not embedded in the installer.";
            Controls.Add(status);

            progress = new ProgressBar();
            progress.Location = new Point(31, uninstall ? 225 : 377);
            progress.Size = new Size(510, 15);
            progress.Style = ProgressBarStyle.Marquee;
            progress.MarqueeAnimationSpeed = 30;
            progress.Visible = false;
            Controls.Add(progress);

            action = new Button();
            action.Text = uninstall ? "Uninstall" : "Install";
            action.Location = new Point(350, uninstall ? 265 : 420);
            action.Size = new Size(90, 32);
            action.Enabled = uninstall;
            action.BackColor = Color.FromArgb(40, 137, 219);
            action.ForeColor = Color.White;
            action.FlatStyle = FlatStyle.Flat;
            action.Click += OnAction;
            Controls.Add(action);

            cancel = new Button();
            cancel.Text = "Cancel";
            cancel.Location = new Point(450, uninstall ? 265 : 420);
            cancel.Size = new Size(90, 32);
            cancel.Click += delegate { Close(); };
            Controls.Add(cancel);

            AcceptButton = action;
            CancelButton = cancel;
        }

        private void OnAction(object sender, EventArgs e)
        {
            if (!uninstall && !consent.Checked) return;
            action.Enabled = false;
            cancel.Enabled = false;
            consent.Enabled = false;
            progress.Visible = true;
            status.Text = uninstall ? "Stopping services and removing HandShake components…" : "Verifying the package and installing components…";
            Refresh();

            try
            {
                if (uninstall) InstallerEngine.Uninstall();
                else InstallerEngine.Install();

                progress.Visible = false;
                status.Text = uninstall
                    ? "HandShake VPN has been removed. Some empty folders may disappear after restart."
                    : "Installation is complete. Open HandShake VPN and enter your activation key.";
                if (!uninstall && !InstallerEngine.LaunchInstalledApplication())
                    status.Text = "Installation is complete. A HandShake VPN desktop shortcut was created, but automatic launch failed.";
                action.Visible = false;
                cancel.Enabled = true;
                cancel.Text = "Close";
            }
            catch (Exception ex)
            {
                progress.Visible = false;
                status.Text = "The operation stopped: " + ex.Message;
                cancel.Enabled = true;
                cancel.Text = "Close";
                MessageBox.Show(ex.ToString(), Product.Name + " — error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    internal static class InstallerEngine
    {
        private static readonly string[] AllowedPayloadFiles =
        {
            "HandShake VPN.exe",
            "client.config",
            "HandShakeVpnService.exe",
            "HandShakeNodeService.exe",
            "Firewall-Policy.ps1",
            @"runtime\vpn\xray.exe",
            @"runtime\vpn\geoip.dat",
            @"runtime\vpn\geosite.dat",
            @"runtime\vpn\wintun.dll",
            @"runtime\node\xray.exe",
            @"runtime\node\geoip.dat",
            @"runtime\node\geosite.dat",
            @"licenses\Xray-core-LICENSE.txt",
            @"licenses\Wintun-LICENSE.txt",
            @"licenses\Xray-core-README.md"
        };

        private static readonly HashSet<string> AllowedPayloadSet =
            new HashSet<string>(AllowedPayloadFiles, StringComparer.OrdinalIgnoreCase);

        private static readonly Dictionary<string, string> PinnedRuntimeSha256 =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { @"runtime\vpn\xray.exe", "43fa465275a8a64ddce4a27c3317ae3e99f0c264fec1962e04c3fadda83adc79" },
                { @"runtime\vpn\geoip.dat", "3cf2236c19063c1c80803368cca5ff589c5033129fdf9ba154230c689b81fc2a" },
                { @"runtime\vpn\geosite.dat", "51211fde21696bbde05d1102f47f586261e98987a3cae23f7dd1cd742c62c2d2" },
                { @"runtime\vpn\wintun.dll", "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce" },
                { @"runtime\node\xray.exe", "43fa465275a8a64ddce4a27c3317ae3e99f0c264fec1962e04c3fadda83adc79" },
                { @"runtime\node\geoip.dat", "3cf2236c19063c1c80803368cca5ff589c5033129fdf9ba154230c689b81fc2a" },
                { @"runtime\node\geosite.dat", "51211fde21696bbde05d1102f47f586261e98987a3cae23f7dd1cd742c62c2d2" },
                { @"licenses\Xray-core-LICENSE.txt", "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5" },
                { @"licenses\Wintun-LICENSE.txt", "183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2" },
                { @"licenses\Xray-core-README.md", "0d098928cf19c756a8c956c0b5ca736b75f9eaff0765fd71c26a3dcb413a3dde" }
            };

        private static readonly HashSet<string> LegacyManagedPayloadSet =
            new HashSet<string>(new[]
            {
                @"xray\xray.exe",
                @"xray\geoip.dat",
                @"xray\geosite.dat",
                @"xray\wintun.dll",
                @"xray\LICENSE",
                @"xray\LICENSE-wintun.txt",
                @"xray\README.md"
            }, StringComparer.OrdinalIgnoreCase);

        private sealed class CoreServiceConfiguration
        {
            public string BinaryPath;
            public uint StartType;
            public string DisplayName;
            public string[] Dependencies;
        }

        private sealed class FailureActionsConfiguration
        {
            public uint ResetPeriod;
            public string RebootMessage;
            public string Command;
            public List<ServiceFailureAction> Actions;
        }

        internal static string DescribePlan()
        {
            return string.Join("\r\n", new[]
            {
                "Application directory: " + Product.InstallRoot,
                "State directory: " + Product.DataRoot,
                "Protected staging directory: " + Product.StagingRoot,
                "Services:",
                " • " + Product.VpnServiceDisplayName + " (automatic start)",
                " • " + Product.NodeServiceDisplayName + " (automatic start)",
                "Shortcuts: all-users Start menu and shared desktop.",
                "The application opens automatically after a successful installation.",
                "",
                "Accepting the terms when obtaining a key also records consent for Node Service participation in the free P2P network.",
                "Shared VLESS/REALITY secrets are not included in the package.",
                "Removal is limited to the listed product directories, shortcuts, and application registration."
            });
        }

        internal static string SelfTest()
        {
            string stage = CreateStageDirectory();
            try
            {
                PayloadManifest manifest = ExtractAndValidatePayload(stage);
                ValidateOwnedRoots();
                return string.Format(CultureInfo.InvariantCulture,
                    "Package version {0} passed verification.\r\nFiles: {1}.\r\nXray: {2}.\r\nPermanent product files and system settings were not changed.",
                    manifest.productVersion, manifest.files.Count, manifest.xrayVersion);
            }
            finally
            {
                TryDeleteStageDirectory(stage);
            }
        }

        private static bool backgroundUpdate;
        private static string verifiedCleanupHelper;
        private static PayloadFile verifiedCleanupManifest;

        internal static int BackgroundUpdate()
        {
            if (!WindowsIdentity.GetCurrent().IsSystem || !File.Exists(Path.Combine(Product.InstallRoot, "HandShakeNodeService.exe")) ||
                !File.Exists(Path.Combine(Product.DataRoot, "installer", "consent.json"))) return 1;
            string updates = Path.Combine(Product.DataRoot, "updates");
            RejectReparsePoint(updates, "update directory");
            string pending = Path.Combine(updates, "pending.json");
            RejectReparsePoint(pending, "update task");
            if (!File.Exists(pending) || new FileInfo(pending).Length > 16384) return 1;
            var serializer = new JavaScriptSerializer();
            var job = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(pending));
            string version = Convert.ToString(job["version"]);
            string hash = Convert.ToString(job["sha256"]);
            long size = Convert.ToInt64(job["sizeBytes"], CultureInfo.InvariantCulture);
            string signature = Convert.ToString(job["signature"]);
            string self = Path.GetFullPath(Application.ExecutablePath);
            if (!string.Equals(self, Path.Combine(updates, hash + ".exe"), StringComparison.OrdinalIgnoreCase) ||
                version != HandShake.Release.ProductRelease.Version || new FileInfo(self).Length != size ||
                !HandShake.Release.ReleaseSecurity.Verify(version, hash, size, signature) || ComputeSha256(self) != hash) return 1;
            backgroundUpdate = true;
            Install();
            return 0;
        }

        internal static void Install()
        {
            RunExclusive(InstallCore);
        }

        private static void RunExclusive(Action operation)
        {
            var security = new MutexSecurity();
            security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), MutexRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), MutexRights.FullControl, AccessControlType.Allow));
            bool created;
            using (var gate = new Mutex(false, @"Global\HandShakeInstallerOperation", out created, security))
            {
                bool acquired = false;
                try
                {
                    try { acquired = gate.WaitOne(0); } catch (AbandonedMutexException) { acquired = true; }
                    if (!acquired) throw new InvalidOperationException("Another HandShake installation or removal is in progress.");
                    operation();
                }
                finally { if (acquired) gate.ReleaseMutex(); }
            }
        }

        private static void InstallCore()
        {
            ValidateOwnedRoots();
            AssertOwnedServiceOrAbsent(Product.VpnServiceName);
            AssertOwnedServiceOrAbsent(Product.NodeServiceName);
            string stage = null;
            string backup = null;
            string dataBackup = null;
            bool backupReady = false;
            bool dataBackupReady = false;
            bool serviceChangesStarted = false;
            bool applicationChangesStarted = false;
            bool dataChangesStarted = false;
            bool preserveStage = false;
            bool hadInstall = Directory.Exists(Product.InstallRoot);
            bool hadData = Directory.Exists(Product.DataRoot);
            bool vpnExisted = ServiceExists(Product.VpnServiceName);
            bool nodeExisted = ServiceExists(Product.NodeServiceName);
            bool vpnWasRunning = IsServiceRunning(Product.VpnServiceName);
            bool nodeWasRunning = IsServiceRunning(Product.NodeServiceName);
            ServiceConfigurationSnapshot vpnServiceSnapshot = vpnExisted
                ? CaptureServiceConfiguration(Product.VpnServiceName) : null;
            ServiceConfigurationSnapshot nodeServiceSnapshot = nodeExisted
                ? CaptureServiceConfiguration(Product.NodeServiceName) : null;

            try
            {
                stage = CreateStageDirectory();
                if (hadInstall) ProtectApplicationDirectory(Product.InstallRoot);
                if (hadData) EnsureProtectedDataDirectories();
                PayloadManifest manifest = ExtractAndValidatePayload(stage);
                verifiedCleanupManifest = manifest.files.Single(file => file.path == "Firewall-Policy.ps1");
                verifiedCleanupHelper = SafeCombine(Path.Combine(stage, "files"), "Firewall-Policy.ps1");
                EnsureApplicationClosed();
                serviceChangesStarted = true;
                StopService(Product.VpnServiceName, true);
                StopService(Product.NodeServiceName, true);
                bool existingFirewallState = hadInstall || vpnExisted || nodeExisted ||
                    Directory.Exists(Path.Combine(Product.DataRoot, "firewall"));
                if (existingFirewallState)
                {
                    CleanupManagedFirewallRole("HandShakeVpnService.exe", "RemoveVpn", true);
                    CleanupManagedFirewallRole("HandShakeNodeService.exe", "RemoveNode", true);
                }

                if (hadInstall)
                {
                    backup = Path.Combine(stage, "install-backup");
                    CopyDirectory(Product.InstallRoot, backup);
                    backupReady = true;
                }
                if (hadData)
                {
                    dataBackup = Path.Combine(stage, "data-backup");
                    CopyDirectory(Product.DataRoot, dataBackup, "updates");
                    dataBackupReady = true;
                }

                dataChangesStarted = true;
                EnsureProtectedDataDirectories();
                Log("Starting install of " + manifest.productVersion + ".");

                applicationChangesStarted = true;
                ProtectApplicationDirectory(Product.InstallRoot);
                CopyPayloadFiles(stage, manifest);
                ProtectRuntimeDirectory(Path.Combine(Product.InstallRoot, "runtime"));
                InstallVerifiedUninstaller();
                WriteInstalledFileList(manifest);
                WriteConsent(manifest.productVersion);

                ConfigureService(Product.VpnServiceName, Product.VpnServiceDisplayName,
                    Path.Combine(Product.InstallRoot, "HandShakeVpnService.exe"),
                    "Manages the personal HandShake VPN session. It does not start an unsafe TUN without a kill switch.");
                ConfigureService(Product.NodeServiceName, Product.NodeServiceDisplayName,
                    Path.Combine(Product.InstallRoot, "HandShakeNodeService.exe"),
                    "Provides a HandShake exit node after acceptance of the free P2P version terms.");

                CreateShortcut();
                WriteUninstallRegistration(manifest.productVersion);
                StartService(Product.VpnServiceName);
                StartService(Product.NodeServiceName);
                if (backgroundUpdate)
                    File.WriteAllText(Path.Combine(Product.InstallRoot, "update-installed.json"),
                        new JavaScriptSerializer().Serialize(new { version = manifest.productVersion, installedAtUtc = DateTime.UtcNow.ToString("o") }));
                Log("Installation completed.");

            }
            catch (Exception installError)
            {
                Log("Installation failed: " + installError.Message + "; rollback started.");
                List<string> rollbackErrors = new List<string>();
                if (serviceChangesStarted)
                {
                    RollbackInstallation(rollbackErrors, backup, dataBackup, backupReady, dataBackupReady,
                        hadInstall, hadData, applicationChangesStarted, dataChangesStarted,
                        vpnExisted, nodeExisted, vpnWasRunning, nodeWasRunning,
                        vpnServiceSnapshot, nodeServiceSnapshot);
                }
                if (rollbackErrors.Count != 0)
                {
                    preserveStage = true;
                    Log("Recovery files preserved at " + stage + ".");
                    throw new InvalidOperationException("Installation failed and rollback did not complete: " +
                        string.Join(" | ", rollbackErrors.ToArray()), installError);
                }
                throw;
            }
            finally
            {
                verifiedCleanupHelper = null; verifiedCleanupManifest = null;
                if (stage != null && !preserveStage) TryDeleteStageDirectory(stage);
            }
        }

        private static void RollbackInstallation(List<string> errors, string backup, string dataBackup,
            bool backupReady, bool dataBackupReady, bool hadInstall, bool hadData,
            bool applicationChangesStarted, bool dataChangesStarted,
            bool vpnExisted, bool nodeExisted, bool vpnWasRunning, bool nodeWasRunning,
            ServiceConfigurationSnapshot vpnSnapshot, ServiceConfigurationSnapshot nodeSnapshot)
        {
            bool vpnPresent = vpnExisted;
            bool nodePresent = nodeExisted;
            bool vpnPresenceKnown = TryRollbackStep(errors, "checking VPN Service", delegate { vpnPresent = ServiceExists(Product.VpnServiceName); });
            bool nodePresenceKnown = TryRollbackStep(errors, "checking Node Service", delegate { nodePresent = ServiceExists(Product.NodeServiceName); });
            bool vpnStopped = TryRollbackStep(errors, "stopping VPN Service", delegate { StopService(Product.VpnServiceName, true); });
            bool nodeStopped = TryRollbackStep(errors, "stopping Node Service", delegate { StopService(Product.NodeServiceName, true); });

            bool rollbackCleanupRequired = vpnExisted || nodeExisted || !vpnPresenceKnown || !nodePresenceKnown ||
                vpnPresent || nodePresent || (hadData && Directory.Exists(Path.Combine(Product.DataRoot, "firewall")));
            bool vpnFirewallClean = true;
            bool nodeFirewallClean = true;
            if (rollbackCleanupRequired)
            {
                vpnFirewallClean = vpnStopped && TryRollbackStep(errors, "cleaning VPN firewall", delegate
                {
                    CleanupManagedFirewallRole("HandShakeVpnService.exe", "RemoveVpn", true);
                });
                if (!vpnStopped) AddRollbackError(errors, "VPN firewall cleanup was skipped because the service did not stop");

                nodeFirewallClean = nodeStopped && TryRollbackStep(errors, "cleaning Node firewall", delegate
                {
                    CleanupManagedFirewallRole("HandShakeNodeService.exe", "RemoveNode", true);
                });
                if (!nodeStopped) AddRollbackError(errors, "Node firewall cleanup was skipped because the service did not stop");
            }

            bool treesSafe = vpnStopped && nodeStopped && vpnFirewallClean && nodeFirewallClean;
            bool applicationRestored = false;
            bool dataRestored = false;
            if (treesSafe)
            {
                applicationRestored = TryRollbackStep(errors, "restoring Program Files", delegate
                {
                    if (backupReady)
                    {
                        if (string.IsNullOrEmpty(backup) || !Directory.Exists(backup))
                            throw new DirectoryNotFoundException("The Program Files backup is missing.");
                        SafeDeleteOwnedDirectory(Product.InstallRoot, Product.InstallRoot);
                        RestoreProtectedApplicationDirectory(backup);
                    }
                    else if (!hadInstall)
                    {
                        SafeDeleteOwnedDirectory(Product.InstallRoot, Product.InstallRoot);
                    }
                });
                dataRestored = TryRollbackStep(errors, "restoring ProgramData", delegate
                {
                    if (dataBackupReady)
                    {
                        if (string.IsNullOrEmpty(dataBackup) || !Directory.Exists(dataBackup))
                            throw new DirectoryNotFoundException("The ProgramData backup is missing.");
                        ClearDataForRollback();
                        RestoreProtectedDataDirectory(dataBackup);
                    }
                    else if (!hadData)
                    {
                        ClearDataForRollback();
                    }
                });
            }
            else
            {
                applicationRestored = !applicationChangesStarted;
                dataRestored = !dataChangesStarted;
                if (applicationChangesStarted || dataChangesStarted)
                    AddRollbackError(errors, "restoring modified files or ProgramData was skipped because services or firewall were not brought to a safe state");
            }

            if (!vpnExisted)
            {
                if (vpnStopped && vpnFirewallClean)
                    TryRollbackStep(errors, "removing the new VPN Service", delegate { DeleteService(Product.VpnServiceName); });
                else AddRollbackError(errors, "removing the new VPN Service was skipped because the role did not stop or firewall was not cleaned");
            }
            if (!nodeExisted)
            {
                if (nodeStopped && nodeFirewallClean)
                    TryRollbackStep(errors, "removing the new Node Service", delegate { DeleteService(Product.NodeServiceName); });
                else AddRollbackError(errors, "removing the new Node Service was skipped because the role did not stop or firewall was not cleaned");
            }

            bool vpnScmRestored = !vpnExisted || TryRollbackStep(errors, "restoring VPN Service SCM configuration", delegate
            {
                RestoreServiceConfiguration(Product.VpnServiceName, vpnSnapshot);
            });
            bool nodeScmRestored = !nodeExisted || TryRollbackStep(errors, "restoring Node Service SCM configuration", delegate
            {
                RestoreServiceConfiguration(Product.NodeServiceName, nodeSnapshot);
            });

            if (vpnWasRunning)
            {
                if (vpnStopped && applicationRestored && dataRestored && vpnScmRestored)
                    TryRollbackStep(errors, "restarting VPN Service", delegate { StartService(Product.VpnServiceName); });
                else if (vpnStopped)
                    AddRollbackError(errors, "restarting VPN Service was skipped because required rollback state was not restored");
            }
            if (nodeWasRunning)
            {
                if (nodeStopped && applicationRestored && dataRestored && nodeScmRestored)
                    TryRollbackStep(errors, "restarting Node Service", delegate { StartService(Product.NodeServiceName); });
                else if (nodeStopped)
                    AddRollbackError(errors, "restarting Node Service was skipped because required rollback state was not restored");
            }
        }

        private static bool TryRollbackStep(List<string> errors, string name, Action action)
        {
            try
            {
                action();
                return true;
            }
            catch (Exception ex)
            {
                AddRollbackError(errors, name + ": " + ex.Message);
                return false;
            }
        }

        private static void AddRollbackError(List<string> errors, string message)
        {
            errors.Add(message);
            Log("Rollback warning: " + message);
        }

        internal static void Uninstall()
        {
            RunExclusive(UninstallCore);
        }

        private static void UninstallCore()
        {
            ValidateOwnedRoots();
            AssertOwnedServiceOrAbsent(Product.VpnServiceName);
            AssertOwnedServiceOrAbsent(Product.NodeServiceName);
            EnsureApplicationClosed();
            Log("Uninstall started.");
            StopService(Product.VpnServiceName, true);
            StopService(Product.NodeServiceName, true);
            bool firewallCleanupRequired = Directory.Exists(Product.InstallRoot) ||
                ServiceExists(Product.VpnServiceName) || ServiceExists(Product.NodeServiceName) ||
                Directory.Exists(Path.Combine(Product.DataRoot, "firewall"));
            if (firewallCleanupRequired)
            {
                CleanupManagedFirewallRole("HandShakeVpnService.exe", "RemoveVpn", true);
                CleanupManagedFirewallRole("HandShakeNodeService.exe", "RemoveNode", true);
            }
            DeleteService(Product.VpnServiceName);
            DeleteService(Product.NodeServiceName);
            DeleteShortcut();
            DeleteUninstallRegistration();

            string self = Path.GetFullPath(Application.ExecutablePath);
            string installedUninstaller = Path.GetFullPath(Path.Combine(Product.InstallRoot, "HandShake VPN Uninstall.exe"));
            if (string.Equals(self, installedUninstaller, StringComparison.OrdinalIgnoreCase))
            {
                DeleteDirectoryContentsExcept(Product.InstallRoot, self);
                if (!MoveFileEx(self, null, MoveFileFlags.DelayUntilReboot))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not schedule uninstaller removal.");
                if (!MoveFileEx(Product.InstallRoot, null, MoveFileFlags.DelayUntilReboot))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not schedule application directory removal.");
            }
            else
            {
                SafeDeleteOwnedDirectory(Product.InstallRoot, Product.InstallRoot);
            }

            SafeDeleteOwnedDirectory(Product.DataRoot, Product.DataRoot);
            SafeDeleteOwnedDirectory(Product.StagingRoot, Product.StagingRoot);
        }

        private static void ValidateOwnedRoots()
        {
            string programFiles = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string commonData = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string install = Path.GetFullPath(Product.InstallRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string data = Path.GetFullPath(Product.DataRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string staging = Path.GetFullPath(Product.StagingRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!install.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase) ||
                !data.StartsWith(commonData, StringComparison.OrdinalIgnoreCase) ||
                !staging.StartsWith(commonData, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Installation directories failed safety validation.");
            if (!string.Equals(new DirectoryInfo(Product.InstallRoot).Name, Product.Name, StringComparison.Ordinal) ||
                !string.Equals(new DirectoryInfo(Product.DataRoot).Name, Product.Name, StringComparison.Ordinal) ||
                !string.Equals(new DirectoryInfo(Product.StagingRoot).Name, "HandShake VPN Installer Staging", StringComparison.Ordinal))
                throw new InvalidOperationException("Unexpected product directory name.");
            RejectReparsePoint(Product.InstallRoot, "application directory");
            RejectReparsePoint(Product.DataRoot, "data directory");
            RejectReparsePoint(Product.StagingRoot, "staging directory");
        }

        private static string CreateStageDirectory()
        {
            ValidateOwnedRoots();
            string root = Product.StagingRoot;
            ProtectRuntimeDirectory(root);
            string stage = Path.Combine(root, Guid.NewGuid().ToString("N"));
            ProtectRuntimeDirectory(stage);
            return stage;
        }

        private static PayloadManifest ExtractAndValidatePayload(string stage)
        {
            Stream resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(Product.PayloadResource);
            if (resource == null) throw new InvalidDataException("The installer component package is missing.");
            using (resource)
            using (ZipArchive archive = new ZipArchive(resource, ZipArchiveMode.Read, false))
            {
                long extractedLength = 0;
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string relative = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
                    if (string.IsNullOrEmpty(relative)) continue;
                    bool directoryEntry = entry.FullName.EndsWith("/", StringComparison.Ordinal);
                    if (directoryEntry)
                    {
                        if (!IsAllowedArchiveDirectory(relative))
                            throw new InvalidDataException("The package contains an unexpected directory: " + entry.FullName);
                        continue;
                    }
                    if (!IsAllowedArchiveFile(relative))
                        throw new InvalidDataException("The package contains a file outside the allowlist: " + entry.FullName);
                    if (entry.Length < 0 || entry.Length > 256L * 1024L * 1024L)
                        throw new InvalidDataException("A package file exceeds the allowed size: " + entry.FullName);
                    extractedLength = checked(extractedLength + entry.Length);
                    if (extractedLength > 1024L * 1024L * 1024L)
                        throw new InvalidDataException("The total extracted size exceeds the allowed limit.");
                    string destination = SafeCombine(stage, relative);
                    string parent = Path.GetDirectoryName(destination);
                    if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                    using (Stream input = entry.Open())
                    using (FileStream output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None)) input.CopyTo(output);
                }
            }

            string manifestPath = Path.Combine(stage, "payload-manifest.json");
            if (!File.Exists(manifestPath)) throw new InvalidDataException("The package manifest is missing.");
            if (new FileInfo(manifestPath).Length > 1024L * 1024L) throw new InvalidDataException("The package manifest is too large.");
            PayloadManifest manifest = new JavaScriptSerializer().Deserialize<PayloadManifest>(File.ReadAllText(manifestPath, Encoding.UTF8));
            if (manifest == null || manifest.files == null || manifest.files.Count == 0) throw new InvalidDataException("The package manifest is empty.");
            if (string.IsNullOrWhiteSpace(manifest.productVersion) || string.IsNullOrWhiteSpace(manifest.xrayVersion))
                throw new InvalidDataException("The package manifest does not include the product or Xray version.");
            if (!string.Equals(manifest.productVersion, HandShake.Release.ProductRelease.Version, StringComparison.Ordinal))
                throw new InvalidDataException("Installer and product release versions do not match.");
            if (!string.Equals(manifest.xrayVersion, "26.9.30", StringComparison.Ordinal))
                throw new InvalidDataException("The package Xray version does not match the pinned version.");

            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (PayloadFile file in manifest.files)
            {
                if (file == null) throw new InvalidDataException("The package manifest contains an empty file entry.");
                string relative = NormalizeRelativePath(file.path);
                if (!seen.Add(relative)) throw new InvalidDataException("Duplicate path in the manifest: " + relative);
                if (!AllowedPayloadSet.Contains(relative))
                    throw new InvalidDataException("The manifest contains a file outside the allowlist: " + relative);
                if (file.length < 0) throw new InvalidDataException("The manifest contains a negative file size: " + relative);
                string pinnedSha256;
                if (PinnedRuntimeSha256.TryGetValue(relative, out pinnedSha256) &&
                    !string.Equals(file.sha256, pinnedSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("A pinned runtime file has an unexpected SHA-256 hash: " + relative);
                string source = SafeCombine(Path.Combine(stage, "files"), relative);
                if (!File.Exists(source)) throw new FileNotFoundException("A manifest file is missing.", relative);
                VerifyFile(source, file.length, file.sha256);
            }

            if (!seen.SetEquals(AllowedPayloadSet))
            {
                string missing = AllowedPayloadFiles.FirstOrDefault(delegate(string required) { return !seen.Contains(required); });
                throw new InvalidDataException("The package contents do not match the allowlist" +
                    (missing == null ? "." : ": missing " + missing));
            }

            return manifest;
        }

        private static void CopyPayloadFiles(string stage, PayloadManifest manifest)
        {
            HashSet<string> newFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (PayloadFile file in manifest.files)
            {
                string relative = NormalizeRelativePath(file.path);
                string source = SafeCombine(Path.Combine(stage, "files"), relative);
                string destination = SafeCombine(Product.InstallRoot, relative);
                string parent = Path.GetDirectoryName(destination);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                CopyAndVerifyFile(source, destination, file.length, file.sha256);
                newFiles.Add(relative);
            }

            string priorList = Path.Combine(Product.DataRoot, "installer", "installed-files.txt");
            if (File.Exists(priorList))
            {
                foreach (string old in File.ReadAllLines(priorList, Encoding.UTF8))
                {
                    if (string.IsNullOrWhiteSpace(old) || newFiles.Contains(old)) continue;
                    string normalizedOld = NormalizeRelativePath(old);
                    if (!AllowedPayloadSet.Contains(normalizedOld) && !LegacyManagedPayloadSet.Contains(normalizedOld))
                        throw new InvalidDataException("The previous installed-file list contains an unexpected path: " + normalizedOld);
                    string obsolete = SafeCombine(Product.InstallRoot, normalizedOld);
                    if (File.Exists(obsolete))
                    {
                        RejectOwnedDestinationReparsePoints(obsolete);
                        RejectReparsePoint(obsolete, "obsolete application file");
                        File.Delete(obsolete);
                    }
                }
            }
        }

        private static void WriteInstalledFileList(PayloadManifest manifest)
        {
            string directory = Path.Combine(Product.DataRoot, "installer");
            Directory.CreateDirectory(directory);
            File.WriteAllLines(Path.Combine(directory, "installed-files.txt"),
                manifest.files.Select(delegate(PayloadFile item) { return NormalizeRelativePath(item.path); }).OrderBy(delegate(string item) { return item; }).ToArray(), Encoding.UTF8);
        }

        private static void WriteConsent(string installerVersion)
        {
            string nodeDirectory = Path.Combine(Product.DataRoot, "node");
            string vpnDirectory = Path.Combine(Product.DataRoot, "vpn");
            Directory.CreateDirectory(nodeDirectory);
            Directory.CreateDirectory(vpnDirectory);
            ProtectRuntimeDirectory(nodeDirectory);
            ProtectRuntimeDirectory(vpnDirectory);
            string consentPath = Path.Combine(nodeDirectory, "node-service.json");
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            Dictionary<string, object> nodeConfiguration = CreateDefaultNodeConfiguration();
            HashSet<string> allowedKeys = new HashSet<string>(nodeConfiguration.Keys, StringComparer.OrdinalIgnoreCase);
            if (File.Exists(consentPath))
            {
                try
                {
                    Dictionary<string, object> existing = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(consentPath, Encoding.UTF8));
                    if (existing != null)
                    {
                        foreach (KeyValuePair<string, object> item in existing)
                        {
                            if (allowedKeys.Contains(item.Key)) nodeConfiguration[item.Key] = item.Value;
                        }
                    }
                }
                catch (Exception ex)
                {
                    throw new InvalidDataException("The existing Node Service configuration is damaged and was not overwritten.", ex);
                }
            }

            nodeConfiguration["xrayExecutableSha256"] = ComputeSha256(Path.Combine(Product.InstallRoot, @"runtime\node\xray.exe"));
            // Fresh installs use the fail-closed defaults below. During an in-place
            // upgrade, keep an existing server-verified enrollment so the background
            // node does not silently stop when only the application binaries change.
            // The service validates the protected enrollment and encrypted device token
            // before it can start Xray or advertise availability.
            string temporary = consentPath + ".new";
            File.WriteAllText(temporary, serializer.Serialize(nodeConfiguration), new UTF8Encoding(false));
            if (File.Exists(consentPath)) File.Replace(temporary, consentPath, consentPath + ".previous", true);
            else File.Move(temporary, consentPath);

            string installerDirectory = Path.Combine(Product.DataRoot, "installer");
            Directory.CreateDirectory(installerDirectory);
            ConsentRecord record = new ConsentRecord
            {
                exitConsent = false,
                acceptedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture),
                noticeVersion = "closed-test-2026-10-01",
                installerVersion = installerVersion
            };
            File.WriteAllText(Path.Combine(installerDirectory, "consent.json"), serializer.Serialize(record), new UTF8Encoding(false));
        }

        private static Dictionary<string, object> CreateDefaultNodeConfiguration()
        {
            return new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                { "apiBaseUrl", ReadApiBaseUrl() },
                { "allowInsecureLoopbackForDevelopment", false },
                { "exitConsent", false },
                { "exitConsentVersion", null },
                { "exitConsentAcceptedAtUtc", null },
                { "credentialExpiresAtUtc", null },
                { "nodeId", null },
                { "credentialVersion", 0 },
                { "available", false },
                { "heartbeatIntervalSeconds", 60 },
                { "controlPlaneGraceSeconds", 300 },
                { "countryCode", null },
                { "country", null },
                { "city", null },
                { "endpointPort", null },
                { "connectionMode", "reverse_relay" },
                { "estimatedMbps", null },
                { "latencyMs", null },
                { "xrayProfileVersion", "26.9.9-mvp1" },
                { "xrayExecutableSha256", null }
            };
        }

        private static string ReadApiBaseUrl()
        {
            string path = Path.Combine(Product.InstallRoot, "client.config");
            if (!File.Exists(path)) throw new FileNotFoundException("The API address configuration was not found.", path);
            foreach (string raw in File.ReadAllLines(path, Encoding.UTF8))
            {
                string line = raw.Trim();
                if (line.StartsWith("ApiBaseUrl=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = line.Substring("ApiBaseUrl=".Length).Trim();
                    Uri uri;
                    if (!Uri.TryCreate(value, UriKind.Absolute, out uri) ||
                        (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)))
                        throw new InvalidDataException("ApiBaseUrl must use HTTPS; HTTP is allowed only for loopback development.");
                    return uri.AbsoluteUri;
                }
            }
            throw new InvalidDataException("client.config does not contain ApiBaseUrl.");
        }

        private static void EnsureProtectedDataDirectories()
        {
            ProtectRuntimeDirectory(Product.DataRoot);
            foreach (string child in new[] { "node", "vpn", "firewall", "installer" })
            {
                string path = Path.Combine(Product.DataRoot, child);
                ProtectRuntimeDirectory(path);
            }
        }

        private static void RestoreProtectedDataDirectory(string backup)
        {
            RejectReparsePoint(backup, "ProgramData backup");
            ProtectRuntimeDirectory(Product.DataRoot);
            CopyDirectory(backup, Product.DataRoot);
            EnsureProtectedDataDirectories();
        }

        private static void RestoreProtectedApplicationDirectory(string backup)
        {
            RejectReparsePoint(backup, "application backup");
            ProtectApplicationDirectory(Product.InstallRoot);
            CopyDirectory(backup, Product.InstallRoot);
            ProtectApplicationDirectory(Product.InstallRoot);
        }

        private static void ProtectApplicationDirectory(string path)
        {
            SecurityIdentifier system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            SecurityIdentifier users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            DirectorySecurity security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(administrators);
            security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(administrators, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute, inheritance, PropagationFlags.None, AccessControlType.Allow));
            DirectoryInfo directory = new DirectoryInfo(path);
            if (directory.Exists) RejectReparsePoint(path, "application directory");
            directory.Create(security);
            directory.Refresh();
            RejectReparsePoint(path, "application directory");
            directory.SetAccessControl(security);
            RejectReparsePoint(path, "protected application directory");
        }

        private static void ProtectRuntimeDirectory(string path)
        {
            SecurityIdentifier system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            DirectorySecurity security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(administrators);
            security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(administrators, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            DirectoryInfo directory = new DirectoryInfo(path);
            if (directory.Exists) RejectReparsePoint(path, "directory being protected");
            directory.Create(security);
            directory.Refresh();
            RejectReparsePoint(path, "directory being protected");
            directory.SetAccessControl(security);
            RejectReparsePoint(path, "protected directory");
        }

        private static void RejectReparsePoint(string path, string description)
        {
            if (!Directory.Exists(path) && !File.Exists(path)) return;
            FileAttributes attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("An unsupported reparse point was detected: " + description + ".");
        }

        private static void InstallVerifiedUninstaller()
        {
            string source = Path.GetFullPath(Application.ExecutablePath);
            string destination = Path.GetFullPath(Path.Combine(Product.InstallRoot, "HandShake VPN Uninstall.exe"));
            if (string.Equals(source, destination, StringComparison.OrdinalIgnoreCase))
            {
                RejectReparsePoint(destination, "uninstaller");
                return;
            }

            CopyAndVerifyFile(source, destination);
        }

        private static void EnsureApplicationClosed()
        {
            Process current = Process.GetCurrentProcess();
            List<Process> applications = new List<Process>();
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    if (process.Id == current.Id) { process.Dispose(); continue; }
                    string path = process.MainModule == null ? null : process.MainModule.FileName;
                    if (path != null && string.Equals(Path.GetFullPath(path), Path.Combine(Product.InstallRoot, "HandShake VPN.exe"), StringComparison.OrdinalIgnoreCase))
                        applications.Add(process);
                    else process.Dispose();
                }
                catch (System.ComponentModel.Win32Exception) { process.Dispose(); }
                catch { process.Dispose(); }
            }
            if (backgroundUpdate && applications.Count != 0)
            {
                foreach (Process process in applications) process.Dispose();
                throw new InvalidOperationException("Waiting for the HandShake VPN application to close.");
            }
            foreach (Process process in applications)
            {
                try { process.CloseMainWindow(); }
                catch { }
            }
            foreach (Process process in applications)
            {
                try
                {
                    if (!process.WaitForExit(3000))
                    {
                        // The desktop client normally remains in the tray when its window
                        // is closed. The executable path was verified above, so stop only
                        // that GUI process while leaving both Windows services running.
                        process.Kill();
                        if (!process.WaitForExit(5000))
                            throw new InvalidOperationException("HandShake VPN did not close for the update.");
                    }
                }
                finally { process.Dispose(); }
            }
        }

        private static void ConfigureService(string name, string displayName, string executable, string description)
        {
            if (!File.Exists(executable)) throw new FileNotFoundException("The service executable was not found.", executable);
            AssertOwnedServiceOrAbsent(name);
            ConfigureServiceBinaryPath(name, displayName, executable);
            RunSc("config " + name + " start= delayed-auto", false);
            RunSc("config " + name + " depend= MpsSvc", false);
            RunSc("description " + name + " " + Quote(description), false);
            RunSc("failure " + name + " reset= 86400 actions= restart/5000/restart/15000/restart/60000", false);
            RunSc("failureflag " + name + " 1", false);
            AssertOwnedServiceOrAbsent(name);
        }

        private static ServiceConfigurationSnapshot CaptureServiceConfiguration(string name)
        {
            AssertOwnedServiceOrAbsent(name);
            const uint ScManagerConnect = 0x0001;
            const uint ServiceQueryConfig = 0x0001;
            IntPtr manager = OpenSCManager(null, null, ScManagerConnect);
            if (manager == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not open Service Control Manager to back up configuration.");
            IntPtr service = IntPtr.Zero;
            try
            {
                service = OpenService(manager, name, ServiceQueryConfig);
                if (service == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not read configuration for service " + name + ".");

                CoreServiceConfiguration core = QueryCoreServiceConfiguration(service, name);
                string description = QueryServiceDescription(service, name);
                FailureActionsConfiguration failure = QueryServiceFailureActions(service, name);
                ServiceDelayedAutoStartNative delayed = QueryServiceConfig2Structure<ServiceDelayedAutoStartNative>(service, 3, name);
                ServiceFailureActionsFlagNative failureFlag = QueryServiceConfig2Structure<ServiceFailureActionsFlagNative>(service, 4, name);

                return new ServiceConfigurationSnapshot
                {
                    BinaryPath = core.BinaryPath,
                    StartType = core.StartType,
                    DisplayName = core.DisplayName,
                    Dependencies = core.Dependencies,
                    DelayedAutoStart = delayed.DelayedAutoStart,
                    Description = description,
                    FailureResetPeriod = failure.ResetPeriod,
                    FailureRebootMessage = failure.RebootMessage,
                    FailureCommand = failure.Command,
                    FailureActions = failure.Actions,
                    FailureActionsOnNonCrashFailures = failureFlag.Enabled
                };
            }
            finally
            {
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                CloseServiceHandle(manager);
            }
        }

        private static CoreServiceConfiguration QueryCoreServiceConfiguration(IntPtr service, string name)
        {
            uint required;
            QueryServiceConfig(service, IntPtr.Zero, 0, out required);
            if (required == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not determine configuration size for service " + name + ".");
            IntPtr buffer = Marshal.AllocHGlobal(checked((int)required));
            try
            {
                if (!QueryServiceConfig(service, buffer, required, out required))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not read configuration for service " + name + ".");
                QueryServiceConfigNative native = (QueryServiceConfigNative)Marshal.PtrToStructure(buffer, typeof(QueryServiceConfigNative));
                return new CoreServiceConfiguration
                {
                    BinaryPath = Marshal.PtrToStringUni(native.BinaryPathName),
                    StartType = native.StartType,
                    DisplayName = Marshal.PtrToStringUni(native.DisplayName),
                    Dependencies = ReadMultiString(native.Dependencies)
                };
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string QueryServiceDescription(IntPtr service, string name)
        {
            uint required;
            QueryServiceConfig2(service, 1, IntPtr.Zero, 0, out required);
            if (required == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not determine description size for service " + name + ".");
            IntPtr buffer = Marshal.AllocHGlobal(checked((int)required));
            try
            {
                if (!QueryServiceConfig2(service, 1, buffer, required, out required))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not read the description of service " + name + ".");
                ServiceDescriptionNative native = (ServiceDescriptionNative)Marshal.PtrToStructure(buffer, typeof(ServiceDescriptionNative));
                return Marshal.PtrToStringUni(native.Description);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static FailureActionsConfiguration QueryServiceFailureActions(IntPtr service, string name)
        {
            uint required;
            QueryServiceConfig2(service, 2, IntPtr.Zero, 0, out required);
            if (required == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not determine recovery-action size for service " + name + ".");
            IntPtr buffer = Marshal.AllocHGlobal(checked((int)required));
            try
            {
                if (!QueryServiceConfig2(service, 2, buffer, required, out required))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not read recovery actions for service " + name + ".");
                ServiceFailureActionsNative native = (ServiceFailureActionsNative)Marshal.PtrToStructure(buffer, typeof(ServiceFailureActionsNative));
                List<ServiceFailureAction> actions = new List<ServiceFailureAction>();
                int actionSize = Marshal.SizeOf(typeof(ServiceFailureActionNative));
                for (uint index = 0; index < native.ActionCount; index++)
                {
                    IntPtr actionPointer = new IntPtr(native.Actions.ToInt64() + ((long)index * actionSize));
                    ServiceFailureActionNative action = (ServiceFailureActionNative)Marshal.PtrToStructure(actionPointer, typeof(ServiceFailureActionNative));
                    actions.Add(new ServiceFailureAction { Type = action.Type, DelayMilliseconds = action.DelayMilliseconds });
                }
                return new FailureActionsConfiguration
                {
                    ResetPeriod = native.ResetPeriod,
                    RebootMessage = Marshal.PtrToStringUni(native.RebootMessage),
                    Command = Marshal.PtrToStringUni(native.Command),
                    Actions = actions
                };
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static T QueryServiceConfig2Structure<T>(IntPtr service, uint informationLevel, string name) where T : struct
        {
            uint required;
            QueryServiceConfig2(service, informationLevel, IntPtr.Zero, 0, out required);
            if (required == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not determine extended configuration size for service " + name + ".");
            IntPtr buffer = Marshal.AllocHGlobal(checked((int)required));
            try
            {
                if (!QueryServiceConfig2(service, informationLevel, buffer, required, out required))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not read extended configuration for service " + name + ".");
                return (T)Marshal.PtrToStructure(buffer, typeof(T));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string[] ReadMultiString(IntPtr value)
        {
            if (value == IntPtr.Zero) return new string[0];
            List<string> entries = new List<string>();
            IntPtr current = value;
            while (true)
            {
                string entry = Marshal.PtrToStringUni(current);
                if (string.IsNullOrEmpty(entry)) break;
                entries.Add(entry);
                current = new IntPtr(current.ToInt64() + ((entry.Length + 1L) * 2L));
            }
            return entries.ToArray();
        }

        private static void RestoreServiceConfiguration(string name, ServiceConfigurationSnapshot snapshot)
        {
            if (snapshot == null) throw new InvalidOperationException("The service configuration backup is missing for " + name + ".");
            AssertOwnedServiceOrAbsent(name);
            const uint ScManagerConnect = 0x0001;
            const uint ServiceChangeConfig = 0x0002;
            const uint ServiceStart = 0x0010;
            const uint ServiceNoChange = 0xFFFFFFFF;
            IntPtr manager = OpenSCManager(null, null, ScManagerConnect);
            if (manager == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not open Service Control Manager for rollback.");
            IntPtr service = IntPtr.Zero;
            IntPtr dependencies = IntPtr.Zero;
            try
            {
                // SC_ACTION_RESTART restoration also requires SERVICE_START.
                service = OpenService(manager, name, ServiceChangeConfig | ServiceStart);
                if (service == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not open service " + name + " for rollback.");
                dependencies = AllocateMultiString(snapshot.Dependencies);
                bool changed = ChangeServiceConfigWithDependencyPointer(service, ServiceNoChange, snapshot.StartType,
                    ServiceNoChange, snapshot.BinaryPath, null, IntPtr.Zero, dependencies, null, null, snapshot.DisplayName);
                if (!changed) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not restore core configuration for service " + name + ".");

                ChangeServiceConfig2Structure(service, 3,
                    new ServiceDelayedAutoStartNative { DelayedAutoStart = snapshot.DelayedAutoStart }, name);
                RestoreServiceDescription(service, snapshot.Description, name);
                RestoreServiceFailureActions(service, snapshot, name);
                ChangeServiceConfig2Structure(service, 4,
                    new ServiceFailureActionsFlagNative { Enabled = snapshot.FailureActionsOnNonCrashFailures }, name);
                AssertOwnedServiceOrAbsent(name);
            }
            finally
            {
                if (dependencies != IntPtr.Zero) Marshal.FreeHGlobal(dependencies);
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                CloseServiceHandle(manager);
            }
        }

        private static IntPtr AllocateMultiString(string[] entries)
        {
            string[] safeEntries = entries ?? new string[0];
            foreach (string entry in safeEntries)
            {
                if (string.IsNullOrEmpty(entry) || entry.IndexOf('\0') >= 0)
                    throw new InvalidOperationException("The service dependency backup is damaged.");
            }
            string value = safeEntries.Length == 0 ? "\0" : string.Join("\0", safeEntries) + "\0";
            return Marshal.StringToHGlobalUni(value);
        }

        private static void ChangeServiceConfig2Structure<T>(IntPtr service, uint informationLevel, T value, string name) where T : struct
        {
            IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
            try
            {
                Marshal.StructureToPtr(value, buffer, false);
                if (!ChangeServiceConfig2(service, informationLevel, buffer))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not restore extended configuration for service " + name + ".");
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static void RestoreServiceDescription(IntPtr service, string description, string name)
        {
            IntPtr text = IntPtr.Zero;
            try
            {
                if (description != null) text = Marshal.StringToHGlobalUni(description);
                ChangeServiceConfig2Structure(service, 1, new ServiceDescriptionNative { Description = text }, name);
            }
            finally
            {
                if (text != IntPtr.Zero) Marshal.FreeHGlobal(text);
            }
        }

        private static void RestoreServiceFailureActions(IntPtr service, ServiceConfigurationSnapshot snapshot, string name)
        {
            IntPtr actions = IntPtr.Zero;
            IntPtr rebootMessage = IntPtr.Zero;
            IntPtr command = IntPtr.Zero;
            IntPtr structure = IntPtr.Zero;
            try
            {
                List<ServiceFailureAction> sourceActions = snapshot.FailureActions ?? new List<ServiceFailureAction>();
                int actionSize = Marshal.SizeOf(typeof(ServiceFailureActionNative));
                if (sourceActions.Count != 0)
                {
                    actions = Marshal.AllocHGlobal(checked(actionSize * sourceActions.Count));
                    for (int index = 0; index < sourceActions.Count; index++)
                    {
                        ServiceFailureActionNative action = new ServiceFailureActionNative
                        {
                            Type = sourceActions[index].Type,
                            DelayMilliseconds = sourceActions[index].DelayMilliseconds
                        };
                        Marshal.StructureToPtr(action, new IntPtr(actions.ToInt64() + ((long)index * actionSize)), false);
                    }
                }
                if (snapshot.FailureRebootMessage != null) rebootMessage = Marshal.StringToHGlobalUni(snapshot.FailureRebootMessage);
                if (snapshot.FailureCommand != null) command = Marshal.StringToHGlobalUni(snapshot.FailureCommand);
                ServiceFailureActionsNative failure = new ServiceFailureActionsNative
                {
                    ResetPeriod = snapshot.FailureResetPeriod,
                    RebootMessage = rebootMessage,
                    Command = command,
                    ActionCount = checked((uint)sourceActions.Count),
                    Actions = actions
                };
                structure = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ServiceFailureActionsNative)));
                Marshal.StructureToPtr(failure, structure, false);
                if (!ChangeServiceConfig2(service, 2, structure))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not restore recovery actions for service " + name + ".");
            }
            finally
            {
                if (structure != IntPtr.Zero) Marshal.FreeHGlobal(structure);
                if (command != IntPtr.Zero) Marshal.FreeHGlobal(command);
                if (rebootMessage != IntPtr.Zero) Marshal.FreeHGlobal(rebootMessage);
                if (actions != IntPtr.Zero) Marshal.FreeHGlobal(actions);
            }
        }

        private static void CleanupManagedFirewallRole(string serviceBinaryName, string helperOperation, bool required)
        {
            bool knownPair =
                (string.Equals(serviceBinaryName, "HandShakeVpnService.exe", StringComparison.Ordinal) &&
                 string.Equals(helperOperation, "RemoveVpn", StringComparison.Ordinal)) ||
                (string.Equals(serviceBinaryName, "HandShakeNodeService.exe", StringComparison.Ordinal) &&
                 string.Equals(helperOperation, "RemoveNode", StringComparison.Ordinal));
            if (!knownPair) throw new InvalidOperationException("Unknown firewall cleanup role.");

            if (helperOperation == "RemoveVpn")
                HandShake.Release.WfpCleanup.RemoveOwned(HandShake.Release.WfpCleanup.ProviderKey);

            string serviceBinary = Path.GetFullPath(Path.Combine(Product.InstallRoot, serviceBinaryName));
            if (File.Exists(serviceBinary))
            {
                RejectOwnedDestinationReparsePoints(serviceBinary);
                RejectReparsePoint(serviceBinary, "service used for firewall cleanup");
                if (TryRunManagedProcess(serviceBinary, "--firewall-cleanup")) return;
            }

            string helper = Path.GetFullPath(Path.Combine(Product.InstallRoot, "Firewall-Policy.ps1"));
            if (File.Exists(helper))
            {
                RejectOwnedDestinationReparsePoints(helper);
                RejectReparsePoint(helper, "firewall cleanup script");
                string powershell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
                string planPath = Path.Combine(Product.DataRoot, @"firewall\unused-plan.json");
                string arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File " +
                    QuoteFixedArgument(helper) + " -Operation " + helperOperation + " -PlanPath " + QuoteFixedArgument(planPath);
                if (TryRunManagedProcess(powershell, arguments)) return;
            }

            // A failed old upgrade may have removed its cleanup script. Use only
            // the SHA-256-verified script from this installer's protected stage.
            if (verifiedCleanupHelper != null && verifiedCleanupManifest != null)
            {
                RejectReparsePoint(verifiedCleanupHelper, "verified staged cleanup script");
                VerifyFile(verifiedCleanupHelper, verifiedCleanupManifest.length, verifiedCleanupManifest.sha256);
                string powershell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
                if (TryRunManagedProcess(powershell, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File " +
                    QuoteFixedArgument(verifiedCleanupHelper) + " -Operation " + helperOperation)) return;
            }

            if (required)
                throw new InvalidOperationException("Could not safely remove managed firewall rules for role " + helperOperation + ". The operation stopped before file removal.");
        }

        private static bool TryRunManagedProcess(string executable, string arguments)
        {
            ProcessStartInfo info = new ProcessStartInfo(executable, arguments);
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            try
            {
                using (Process process = Process.Start(info))
                {
                    if (process == null) return false;
                    if (!process.WaitForExit(30000))
                    {
                        try
                        {
                            process.Kill();
                            process.WaitForExit(5000);
                        }
                        catch { }
                        return false;
                    }
                    return process.ExitCode == 0;
                }
            }
            catch
            {
                return false;
            }
        }

        private static string QuoteFixedArgument(string value)
        {
            if (string.IsNullOrEmpty(value) || value.IndexOf('"') >= 0 || value.IndexOf('\r') >= 0 || value.IndexOf('\n') >= 0)
                throw new InvalidOperationException("Invalid fixed process argument.");
            return "\"" + value + "\"";
        }

        private static bool ServiceExists(string name)
        {
            return ServiceController.GetServices().Any(delegate(ServiceController service) { return string.Equals(service.ServiceName, name, StringComparison.OrdinalIgnoreCase); });
        }

        private static bool IsServiceRunning(string name)
        {
            if (!ServiceExists(name)) return false;
            using (ServiceController service = new ServiceController(name)) return service.Status == ServiceControllerStatus.Running;
        }

        private static void StartService(string name)
        {
            if (!ServiceExists(name)) return;
            AssertOwnedServiceOrAbsent(name);
            using (ServiceController service = new ServiceController(name))
            {
                service.Refresh();
                if (service.Status == ServiceControllerStatus.Running || service.Status == ServiceControllerStatus.StartPending) return;
                service.Start();
                service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            }
        }

        private static void StopService(string name, bool requireStopped)
        {
            if (!ServiceExists(name)) return;
            AssertOwnedServiceOrAbsent(name);
            using (ServiceController service = new ServiceController(name))
            {
                service.Refresh();
                if (service.Status == ServiceControllerStatus.Stopped) return;
                if (service.CanStop) service.Stop();
                try { service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30)); }
                catch (System.ServiceProcess.TimeoutException)
                {
                    if (requireStopped) throw new InvalidOperationException("Service " + name + " did not stop. Removal was cancelled.");
                }
            }
        }

        private static void DeleteService(string name)
        {
            if (!ServiceExists(name)) return;
            AssertOwnedServiceOrAbsent(name);
            RunSc("delete " + name, false);
        }

        private static void AssertOwnedServiceOrAbsent(string name)
        {
            if (!ServiceExists(name)) return;
            string expected = ExpectedServiceExecutable(name);
            string actual = ReadServiceExecutable(name);
            if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "Service " + name + " already exists but belongs to another application. The operation stopped without changing that service.");
            }
        }

        private static string ExpectedServiceExecutable(string name)
        {
            if (string.Equals(name, Product.VpnServiceName, StringComparison.OrdinalIgnoreCase))
                return Path.GetFullPath(Path.Combine(Product.InstallRoot, "HandShakeVpnService.exe"));
            if (string.Equals(name, Product.NodeServiceName, StringComparison.OrdinalIgnoreCase))
                return Path.GetFullPath(Path.Combine(Product.InstallRoot, "HandShakeNodeService.exe"));
            throw new InvalidOperationException("Unknown HandShake service name.");
        }

        private static string ReadServiceExecutable(string name)
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name, false))
            {
                if (key == null) throw new InvalidOperationException("Could not verify the owner of service " + name + ".");
                object raw = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                string commandLine = raw as string;
                if (string.IsNullOrWhiteSpace(commandLine))
                    throw new InvalidOperationException("Service " + name + " does not have a verifiable ImagePath.");
                return ParseServiceExecutable(commandLine);
            }
        }

        private static string ParseServiceExecutable(string commandLine)
        {
            string value = Environment.ExpandEnvironmentVariables(commandLine).Trim();
            string executable;
            string remainder;
            if (value.StartsWith("\"", StringComparison.Ordinal))
            {
                int closing = value.IndexOf('\"', 1);
                if (closing <= 1) throw new InvalidOperationException("The service ImagePath contains an unclosed quote.");
                executable = value.Substring(1, closing - 1);
                remainder = value.Substring(closing + 1).Trim();
            }
            else
            {
                int separator = value.IndexOfAny(new[] { ' ', '\t' });
                executable = separator < 0 ? value : value.Substring(0, separator);
                remainder = separator < 0 ? string.Empty : value.Substring(separator).Trim();
            }
            if (remainder.Length != 0)
                throw new InvalidOperationException("The service ImagePath contains unexpected arguments.");
            return Path.GetFullPath(executable);
        }

        private static string RunSc(string arguments, bool allowFailure)
        {
            ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"), arguments);
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            using (Process process = Process.Start(info))
            {
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();
                if (!allowFailure && process.ExitCode != 0) throw new InvalidOperationException("Could not configure the service: " + (error + output).Trim());
                return output;
            }
        }

        private static string Quote(string value)
        {
            if (value == null) throw new ArgumentNullException("value");
            StringBuilder quoted = new StringBuilder(value.Length + 2);
            quoted.Append('"');
            int backslashes = 0;
            foreach (char character in value)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (character == '"')
                {
                    quoted.Append('\\', (backslashes * 2) + 1);
                    quoted.Append('"');
                    backslashes = 0;
                    continue;
                }
                if (backslashes != 0)
                {
                    quoted.Append('\\', backslashes);
                    backslashes = 0;
                }
                quoted.Append(character);
            }
            if (backslashes != 0) quoted.Append('\\', backslashes * 2);
            quoted.Append('"');
            return quoted.ToString();
        }

        private static void ConfigureServiceBinaryPath(string name, string displayName, string executable)
        {
            const uint ScManagerConnect = 0x0001;
            const uint ScManagerCreateService = 0x0002;
            const uint ServiceAllAccess = 0xF01FF;
            const uint ServiceWin32OwnProcess = 0x00000010;
            const uint ServiceAutoStart = 0x00000002;
            const uint ServiceErrorNormal = 0x00000001;
            const uint ServiceNoChange = 0xFFFFFFFF;
            string quotedBinaryPath = "\"" + executable + "\"";

            IntPtr manager = OpenSCManager(null, null, ScManagerConnect | ScManagerCreateService);
            if (manager == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not open Service Control Manager.");
            IntPtr service = IntPtr.Zero;
            try
            {
                service = OpenService(manager, name, ServiceAllAccess);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    const int ErrorServiceDoesNotExist = 1060;
                    if (error != ErrorServiceDoesNotExist) throw new System.ComponentModel.Win32Exception(error, "Could not open service " + name + ".");
                    service = CreateService(manager, name, displayName, ServiceAllAccess, ServiceWin32OwnProcess,
                        ServiceAutoStart, ServiceErrorNormal, quotedBinaryPath, null, IntPtr.Zero, null, null, null);
                    if (service == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not create service " + name + ".");
                }
                else
                {
                    bool changed = ChangeServiceConfig(service, ServiceNoChange, ServiceAutoStart, ServiceNoChange,
                        quotedBinaryPath, null, IntPtr.Zero, null, null, null, displayName);
                    if (!changed) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Could not update service " + name + ".");
                }
            }
            finally
            {
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                CloseServiceHandle(manager);
            }
        }

        private static void WriteUninstallRegistration(string version)
        {
            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(Product.UninstallRegistryKey))
            {
                key.SetValue("DisplayName", Product.Name);
                key.SetValue("DisplayVersion", version);
                key.SetValue("Publisher", Product.Publisher);
                key.SetValue("InstallLocation", Product.InstallRoot);
                key.SetValue("DisplayIcon", Path.Combine(Product.InstallRoot, "HandShake VPN.exe"));
                key.SetValue("UninstallString", Quote(Path.Combine(Product.InstallRoot, "HandShake VPN Uninstall.exe")) + " --uninstall");
                key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            }
        }

        private static void DeleteUninstallRegistration()
        {
            Registry.LocalMachine.DeleteSubKeyTree(Product.UninstallRegistryKey, false);
        }

        private static void CreateShortcut()
        {
            Directory.CreateDirectory(Product.StartMenuRoot);
            string desktopRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
            if (string.IsNullOrWhiteSpace(desktopRoot)) throw new InvalidOperationException("Windows did not return the shared desktop path.");
            Directory.CreateDirectory(desktopRoot);
            Type shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) throw new InvalidOperationException("Windows Script Host is unavailable for shortcut creation.");
            object shell = Activator.CreateInstance(shellType);
            try
            {
                SaveShortcut(shellType, shell, Path.Combine(Product.StartMenuRoot, Product.Name + ".lnk"));
                SaveShortcut(shellType, shell, Product.DesktopShortcutPath);
            }
            finally
            {
                if (Marshal.IsComObject(shell)) Marshal.FinalReleaseComObject(shell);
            }
        }

        private static void SaveShortcut(Type shellType, object shell, string shortcutPath)
        {
            object shortcut = null;
            try
            {
                shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { shortcutPath });
                Type shortcutType = shortcut.GetType();
                string executable = Path.Combine(Product.InstallRoot, "HandShake VPN.exe");
                shortcutType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, new object[] { executable });
                shortcutType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, new object[] { Product.InstallRoot });
                shortcutType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut, new object[] { Product.Name });
                shortcutType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, new object[] { executable + ",0" });
                shortcutType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
            }
            finally
            {
                if (shortcut != null && Marshal.IsComObject(shortcut)) Marshal.FinalReleaseComObject(shortcut);
            }
        }

        private static void DeleteShortcut()
        {
            string path = Path.Combine(Product.StartMenuRoot, Product.Name + ".lnk");
            if (File.Exists(path)) File.Delete(path);
            if (File.Exists(Product.DesktopShortcutPath)) File.Delete(Product.DesktopShortcutPath);
            if (Directory.Exists(Product.StartMenuRoot) && Directory.GetFileSystemEntries(Product.StartMenuRoot).Length == 0) Directory.Delete(Product.StartMenuRoot);
        }

        internal static bool LaunchInstalledApplication()
        {
            try
            {
                string executable = Path.Combine(Product.InstallRoot, "HandShake VPN.exe");
                if (!File.Exists(executable)) return false;
                ProcessStartInfo info = new ProcessStartInfo(
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), Quote(executable));
                info.UseShellExecute = true;
                // Explorer delegates to the interactive desktop. ShellExecute may
                // return no new process even though that delegation succeeded.
                using (Process launched = Process.Start(info)) { }
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsAllowedArchiveFile(string relative)
        {
            string normalized = NormalizeRelativePath(relative);
            if (string.Equals(normalized, "payload-manifest.json", StringComparison.OrdinalIgnoreCase)) return true;
            const string payloadPrefix = "files\\";
            if (!normalized.StartsWith(payloadPrefix, StringComparison.OrdinalIgnoreCase)) return false;
            return AllowedPayloadSet.Contains(normalized.Substring(payloadPrefix.Length));
        }

        private static bool IsAllowedArchiveDirectory(string relative)
        {
            string normalized = relative.Replace('/', Path.DirectorySeparatorChar).TrimEnd(Path.DirectorySeparatorChar);
            normalized = NormalizeRelativePath(normalized);
            if (string.Equals(normalized, "files", StringComparison.OrdinalIgnoreCase)) return true;
            string prefix = normalized + Path.DirectorySeparatorChar;
            return AllowedPayloadFiles.Any(delegate(string allowed)
            {
                return ("files\\" + allowed).StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
            });
        }

        private static string NormalizeRelativePath(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) throw new InvalidDataException("The manifest contains an empty path.");
            string normalized = value.Replace('/', Path.DirectorySeparatorChar);
            if (Path.IsPathRooted(normalized) || normalized.Split(Path.DirectorySeparatorChar).Any(delegate(string part) { return part == ".." || part == "." || string.IsNullOrEmpty(part); }))
                throw new InvalidDataException("Invalid relative path: " + value);
            return normalized;
        }

        private static string SafeCombine(string root, string relative)
        {
            string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string result = Path.GetFullPath(Path.Combine(fullRoot, relative));
            if (!result.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("The path escapes the allowed directory.");
            return result;
        }

        private static string ComputeSha256(string path)
        {
            using (SHA256 hash = SHA256.Create())
            using (FileStream input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                return ComputeSha256(hash, input);
        }

        private static string ComputeSha256(SHA256 hash, Stream input)
        {
            return BitConverter.ToString(hash.ComputeHash(input)).Replace("-", string.Empty).ToLowerInvariant();
        }

        private static void VerifyFile(string path, long expectedLength, string expectedSha256)
        {
            ValidateExpectedHash(expectedSha256);
            RejectReparsePoint(path, "file being verified");
            FileInfo info = new FileInfo(path);
            if (!info.Exists || info.Length != expectedLength)
                throw new InvalidDataException("File size mismatch: " + Path.GetFileName(path));
            string actual = ComputeSha256(path);
            if (!string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("File checksum mismatch: " + Path.GetFileName(path));
        }

        private static void ValidateExpectedHash(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length != 64 || value.Any(delegate(char c)
            {
                return !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
            }))
                throw new InvalidDataException("The manifest contains an invalid SHA-256 hash.");
        }

        private static void CopyAndVerifyFile(string source, string destination, long expectedLength, string expectedSha256)
        {
            ValidateExpectedHash(expectedSha256);
            RejectReparsePoint(source, "source file");
            using (FileStream input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (input.Length != expectedLength)
                    throw new InvalidDataException("The source file size changed immediately before copying.");
                string actualSource;
                using (SHA256 hash = SHA256.Create()) actualSource = ComputeSha256(hash, input);
                if (!string.Equals(actualSource, expectedSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("The source file checksum changed immediately before copying.");
                input.Position = 0;
                CopyLockedFileAndVerify(input, destination, expectedLength, expectedSha256);
            }
        }

        private static void CopyAndVerifyFile(string source, string destination)
        {
            RejectReparsePoint(source, "backup source file");
            using (FileStream input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                long length = input.Length;
                string hashValue;
                using (SHA256 hash = SHA256.Create()) hashValue = ComputeSha256(hash, input);
                input.Position = 0;
                CopyLockedFileAndVerify(input, destination, length, hashValue);
            }
        }

        private static void CopyLockedFileAndVerify(Stream input, string destination, long expectedLength, string expectedSha256)
        {
            RejectOwnedDestinationReparsePoints(destination);
            string temporary = destination + ".new-" + Guid.NewGuid().ToString("N");
            try
            {
                using (FileStream output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    input.CopyTo(output);
                    output.Flush(true);
                }

                VerifyFile(temporary, expectedLength, expectedSha256);
                if (File.Exists(destination))
                {
                    RejectReparsePoint(destination, "application file being replaced");
                    File.Delete(destination);
                }
                File.Move(temporary, destination);
                VerifyFile(destination, expectedLength, expectedSha256);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        private static void RejectOwnedDestinationReparsePoints(string destination)
        {
            string full = Path.GetFullPath(destination);
            foreach (string candidate in new[] { Product.InstallRoot, Product.DataRoot, Product.StagingRoot })
            {
                string root = Path.GetFullPath(candidate).TrimEnd(Path.DirectorySeparatorChar);
                string prefix = root + Path.DirectorySeparatorChar;
                if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
                RejectReparsePoint(root, "destination root directory");
                string parent = Path.GetDirectoryName(full);
                if (string.IsNullOrEmpty(parent)) throw new InvalidOperationException("The destination file has no parent directory.");
                string relative = parent.Length <= root.Length ? string.Empty : parent.Substring(root.Length).TrimStart(Path.DirectorySeparatorChar);
                string current = root;
                if (relative.Length != 0)
                {
                    foreach (string part in relative.Split(Path.DirectorySeparatorChar))
                    {
                        current = Path.Combine(current, part);
                        RejectReparsePoint(current, "destination subdirectory");
                    }
                }
                return;
            }
            throw new InvalidOperationException("The destination file is outside HandShake directories.");
        }

        private static void CopyDirectory(string source, string destination, string excludedTopLevelDirectory = null)
        {
            string sourceRoot = Path.GetFullPath(source).TrimEnd(Path.DirectorySeparatorChar);
            RejectReparsePoint(sourceRoot, "backup source directory");
            Directory.CreateDirectory(destination);
            RejectReparsePoint(destination, "backup directory");
            CopyDirectoryRecursive(sourceRoot, sourceRoot, Path.GetFullPath(destination).TrimEnd(Path.DirectorySeparatorChar), excludedTopLevelDirectory);
        }

        private static void CopyDirectoryRecursive(string sourceRoot, string current, string destinationRoot, string excludedTopLevelDirectory = null)
        {
            foreach (string directory in Directory.GetDirectories(current, "*", SearchOption.TopDirectoryOnly))
            {
                if (String.Equals(current, sourceRoot, StringComparison.OrdinalIgnoreCase) &&
                    String.Equals(Path.GetFileName(directory), excludedTopLevelDirectory, StringComparison.OrdinalIgnoreCase)) continue;
                RejectReparsePoint(directory, "backup subdirectory");
                string relative = directory.Substring(sourceRoot.Length).TrimStart(Path.DirectorySeparatorChar);
                string target = SafeCombine(destinationRoot, relative);
                Directory.CreateDirectory(target);
                CopyDirectoryRecursive(sourceRoot, directory, destinationRoot, excludedTopLevelDirectory);
            }
            foreach (string file in Directory.GetFiles(current, "*", SearchOption.TopDirectoryOnly))
            {
                RejectReparsePoint(file, "backup file");
                string relative = file.Substring(sourceRoot.Length).TrimStart(Path.DirectorySeparatorChar);
                string target = SafeCombine(destinationRoot, relative);
                string parent = Path.GetDirectoryName(target);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                CopyAndVerifyFile(file, target);
            }
        }

        private static void ClearDataForRollback()
        {
            if (!Directory.Exists(Product.DataRoot)) return;
            RejectReparsePoint(Product.DataRoot, "rollback data root");
            string updates = Path.GetFullPath(Path.Combine(Product.DataRoot, "updates"));
            if (Directory.Exists(updates)) RejectReparsePoint(updates, "update cache");
            // The running installer can live in updates. Preserve that whole
            // directory; remove only the remaining product state without links.
            DeleteContentsWithoutFollowingReparsePoints(Product.DataRoot, updates);
        }

        private static void SafeDeleteOwnedDirectory(string path, string expected)
        {
            string actual = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
            string allowed = Path.GetFullPath(expected).TrimEnd(Path.DirectorySeparatorChar);
            if (!string.Equals(actual, allowed, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Refusing to remove an unexpected directory.");
            RejectReparsePoint(actual, "product directory being removed");
            if (Directory.Exists(actual)) DeleteTreeWithoutFollowingReparsePoints(actual);
        }

        private static void DeleteDirectoryContentsExcept(string directory, string exceptFile)
        {
            if (!Directory.Exists(directory)) return;
            string actual = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar);
            string expectedRoot = Path.GetFullPath(Product.InstallRoot).TrimEnd(Path.DirectorySeparatorChar);
            if (!string.Equals(actual, expectedRoot, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Refusing to clean an unexpected application directory.");
            RejectReparsePoint(actual, "application directory");
            string except = Path.GetFullPath(exceptFile);
            DeleteContentsWithoutFollowingReparsePoints(actual, except);
        }

        private static void DeleteTreeWithoutFollowingReparsePoints(string directory)
        {
            DeleteContentsWithoutFollowingReparsePoints(directory, null);
            Directory.Delete(directory, false);
        }

        private static void DeleteContentsWithoutFollowingReparsePoints(string directory, string exceptFile)
        {
            foreach (string entry in Directory.GetFileSystemEntries(directory, "*", SearchOption.TopDirectoryOnly))
            {
                string full = Path.GetFullPath(entry);
                if (exceptFile != null && string.Equals(full, exceptFile, StringComparison.OrdinalIgnoreCase)) continue;
                FileAttributes attributes = File.GetAttributes(entry);
                bool isDirectory = (attributes & FileAttributes.Directory) != 0;
                bool isReparse = (attributes & FileAttributes.ReparsePoint) != 0;
                if (isDirectory && !isReparse)
                {
                    DeleteTreeWithoutFollowingReparsePoints(entry);
                }
                else if (isDirectory)
                {
                    Directory.Delete(entry, false);
                }
                else
                {
                    File.Delete(entry);
                }
            }
        }

        private static void TryDeleteStageDirectory(string path)
        {
            try
            {
                string stage = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
                string root = Path.GetFullPath(Product.StagingRoot).TrimEnd(Path.DirectorySeparatorChar);
                string parent = Path.GetDirectoryName(stage);
                Guid ignored;
                if (!string.Equals(parent, root, StringComparison.OrdinalIgnoreCase) ||
                    !Guid.TryParseExact(Path.GetFileName(stage), "N", out ignored)) return;
                RejectReparsePoint(stage, "staging work directory");
                if (Directory.Exists(stage)) DeleteTreeWithoutFollowingReparsePoints(stage);
                RejectReparsePoint(root, "staging directory");
                if (Directory.Exists(root) && Directory.GetFileSystemEntries(root).Length == 0) Directory.Delete(root, false);
            }
            catch { }
        }

        private static void Log(string message)
        {
            try
            {
                if (!Directory.Exists(Product.DataRoot)) return;
                RejectReparsePoint(Product.DataRoot, "data directory");
                ProtectRuntimeDirectory(Product.DataRoot);
                string directory = Path.Combine(Product.DataRoot, "installer");
                Directory.CreateDirectory(directory);
                ProtectRuntimeDirectory(directory);
                File.AppendAllText(Path.Combine(directory, "install.log"), DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) + " " + message + Environment.NewLine, Encoding.UTF8);
            }
            catch { }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct QueryServiceConfigNative
        {
            public uint ServiceType;
            public uint StartType;
            public uint ErrorControl;
            public IntPtr BinaryPathName;
            public IntPtr LoadOrderGroup;
            public uint TagId;
            public IntPtr Dependencies;
            public IntPtr ServiceStartName;
            public IntPtr DisplayName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceDescriptionNative
        {
            public IntPtr Description;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceFailureActionsNative
        {
            public uint ResetPeriod;
            public IntPtr RebootMessage;
            public IntPtr Command;
            public uint ActionCount;
            public IntPtr Actions;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceFailureActionNative
        {
            public int Type;
            public uint DelayMilliseconds;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceDelayedAutoStartNative
        {
            [MarshalAs(UnmanagedType.Bool)]
            public bool DelayedAutoStart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceFailureActionsFlagNative
        {
            [MarshalAs(UnmanagedType.Bool)]
            public bool Enabled;
        }

        [Flags]
        private enum MoveFileFlags
        {
            DelayUntilReboot = 0x4
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool MoveFileEx(string existingFileName, string newFileName, MoveFileFlags flags);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenService(IntPtr serviceManager, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryServiceConfig(IntPtr service, IntPtr serviceConfig, uint bufferSize, out uint bytesNeeded);

        [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfig2W", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryServiceConfig2(IntPtr service, uint informationLevel, IntPtr buffer, uint bufferSize, out uint bytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateService(IntPtr serviceManager, string serviceName, string displayName,
            uint desiredAccess, uint serviceType, uint startType, uint errorControl, string binaryPathName,
            string loadOrderGroup, IntPtr tagId, string dependencies, string serviceStartName, string password);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ChangeServiceConfig(IntPtr service, uint serviceType, uint startType,
            uint errorControl, string binaryPathName, string loadOrderGroup, IntPtr tagId,
            string dependencies, string serviceStartName, string password, string displayName);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfigW", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ChangeServiceConfigWithDependencyPointer(IntPtr service, uint serviceType, uint startType,
            uint errorControl, string binaryPathName, string loadOrderGroup, IntPtr tagId,
            IntPtr dependencies, string serviceStartName, string password, string displayName);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ChangeServiceConfig2(IntPtr service, uint informationLevel, IntPtr information);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr serviceHandle);
    }
}
