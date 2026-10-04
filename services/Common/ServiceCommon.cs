using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

[assembly: AssemblyCompany("HandShake VPN")]
[assembly: AssemblyProduct("HandShake VPN test services")]
[assembly: AssemblyCopyright("Copyright 2026")]
[assembly: AssemblyVersion("0.1.0.0")]
[assembly: AssemblyFileVersion("0.1.0.0")]

namespace HandShake.Services
{
    internal static class ProductInfo
    {
        public const string Version = HandShake.Release.ProductRelease.Version;
        public const string ProductDirectoryName = "HandShake VPN";

        public static string ProgramDataRoot
        {
            get
            {
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    ProductDirectoryName);
            }
        }

        public static string VpnXrayExecutablePath
        {
            get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "runtime", "vpn", "xray.exe"); }
        }

        public static string NodeXrayExecutablePath
        {
            get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "runtime", "node", "xray.exe"); }
        }

        public static string FirewallHelperPath
        {
            get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Firewall-Policy.ps1"); }
        }
    }

    internal sealed class ServiceConfigurationException : Exception
    {
        public ServiceConfigurationException(string message) : base(message) { }
        public ServiceConfigurationException(string message, Exception inner) : base(message, inner) { }
    }

    internal static class JsonFile
    {
        private static readonly JavaScriptSerializer Serializer = new JavaScriptSerializer
        {
            MaxJsonLength = 4 * 1024 * 1024,
            RecursionLimit = 100
        };

        public static T ReadStrict<T>(string path, IEnumerable<string> allowedKeys, int maximumBytes)
        {
            if (!File.Exists(path))
            {
                throw new ServiceConfigurationException("Required configuration file is missing: " + path);
            }

            FileInfo info = new FileInfo(path);
            if (info.Length <= 1 || info.Length > maximumBytes)
            {
                throw new ServiceConfigurationException("Configuration file has an invalid size: " + path);
            }

            string json = File.ReadAllText(path, Encoding.UTF8);
            ValidateTopLevelKeys(json, allowedKeys);
            try
            {
                T result = Serializer.Deserialize<T>(json);
                if (result == null)
                {
                    throw new ServiceConfigurationException("Configuration JSON is empty: " + path);
                }
                return result;
            }
            catch (ServiceConfigurationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new ServiceConfigurationException("Configuration JSON is invalid: " + path, ex);
            }
        }

        public static object ParseObject(string json)
        {
            try
            {
                return Serializer.DeserializeObject(json);
            }
            catch (Exception ex)
            {
                throw new ServiceConfigurationException("JSON is invalid.", ex);
            }
        }

        public static string Serialize(object value)
        {
            return Serializer.Serialize(value);
        }

        public static void WriteAtomic(string path, object value)
        {
            string directory = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(directory))
            {
                throw new InvalidOperationException("State path has no parent directory.");
            }
            Directory.CreateDirectory(directory);

            string temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
            File.WriteAllText(temporary, Serialize(value), new UTF8Encoding(false));
            try
            {
                if (File.Exists(path))
                {
                    File.Replace(temporary, path, null, true);
                }
                else
                {
                    File.Move(temporary, path);
                }
            }
            finally
            {
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }
        }

        private static void ValidateTopLevelKeys(string json, IEnumerable<string> allowedKeys)
        {
            object parsed = ParseObject(json);
            IDictionary<string, object> dictionary = parsed as IDictionary<string, object>;
            if (dictionary == null)
            {
                throw new ServiceConfigurationException("The JSON root must be an object.");
            }

            HashSet<string> allowed = new HashSet<string>(allowedKeys, StringComparer.Ordinal);
            foreach (string key in dictionary.Keys)
            {
                if (!allowed.Contains(key))
                {
                    throw new ServiceConfigurationException("Unknown configuration property: " + key);
                }
            }
        }
    }

    internal static class Validation
    {
        public static void Require(bool condition, string message)
        {
            if (!condition)
            {
                throw new ServiceConfigurationException(message);
            }
        }

        public static bool IsSha256(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length != 64)
            {
                return false;
            }
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                {
                    return false;
                }
            }
            return true;
        }

        public static Uri RequireProtectedApiBase(string value, bool allowInsecureLoopback)
        {
            Uri uri;
            if (!Uri.TryCreate(value, UriKind.Absolute, out uri))
            {
                throw new ServiceConfigurationException("apiBaseUrl must be an absolute URI.");
            }
            if (!string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            {
                throw new ServiceConfigurationException("apiBaseUrl must not contain credentials, query, or fragment.");
            }
            if (string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                return EnsureTrailingSlash(uri);
            }
            if (allowInsecureLoopback && string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) && uri.IsLoopback)
            {
                return EnsureTrailingSlash(uri);
            }
            throw new ServiceConfigurationException("Bearer tokens require HTTPS. HTTP is allowed only for explicit loopback development.");
        }

        public static DateTime ParseUtc(string value, string fieldName)
        {
            DateTime parsed;
            if (!DateTime.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out parsed))
            {
                throw new ServiceConfigurationException(fieldName + " must be an ISO-8601 UTC timestamp.");
            }
            return parsed.ToUniversalTime();
        }

        public static void RequireFixedFileUnder(string filePath, string expectedDirectory)
        {
            string fullFile = Path.GetFullPath(filePath);
            string fullDirectory = Path.GetFullPath(expectedDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!fullFile.StartsWith(fullDirectory, StringComparison.OrdinalIgnoreCase))
            {
                throw new ServiceConfigurationException("A managed file resolved outside its fixed service directory.");
            }
        }

        private static Uri EnsureTrailingSlash(Uri uri)
        {
            string absolute = uri.AbsoluteUri;
            if (!absolute.EndsWith("/", StringComparison.Ordinal))
            {
                absolute += "/";
            }
            return new Uri(absolute, UriKind.Absolute);
        }
    }

    internal static class SecretFile
    {
        public static string ReadBearerToken(string path)
        {
            if (!File.Exists(path))
            {
                throw new ServiceConfigurationException("Device token file is missing.");
            }
            AccessControlGuard.RequireSystemAndAdministratorsOnly(path, false);
            string token = File.ReadAllText(path, Encoding.UTF8).Trim();
            if (token.Length < 20 || token.Length > 512 || token.IndexOfAny(new[] { '\r', '\n', '\t', ' ' }) >= 0)
            {
                throw new ServiceConfigurationException("Device token file has an invalid value.");
            }
            return token;
        }

    }

    internal static class AccessControlGuard
    {
        public static void RequireSystemAndAdministratorsOnly(string path, bool directory)
        {
            FileSystemSecurity security;
            try
            {
                security = directory
                    ? (FileSystemSecurity)Directory.GetAccessControl(path, AccessControlSections.Access)
                    : (FileSystemSecurity)File.GetAccessControl(path, AccessControlSections.Access);
            }
            catch (Exception ex)
            {
                throw new ServiceConfigurationException("Could not verify a service input ACL.", ex);
            }

            AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
            SecurityIdentifier system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow)
                {
                    continue;
                }
                SecurityIdentifier sid = rule.IdentityReference as SecurityIdentifier;
                if (sid != null && (sid.Equals(system) || sid.Equals(administrators)))
                {
                    continue;
                }
                if ((rule.FileSystemRights & ~FileSystemRights.Synchronize) != 0)
                {
                    throw new ServiceConfigurationException("A service input ACL grants access outside SYSTEM and Administrators.");
                }
            }
        }

        public static void RequireNoWriteAccessOutsideSystemAndAdministrators(string path)
        {
            FileSystemSecurity security;
            try { security = File.GetAccessControl(path, AccessControlSections.Access); }
            catch (Exception ex) { throw new ServiceConfigurationException("Could not verify the protected configuration ACL.", ex); }
            AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
            SecurityIdentifier system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            // Composite rights such as Modify and FullControl also contain read
            // bits. Using them as a bit mask makes a safe ReadAndExecute ACE
            // appear writable. Check only the individual mutation rights.
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                SecurityIdentifier sid = rule.IdentityReference as SecurityIdentifier;
                if (sid != null && (sid.Equals(system) || sid.Equals(administrators))) continue;
                if (GrantsMutationRights(rule.FileSystemRights))
                    throw new ServiceConfigurationException("The protected configuration is writable outside SYSTEM and Administrators.");
            }
        }

        private static bool GrantsMutationRights(FileSystemRights rights)
        {
            FileSystemRights dangerous = FileSystemRights.WriteData | FileSystemRights.AppendData |
                FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes |
                FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.Delete |
                FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
            return (rights & dangerous) != 0;
        }

        internal static bool GrantsMutationRightsForSelfTest(FileSystemRights rights)
        {
            return GrantsMutationRights(rights);
        }
    }

    internal sealed class ServiceLog
    {
        private readonly string _path;
        private readonly object _sync = new object();

        public ServiceLog(string path)
        {
            _path = path;
        }

        public void Info(string message)
        {
            Write("INFO", message);
        }

        public void Error(string message)
        {
            Write("ERROR", message);
        }

        private void Write(string level, string message)
        {
            try
            {
                lock (_sync)
                {
                    string directory = Path.GetDirectoryName(_path);
                    Directory.CreateDirectory(directory);
                    RotateIfNeeded();
                    string safe = (message ?? string.Empty).Replace("\r", " ").Replace("\n", " ");
                    File.AppendAllText(_path,
                        DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) + " " + level + " " + safe + Environment.NewLine,
                        new UTF8Encoding(false));
                }
            }
            catch
            {
                // Logging must never crash the service. Tokens and raw hardware IDs are never passed here.
            }
        }

        private void RotateIfNeeded()
        {
            if (!File.Exists(_path) || new FileInfo(_path).Length < 2 * 1024 * 1024)
            {
                return;
            }
            string previous = _path + ".1";
            if (File.Exists(previous))
            {
                File.Delete(previous);
            }
            File.Move(_path, previous);
        }
    }

    internal sealed class XraySupervisor : IDisposable
    {
        private readonly ServiceLog _log;
        private readonly string _executablePath;
        private readonly Action<string> _standardOutput;
        private Process _process;
        private IntPtr _jobHandle;
        private string _runningConfigSha256;
        private string _runningExecutableSha256;
        private DateTime _nextStartUtc = DateTime.MinValue;
        private int _consecutiveFailures;
        private bool _stopping;

        public XraySupervisor(ServiceLog log, string executablePath, Action<string> standardOutput = null)
        {
            _log = log;
            _executablePath = Path.GetFullPath(executablePath);
            _standardOutput = standardOutput;
        }

        public bool IsRunning
        {
            get
            {
                Process process = _process;
                if (process == null)
                {
                    return false;
                }
                try { return !process.HasExited; }
                catch { return false; }
            }
        }

        public int? ProcessId
        {
            get
            {
                if (!IsRunning) { return null; }
                try { return _process.Id; }
                catch { return null; }
            }
        }

        public int RestartCount { get { return _consecutiveFailures; } }

        public void EnsureRunning(string configPath, string expectedExecutableSha256)
        {
            if (_stopping)
            {
                return;
            }
            string executable = _executablePath;
            if (!File.Exists(executable))
            {
                throw new ServiceConfigurationException("xray.exe is not installed in its protected role-specific runtime directory.");
            }
            string executableSha256 = CalculateSha256(executable);
            if (!string.IsNullOrWhiteSpace(expectedExecutableSha256))
            {
                VerifySha256Value(executableSha256, expectedExecutableSha256);
            }
            if (!File.Exists(configPath))
            {
                throw new ServiceConfigurationException("The provisioned Xray configuration is missing.");
            }
            string configSha256 = CalculateSha256(configPath);

            if (IsRunning)
            {
                if (string.Equals(_runningConfigSha256, configSha256, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(_runningExecutableSha256, executableSha256, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
                _log.Info("The managed Xray profile or executable changed; restarting its isolated process tree.");
                StopProcess(false);
            }
            ObservePreviousExit();
            if (DateTime.UtcNow < _nextStartUtc)
            {
                return;
            }

            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = executable;
            start.Arguments = "run -config \"" + configPath.Replace("\"", "\\\"") + "\"";
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.WorkingDirectory = Path.GetDirectoryName(executable);
            start.RedirectStandardOutput = _standardOutput != null;
            // Services have no console. Provide a valid stderr handle rather
            // than inheriting an absent console handle, and retain only fixed
            // diagnostic categories (never destinations or credentials).
            start.RedirectStandardError = true;

            EnsureJobObject();
            Process started = new Process();
            started.StartInfo = start;
            started.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs args)
            {
                string category = ClassifyRuntimeError(args.Data);
                if (category != null) _log.Error("Managed Xray reported " + category + ".");
            };
            if (_standardOutput != null)
            {
                started.OutputDataReceived += delegate(object sender, DataReceivedEventArgs args)
                {
                    if (!string.IsNullOrWhiteSpace(args.Data))
                    {
                        try { _standardOutput(args.Data); } catch { }
                    }
                };
            }
            if (!started.Start())
            {
                started.Dispose();
                throw new InvalidOperationException("Windows did not create the Xray process.");
            }
            if (_standardOutput != null) started.BeginOutputReadLine();
            started.BeginErrorReadLine();
            try
            {
                if (!NativeJob.AssignProcessToJobObject(_jobHandle, started.Handle))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                        "Windows could not place Xray in the service-owned Job Object.");
                }
                _process = started;
                _runningConfigSha256 = configSha256;
                _runningExecutableSha256 = executableSha256;
            }
            catch
            {
                try { started.Kill(); started.WaitForExit(5000); } catch { }
                started.Dispose();
                CloseJobObject();
                throw;
            }
            _log.Info("Started the managed Xray process.");
        }

        public void Tick()
        {
            if (_process == null || IsRunning)
            {
                return;
            }
            ObservePreviousExit();
        }

        internal static string ClassifyRuntimeError(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return null;
            if (line.IndexOf("panic:", StringComparison.OrdinalIgnoreCase) >= 0 ||
                line.IndexOf("fatal error:", StringComparison.OrdinalIgnoreCase) >= 0) return "runtime_failure";
            if (line.IndexOf("Failed to start:", StringComparison.OrdinalIgnoreCase) >= 0) return "startup_failure";
            if (line.IndexOf("failed", StringComparison.OrdinalIgnoreCase) >= 0 &&
                (line.IndexOf("adapter", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 line.IndexOf("wintun", StringComparison.OrdinalIgnoreCase) >= 0))
            {
                string category = line.IndexOf("timed out", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    line.IndexOf("timeout", StringComparison.OrdinalIgnoreCase) >= 0
                    ? "tun_adapter_timeout" : "tun_adapter_failure";
                var code = System.Text.RegularExpressions.Regex.Match(line, @"\b0x[0-9a-fA-F]{8}\b");
                return code.Success ? category + " code=" + code.Value.ToUpperInvariant() : category;
            }
            return null;
        }

        public void Stop()
        {
            _stopping = true;
            StopProcess(true);
        }

        public void AllowStarts()
        {
            _stopping = false;
        }

        public void Dispose()
        {
            Stop();
            CloseJobObject();
        }

        private void ObservePreviousExit()
        {
            Process previous = _process;
            if (previous == null)
            {
                return;
            }
            int exitCode = -1;
            try { exitCode = previous.ExitCode; }
            catch { }
            CloseJobObject();
            previous.Dispose();
            _process = null;
            _runningConfigSha256 = null;
            _runningExecutableSha256 = null;
            _consecutiveFailures++;
            int delaySeconds = Math.Min(60, (int)Math.Pow(2, Math.Min(_consecutiveFailures, 5)));
            _nextStartUtc = DateTime.UtcNow.AddSeconds(delaySeconds);
            _log.Error("Managed Xray exited with code " + exitCode.ToString(CultureInfo.InvariantCulture) + "; restart is delayed.");
        }

        private void StopProcess(bool logStop)
        {
            Process process = _process;
            if (process == null)
            {
                CloseJobObject();
                return;
            }
            bool exited;
            try { exited = process.HasExited; }
            catch { exited = false; }
            if (!exited)
            {
                // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE terminates Xray and any descendants together.
                CloseJobObject();
                try { exited = process.WaitForExit(10000); }
                catch { exited = false; }
            }
            if (!exited)
            {
                try { process.Kill(); } catch { }
                try { exited = process.WaitForExit(5000); }
                catch { exited = false; }
            }
            if (!exited)
            {
                throw new ServiceConfigurationException("The managed Xray process tree did not stop; firewall policy remains fail-closed.");
            }
            // Even when the parent exited on its own, closing the Job Object terminates any child
            // it may have left behind. Do not release the Process object until this succeeds.
            CloseJobObject();
            process.Dispose();
            _process = null;
            _runningConfigSha256 = null;
            _runningExecutableSha256 = null;
            if (logStop) { _log.Info("Stopped the managed Xray process tree."); }
        }

        private void EnsureJobObject()
        {
            if (_jobHandle != IntPtr.Zero) { return; }
            _jobHandle = NativeJob.CreateKillOnCloseJob();
        }

        private void CloseJobObject()
        {
            IntPtr handle = _jobHandle;
            if (handle == IntPtr.Zero) { return; }
            if (!NativeJob.CloseHandle(handle))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                    "Windows could not close the service-owned Job Object.");
            }
            _jobHandle = IntPtr.Zero;
        }

        private static string CalculateSha256(string path)
        {
            using (FileStream stream = File.OpenRead(path))
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(stream);
                StringBuilder value = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++)
                {
                    value.Append(hash[i].ToString("x2", CultureInfo.InvariantCulture));
                }
                return value.ToString();
            }
        }

        private static void VerifySha256Value(string actual, string expected)
        {
            if (!Validation.IsSha256(expected))
            {
                throw new ServiceConfigurationException("xrayExecutableSha256 is invalid.");
            }
            if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            {
                throw new ServiceConfigurationException("xray.exe SHA-256 does not match the provisioned value.");
            }
        }
    }

    internal static class NativeJob
    {
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;
        private const int JobObjectExtendedLimitInformation = 9;

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedLimitInformation
        {
            public BasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr job,
            int informationClass,
            ref ExtendedLimitInformation information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        internal static IntPtr CreateKillOnCloseJob()
        {
            IntPtr handle = CreateJobObject(IntPtr.Zero, null);
            if (handle == IntPtr.Zero)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                    "Windows could not create the service-owned Job Object.");
            }
            ExtendedLimitInformation limits = new ExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
            if (!SetInformationJobObject(handle, JobObjectExtendedLimitInformation, ref limits,
                (uint)Marshal.SizeOf(typeof(ExtendedLimitInformation))))
            {
                int error = Marshal.GetLastWin32Error();
                CloseHandle(handle);
                throw new System.ComponentModel.Win32Exception(error,
                    "Windows could not configure the service-owned Job Object.");
            }
            return handle;
        }
    }

    internal static class XrayConfigChecks
    {
        private static readonly string[] RequiredPrivateRanges = new[]
        {
            "geoip:private", "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
            "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
            "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
            "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "64:ff9b::/96",
            "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "2002::/16",
            "fc00::/7", "fe80::/10", "ff00::/8"
        };

        public static void ValidateExitNode(string path)
        {
            IDictionary<string, object> root = ReadXrayRoot(path);
            Validation.Require(CountDictionaries(Get(root, "inbounds")) == 0,
                "The reverse exit profile must not expose a static inbound listener.");
            Validation.Require(CountDictionaries(Get(root, "outbounds")) == 3,
                "The reverse exit profile must contain only blackhole, freedom, and REALITY outbounds.");
            IDictionary<string, object> blocked = FindSingleOutbound(root, "blackhole", null);
            IDictionary<string, object> freedom = FindSingleOutbound(root, "freedom", null);
            IDictionary<string, object> relay = FindSingleRealityOutbound(root);
            string blockedTag = RequiredText(blocked, "tag", "The blackhole outbound must have a tag.");
            string freedomTag = RequiredText(freedom, "tag", "The public freedom outbound must have a tag.");

            IDictionary<string, object> relaySettings = AsDictionary(Get(relay, "settings"));
            IDictionary<string, object> reverse = AsDictionary(Get(relaySettings, "reverse"));
            Validation.Require(reverse != null && string.Equals(Get(reverse, "tag") as string, "reverse-in", StringComparison.Ordinal),
                "The exit-node REALITY outbound must declare reverse.tag as reverse-in.");

            ValidateProtectedRoute(root, "reverse-in", blockedTag, freedomTag);
            ValidateFreedomFinalRules(freedom);
            XrayNetworkInspector.InspectExitRelay(path);
        }

        public static void ValidateVpnClient(string path)
        {
            IDictionary<string, object> root = ReadXrayRoot(path);
            Validation.Require(CountDictionaries(Get(root, "inbounds")) == 1,
                "The client profile must contain only its managed TUN inbound.");
            Validation.Require(CountDictionaries(Get(root, "outbounds")) == 2,
                "The client profile must contain only blackhole and REALITY outbounds.");
            IDictionary<string, object> tun = null;
            foreach (IDictionary<string, object> inbound in DictionaryList(Get(root, "inbounds")))
            {
                if (!string.Equals(Get(inbound, "protocol") as string, "tun", StringComparison.Ordinal)) { continue; }
                Validation.Require(tun == null, "The client profile must contain exactly one TUN inbound.");
                tun = inbound;
            }
            Validation.Require(tun != null, "Client Xray config must contain exactly one TUN inbound.");
            string tunTag = RequiredText(tun, "tag", "The TUN inbound must have a tag.");
            IDictionary<string, object> tunSettings = AsDictionary(Get(tun, "settings"));
            Validation.Require(tunSettings != null, "The TUN inbound settings are missing.");
            List<string> routes = StringList(Get(tunSettings, "autoSystemRoutingTable"));
            Validation.Require(routes.Contains("::/0") &&
                (routes.Contains("0.0.0.0/0") || routes.Count >= 9),
                "The managed TUN must install IPv6 and a complete IPv4 route set with only the relay exception.");

            IDictionary<string, object> blocked = FindSingleOutbound(root, "blackhole", null);
            IDictionary<string, object> relay = FindSingleRealityOutbound(root);
            string blockedTag = RequiredText(blocked, "tag", "The blackhole outbound must have a tag.");
            string relayTag = RequiredText(relay, "tag", "The REALITY outbound must have a tag.");
            ValidateProtectedRoute(root, tunTag, blockedTag, relayTag);
            XrayNetworkInspector.InspectVpn(path);
        }

        private static IDictionary<string, object> ReadXrayRoot(string path)
        {
            if (!File.Exists(path))
            {
                throw new ServiceConfigurationException("Provisioned Xray configuration is missing.");
            }
            FileInfo info = new FileInfo(path);
            if (info.Length <= 1 || info.Length > 4 * 1024 * 1024)
            {
                throw new ServiceConfigurationException("Provisioned Xray configuration has an invalid size.");
            }
            object parsed = JsonFile.ParseObject(File.ReadAllText(path, Encoding.UTF8));
            IDictionary<string, object> root = AsDictionary(parsed);
            Validation.Require(root != null, "The Xray configuration root must be an object.");
            return root;
        }

        private static IDictionary<string, object> FindSingleOutbound(
            IDictionary<string, object> root,
            string protocol,
            string requiredTag)
        {
            IDictionary<string, object> found = null;
            foreach (IDictionary<string, object> outbound in DictionaryList(Get(root, "outbounds")))
            {
                if (!string.Equals(Get(outbound, "protocol") as string, protocol, StringComparison.Ordinal)) { continue; }
                if (requiredTag != null && !string.Equals(Get(outbound, "tag") as string, requiredTag, StringComparison.Ordinal)) { continue; }
                Validation.Require(found == null, "The Xray profile contains a duplicate protected outbound.");
                found = outbound;
            }
            Validation.Require(found != null, "The Xray profile is missing a required " + protocol + " outbound.");
            return found;
        }

        private static IDictionary<string, object> FindSingleRealityOutbound(IDictionary<string, object> root)
        {
            IDictionary<string, object> found = null;
            foreach (IDictionary<string, object> outbound in DictionaryList(Get(root, "outbounds")))
            {
                if (!string.Equals(Get(outbound, "protocol") as string, "vless", StringComparison.Ordinal)) { continue; }
                IDictionary<string, object> stream = AsDictionary(Get(outbound, "streamSettings"));
                if (stream == null || !string.Equals(Get(stream, "security") as string, "reality", StringComparison.Ordinal)) { continue; }
                Validation.Require(found == null, "The Xray profile contains multiple VLESS REALITY outbounds.");
                found = outbound;
            }
            Validation.Require(found != null, "The Xray profile is missing its VLESS REALITY outbound.");
            return found;
        }

        private static void ValidateProtectedRoute(
            IDictionary<string, object> root,
            string inboundTag,
            string blockedTag,
            string permittedTag)
        {
            IDictionary<string, object> routing = AsDictionary(Get(root, "routing"));
            Validation.Require(routing != null, "The Xray routing object is missing.");
            List<IDictionary<string, object>> rules = new List<IDictionary<string, object>>(DictionaryList(Get(routing, "rules")));
            int privateDomainIndex = -1;
            int privateIpIndex = -1;
            int permittedIndex = -1;
            int protectedRuleCount = 0;
            for (int i = 0; i < rules.Count; i++)
            {
                IDictionary<string, object> rule = rules[i];
                if (!StringList(Get(rule, "inboundTag")).Contains(inboundTag)) { continue; }
                protectedRuleCount++;
                Validation.Require(string.Equals(Get(rule, "type") as string, "field", StringComparison.Ordinal),
                    "Every protected inbound route must be a field rule.");
                string outboundTag = Get(rule, "outboundTag") as string;
                if (string.Equals(outboundTag, blockedTag, StringComparison.Ordinal))
                {
                    if (StringList(Get(rule, "domain")).Contains("geosite:private") &&
                        !HasSelector(rule, "ip") && !HasSelector(rule, "port") &&
                        !HasSelector(rule, "network") && !HasSelector(rule, "protocol"))
                    {
                        Validation.Require(privateDomainIndex < 0, "The protected inbound has duplicate private-domain rules.");
                        privateDomainIndex = i;
                    }
                    if (ContainsAll(StringList(Get(rule, "ip")), RequiredPrivateRanges) &&
                        !HasSelector(rule, "domain") && !HasSelector(rule, "port") &&
                        !HasSelector(rule, "network") && !HasSelector(rule, "protocol"))
                    {
                        Validation.Require(privateIpIndex < 0, "The protected inbound has duplicate private-address rules.");
                        privateIpIndex = i;
                    }
                }
                else if (string.Equals(outboundTag, permittedTag, StringComparison.Ordinal) &&
                    !HasSelector(rule, "domain") && !HasSelector(rule, "ip") && !HasSelector(rule, "port") &&
                    !HasSelector(rule, "network") && !HasSelector(rule, "protocol"))
                {
                    Validation.Require(permittedIndex < 0, "The protected inbound has duplicate catch-all routes.");
                    permittedIndex = i;
                }
            }
            Validation.Require(protectedRuleCount == 3,
                "The protected inbound must have only private-domain block, private-address block, and one catch-all route.");
            Validation.Require(privateDomainIndex >= 0, "The protected inbound must block geosite:private.");
            Validation.Require(privateIpIndex >= 0, "The protected inbound must block all required private/special IP ranges.");
            Validation.Require(permittedIndex > privateDomainIndex && permittedIndex > privateIpIndex,
                "Private destination blocks must precede the protected inbound catch-all route.");
        }

        private static void ValidateFreedomFinalRules(IDictionary<string, object> freedom)
        {
            IDictionary<string, object> settings = AsDictionary(Get(freedom, "settings"));
            Validation.Require(settings != null, "The exit freedom outbound settings are missing.");
            Validation.Require(string.Equals(Get(settings, "domainStrategy") as string, "UseIP", StringComparison.Ordinal),
                "The exit freedom outbound must resolve domains before applying final IP rules.");
            List<IDictionary<string, object>> rules = new List<IDictionary<string, object>>(DictionaryList(Get(settings, "finalRules")));
            Validation.Require(rules.Count == 4, "The exit freedom outbound requires exactly four ordered finalRules.");
            HashSet<string> blockedPorts = new HashSet<string>(
                ((Get(rules[0], "port") as string) ?? string.Empty).Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries),
                StringComparer.Ordinal);
            Validation.Require(string.Equals(Get(rules[0], "action") as string, "block", StringComparison.Ordinal) &&
                string.Equals(Get(rules[0], "network") as string, "tcp", StringComparison.Ordinal) &&
                blockedPorts.Contains("22") && blockedPorts.Contains("25") && blockedPorts.Contains("465") && blockedPorts.Contains("587"),
                "The first exit freedom finalRule must block SSH and mail submission ports.");
            Validation.Require(string.Equals(Get(rules[1], "action") as string, "block", StringComparison.Ordinal) &&
                ContainsAll(StringList(Get(rules[1], "ip")), RequiredPrivateRanges),
                "The second exit freedom finalRule must block private/special IP ranges.");
            Validation.Require(string.Equals(Get(rules[2], "action") as string, "allow", StringComparison.Ordinal) &&
                StringList(Get(rules[2], "ip")).Contains("!geoip:private") &&
                string.Equals(Get(rules[2], "network") as string, "tcp,udp", StringComparison.Ordinal),
                "The third exit freedom finalRule must explicitly allow TCP/UDP to non-private destinations.");
            Validation.Require(string.Equals(Get(rules[3], "action") as string, "block", StringComparison.Ordinal) &&
                !HasSelector(rules[3], "ip") && !HasSelector(rules[3], "port") &&
                !HasSelector(rules[3], "network"),
                "The exit freedom finalRules must end with an unconditional block.");
        }

        private static bool HasSelector(IDictionary<string, object> rule, string key)
        {
            object value = Get(rule, key);
            if (value == null) { return false; }
            string text = value as string;
            if (text != null) { return text.Length > 0; }
            IEnumerable enumerable = value as IEnumerable;
            if (enumerable == null) { return true; }
            foreach (object ignored in enumerable) { return true; }
            return false;
        }

        private static bool ContainsAll(List<string> values, IEnumerable<string> required)
        {
            foreach (string item in required)
            {
                if (!values.Contains(item)) { return false; }
            }
            return true;
        }

        private static string RequiredText(IDictionary<string, object> dictionary, string key, string message)
        {
            string value = Get(dictionary, key) as string;
            Validation.Require(!string.IsNullOrWhiteSpace(value), message);
            return value;
        }

        private static object Get(IDictionary<string, object> dictionary, string key)
        {
            object value;
            return dictionary != null && dictionary.TryGetValue(key, out value) ? value : null;
        }

        private static IDictionary<string, object> AsDictionary(object value)
        {
            return value as IDictionary<string, object>;
        }

        private static IEnumerable<IDictionary<string, object>> DictionaryList(object value)
        {
            IEnumerable sequence = value as IEnumerable;
            if (sequence == null || value is string) { yield break; }
            foreach (object item in sequence)
            {
                IDictionary<string, object> dictionary = AsDictionary(item);
                if (dictionary != null) { yield return dictionary; }
            }
        }

        private static int CountDictionaries(object value)
        {
            int count = 0;
            foreach (IDictionary<string, object> ignored in DictionaryList(value)) { count++; }
            return count;
        }

        private static List<string> StringList(object value)
        {
            List<string> result = new List<string>();
            string single = value as string;
            if (single != null) { result.Add(single); return result; }
            IEnumerable sequence = value as IEnumerable;
            if (sequence == null) { return result; }
            foreach (object item in sequence)
            {
                string text = item as string;
                if (text != null) { result.Add(text); }
            }
            return result;
        }
    }

    internal static class WorkerHost
    {
        public static int RunConsole(Action start, Action stop)
        {
            using (ManualResetEvent finished = new ManualResetEvent(false))
            {
                ConsoleCancelEventHandler handler = delegate(object sender, ConsoleCancelEventArgs args)
                {
                    args.Cancel = true;
                    finished.Set();
                };
                Console.CancelKeyPress += handler;
                try
                {
                    start();
                    Console.WriteLine("Service worker is running in console mode. Press Ctrl+C to stop.");
                    finished.WaitOne();
                    return 0;
                }
                finally
                {
                    stop();
                    Console.CancelKeyPress -= handler;
                }
            }
        }
    }
}
