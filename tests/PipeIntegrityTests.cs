using System;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using HandShake.Services;

internal static class PipeIntegrityTests
{
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetKernelObjectSecurity(IntPtr handle, uint information, byte[] descriptor, uint length, out uint needed);
    public static int Main(string[] args)
    {
        string report = args[0];
        string phase = "legacy-create";
        try {
            Type hostType = typeof(LocalServicePipeHost);
            MethodInfo label = hostType.GetMethod("ApplyMediumIntegrityLabel", BindingFlags.Static | BindingFlags.NonPublic);
            MethodInfo securityMethod = hostType.GetMethod("BuildPipeSecurity", BindingFlags.Static | BindingFlags.NonPublic);
            string sid = WindowsIdentity.GetCurrent().User.Value;
            PipeSecurity security = (PipeSecurity)securityMethod.Invoke(null, new object[] { sid });
            bool oldDenied = false;
            using (NamedPipeServerStream oldPipe = new NamedPipeServerStream("HandShake.Label.Legacy." + Guid.NewGuid().ToString("N"),
                PipeDirection.InOut, 4, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 65536, 65536, security)) {
                try { label.Invoke(null, new object[] { oldPipe.SafePipeHandle }); }
                catch (TargetInvocationException exception) {
                    Win32Exception error = exception.InnerException as Win32Exception;
                    if (error == null || error.NativeErrorCode != 5) throw;
                    oldDenied = true;
                }
            }
            if (!oldDenied) throw new Exception("The original missing WRITE_OWNER failure was not reproduced.");
            // Use the actual production factory, not a copy which skips labeling.
            string name = "HandShake.Label.Fixed." + Guid.NewGuid().ToString("N");
            LocalServicePipeHost host = new LocalServicePipeHost(name,
                new string[0], delegate { return null; }, new ServiceLog(report + ".log"));
            MethodInfo create = hostType.GetMethod("CreatePipe", BindingFlags.Instance | BindingFlags.NonPublic);
            NamedPipeServerStream[] pipes = new NamedPipeServerStream[4];
            try {
                for (int i = 0; i < pipes.Length; i++) {
                    phase = "factory-instance-" + i;
                    pipes[i] = (NamedPipeServerStream)create.Invoke(host, new object[] { sid });
                }
                phase = "read-actual-label";
                using (NamedPipeClientStream client = new NamedPipeClientStream(".", name, PipeDirection.InOut)) {
                    client.Connect(3000);
                    uint needed;
                    GetKernelObjectSecurity(pipes[0].SafePipeHandle.DangerousGetHandle(), 0x10, null, 0, out needed);
                    byte[] bytes = new byte[needed];
                    if (!GetKernelObjectSecurity(pipes[0].SafePipeHandle.DangerousGetHandle(), 0x10, bytes, needed, out needed))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    RawSecurityDescriptor actual = new RawSecurityDescriptor(bytes, 0);
                    // .NET Framework's SDDL serializer omits mandatory-label ACEs.
                    // Read the actual kernel ACE: mandatory label=17, NoWriteUp=1,
                    // Medium integrity SID=S-1-16-8192.
                    if (actual.SystemAcl == null || actual.SystemAcl.Count != 1)
                        throw new Exception("The kernel mandatory-label ACL is missing.");
                    GenericAce ace = actual.SystemAcl[0];
                    byte[] aceBytes = new byte[ace.BinaryLength];
                    ace.GetBinaryForm(aceBytes, 0);
                    if ((int)ace.AceType != 17 || ace.AceFlags != AceFlags.None ||
                        BitConverter.ToUInt32(aceBytes, 4) != 1 ||
                        new SecurityIdentifier(aceBytes, 8).Value != "S-1-16-8192")
                        throw new Exception("The kernel mandatory label is not Medium/NoWriteUp.");
                }
            } finally {
                foreach (NamedPipeServerStream pipe in pipes) if (pipe != null) pipe.Dispose();
            }
            File.WriteAllText(report, "PASS: original label setter denied with Win32 5; production factory creates all four instances; actual kernel label is Medium/NoWriteUp. No service/ProgramData/network changes.\r\n");
            return 0;
        } catch (Exception error) {
            while (error.InnerException != null) error = error.InnerException;
            File.WriteAllText(report, "FAIL: phase=" + phase + " admin=" + new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator) +
                " " + error.GetType().Name + ": " + error.Message);
            return 1;
        }
    }
}
