using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using HandShake.Services;
using HandShake.ServiceIntegration;

internal static class ServiceIpcDeadlineTests
{
    private static int checks;
    private static void Check(bool condition, string name)
    { if (!condition) throw new Exception(name); checks++; Console.WriteLine("OK: " + name); }

    private static byte[] Read(Stream stream, int size)
    {
        byte[] value = new byte[size]; int offset = 0;
        while (offset < size)
        {
            IAsyncResult pending = stream.BeginRead(value, offset, size - offset, null, null);
            if (!pending.AsyncWaitHandle.WaitOne(4000)) throw new Exception("Test reader timed out");
            int count = stream.EndRead(pending); pending.AsyncWaitHandle.Close();
            if (count == 0) throw new EndOfStreamException();
            offset += count;
        }
        return value;
    }

    private static void DripFrameMustExpire()
    {
        string name = "HS-Ipc-Deadline-" + Guid.NewGuid().ToString("N");
        using (LocalServicePipeHost host = new LocalServicePipeHost(name, new string[0], null, null, 600))
        using (NamedPipeServerStream server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
        {
            MethodInfo reader = typeof(LocalServicePipeHost).GetMethod("ReadFrame", BindingFlags.Instance | BindingFlags.NonPublic);
            long elapsed = 0; bool rejected = false;
            Task reading = Task.Run(delegate {
                server.WaitForConnection(); Stopwatch time = Stopwatch.StartNew();
                try { reader.Invoke(host, new object[] { server }); }
                catch (TargetInvocationException error) { rejected = error.InnerException is IOException; }
                elapsed = time.ElapsedMilliseconds;
            });
            using (NamedPipeClientStream client = new NamedPipeClientStream(".", name, PipeDirection.InOut))
            {
                client.Connect(3000);
                try
                {
                    foreach (byte value in BitConverter.GetBytes(3)) { Thread.Sleep(100); client.WriteByte(value); }
                    for (int index = 0; index < 3; index++) { Thread.Sleep(150); client.WriteByte(65); }
                }
                catch (IOException) { }
            }
            Check(reading.Wait(2000), "Slow request cancellation releases the server reader");
            Check(rejected, "Small periodic chunks cannot renew the request deadline");
            Check(elapsed >= 500 && elapsed < 1000, "One deadline covers header and body");
            Check(!server.IsConnected, "Expired channel is disposed, not left with pending reads");
        }
    }

    private static void ResponseAndAcknowledgementShareDeadline()
    {
        string name = "HS-Ipc-Reply-" + Guid.NewGuid().ToString("N");
        using (LocalServicePipeHost host = new LocalServicePipeHost(name, new string[0], null, null, 500))
        using (NamedPipeServerStream server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
        {
            MethodInfo writer = typeof(LocalServicePipeHost).GetMethod("WriteFrame", BindingFlags.Instance | BindingFlags.NonPublic);
            bool rejected = false; long elapsed = 0;
            Task writing = Task.Run(delegate {
                server.WaitForConnection(); Stopwatch time = Stopwatch.StartNew();
                try { writer.Invoke(host, new object[] { server, new byte[] { 1, 2, 3 } }); }
                catch (TargetInvocationException error) { rejected = error.InnerException is IOException; }
                elapsed = time.ElapsedMilliseconds;
            });
            using (NamedPipeClientStream client = new NamedPipeClientStream(".", name, PipeDirection.InOut))
            {
                client.Connect(3000);
                Check(BitConverter.ToInt32(Read(client, 4), 0) == 3 && Read(client, 3).Length == 3, "Normal response framing is unchanged");
                Check(writing.Wait(1500), "Missing response ACK cannot retain a worker indefinitely");
            }
            Check(rejected && elapsed >= 400 && elapsed < 1000, "Response delivery and ACK use a bounded combined deadline");
        }
    }

    private static void SlowPeerDoesNotBlockNormalOwner(string scratch)
    {
        string ownerDirectory = Path.Combine(scratch, "broker");
        Directory.CreateDirectory(ownerDirectory);
        File.WriteAllText(Path.Combine(ownerDirectory, "owner.sid"), WindowsIdentity.GetCurrent().User.Value);
        string name = "HS-Ipc-Pool-" + Guid.NewGuid().ToString("N");
        ServiceLog log = new ServiceLog(Path.Combine(scratch, "isolated-ipc.log"));
        using (LocalServicePipeHost host = new LocalServicePipeHost(name, new string[0],
            delegate { return new ServiceStatus { state = "idle" }; }, log, 2500))
        {
            host.Start();
            using (NamedPipeClientStream slow = new NamedPipeClientStream(".", name, PipeDirection.InOut))
            {
                slow.Connect(3000); slow.WriteByte(1);
                Stopwatch time = Stopwatch.StartNew();
                using (NamedPipeClientStream ordinary = new NamedPipeClientStream(".", name, PipeDirection.InOut))
                {
                    ordinary.Connect(3000);
                    byte[] frame = ServiceWireCodec.Encode(new ServiceRequest { protocolVersion = 1,
                        requestId = Guid.NewGuid().ToString("N"), command = ServiceProtocol.GetStatus, payload = new Dictionary<string,object>() });
                    ordinary.Write(BitConverter.GetBytes(frame.Length), 0, 4); ordinary.Write(frame, 0, frame.Length);
                    byte[] response = Read(ordinary, BitConverter.ToInt32(Read(ordinary, 4), 0));
                    ordinary.WriteByte(ServiceProtocol.ResponseAcknowledgement);
                    ServiceResponse value = ServiceWireCodec.Decode<ServiceResponse>(response);
                    Check(value.success && value.status.state == "idle", "Real Windows pipe caller remains authorized");
                    Check(time.ElapsedMilliseconds < 1500, "Normal owner command succeeds while another peer drips a request");
                }
                Stopwatch stop = Stopwatch.StartNew(); host.Stop();
                Check(stop.ElapsedMilliseconds < 2000, "Stop cancels all pending pipe workers promptly");
                host.Start(); host.Stop();
                Check(true, "Bounded worker pool can restart cleanly");
            }
        }
    }

    private static int Main(string[] args)
    {
        try
        {
            DripFrameMustExpire(); ResponseAndAcknowledgementShareDeadline(); SlowPeerDoesNotBlockNormalOwner(args[0]);
            Check(LocalServicePipeHost.NetworkClientRejectionEnabledForSelfTest(), "Network-logon rejection preserved");
            Check(LocalServicePipeHost.PipeAclTransitionsToOwnerOnlyForSelfTest(), "Existing enrollment/owner ACL policy preserved");
            Console.WriteLine("PASS: " + checks + " IPC security checks on actual Windows pipes."); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
