using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace HandShake.Release
{
    // The service and installer share cleanup, including upgrade rollback.
    // Only this provider's filters are removed; other VPNs are untouched.
    public static class WfpCleanup
    {
        public static readonly Guid ProviderKey = new Guid("597b2665-25ef-4824-b2a6-5b436cce10a1");
        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] private static extern uint FwpmEngineOpen0(string server, uint authentication, IntPtr identity, IntPtr session, out IntPtr engine);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr handle);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr handle, uint requested, out IntPtr entries, out uint count);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr handle);
        [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll")] private static extern void FwpmFreeMemory0(ref IntPtr pointer);
        private static void Check(uint code)
        { if (code != 0) throw new InvalidOperationException("HandShake WFP cleanup failed (0x" + code.ToString("X8") + "). Networking protection was retained."); }
        public static void RemoveOwned(Guid provider)
        {
            if (IntPtr.Size != 8) throw new InvalidOperationException("WFP cleanup requires x64.");
            IntPtr engine; Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out engine));
            try {
                Check(FwpmTransactionBegin0(engine, 0));
                try {
                    IntPtr enumeration; Check(FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out enumeration));
                    List<Guid> keys = new List<Guid>();
                    try {
                        uint count; IntPtr entries;
                        do {
                            Check(FwpmFilterEnum0(engine, enumeration, 256, out entries, out count));
                            try {
                                for (int i = 0; i < count; i++) {
                                    IntPtr filter = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                                    IntPtr owner = Marshal.ReadIntPtr(filter, 40);
                                    if (owner != IntPtr.Zero && (Guid)Marshal.PtrToStructure(owner, typeof(Guid)) == provider)
                                        keys.Add((Guid)Marshal.PtrToStructure(filter, typeof(Guid)));
                                }
                            } finally { FwpmFreeMemory0(ref entries); }
                        } while (count != 0);
                    } finally { FwpmFilterDestroyEnumHandle0(engine, enumeration); }
                    foreach (Guid value in keys) { Guid key = value; Check(FwpmFilterDeleteByKey0(engine, ref key)); }
                    Check(FwpmTransactionCommit0(engine));
                } catch { FwpmTransactionAbort0(engine); throw; }
            } finally { FwpmEngineClose0(engine); }
        }
    }
}
