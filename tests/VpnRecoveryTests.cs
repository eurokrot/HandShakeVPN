using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using HandShake.Services;
using HandShake.ServiceIntegration;

internal static class VpnRecoveryTests
{
    private static int checks;

    private static void Check(bool value, string message)
    {
        if (!value) throw new Exception(message);
        checks++;
    }

    public static int Main()
    {
        try {
            // The existing state file can still say stopped while a new tunnel
            // starts or while a previous failed cleanup is being retried.
            ServiceStatus stale = new ServiceStatus { state = "stopped", trafficSafety = "no-active-tunnel",
                xrayRunning = false, updatedAtUtc = DateTime.UtcNow.AddMinutes(-1).ToString("o") };
            VpnDisconnectOperation pending = new VpnDisconnectOperation("new-request");
            Check(stale.state == "stopped" && pending.CompletedStatus == null,
                "A stale stopped status acknowledged a disconnect before its own cleanup.");

            for (int failure = 0; failure < 3; failure++) {
                VpnDisconnectOperation operation = new VpnDisconnectOperation("fault-" + failure);
                List<string> events = new List<string>();
                int selected = failure;
                Action stop = delegate { events.Add("stop"); if (selected == 0) throw new IOException("Injected stop failure"); };
                Action restore = delegate { events.Add("restore"); if (selected == 1) throw new IOException("Injected residual cleanup failure"); };
                Action unprotect = delegate { events.Add("unprotect"); if (selected == 2) throw new IOException("Injected native cleanup failure"); };
                bool failed = false;
                try { operation.CompleteCleanup(stop, restore, unprotect); } catch (IOException) { failed = true; }
                Check(failed && operation.CompletedStatus == null, "A failed cleanup was acknowledged.");
                Check(events.Count == failure + 1, "Cleanup continued beyond a failed safety boundary.");
                Check(failure == 2 || !events.Contains("unprotect"), "Native protection was removed before cleanup confirmation.");
                operation.CompleteCleanup(delegate { }, delegate { }, delegate { });
                Check(operation.CompletedStatus != null && operation.CompletedStatus.sessionId == "fault-" + failure,
                    "Failed cleanup could not be retried independently of API or activation.");
            }

            using (ManualResetEvent restoring = new ManualResetEvent(false))
            using (ManualResetEvent release = new ManualResetEvent(false)) {
                VpnDisconnectOperation operation = new VpnDisconnectOperation("slow-cleanup");
                Exception threadError = null;
                bool protectionRemoved = false;
                Thread worker = new Thread(delegate() {
                    try {
                        operation.CompleteCleanup(delegate { }, delegate { restoring.Set(); release.WaitOne(); },
                            delegate { protectionRemoved = true; });
                    } catch (Exception error) { threadError = error; }
                });
                worker.Start();
                try {
                    Check(restoring.WaitOne(5000), "Slow cleanup fixture did not start.");
                    Check(operation.CompletedStatus == null && !protectionRemoved,
                        "Disconnect acknowledged or removed protection while restoration was still running.");
                } finally { release.Set(); }
                Check(worker.Join(5000) && threadError == null, "Cleanup worker did not finish.");
                ServiceStatus done = operation.CompletedStatus;
                Check(done != null && protectionRemoved && done.state == "session-disabled" &&
                    done.trafficSafety == "no-active-tunnel" && done.xrayRunning == false && done.sessionId == "slow-cleanup",
                    "Verified cleanup did not return its own current completion.");
                DateTime updated;
                Check(DateTime.TryParse(done.updatedAtUtc, out updated) && DateTime.UtcNow - updated.ToUniversalTime() < TimeSpan.FromSeconds(5),
                    "Verified disconnect returned an old timestamp.");
            }
            Console.WriteLine("PASS: " + checks + " isolated VPN disconnect checks (stale status, fault boundaries, retry, slow cleanup).");
            return 0;
        } catch (Exception error) {
            Console.Error.WriteLine("VPN recovery checks failed: " + error.Message);
            return 1;
        }
    }
}
