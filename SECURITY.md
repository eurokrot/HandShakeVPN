# Security status of this source snapshot

This is a preview and a partial source publication. An internal security review on
3 October 2026 identified issues requiring follow-up. Publication does not fix them.
The published shared service IPC implementation now uses one monotonic deadline
for the whole request header and body, a bounded response/acknowledgement deadline,
and four receive workers. Profile mutations remain serialized and owner/SCM checks
are preserved. Windows named-pipe deadline, slow-peer isolation, acknowledgement
and shutdown regression checks were added. A process running as the owner can still
attempt to exhaust legitimate operations; this is not a promise of immunity to all
local denial of service. Full Windows boot/crash/network-change
and external IPv6 validation, trusted Authenticode release signing and comprehensive
dependency verification are also pending. No statement of an independent audit or
absence of vulnerabilities is made.

On October 4 preview.10 passed real Windows TUN HTTPS exit, UDP DNS and 1 MiB
download checks through infrastructure and participant exits, followed by explicit
disconnect and successful ordinary HTTPS. A forced-Xray-crash check kept direct
traffic blocked but failed to restore the tunnel within 35 seconds, with a TUN
adapter creation error. Preview.11 pins official Windows Xray 26.9.30, which restores
opening an existing Wintun adapter. The same forced-crash and service-stop/restart
check passed on the installed preview.11: direct IPv4/DNS remained blocked,
tunnel HTTPS recovered, Node Service remained running, and disconnect restored
ordinary networking. NL/FR/participant HTTPS, UDP DNS and 1 MiB checks also passed
again on preview.11. These checks on one Windows PC do not establish complete
Windows 10/11 boot, uninstall, update-failure, network-change or external IPv6
coverage, or explain the historical incidents whose original states were lost.

Preview.12 adds verified own-disconnect completion, strictly scoped managed-TUN
residual cleanup before native protection removal, and a durable protected installer
journal. Isolated fault tests cover bounded recovery, adapter identity changes,
partial cleanup retry, interrupted installer phases, backup retention, invalid
journals and atomic notice replacement. These fixtures do not constitute live
power-loss, reboot or clean-uninstall evidence. Automatic whole-installation
rollback after power loss remains unavailable.

One self-targeted SYSTEM background update preview.11 -> preview.12 completed on
October 4 with both services running. Installed preview.12 fault/network checks
are in progress at this snapshot. No fresh provider-side Russian network test is
claimed. Previous preview.11 success is not treated as preview.12 coverage.

The official update verifier requires the pinned public key and checks version,
installer hash and size. Authenticode publisher verification is a separate release
process. A fork or locally rebuilt unsigned installer is not an authorized update.

The closed backend, Node Service worker, Linux Agent and administrative client are
outside this source publication. Their internal review findings and exploit
reproductions are deliberately not distributed in this public source package.

For a security concern, contact the project maintainer through a private channel
they establish on the GitHub repository. No reporting email or response SLA is
invented in this snapshot. Avoid posting credentials or participant information.
