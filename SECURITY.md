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

The official update verifier requires the pinned public key and checks version,
installer hash and size. Authenticode publisher verification is a separate release
process. A fork or locally rebuilt unsigned installer is not an authorized update.

The closed backend, Node Service worker, Linux Agent and administrative client are
outside this source publication. Their internal review findings and exploit
reproductions are deliberately not distributed in this public source package.

For a security concern, contact the project maintainer through a private channel
they establish on the GitHub repository. No reporting email or response SLA is
invented in this snapshot. Avoid posting credentials or participant information.
