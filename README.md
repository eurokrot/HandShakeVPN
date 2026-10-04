# HandShake VPN — selected Windows sources

This repository contains the selected Windows source components of HandShake VPN
0.7-preview.12. It is a **partial source publication**, not the full product source.

## Published components

| Folder | Contents |
| --- | --- |
| src | Compact Windows GUI, map, localization, activation/API integration, update check |
| services | VPN Service, shared IPC/runtime helpers, TUN/DNS policy, WFP kill switch, standalone network recovery |
| shared | Protocol contracts, release/version checks, public update verification key, WFP cleanup |
| installer | Installer source, allowlisted payload extraction, ACL/service setup, rollback, interruption detection |
| relay/templates | Unfilled VLESS + REALITY examples; no working credentials |
| tests | Core, IPC, signing, scoped WFP, bounded disconnect/TUN recovery and isolated installer fault checks |

Node Service worker, its background updater/uplink binding, backend, Linux Agent,
Android client and administrative panel are **not included**. The GUI/shared code
contains integration contracts for Node Service, and the permitted Xray exit
template describes the transport. Those contracts do not publish the Node worker.

## Product behavior and privacy boundaries

The installed product uses two independent Windows services. Closing the GUI or
disconnecting the personal VPN does not stop an enabled Node Service. Exit-node
participation is governed by the recorded activation consent and service policy.
The closed Node implementation cannot be independently rebuilt from this repository.

The Windows client sends activation/device and application diagnostic data to a
control plane. The current administrative Live Traffic display is intended to show
upload/download volumes and the selected servers. Diagnostic event codes and
technical live-watch message contracts are visible in the published client/service
source; their presence does not establish that every watch function is operational.
Backend implementation and its storage behavior are outside this publication.
See the included privacy draft for the implemented data handling and remaining
release work; publishing this source does not make that draft effective.

VLESS + REALITY remains the transport. The current MVP uses a reverse relay to reach
exit participants behind NAT/CGNAT. This is not a Tor anonymity implementation.
The current personal VPN carries IPv4 and blocks IPv6 rather than supplying full IPv6 connectivity.

## Build the published components

Use Windows 10/11 x64 with .NET Framework 4.x and PowerShell. No publisher secret
or private key is required to build the GUI and VPN Service:

```powershell
.\build.ps1
.\services\build.ps1
& '.\dist\HandShake VPN.exe' --self-test
.\tests\Test-ReleaseSigning.ps1
.\tests\Test-ServiceIpcSecurity.ps1
.\tests\Test-VpnRecovery.ps1
.\tests\Test-VpnTunCleanup.ps1
.\tests\Test-Installer-InterruptionJournal.ps1
.\tests\Test-Installer-RecoveryStaging.ps1
```

These builds/tests do not install services or change firewall/routing settings. IPC
regression tests use unique pipes and redirected owner storage. They retain the
production native pipe factory, medium integrity label and caller authorization.
Recovery tests inject network/process operations or redirect
installer paths to disposable directories; they do not install or stop live services,
change live routes, or require the closed Node worker. The recovery-staging test
uses non-executable fixture files derived from the public installer allowlist/pins.
GUI smoke test opens test windows briefly. The build creates a placeholder client.config from
src/client.config.example; configure your own HTTPS control plane for live use.
WFP runtime requires a protected numeric public HTTPS control endpoint. Actual
activation, catalog and VPN use require a compatible backend and enrolled nodes.

## Installer boundary

The installer source is included for inspection and development. A complete Setup
requires the separately obtained closed HandShakeNodeService.exe and official
Xray 26.9.30 assets, in addition to the published GUI/VPN Service outputs.
No closed binary or third-party executable is shipped in this source archive.
The unfilled relay templates are transport examples, not authoritative current
runtime configurations. The VPN Service's typed configuration builder defines
the current routing, DNS, IPv6 blocking and kill-switch behavior.

```powershell
.\installer\build-installer.ps1 `
  -ServicesDirectory 'C:\separate-build-inputs\services' `
  -XrayDirectory 'C:\separate-build-inputs\xray-26.9.30' `
  -UnsignedDevelopmentBuild
```

The separate services input must contain VPN Service, Node Service and
Firewall-Policy.ps1. Third-party asset lengths/hashes are pinned in the existing
packager. Unsigned development Setup is **not accepted** by the official updater.
For a fork, choose a separate signing identity and matching public trust key;
never add a publisher/private signing key to Git. The public update verification
key in shared is intentionally public and cannot sign a release.

These sources do not grant access to administrative APIs, servers or SSH accounts.
Security review is ongoing; see SECURITY.md before interpreting this snapshot as
a production security guarantee. See PUBLICATION_MANIFEST.json for file provenance
and the three build-script adaptations plus one isolated-test-fixture adaptation
applied to the export only.

## Recovery and verification limits

Preview.12 validates completion of its own disconnect cleanup rather than an old
status file. Managed TUN cleanup verifies the adapter GUID/driver, restores only
its DNS/routes/addresses, and confirms cleanup before removing native protection.
Installer checkpoints use flushed atomic journals in protected GUID staging
directories. An interrupted or invalid journal preserves backups and blocks a new
installation/removal until reviewed. Successful commit/rollback checkpoints do not
block later operations. This is safe interruption detection; automatic file/SCM
rollback after power loss is not implemented.

On October 4, one real SYSTEM background update from preview.11 to preview.12
completed on the maintainer's Windows PC with both services running. Installed
preview.12 fault/network tests are still being completed; no new test initiated
from a Russian provider is claimed in this snapshot. See SECURITY.md for gaps.
The selected source checkout was built separately: GUI smoke, VPN/firewall
self-tests, 13 Windows pipe checks, 18 disconnect checks, 46 owned-TUN checks,
30 interruption checks, 10 staging/notice checks, locked-cache rollback and
release-signing preflight passed without changing the installed product.

## License

Original HandShake material uses **HandShake Source Inspection License 1.0**;
copyright (c) 2026 Daniil Stagge, Malta. Read LICENSE before building or reusing it.
Inspection, paid security review and private evaluation are permitted. Incorporating
substantial original code into another product or redistributing it requires
separate permission, subject to the license's statutory/GitHub exceptions.
This is source available, not an OSI-approved open-source license.
See legal/LICENSE.ru.md for a Russian explanation. Licensing/support contact:
eurokit.kat@proton.me. Service/privacy documents in legal are release drafts and
do not automatically change the terms accepted by existing users.
Third-party assets retain their upstream notices; see THIRD_PARTY_NOTICES.md.
