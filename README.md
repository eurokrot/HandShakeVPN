# HandShake VPN — selected Windows sources

This repository contains the selected Windows source components of HandShake VPN
0.7-preview.10. It is a **partial source publication**, not the full product source.

## Published components

| Folder | Contents |
| --- | --- |
| src | Compact Windows GUI, map, localization, activation/API integration, update check |
| services | VPN Service, shared IPC/runtime helpers, TUN configuration, DNS policy, WFP kill switch |
| shared | Protocol contracts, release/version checks, public update verification key, WFP cleanup |
| installer | Installer source, allowlisted payload extraction, ACL/service setup and rollback |
| relay/templates | Unfilled VLESS + REALITY examples; no working credentials |
| tests | Core, signing-preflight and scoped WFP checks |

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
control plane. The published VPN Service contains optional live destination-domain
telemetry for an authenticated administrator's active watch. This is not a claim
that the product never processes destination metadata. Diagnostic event codes and
live event flows are visible in the published client/service source; backend
implementation and its storage behavior are outside this publication.

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
```

These builds/tests do not install services or change firewall/routing settings. IPC
regression tests use unique pipes and redirected owner storage. They preserve the
production authorization logic but do not apply its SYSTEM integrity label from
the ordinary test user. GUI smoke
test opens test windows briefly. The build creates a placeholder client.config from
src/client.config.example; configure your own HTTPS control plane for live use.
WFP runtime requires a protected numeric public HTTPS control endpoint. Actual
activation, catalog and VPN use require a compatible backend and enrolled nodes.

## Installer boundary

The installer source is included for inspection and development. A complete Setup
requires the separately obtained closed HandShakeNodeService.exe and official
Xray 26.9.9 assets, in addition to the published GUI/VPN Service outputs.
No closed binary or third-party executable is shipped in this source archive.
The unfilled relay templates are transport examples, not authoritative current
runtime configurations. The VPN Service's typed configuration builder defines
the current routing, DNS, IPv6 blocking and kill-switch behavior.

```powershell
.\installer\build-installer.ps1 `
  -ServicesDirectory 'C:\separate-build-inputs\services' `
  -XrayDirectory 'C:\separate-build-inputs\xray-26.9.9' `
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
and the three build-script adaptations applied to the export only.

## License

The owner has not selected a source-code license for this snapshot. It is prepared
for source inspection; it is not labelled as a fully open-source product.
Third-party assets retain their upstream notices; see THIRD_PARTY_NOTICES.md.
