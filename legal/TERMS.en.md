# HandShake VPN Terms of Use

Version: terms-draft-2026-10-04. Prepared on 4 October 2026.
Status: draft for review before release; this revision has not taken effect.

## 1. Operator and contacts

HandShake VPN is provided by Daniil Stagge, Malta.
Website: https://handshakevpn.tech/.
Support and data enquiries: eurokit.kat@proton.me.
Additional channels: https://t.me/eurokrot and Discord @eurokrot.
Do not send activation keys, device tokens or passwords in public conversations.

## 2. Service and activation

HandShake routes internet traffic through an available exit node. External
services see the exit's public IP. The current single-exit route does not promise
Tor-style anonymity or that a participant cannot be identified. Locations and
latency are approximate; availability and throughput vary.

The current test requires no registered account. A new free key lasts 7 days
from issuance and is for one device; its expiry is displayed at issuance.
Windows binds using a SHA-256 hash of the system disk identifier, without sending
the original disk serial number to the server. Reinstallation, disk replacement
or transfer requires a binding check. The full key is displayed at issuance;
the database stores its hash and a short prefix.

## 3. Free service and network participation

The free service is based on P2P participation. Before obtaining a key, users
must be informed that their device and internet connection can serve other
participants, including carrying their traffic out through the user's public IP.
This consumes the connection and may affect speed and the ISP's quota. An
external destination sees the public IP of the participant providing the exit.

Closing the window, exiting the tray or disconnecting the personal VPN does not
stop Node Service. The administrator controls the node's server admission and
may suspend its use. Accepting general terms does not replace separate consent
where required for a particular processing activity.

To stop participation, contact support to disable your node or uninstall
HandShake. A local participation switch may also be used where the installed
version provides it; not all released builds are assumed to have that switch.
Stopping participation may make the device ineligible for the free P2P network.
It does not remove the right to uninstall, withdraw necessary consent or
exercise data-protection rights.

## 4. Windows services and network configuration

The Windows 10/11 x64 installer adds HandShake VPN Service and a separate
HandShake Node Service under Program Files. Both start automatically with
Windows and run independently of the application window. Installation and
uninstallation require administrator permission.

The personal VPN applies a TUN and traffic-protection rules. Following a fault,
the kill switch can block ordinary internet access until proper disconnection
or recovery. Use Disconnect or Restore ordinary internet. Personal VPN recovery
does not itself mean that Node Service participation has stopped. Do not manually
delete files while services and network rules are still operating.

## 5. Uninstallation

Use Windows Settings → Apps → HandShake VPN or the official uninstaller. It is
designed to stop the product's services, remove its own rules, restore saved
settings and remove its services and shortcuts. If it reports an error, the
operation must not be treated as complete: contact support and use network
recovery. Reinstalling Windows is not the standard way to disconnect the product.

Uninstallation does not automatically erase technical records on the server.
Request data erasure using the contacts in the privacy policy. Expiry of a key
or stopping payment is also not the same as uninstalling the application.

## 6. Subscription and future paid features

The current version is a free test. These terms do not initiate a paid
subscription, automatic renewal or a charge. Premium, additional routes and
other planned features are unavailable until they are actually released.

Before purchase, users will be shown the price and currency, duration, features,
P2P participation conditions, any automatic renewal, cancellation method and
applicable refund terms. Paid access requires a separate purchase action.
Accepting free-service terms does not authorize charges. Mandatory consumer
rights and the applicable payment-platform rules remain unaffected.

## 7. Acceptable use

Do not use the service for unauthorized access, attacks, spam, malware
distribution or other unlawful activity. Do not attempt access to participants'
local networks or files, bypass authentication, forge updates or disrupt the
network. Users must follow applicable law and their ISP's terms.

The administrator may restrict or revoke access for abuse, compromised keys or
to protect the network. Contact support for an explanation and review.
Blocking does not remove data-protection rights or mandatory refund rights.

## 8. Data and updates

The privacy policy describes technical data processing. The administrator can
access activation, device and connection data, diagnostic events and technical
traffic-usage counters. Product updates may download and install in the
background; an offline device's task can wait for its next connection. Installing
an update can briefly interrupt the product's own services.

A client update is not automatic consent to every new data-processing activity.
Material changes to terms must be communicated. Where renewed consent is needed,
the corresponding processing must not start before it is obtained. Effective
revisions must be versioned and dated, with previous versions retained for review.

## 9. Limitations and applicable law

The service depends on nodes, servers, ISPs and equipment. Test builds can contain
errors; constant speed and uninterrupted availability are not guaranteed. This
does not exclude liability or rights that applicable law does not permit to be
excluded.

Malta law applies, preserving mandatory protections applicable to the user,
including consumer rights and jurisdiction rules. Contact the operator first
with enquiries or disputes. GitHub source access has a separate source license.
