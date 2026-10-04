# HandShake VPN Privacy Policy

Version: privacy-draft-2026-10-04. Prepared on 4 October 2026.
Status: review draft; primary-record and backup retention must be approved and
implemented before a release revision takes effect.

## 1. Responsibility and contacts

Service operator and data controller: Daniil Stagge, Malta.
Data enquiries: eurokit.kat@proton.me.
Support: https://t.me/eurokrot and Discord @eurokrot.
Website: https://handshakevpn.tech/.

## 2. Website and activation data

Key issuance processes the observed IP, issuance time, accepted-terms version
and acceptance record. Activation stores a key hash, short prefix, access expiry
and status, device binding and applicable consent records. Windows sends a
SHA-256 hash of the system disk identifier, not the original serial number.
Hashes and IPs may still constitute personal data when linkable to a participant.

The current free test requires no account name, email or account password.
A device token authenticates the client; protected local storage retains it,
while the primary database retains its verification hash. Technical components
may process working tunnel credentials; these are not published on the map or
in the public source repository.

## 3. Device, node and connection data

The server processes device identifiers, computer name, OS/build and client
version, time zone, first/last seen times, status and assigned update details.
Network operation uses observed IPs, the original IP where it can be established,
approximate country/city derived from IP, node state, estimated latency and
assigned routes.

Technical counters represent uploaded/downloaded volumes and connection/server
usage. The public map shows approximate location and latency, without IPs,
computer names or keys. The map requires no precise GPS location, street address
or contents of a user's files.

## 4. Administrator access

Authorized administrators can see technical IPs, approximate location, device
identifiers and information, key prefixes, activation status, online state,
routes, client version, node state, updates, diagnostics and traffic counters.
Live Traffic in the mode described here provides technical upload/download
volumes and server usage.

The purposes are access delivery, routing, troubleshooting, abuse prevention
and network administration. These records must not be exposed in public
participant lists. Clearing the visible administrator list can hide a record;
it does not fulfill a personal-data erasure request.

## 5. Diagnostics and traffic content

The server accepts defined application diagnostic event codes, with component,
severity, time and permitted technical descriptions. This does not authorize
uploading arbitrary user files, correspondence or passwords. Administrators
use diagnostics for support and repairs.

The contents of pages, messages, audio and video are not analytics inputs in
the described mode. Encryption between device and exit does not replace HTTPS
to a destination service. Exit nodes and ISPs technically carry connections;
HandShake does not promise to eliminate all external observation.

## 6. Purposes and legal bases

Processing necessary to deliver requested VPN access is intended to rely on
performance of the contract. Limited security and abuse prevention are intended
to rely on legitimate interests after a necessity and rights-balancing assessment.
Where consent is required, it must precede that processing and can be withdrawn.

Accepting service terms is not consent to every analytics activity or new
processing purpose. This policy provides information; merely reading it is not
a substitute for required consent. Support processes information voluntarily
provided in an enquiry. Withdrawal does not invalidate earlier lawful processing,
but stops subsequent processing that relies solely on that consent.

## 7. Recipients and transfers

The operator and authorized administrators have access needed for their roles.
Hosting and network providers supply infrastructure, and exit participants
provide connections. Telegram, Discord and the email provider process support
communications under their own rules when you choose those channels.

The list of infrastructure providers, processing regions and applicable
international-transfer safeguards must be completed before public release.
Do not assume all routing takes place in Malta or the EU: exits can be located
in different countries. Data may be disclosed as required by a binding lawful
request, to the extent applicable.

## 8. Retention: current implementation

Diagnostic events have a programmed 30-day window and a global 5,000-record cap;
old records are pruned when new events are ingested. This is not a statement
that an independent daily cleanup job runs or that backups erase them immediately.

The current test retains activation, device, route, counter, update and technical
audit records after a key expires; a universal scheduled retention purge is not
implemented. A free key's 7-day validity does not determine those records' retention.

Proposed release schedule for approval: device and completed-route records up
to 30 days after access ends; minimal acceptance/security records up to 90 days
where necessary; working backups up to 30 days of rotation. These are proposed
periods, not claims that the procedures are already operational. Until this
schedule is approved and implemented, this document remains a draft rather
than an effective release privacy policy.

Any exception for a specific legal obligation or justified dispute needs an
identified basis and its own period. Indefinite retention of all history
"just in case" is not an intended purpose.

## 9. Access, correction and erasure requests

Email eurokit.kat@proton.me with subject "HandShake — data request". Describe
the access, correction, restriction or erasure requested and provide a safe
device identifier or key prefix if known. Do not send a full key, device token,
password or disk copy. Proportionate verification may be needed to establish
your connection to the device and protect other users' information.

The operator handles current-test requests manually. The administrator's delete
key action revokes access while retaining a technical record, and clear-list
actions hide participants. Neither is itself complete erasure. Uninstalling
also does not automatically erase server history.

Where GDPR applies, requests must be answered within its applicable period,
usually one month; an allowed extension must be communicated with a reason.
Rights can include access, correction, erasure, restriction, objection,
portability where applicable and withdrawal of consent. They do not depend on
a paid subscription. Complaints may be directed to Malta's IDPC:
https://idpc.org.mt/for-individuals/.

## 10. Protection, local storage and changes

Measures include HTTPS, authenticated administrative APIs, access restrictions
on local service files and platform-protected device credentials. This is not
a promise of absence of vulnerabilities. The website stores language preference
in the browser; it does not place the displayed full key in localStorage.

Local settings and technical files may remain in a user profile after
uninstallation. Removing them must not require sending secrets to support.
Changes in processing and purpose require a new version of the policy and
the applicable notices and consents.
