# PBXSense Agent Development

This repository contains the PBXSense Agent service. It is a FastAPI app that
normalizes PBX data for the PBXSense app.

## Local Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Run in mock mode:

```bash
PBXSENSE_AGENT_MODE=mock uvicorn pbxsense_agent.main:app --host 0.0.0.0 --port 8765 --reload
```

Open:

```text
http://127.0.0.1:8765/home
```

## Running Against Asterisk

```bash
. .venv/bin/activate
PBXSENSE_AGENT_MODE=ami \
ASTERISK_AMI_HOST=127.0.0.1 \
ASTERISK_AMI_PORT=5038 \
ASTERISK_AMI_USERNAME=pbxsense \
ASTERISK_AMI_PASSWORD=your-secret \
  uvicorn pbxsense_agent.main:app --host 0.0.0.0 --port 8765 --reload
```

## Running Tests

The current test suite uses Python `unittest`:

```bash
python -m unittest discover -s tests
```

Run a single test module:

```bash
python -m unittest tests.test_pulse
```

## Project Layout

```text
pbxsense_agent/
  main.py          FastAPI routes, pairing, diagnostics, live WebSocket
  settings.py      Environment parsing and PBX type normalization
  connectors.py    Connector protocol and connector selection
  ami.py           Asterisk AMI connector
  freeswitch.py    FreeSWITCH Event Socket connector
  mock.py          Development fixture connector
  pulse.py         PBXSense Home payload and signal generation
  history.py       CDR and voicemail evidence readers
  live.py          Live event diffing
  version.py       Agent version
scripts/
  setup_docker.sh  Interactive Docker connector setup and startup
  install_common.sh Shared Linux service setup
  install_debian.sh Debian/Ubuntu/Raspberry Pi OS installer entry point
  install_fedora.sh Fedora/RHEL-family installer entry point
  ensure_token.py  Token generator
tests/
  test_pulse.py    Mapping and signal tests
```

## App Contract

The PBXSense app should consume the Agent, not PBX internals:

```text
GET /home
WS  /live
GET /pair
GET /diagnostics
GET /recordings/{recording-id}
POST /push/devices
GET /push/devices/status
POST /push/devices/revoke
```

The app should not talk directly to AMI, ESL, ARI, SIP, SSH, or raw PBX logs.

## Runtime Data Flow

`main.py` owns one central snapshot task. It polls the selected connector once,
enriches Asterisk-family snapshots with local history, advances signal/activity
trackers once, and stores an immutable observation. `/home`, every `/live`
client, and the relay publisher consume that cached state. Do not introduce PBX
polling inside request or WebSocket handlers; doing so can reorder transitions
and makes connector load proportional to connected clients.

`/live` emits a small `heartbeat` event every ten seconds when no PBX data has
changed. The app uses it only as transport liveness; without it, a quiet PBX can
look stale even while WebSocket ping/pong remains healthy.

Feed Signal IDs stay stable for UI updates. Interruptive outage Signals also
carry an occurrence-scoped `notificationId`. Relay idempotency and Android
notification tags use that occurrence so local and FCM copies collapse while a
genuine later outage can notify again.

### Phone-availability notification contract

Per-device Health Signals remain visible and diagnosable in the feed. Push
delivery applies a separate correlation policy so a temporary shared outage on
a large PBX does not generate dozens of notifications:

- hold newly confirmed phone outages for a 15-second correlation window;
- release one affected phone as an individual notification after the window;
- combine two affected phones into one confirmed two-phone notification;
- correlate three or more recently affected phones into one incident;
- update the same Android notification no more than once every 30 seconds;
- suppress per-phone outage and recovery pushes while the PBX or Agent
  connection itself is unavailable;
- require 15 continuous healthy seconds before sending one grouped recovery;
- keep the completed incident in a two-minute cooldown before starting a new
  episode.
- preserve the same phone-outage occurrence through incomplete endpoint
  inventories and throughout the recovery-confirmation window; only sustained,
  explicit reachable evidence can rearm it.

Message wording follows the current affected count. Shared network/PBX wording
is valid only while at least three phones remain unavailable. When the incident
drops to two or one phone, use remaining-phone wording such as **1 phone still
looks unavailable** and explain that the other affected phones recovered. Never
show **A shared network or PBX interruption may be affecting 1 phone**.

Grouped updates use unique event IDs for relay idempotency and one stable
notification tag for Android replacement. The grouped recovery uses that same
tag so it replaces the outage notification instead of stacking beside it.

The relay presence heartbeat is a separate task. Relay requests reuse a verified
HTTPS connection to avoid repeating TLS setup on every heartbeat. The heartbeat
must remain independent of PBX snapshot, history, and signal failures so a slow
connector cannot create a false Agent-lost notification.
Signal relay evaluation runs independently every five seconds rather than after
every PBX snapshot. This preserves the proven `0.6.7-beta` task cadence and
prevents one-second connector polling from multiplying relay work.
Encrypted relay identity persistence is change-aware: an unchanged evaluation
must not repeat AES-GCM encryption or replace the identity file.
The 30-second Asterisk/Grandstream history check compares CDR and security-log
size/mtime plus voicemail-message metadata before reading. Unchanged history
sources must not be reopened or reparsed.
The Docker health check uses the small `curl` client rather than starting a new
Python interpreter every 30 seconds. Keep TLS-aware `/health` behavior in
`docker/healthcheck.sh`; interpreter startup is visible as container CPU usage.
Asterisk and Grandstream snapshots reuse one authenticated AMI session. A socket
or protocol failure closes it immediately; the following poll creates and
authenticates a fresh session.

The optional Secure Internet Relay runs as another independent outbound task.
Keep its command allowlist explicit and bounded. Home data uses a separate
per-device encrypted envelope; the app-held X25519 private key must never be
sent to the Agent or relay. Any new relayed field must remain inside that
envelope and pass the projection/privacy tests. Diagnostics, recordings, and
PBX control remain outside the Internet Relay contract.

## Adding Connectors

Read `docs/CONNECTORS.md` before adding a connector. The short version:

- Implement the `PBXConnector` protocol.
- Return the current neutral snapshot types from `pbxsense_agent/pulse.py`.
- Keep raw PBX details inside diagnostics or `technical` evidence.
- Register the connector in `connector_for_settings()`.
- Add settings to `pbxsense_agent/settings.py` and `.env.example`.
- Add focused tests for connector selection and mapping.

## Release Artifacts

Generated release files belong in `dist/` locally and should be attached to
GitHub Releases instead of committed.

Expected release asset names look like:

```text
dist/
  PBXSenseAgent-<version>-linux-source-installer.tar.gz
```

Release notes should include supported connectors, upgrade notes, and installer
changes.

## Automated GitHub Releases

Pushing to `main` or opening a pull request targeting it triggers
`.github/workflows/release-agent.yml`. It:

1. reads `AGENT_VERSION` from `pbxsense_agent/version.py`;
2. detects an existing `agent-v<version>` release and skips publishing it;
3. installs dependencies and runs the full unit-test suite;
4. builds the Linux source installer with `packaging/linux/build_release.ps1`;
5. generates `SHA256SUMS.txt`; and
6. creates the matching GitHub tag and Release with both assets attached.

When the Agent version already has a tag or release, validation and packaging
still run and the Publish job exits successfully without replacing the existing
release.

On pull requests, the `Test and package` job runs in full and the Publish job is
skipped unconditionally. This makes `Test and package` safe to require in the
`main` branch ruleset.

Functional changes therefore need a new `AGENT_VERSION` before they are pushed
to `main`. Keep the default in `packaging/linux/build_release.ps1` and the
release examples in `README.md` synchronized with it. Breeze beta versions are
published as normal GitHub Releases so server installers remain easy to find.
The workflow also supports a manual retry through `workflow_dispatch`.

Run `python scripts/check_contract.py` before packaging. Release and security CI
also run it automatically; it rejects mismatched Agent/Relay versions, installer
filenames, documented environment defaults, and release documentation.

Release CI also publishes a CycloneDX dependency SBOM and creates GitHub
artifact attestations for installer provenance and the SBOM. The separate
security workflow audits both hashed dependency locks, runs CodeQL's extended
Python queries, builds the production container, and verifies its configured
runtime user is non-root. Keep every action pinned to a full commit SHA; accept
Dependabot action updates only after reviewing the upstream release and commit.
# Reliability contract (Agent 0.6.27-beta / Relay 0.5.21)

Encrypted relay snapshots preserve `connection.kind=reconnecting` when the PBX
is unavailable. The additive `connection.transport=internetRelay` describes the
working transport separately; `connection.pbxReachable` describes PBX health.
Healthy remote snapshots retain the existing `kind=internetRelay` value.

If people, trunks, or queues lose members, `/live` sends a complete
`home_snapshot` instead of partial deltas. Existing consumers must replace all
collections on that event, including when signals or calls also change.

Notification events have a transactional delivery lease and durable completed
recipient token hashes. The event and hourly quota are created atomically;
retries do not charge the durable event quota again. Transient recipient errors
return HTTP 503 so the Agent outbox retries only unfinished recipients. A crashed
sender's lease can be reclaimed after 60 seconds. Permanent recipient failures
are terminal, and legacy deduplication records remain terminal during upgrade.

Delivery is at-least-once: if FCM accepts a send but the process dies before
checkpointing, a retry can repeat it. Stable notification IDs/tags limit visible
duplicates; FCM acceptance does not prove delivery to the handset. No database
transaction can atomically commit an external FCM send.

## Collection and backend concurrency (0.6.27-beta / Relay 0.5.21)

The collector exclusively owns connector/history/tracker mutation, but does not
hold the snapshot publication lock while doing I/O. Readers continue to use the
last complete state. Payload builds are separately serialized and cached only
if their source state is still current. Snapshots include `snapshotObservedAt`
and `snapshotStale`; after the existing freshness window expires, cached data
remains visible but the connection is marked reconnecting. The normal one-second
polling cadence is unchanged.

Diagnostics report collection-in-progress, elapsed seconds, and stalled status.
The watchdog does not start overlapping collectors to replace stuck threads.
AMI commands/login/frame reads and ESL authentication/API replies have absolute
monotonic deadlines using `PBXSENSE_CONNECT_TIMEOUT`, not a fresh allowance for
every incoming byte. A snapshot containing multiple commands can take multiple
command budgets; filesystem work is not forcibly interrupted.

Cloud relay async routes cache their bounded request body on the ASGI loop, then
execute Firebase/database work in a worker with at most 16 backend jobs active
per instance. Request streams are never read from worker event loops. Waiting
requests yield to the server loop, and the in-memory event limiter is protected
against concurrent worker access. Existing Firestore transactions remain the
cross-instance authority for quotas and delivery ownership.

## Snapshot runtime extraction

Agent 0.6.27-beta delegates collection ownership, snapshot publication, payload
caching, freshness and collection diagnostics to `SnapshotRuntime`. PBX and
history policies remain callbacks in `main.py`. See
[the architecture stages](ARCHITECTURE.md) for the completed boundary, preserved
contract, regression expectations and the next small refactors.

Agent 0.6.28-beta extracts `RelayHttpTransport` from the relay client. It accepts
a signing callback rather than owning an identity, and keeps reusable delivery
connections separate from disposable heartbeat connections. The external
protocol and persisted identity/outbox format are unchanged; the cloud relay
does not need redeployment for this Agent-only extraction.

Agent 0.6.29-beta extracts `RelayStateStore` for encrypted identity/outbox files.
The relay client retains state mutation and notification policy. Envelope format,
key derivation, legacy migration, atomic replacement and permissions are
unchanged. Independent persistence tests supplement the existing delivery
regressions; neither the Flutter app nor cloud relay needs a version/deployment
change for this internal boundary.

Agent 0.6.30-beta extracts `RelayNotificationPolicy` for notification eligibility,
deduplication and endpoint incident transitions. Its state and time are supplied
by the caller, and synchronous event callbacks preserve the original durable
queue write points. Enrollment, outbox limits, persistence and delivery remain
in `AgentRelay`. Notification timers, wording and public contracts are unchanged.

Relay 0.5.22 separates signed-request cryptographic verification into
`push_relay/request_auth.py`. Firebase identity lookup, nonce replay claims and
presence updates remain in the application in their original order. The new
module is independently tested and copied into the Cloud Run image; deployment
is separate from Agent/app updates. See the architecture stages for scope.

Relay 0.5.23 extracts event notification coordination into
`push_relay/notification_delivery.py`. Database quota/lease transactions remain
in `app.py`, and synchronous callbacks preserve checkpoint, cleanup and usage
reporting order. The component is independently tested without Firebase.
Agent-status sending is not moved in this step; its shared token helper is.

Relay 0.5.24 moves Agent-status sending into `AgentStatusDelivery` and
notification outcome counters into `NotificationUsageRecorder`. Identity lookup,
heartbeat state transitions, daily usage aggregation and event quota ownership
remain in the application. Injected services permit focused tests without
Firebase; public payloads, preference semantics and write order are unchanged.

Relay 0.5.25 separates `UsageAccounting` and pure dashboard rendering. Database
and clock dependencies are injected into accounting; the renderer consumes the
existing report with a version and cost callback. UTC rollover/archive paths,
counter fields, daily bounds and display sections are preserved. Cost formulas,
report query orchestration and administrator authentication stay in `app.py`.

Relay 0.5.26 moves report query orchestration into `UsageReporter` and cost
configuration/formulas into `RelayCostModel`. Existing query/output limits,
report fields, environment variables, units and projection rules are retained.
Administrator authorization stays at the route boundary. These modules can be
tested without Firebase initialization; both are included in the relay image.

Relay 0.5.27 completes the local cloud-boundary extraction: `routes.py` registers
the existing handlers without changing their signatures/workers, while
`RelayAuthentication` owns identity/replay/device/ticket/admin coordination.
Domain operations, middleware and quota/delivery transactions remain in
`app.py`. The 21-route contract and unauthorized request paths are tested with
mocked cloud services. Deployment and real-device verification remain separate.

Agent 0.6.33-beta completes the local snapshot-domain extraction with
`HistoryCollector` and `SignalCollector`. Named history records and fingerprints
are committed together only after successful reads; tracker order, timers and
payload fields are preserved. SnapshotRuntime serializes these services. Tests
inject clocks/readers/trackers without a PBX or local history mount; integration
checks verify that history enrichment precedes signal observation.
