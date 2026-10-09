# PBXSense Agent architecture and staged refactoring

## Boundaries

The Agent remains a single process near the PBX. Connector adapters normalize
vendor observations. Domain trackers and history readers build operational
state. FastAPI exposes authenticated LAN APIs and the administrator pages.
The outbound relay client owns cloud identity and delivery; the Internet Relay
path publishes per-device encrypted snapshots. The cloud relay is separately
deployed and uses Firestore and FCM; the Flutter consumer lives in `../pbxsense`.

## Stage 1 complete: snapshot runtime (Agent 0.6.27-beta)

`pbxsense_agent/snapshot_runtime.py` owns collection serialization, publication,
payload caching, monotonic freshness, and collection diagnostics. It has no
FastAPI, connector, signal, or relay imports. It accepts collector and builder
callbacks, making it independently testable without a PBX or service startup.

`main.py` still owns PBX/history/tracker policy through `_collect_home_state` and
payload construction through `_home_payload_from_state`. Its public and
background consumers delegate to the same runtime rather than managing global
snapshot/cache locks themselves. History caches and connector domain models
are deliberately not moved in this stage.

One collector runs at a time. It publishes a complete generation only on
success; failures retain the previous state. Concurrent first readers trigger
one initial collection. Payloads are cached per moments period and generation.
A late build of an old generation cannot populate the new generation's cache,
and freshness is evaluated against the generation actually returned. Collection
can proceed while cached payloads are read or new payloads are built.

The one-second polling cadence, endpoint routes, authentication, and payload
shape remain unchanged. Stale snapshots retain data while reporting
reconnecting, as introduced in the previous reliability update. No Flutter
source or app version change is needed for this extraction.

## Stage 2a complete: relay HTTP transport (Agent 0.6.28-beta)

`relay_transport.py` owns URL validation, canonical JSON serialization, v1/v2
request signatures, nonce generation, HTTP connection reuse, response bounds,
and HTTP error classification. It receives a signing callback; it never reads
or writes identity files and has no notification, outbox or PBX dependencies.

`AgentRelay` retains identity/key ownership, durable outbox state and notification
policy. Its `_request` delegates to the transport, preserving existing call
contracts and `RelayRequestError` imports. A transport lock serializes the shared
delivery stream; heartbeat calls use an isolated, disposable thread-local
connection without waiting for that lock. Transport failures discard only the
affected connection. Malformed JSON/UTF-8 also discard it before retry, rather
than retaining a questionable stream.

Direct tests verify both Ed25519 signatures against the exact canonical body,
fresh nonces, logical signing paths versus URL prefixes, response bounds,
connection reuse/recovery, error retry classification and busy-stream heartbeat
isolation. Identity encryption, on-disk format, relay routes, cloud service,
app version and polling intervals are unchanged.

## Stage 2b complete: encrypted relay state (Agent 0.6.29-beta)

`relay_state_store.py` owns encrypted identity/outbox file persistence, state-key
derivation, legacy-key reads, plaintext migration, restrictive Linux permissions,
atomic replacement and unchanged-save suppression. It receives and returns state
dictionaries; `AgentRelay` still owns their mutation, synchronization, private-key
use, notification policy and durable retry decisions.

The existing `pbxsense-relay-state-v1` envelope, key derivation, state paths and
unknown fields are preserved. A wrong or missing decryption key still fails
closed instead of silently replacing an identity. The first save rewrites legacy
plaintext or old-key state using the current key; failed replacement preserves
the previous file and does not suppress the next retry.

Independent tests cover identity/outbox round trips, migration, legacy-key
rotation, missing/wrong keys, malformed encrypted envelopes, write failure,
unchanged saves and Linux permission requests. App APIs, notification timing,
cloud protocol and deployment are unchanged.

## Stage 2c complete: relay notification policy (Agent 0.6.30-beta)

`relay_notification_policy.py` owns signal eligibility, semantic deduplication,
endpoint outage correlation, grouped updates, recovery suppression and cooldown
transitions. It has no file, network, pairing or cryptography dependencies.
The caller provides the existing durable state dictionary and an explicit
observation timestamp; all continuity remains in that dictionary, not in a
second policy cache.

`AgentRelay.observe` retains enrollment, its state lock, synchronous durable
queueing, persistence and flushing. Policy events are emitted through a callback
at the original transition/save points, preserving retry and restart semantics.
The callback must not reenter `observe`; the caller owns synchronization.
Queue limits, event replacement, preference handling in the cloud, timers,
notification wording, state keys and payload fields remain unchanged.

Independent policy regressions cover exact delay boundaries, grouped updates,
stable recovery, transient outage suppression, connector failure, repeated
episodes, persisted deduplication, cooldown expiry, eligibility and synchronous
emission ordering. Existing relay integration tests still exercise the durable
outbox and delivery path. App and cloud relay changes are not required.

## Stage 3a complete locally: signed-request verification (Relay 0.5.22)

`push_relay/request_auth.py` verifies Agent and activation Ed25519 signatures,
the existing five-minute timestamp window, nonce syntax, exact body/path binding
and v2 method/body-digest binding. It receives an explicit timestamp and raw body,
imports no Firebase code and performs no database reads or writes.

`app.py` retains identity lookup, revoked-Agent checks, body limits, durable
nonce claims and presence updates. Activation nonce IDs remain scoped by public
key; Agent nonce claims remain under the Agent identity. A verified nonce is not
authorization to proceed until its existing Firestore create succeeds. Replay
conflicts remain HTTP 409, invalid signatures remain HTTP 401, and database
failures still propagate without marking the request accepted.

The Cloud Run image includes the new module and supports both package and
top-level imports. Direct cryptographic and database-wrapper tests cover valid
requests, tampering, timestamp boundaries, malformed keys/nonces/signatures,
nonce scope, replay conflicts and verification-before-write order.
Enrollment modes, ticket handling, quotas, FCM delivery and public routes are
unchanged. This cloud-only change does not advance Agent or app versions and
requires a separate relay deployment; local checks are not deployment evidence.

## Stage 3b complete locally: event delivery coordination (Relay 0.5.23)

`push_relay/notification_delivery.py` owns event recipient selection, token
deduplication, FCM message construction, outcome classification and delivery
checkpoint/cleanup/reporting order. It receives messaging and persistence
callbacks rather than initializing Firebase or holding database references.

`app.py` retains authentication, input validation, rate limiting, the event
fingerprint, atomic event/quota claim, lease ownership and database recipient
lookup. The checkpoint callback retains the original owner-checked Firestore
transaction. No new quota is charged for a resumed event, and completed recipient
digests continue to exclude successful/permanently failed recipients on retry.
Agent-status notification coordination remains in `app.py`; it reuses the
same extracted token-deduplication helper.

No-recipient completion, transport-error handling, checkpoint-before-cleanup/
usage ordering, message tags, preference semantics and at-least-once delivery
are preserved. Existing failure propagation is intentionally unchanged: a
usage write failure during transport-error handling can leave the lease to
expire, and malformed FCM result lists can fail cleanup after a pending
checkpoint. This extraction does not claim exactly-once handset delivery.

Standalone regressions cover recipient preferences/expiry/muting, duplicate
tokens, resumed deliveries, permanent/transient failures, transport exceptions,
lost leases, reporting failures, incomplete outcomes and callback ordering.
Existing atomic quota/lease tests and mocked relay startup/schema checks also
pass. Agent/app versions and public contracts are unchanged; relay deployment
is separate and has not been performed as part of this local stage.

## Stage 3c complete locally: Agent-status delivery and notification usage (Relay 0.5.24)

`AgentStatusDelivery` in `notification_delivery.py` now owns lost/restored
Agent recipient selection, FCM message construction, cleanup and reporting
order. Database identity/recipient lookup, heartbeat loss detection and
state transitions remain in `app.py`. Meaningful-notification preferences,
expiry, token deduplication and the `agent_connection` payload are unchanged.
Status notifications still do not use event quota/lease transactions.

`notification_usage.py` owns notification-attempt field construction and the
Agent usage write through injected database, timestamp and rollup callbacks.
The existing `_usage_update` daily rollover/aggregation logic remains in the
application. Counter names, nonnegative clamping, no-recipient attempts,
FCM-attempt counts and optional event quota fields are preserved; status
reporting does not overwrite the event quota.

Cleanup precedes reporting for completed status sends, transport errors report
before propagating, and reporting/cleanup failures keep their existing behavior.
Direct regressions cover preference/expiry/deduplication, no recipients,
send/cleanup/reporting failures, exact counters, quota isolation and rollup
failure before the Agent update. The full mocked startup/schema check includes
both modules. This is local validation, not a live Firebase/handset test or
deployment. Agent and app versions are unchanged.

## Stage 3d complete locally: daily accounting and dashboard rendering (Relay 0.5.25)

`usage_accounting.py` owns UTC-day counter updates, completed-day archives,
hashed entity identifiers, numeric counter filtering and daily rollup reads.
Database access, server timestamps, increment operations and the clock are
injected. Existing archive-before-marker order, 90-day expiry, deterministic
archive paths, day bounds and same-day increments are preserved. This does not
introduce transactional rollover or repair pre-existing concurrent rollover
semantics; failures still propagate rather than returning reset counters.

`usage_dashboard.py` renders the operations dashboard from a report dictionary
and caller-supplied relay version/cost estimator. It imports no Firebase code,
performs no database access and retains HTML escaping, presentation and metric
notes. The cost formulas and configured rates, report query coordination,
administrator authentication/login and response headers remain in `app.py`.

Regressions cover rollover write order/failures, already-archived/invalid days,
counter filtering, daily Agent/app aggregation, day bounds, retained dashboard
sections and escaping. Existing mocked startup/schema and cost tests pass.
Both modules are copied into the Cloud Run image. Agent/app versions are
unchanged and no cloud deployment is implied by these local checks.

## Stage 3e complete locally: report queries and cost configuration (Relay 0.5.26)

`usage_report.py` owns usage-report query coordination and fleet/report metrics
with injected database, accounting callbacks, clock, policy and cost model.
The 1,000-Agent query limit, 100-row workload-sorted output, two-minute app
presence window, Agent loss window, scheduler freshness threshold, archive
callbacks and report fields are preserved. This remains a bounded operational
sample, not an unlimited fleet inventory.

`cost_model.py` owns immutable cost settings loaded from the existing
`PBXSENSE_RELAY_COST_*` variables and the unchanged workload-cost formulas.
Rate bounds/default fallbacks, currency label, estimated snapshot egress and
the projection's one-hour UTC observation floor remain unchanged. Currency is
a label, not an exchange-rate conversion; estimates are not billing invoices.

`app.py` retains administrator authorization and route wiring, forwarding to
the report service and cost model. Independent tests cover empty/populated
fleets, numeric totals, retention/presence/quota boundaries, hashed identifiers,
sorting/truncation, callback failure propagation, environment overrides and
cost formulas. Mocked relay startup/schema checks include both new modules.
Agent/app versions are unchanged; deployment remains a separate operation.

## Stage 3f complete locally: route registration and authentication (Relay 0.5.27)

`routes.py` explicitly registers all 21 public method/path/handler bindings.
It reuses the existing handler objects, annotations, response classes and
backend-worker wrappers, preserving OpenAPI and dispatch behavior. Missing
bindings fail during startup rather than at the first request. Domain handlers,
middleware and Firestore transaction functions remain in `app.py`; this is a
route-wiring boundary, not a rewrite of domain operations.

`authentication.py` coordinates Agent identity lookup/revocation, request
limits, signature verification, durable nonce claims and optional presence
updates. It also owns paired-app bearer credential/expiry checks, activation
nonce claims, enrollment ticket signing/validation and administrator cookies/
header authorization with injected storage, secrets, validators and clocks.
Enrollment mode selection remains unchanged at the application boundary.

Nonce verification/creation precedes presence updates, replay conflicts remain
HTTP 409, and database failures do not silently authorize a request. Internal
administrator APIs remain header-token-only; the dashboard may use its signed
expiring cookie. Paired-app credential and ticket semantics are unchanged.
Independent tests cover these checks, all route bindings, handler preservation,
worker dispatch and startup failure for missing bindings. The full mocked ASGI
startup/schema test verifies the 21-route contract and unauthorized Agent,
paired-app and internal-admin requests.

The cloud-relay separation bullet is complete locally: transport verification,
authentication coordination, route wiring, notification delivery and usage/
cost reporting now have explicit boundaries. Transactional quota/delivery
ownership is retained. Relay 0.5.27 must be deployed separately before these
changes are live; real Firebase/handset delivery is not validated by mocks.

## Stage 4a complete locally: named collected state (Agent 0.6.31-beta)

`collected_state.py` defines keyword-only `CollectedHomeState` in place of the
ten-field positional tuple. Collection, polling and payload construction now
access named fields. Frozen field bindings prevent accidental reassignment;
the contained collections remain runtime-owned and must not be mutated after
publication. No per-poll copies or public JSON changes were introduced.

Focused tests cover named construction, immutable bindings, payload field
mapping, collection identity and delayed aggregate-tip visibility. Polling,
notification lifecycle and snapshot freshness behavior remain unchanged.

## Stage 4b complete locally: neutral observations (Agent 0.6.32-beta)

`observations.py` owns the shared `PbxChannel`, `PbxEndpoint`, `PbxQueue` and
`PbxSnapshot` dataclasses without importing connector or payload-builder code.
All connectors, JTAPI, collected state, presence tracking and payload building
use these vendor-neutral names. Existing `pulse.Ami*` imports remain supported
as exact class aliases, preserving constructors, equality, replacement and
type checks rather than introducing wrappers or competing model classes.

Field names/order, defaults, mutable collection ownership, health confidence,
presence and optional history semantics are unchanged. This is an internal
model boundary: public JSON, diagnostics, polling and vendor-specific parsing
are unchanged. Tests cover alias identity, independent collection defaults,
frozen bindings, every connector's return type and legacy payload construction.

## Stage 4c complete locally: history and tracker coordination (Agent 0.6.33-beta)

`history_collection.py` owns named cached records, file fingerprints and the
configured history refresh interval. Asterisk/Grandstream retain metadata-based
CDR, voicemail and security-log refresh; unchanged security records expire at
the existing 15-minute cutoff. CUCM retains interval-based CDR/CMR reads and
per-observation trunk enrichment. FreeSWITCH, Yeastar and mock observations pass
through without extra history I/O. Diagnostics use the same path-selection
helpers; their public fields are unchanged.

Cache records and fingerprints now commit together after every reader succeeds.
Previously, a later reader exception could commit an earlier file fingerprint
without its records, preventing a retry from recovering that file's update.
The failed generation now propagates the error without advancing its cache or
refresh clock. Existing published collections are not modified.

`signal_collection.py` coordinates injected activity, endpoint, trunk, aggregate
tip and last-active trackers in their existing order and returns named collected
state. Tracker configuration, persistence and notification-episode handling are
not rewritten. `SnapshotRuntime` remains the serialized collection/publication
owner; these collectors must not be called concurrently outside that boundary.
`main.py` composes the services and retains payload construction and loop wiring.

Focused tests cover interval boundaries, fingerprints, failed-read retry,
security expiry, connector-specific behavior, tracker order and runtime wiring.
Polling and notification timers, public JSON and the app contract are unchanged.

## Integration verification (Agent 0.6.34-beta)

`test_snapshot_pipeline.py` exercises the composed runtime, history collector,
real signal trackers and production payload builder with isolated persistence
and controlled clocks. It checks five-second phone outage confirmation,
15-second recovery/rearming, distinct subsequent notification IDs, unchanged
previous payloads and partial inventories that must not declare all phones
recovered. Failed history reads bypass tracker observation, preserve the last
published generation with stale/reconnecting metadata, and recover on retry.

Release regressions walk the relay application's transitive local Python
imports and require every dependency to be copied into its Cloud Run image.
The existing mocked top-level startup/ASGI checks verify cloud import mode and
route authorization without contacting Firebase. No new functional defect or
runtime behavior change was found in this integration pass.

## Architectural extraction status

### Persistent daily evidence (Agent 0.6.39-beta)

`SignalCollector` owns `DailySummaryTracker` under the existing serialized
collection boundary. It observes enriched snapshots once and publishes a copied
summary alongside other collected state; payload construction is read-only.
The engine no longer derives whole-day queue success, operating/service streaks,
or daily/weekly/monthly volume targets from the latest 1,000 CDR records.

A private SQLite transaction commits hashed event deduplication and aggregate
counts together. Repeated/cached snapshots and restarts do not increment counters
again. Coverage is deliberately separate from counts: failed sources, inventory
changes, observation gaps, capped initial windows and lost CDR overlap suppress
claims even when retained totals remain useful. Queue maximum wait persists
after a queue empties. Batched deduplication reads run on fresh history evidence,
not every live snapshot; no new PBX or Relay polling is introduced.

Completed-day claims use PBX-local midnight plus a five-minute settling window.
This is observed evidence, not vendor SLA certification or an audit of arbitrarily
late CDRs. Retention, learning thresholds, storage failure and timing limits are
documented in `CONFIGURATION.md`. The existing signal kinds remain compatible;
no companion app or Relay update is required for this correction.

### Source failure handling update (Agent 0.6.38-beta)

Optional history I/O failures now retain that source's cache/fingerprint and
publish unavailable source metadata while core collection and signal observation
continue. Strict production readers distinguish a failed read from a successful
empty read; best-effort diagnostic helpers keep their legacy interface.
Unexpected programming errors still abort the generation atomically.
Queue responses require complete schema evidence before cache replacement.
The coordinated app 0.6.7-beta+284 renders unknown queue/live-call evidence
without presenting it as a successful empty observation.

The planned snapshot, relay, neutral-model and history/tracker extraction
bullets are complete locally. Deployment and real-PBX/device validation remain
separate; passing local regressions is not a production-readiness declaration.

Each stage requires focused regressions, the full Agent suite, contract checks,
an Agent patch version and installer rebuild when Agent source changes. App
changes require coordinated consumer tests only when the external contract or
user-visible behavior changes. Cloud deployment success is not evidence of
real-phone delivery or real-PBX correctness.
