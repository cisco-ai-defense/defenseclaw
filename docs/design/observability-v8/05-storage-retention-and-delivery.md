# Storage, Retention, and Delivery

## 1. Storage Roles

The v8 design has three distinct storage roles:

1. **Required event history** — the one mandatory built-in SQLite event store,
   `audit.db`, records every collected log after application of the bucket/default
   projection profile; that profile is `none` by default.
2. **Normalized projections** — query-oriented tables retain scan, finding,
   compliance activity, egress, and destination-health shapes required by APIs,
   CLI, TUI, dashboards, and policy workflows.
3. **Local forensic judge bodies** — the separate SQLite `judge_bodies.db` database
   is the authoritative v8 store for explicitly retained raw judge responses. It
   is not an observability destination, does not satisfy the mandatory `audit.db`
   requirement, and is never a general log-export source.

SQLite does not store complete trace graphs or raw metric series. Queryable summary
logs and normalized projections may describe trace/metric health.

## 2. Built-in SQLite Store

### 2.1 Initialization

- Exactly one mandatory SQLite event-history store, `audit.db`, is created
  internally; it is not listed under source `destinations` and cannot be disabled.
  The separately opened `judge_bodies.db` forensic database described in section 4
  is not a second event-history store or destination.
- The gateway MUST open the database, apply append-only migrations, verify required
  pragmas and write capability, and initialize the reaper before reporting ready.
- Failure to initialize the built-in SQLite store causes startup failure.
- When judge-body capture is enabled, or a required legacy judge-body cutover has
  work to process, `judge_bodies.db` MUST also initialize and prove write capability
  before the gateway serves; failure aborts startup or the required upgrade. When
  capture is disabled and no cutover work exists, its validated path need not be
  opened. Capture enablement remains distinct from age: the shared
  `observability.local.retention_days` policy is the only retention-age source for
  event, evidence, and judge-body history.
- V8 schema migrations are additive and MUST leave the database readable by the
  immediately previous supported release: do not drop/rename a previous column or
  table, change an existing column's wire meaning, or require the previous binary
  to understand a new table before it can open and query its existing surfaces.
  Rollback compatibility is exercised against the actual previous binary and a v8-
  migrated fixture, not inferred solely from successful v8 migrations.
- Existing database migrations are never reordered or removed.
- The SQLite path is restart-required.
- Newly created data directories use owner-only permissions and database files use
  mode `0600` unless an explicitly supported managed group-readable mode is
  configured and validated. Existing permissions must never be widened by startup,
  migration, or retention.
- Database paths must pass symlink, ownership, and managed-enterprise trust checks.
- A root-owned sticky world-writable directory may be a path ancestor, but MUST
  NOT be the immediate database parent. The immediate parent must prevent an
  untrusted local principal from pre-creating, replacing, reading, or writing the
  SQLite database and its `-wal`, `-shm`, and journal siblings.
- On Windows, every path element rejects symlinks, junctions, and other reparse
  points, and every directory ancestor rejects untrusted child-mutation rights
  that could substitute a validated descendant. Owners and DACLs are validated;
  newly created immediate parents and
  database files receive a protected DACL limited to the current user,
  Administrators, and LocalSystem. Untrusted inheritable read access on the
  immediate parent is unsafe because SQLite auxiliary files inherit it.

### 2.2 Write contract

For every collected log:

1. Resolve the bucket profile, configured global profile, then the bucket's
   versioned catalog default.
2. Clone and redact using that effective profile.
3. Validate the projected record.
4. Insert one event-history row.
5. Insert or update applicable normalized projections in the same transaction when
   atomic visibility is required.

Mandatory-floor-only records follow the same sequence but are minimal and skip all
optional destinations.

The row persisted in SQLite is the canonical **local representation**, not a direct
producer object. With the default `none` profile its governed content remains
unredacted, while schema validation, bounds, serialization, provenance, and
integrity rules still apply. Selecting a redacting default/bucket profile changes
new local projections. Judge bodies remain the separate forensic store described in
section 4 because they are not ordinary canonical log bodies.

### 2.3 Event-history schema evolution

The existing `audit_events` table remains the compatibility anchor. Its current
operator-facing columns remain readable. A v8 migration adds or standardizes:

| Column | Purpose |
|---|---|
| `bucket` | Required v8 semantic bucket |
| `event_name` | Required stable event name |
| `source` | Required normalized producer |
| `connector` | Optional connector |
| `signal` | `logs`; reserved for explicit future local signal summaries |
| `bucket_catalog_version` | Catalog version governing the stored bucket assignment |
| `payload_json` | Complete redacted typed body for the SQLite projection |
| `projected_record_json` | Complete deterministic projected record used for local hash/HMAC verification; contains only the already-projected body and delivery metadata, never a hidden raw body |
| `record_schema_version` | Canonical v8 record-envelope version; separate from the legacy v7 `schema_version` compatibility column |
| `projection_hash` | SHA-256 identity of `projected_record_json`; separate from the legacy v7 `content_hash` configuration fingerprint |
| `redaction_profile` | Effective profile name used for persistence |
| `mandatory` | Whether the event belongs to the compliance floor |
| `request_id`, `session_id`, `turn_id`, `trace_id` | Direct indexed correlation keys |
| `evaluation_id`, `scan_id`, `finding_id`, `enforcement_action_id` | Direct semantic join keys |
| `schema_version`, `content_hash`, `generation`, `binary_version` | Legacy-compatible provenance metadata; `schema_version` and `content_hash` retain their v7 meanings and are never repurposed as canonical-record version or projection digest |

`action`, `target`, `actor`, `details`, `structured_json`, `severity`, and existing
correlation fields remain populated where meaningful during compatibility. New v8
readers use bucket, event name, and typed payload rather than parsing `details`.

The `audit_events.record_schema_version` column projects the canonical record
envelope version, which is integer `1` for this contract; detailed family schemas
have their own independent versions. The legacy `audit_events.schema_version`
column remains the v7 event-wire provenance version so rollback readers do not see
its meaning change. The SQLite table named `schema_version` is database-migration
state. These three version surfaces are unrelated despite the similar names; the
table is protected current state and is never reaped.

Payload JSON and projected-record JSON MUST be bounded, deterministic, and already
redacted. `payload_json` is the query-oriented typed body. `projected_record_json`
is the exact canonical projection byte sequence used for `projection_hash` and HMAC,
so local verification never needs to reconstruct omitted envelope fields or consult
the current registry/configuration. The writer MUST reject a projection whose
profile does not match the effective local route profile supplied by the compiled
runtime graph. `projection_hash` is computed from this stored projected canonical
serialization. Existing `content_hash` readers continue to observe the v7
configuration-fingerprint meaning.

### 2.4 Normalized projections

The following query-oriented projections remain supported:

- `scan_results` for `asset.scan` summaries.
- Legacy `findings` during compatibility reads.
- `scan_findings` for `security.finding` detail.
- `activity_events` for `compliance.activity` mutations.
- Alert acknowledgement/dismissal current state, immutable operation receipts used
  for replay/idempotency, legacy baselines, and bounded current health keyed to
  immutable occurrence/event IDs. These are protected correctness state, not
  retention-bound event history.
- `network_egress_events` for `network.egress` queries.
- `sink_health`, renamed in API vocabulary to destination health while retaining
  the table for migration compatibility.
- Legacy `judge_responses` in `audit.db` until migration/retention has removed all
  required compatibility data.

The event-history row is authoritative for v8 observability. Projections are derived
transactionally and MUST NOT cause a second exported event. A projection failure
rolls back the event insert when the API requires the projection for correctness;
otherwise it creates a mandatory projection-health failure with explicit degraded
state.

Failure and degraded-state reporters MUST be invoked only after the failed SQLite
transaction has rolled back or the successful transaction has committed **and** the
originating operation has released Store lifecycle ownership. Reporter
implementations are allowed to query, persist a mandatory health event through, or
close the same single-connection store; invoking them while the originating
transaction or lifecycle lock remains active would self-deadlock. Signed/unsigned
integrity state is staged in commit order, and external callbacks use a bounded,
serialized, reentrancy-safe queue that coalesces identical pending health states
without dropping a later unsigned transition separated by signed recovery. Reporter
failures do not reopen or change the already completed transaction.

### 2.5 State tables are not event history

The following are current-state stores and MUST NOT be deleted by event retention:

- `actions`
- `target_snapshots`
- `schema_version`
- `observability_store_readiness`
- `alert_acknowledgement_projection`
- `alert_acknowledgement_operations`
- `alert_acknowledgement_baselines`
- `alert_acknowledgement_health`

The immutable operation rows are retained as correctness state because v8 promises
timeless exact operation-ID retries and uses their gap-free applied sequence to
rebuild mutable alert state after corresponding `audit_events` age out. They contain
only bounded command/result controls and the locally projected actor representation,
are never remote-exported directly, and are included in capacity reporting. This is
an intentional unbounded-cardinality tradeoff; changing it requires a separately
specified finite idempotency window and transactional reconciliation checkpoint.

Any new current-state table must explicitly declare retention ownership before
being added.

## 3. Finding Persistence

- Each observed finding is an immutable occurrence with its own `finding_id`.
- `rule_id` is stable for aggregation but is not itself an occurrence ID.
- Scan/evaluation correlation must be retained.
- Evidence summary, description, location, and remediation are stored after the
  local bucket/default projection; by default that projection is unredacted.
- v8 does not add `status: open` or update a row to resolved/reopened.
- Repeated observations may be aggregated in queries using rule ID, target, and a
  safe fingerprint, but the logger does not silently collapse occurrences.
- Alert acknowledgement/dismissal state lives in a separate mutable projection
  keyed to the immutable occurrence/event. Its per-alert version and operation-ID
  uniqueness enforce the compare-and-swap and retry contract in
  `02-taxonomy-and-data-model.md` section 5.6. A first-seen command atomically stores
  its idempotency result and immutable `compliance.activity` event and, only for an
  applied transition, advances the projection. It never rewrites the finding row or
  its severity. Projection rebuild uses the protected gap-free applied receipt
  sequence, not timestamps or retention-bound audit rows; ambiguous receipts or a
  retained event that contradicts its receipt fail closed and emit mandatory
  projection health. Legacy `ACK` severity rows are interpreted as a versioned
  compatibility baseline using the same section's rule. The idempotent baseline
  scan runs on every v8 startup so an `ACK` written by the previous supported binary
  during rollback is captured before retention.
- A first-seen mutation is accepted only for a locally known finding occurrence,
  recognized legacy alert occurrence, or target already represented by protected
  alert state/receipts. The protected operation receipt stores a domain-separated,
  correlation-keyed HMAC command fingerprint; the canonical compliance event does
  not store or export that fingerprint.

If a later case-management feature introduces mutable finding cases, it must use a
separate table and event stream rather than changing the meaning of occurrence rows.

## 4. Judge-Body Store

- `judge_bodies.db` remains a separate schema and connection pool and is the sole
  authoritative store for new v8 judge-body writes.
- Its `judge_responses` rows retain raw response bodies only when forensic retention
  is explicitly enabled by the guardrail configuration.
- Raw judge bodies are never copied to `audit_events.payload_json`, JSONL, console,
  Splunk, HTTP JSONL, or OTLP.
- The store retains request/trace/run/session/agent/policy/tool correlation and
  provenance needed for local investigation.
- The store follows the same age cutoff as event history.
- If the feature is disabled, new bodies are not written; existing bodies age out
  under retention rather than being immediately destroyed unless a separate
  explicit purge command is invoked.
- Because judge bodies can contain raw model output, the judge-body file must never
  be more permissive than the audit database and should be called out separately by
  doctor when permissions are unsafe.

### 4.1 Legacy cutover and cleanup

The legacy `audit.db.judge_responses` table becomes a read-only compatibility
source at the writer cutover. The v8 runtime MUST NOT dual-write judge bodies: it
does not begin serving or accept a judge-body write until the cutover below has
completed, and every write after that point goes exclusively to `judge_bodies.db`.
The pre-upgrade writer may remain active only before the cutover lock is acquired.
The upgrade performs the cutover in this order:

1. Initialize and migrate `judge_bodies.db` without changing the active writer.
2. Acquire the judge-writer cutover lock so no new legacy write can race the copy.
3. Copy legacy rows in deterministic batches, preserving stable identifiers,
   timestamps, correlations, and body bytes. Target insertion uses the stable
   identifier as its unique key with insert-ignore/upsert semantics, so re-running
   a partial batch is idempotent and cannot duplicate a body.
4. Commit and verify each target batch before marking its source rows migrated.
5. Atomically switch the only judge-body writer to `judge_bodies.db`, then release
   the cutover lock; only now may the v8 runtime accept judge-body writes, and from
   this point `audit.db.judge_responses` is permanently read-only.
6. Retain verified legacy rows only for compatibility reads until normal retention
   or an explicit purge removes them.

Compatibility reads and any authorized local forensic export read
`judge_bodies.db` first, then add only legacy rows whose stable identifier is not
already present; a migrated body is returned or exported once. Judge bodies are
never included in an observability-destination export. If an authorized forensic
operation requests export followed by purge, it MUST finish and verify the local
export before either database is purged.

Migration cleanup MUST copy, commit, and verify a row in `judge_bodies.db` before
purging its legacy source copy. For age retention or an explicit purge that covers
both databases, delete matching legacy copies from `audit.db` first and the
authoritative rows from `judge_bodies.db` second. A failure between those commits
therefore leaves, at worst, the authoritative copy pending a later purge and cannot
make a deleted authoritative body reappear through the legacy compatibility read.

`legacy_judge_cutover_state` is protected cutover current state, not event history.
`legacy_judge_cutover_rows` is per-source migration evidence. It is retained while
the corresponding legacy compatibility rows exist and is eligible for cleanup only
after those source rows have been purged and the authoritative copy is no longer
dependent on replay evidence. The global reaper owns that cleanup; ordinary
event-history retention never deletes either table blindly.

## 5. Retention Contract

### 5.1 Configuration

- One global `retention_days` value lives under `observability.local`.
- Default: 90 days.
- `0`: retain event/evidence history forever and do not schedule deletion.
- Positive integer: delete rows strictly older than the UTC cutoff.
- Negative, fractional, or unreasonably large values that overflow duration
  calculation are invalid.

The cutoff is calculated once per reaper run from an injected clock:

`cutoff = now.UTC() - retention_days * 24h`

Rows with timestamp equal to the cutoff are retained. Rows older than it are
eligible.

### 5.2 Included tables

The reaper covers:

- `audit_events`
- `activity_events`
- `network_egress_events`
- `sink_health`
- `scan_findings`
- Legacy `findings`
- `scan_results`
- Legacy `audit.db` `judge_responses`
- Separate `judge_bodies.db` `judge_responses`

New event-history/projection tables MUST be added to the reaper registry in the same
change that creates them. A completeness test compares the table registry with the
migration catalog.

The protected tables in section 2.5 are explicitly excluded. In particular,
retention may delete an alert's `compliance.activity` audit event while preserving
its operation receipt; exact retry returns the original opaque event ID and
timestamp without recreating the deleted event. Before deleting an eligible legacy
`ACK` occurrence, the reaper MUST successfully materialize its baseline.

### 5.3 Deletion order

Within scan history, delete children before parents:

1. `scan_findings`
2. Legacy `findings`
3. `scan_results`

Other independent history tables may be deleted in deterministic table order.
Foreign keys remain enabled; the implementation MUST NOT disable integrity checks to
make retention succeed.

Judge-body deletion follows the cross-database order in section 4.1: legacy
`audit.db.judge_responses` copies first, authoritative
`judge_bodies.db.judge_responses` rows second. Each database commits independently;
on failure, health is degraded and the next run resumes idempotently.

### 5.4 Scheduling and batching

- Run once after successful startup initialization.
- Run every six hours thereafter.
- Use an injected clock and scheduler in tests.
- Delete at most 1,000 rows per table per transaction.
- Commit between batches and yield so interactive queries and writes can proceed.
- Continue batches until no eligible rows remain or context is cancelled.
- Use indexed timestamp predicates.
- A live reload of `retention_days` changes the next run and MAY trigger one prompt
  asynchronous run when the age becomes shorter.

### 5.5 Maintenance

- Do not run blocking `VACUUM` automatically.
- A passive WAL checkpoint MAY run after a successful reaper cycle.
- Full compaction remains an explicit maintenance command.
- Retention failure leaves the affected data intact, changes health to degraded,
  increments bounded failure metrics, and emits a mandatory record.

### 5.6 Retention telemetry

Per run, record bounded metrics:

- Rows deleted by table class.
- Run duration.
- Batch count.
- Last successful completion time.
- Failure count by stable error class.

Table names in metrics must come from the fixed reaper registry.

## 6. Optional Destination Delivery

### 6.1 Isolation

Every queue-backed optional destination (`jsonl`, `console`, `splunk_hec`,
`http_jsonl`, and push-capable `otlp`) owns:

- Its own bounded count-and-byte queue.
- Transport or local writer.
- Batch processor where applicable.
- Retry/circuit state.
- Health state.
- Counters for accepted, delivered, retried, dropped, and rejected records.

No optional destination shares a queue with SQLite or another destination.
Prometheus is pull-based and has no destination queue. An SDK-managed metric
reader/exporter follows its SDK backpressure contract rather than being silently
wrapped in a second DefenseClaw queue.

### 6.2 Enqueue and backpressure

- Producer paths MUST NOT wait for optional destination I/O. Enqueue is a bounded,
  nonblocking operation after required local persistence.
- Every DefenseClaw-owned log/trace queue is bounded independently by both
  `batch.max_queue_size` and `batch.max_queue_bytes`. JSONL and console use the
  same queue grammar as remote push destinations so disk or terminal backpressure
  cannot stall other destinations.
- Queue byte accounting is the exact length of each immutable projected payload
  retained for that destination. Adapter wrappers are created after dequeue and do
  not permit the queue to retain an unaccounted raw/canonical object.
- If accepting an item would exceed either configured limit, the queue is full:
  the newest attempted enqueue is dropped without temporarily inserting it or
  evicting an older item. Existing FIFO order is unchanged, the locally persisted
  record remains available, and bounded health telemetry records the drop.
- Drop health emission must be rate-limited and recursion-safe.
- Prometheus is a pull destination and does not use a push queue.
- Metric SDK reader/exporter backpressure follows SDK semantics but must expose
  export failures and collection duration.

The defaults and practical maxima are normative in 03 §4.4. In particular, a
queue accepts at most 65,536 records and 268,435,456 projected bytes even if a
language integer or SDK accepts a larger value. Invalid limits fail validation
before a queue allocates memory.

### 6.3 Retry

- Retry only failures classified as transient or as an ambiguous acknowledgement
  after request bytes may have reached the destination. An ambiguous retry reuses
  the exact immutable projected bytes and record ID; it never re-runs routing or
  redaction. Operators and downstream consumers must therefore use the record ID
  for deduplication when the first acknowledgement was lost.
- Do not retry authentication or permanently malformed payload failures until
  configuration changes or the circuit probe interval elapses.
- Use bounded exponential backoff with jitter.
- Respect shutdown deadlines and request context.
- Do not re-run redaction on every retry; retry the immutable projected payload.
- Push batching stops before either `batch.max_export_batch_size` or
  `batch.max_export_batch_bytes` would be exceeded. The encoded request, including
  separators and destination wrapper bytes, MUST remain within the byte ceiling;
  adapters may not build an unbounded intermediate buffer. A valid individual
  projection plus its bounded wrapper always fits the minimum allowed ceiling.

### 6.4 Per-destination health states

Destinations report:

- `disabled`
- `initializing`
- `healthy`
- `degraded`
- `failing`
- `draining`
- `stopped`

Health transitions, not every identical failure, produce mandatory health logs.
Detailed attempt counters remain metrics/projections.

### 6.5 Delivery guarantees

- SQLite: required local durability after a successful transaction.
- Optional remote push destinations: at-most-once enqueue with bounded in-process
  retry; duplicates MAY occur after ambiguous transport acknowledgements.
- The record ID and per-projection hash permit downstream deduplication without
  overloading the legacy SQLite `content_hash` provenance column.
- No claim of exactly-once remote delivery is made.

## 7. JSONL and Console

- JSONL receives the same projected record shape as other log destinations.
- Both adapters use the queue-only `batch.max_queue_size` and
  `batch.max_queue_bytes` grammar. Omitting `batch` uses the reviewed defaults;
  operators add it only to tune advanced capacity. Push-only batch fields are
  invalid for JSONL and console.
- Existing file ownership, permissions, and reopen behavior must be preserved and
  documented by the adapter. The v7 gateway defaults become explicit rotation
  knobs: 50 MiB, 5 backups, 30 days, and compression enabled.
- The v7 `DEFENSECLAW_JSONL_DISABLE` state is migrated once into the destination's
  `enabled` value; v8 does not continue consulting that environment kill switch.
- Console rendering derives from the projected record and must never reach back to
  the canonical raw body for “pretty” output.
- Failure to write optional JSONL or console output does not fail SQLite writes.

## 7.1 Splunk compatibility projection boundary

The Splunk adapter may add documented HEC wrapper fields and compatibility aliases,
but their sole input is the immutable projection selected and redacted for that
Splunk destination. Alias extraction is a projection-to-projection transform: an
alias equals the destination-redacted source value or is absent. It never receives
the canonical record, a gateway/audit producer object, raw body material, or a
projection created for another destination. Producer-supplied opaque extra HEC
events are not a compatibility mechanism and are rejected.

## 8. Inbound OTLP

The complete accepted-record, field-mapping, identity/provenance, partial-batch,
origin/hop, compatibility, and executable-test contract is
[`15-inbound-otlp-import-and-reexport.md`](15-inbound-otlp-import-and-reexport.md).
That document is normative; this section is its storage/delivery summary.

- Inbound OTLP logs, traces, and metrics are producer inputs, not trusted pre-routed
  output.
- Normalize only records with one exact generated registry binding into canonical
  buckets and event names. Zero or ambiguous matches have no generic fallback.
- Apply collection before local persistence or re-export.
- Malformed batches follow the existing retry-suppression requirements only where
  returning a transport error would create an unsafe retry storm; the rejection is
  still recorded as `telemetry.ingest` health metadata.
- Remove opaque transport-specific raw bypasses such as preserved decoded HEC event
  blobs. Retain safe normalized fields or bounded redacted summaries.
- A receiver must not export a record back to its origin in an infinite loop;
  generated import provenance, exact per-leaf self suppression, and the fixed
  four-hop limit are required.
- Imported logs use the same SQLite-first guarantee as locally produced logs.
  Imported traces and metrics do not acquire SQLite storage. Every optional export
  is reconstructed from the new local canonical record and its route-specific
  central projection; adapters never receive the decoded inbound leaf.

## 9. Query and Operator Surfaces

- Existing audit, alert, scan, and egress API/TUI queries continue to work through
  projections during migration.
- New queries support bucket, event name, source, connector, severity, time, and
  correlation identifiers without parsing free text.
- Doctor and TUI expose SQLite status, retention, last reaper result, destination
  health, queue drops, and effective unredacted/redacted profiles.
- `DEFENSECLAW_REVEAL_PII`, if retained, is an authorized local display-time reveal
  control only. It does not change persisted/exported route projections or enable
  judge-body retention.

## 10. Record Integrity and Verification

DefenseClaw currently supports payload HMACs derived from the device identity. v8
preserves this capability but moves it after route-specific redaction.

- Every log destination projection MAY carry `payload_hmac`, `integrity_algorithm`,
  and `integrity_key_id` when an integrity key is available.
- The HMAC covers the final canonical serialized envelope and redacted body plus the
  integrity algorithm and key ID, excluding only the HMAC field itself.
- SQLite stores the HMAC for its own projection. A Splunk/OTLP/JSONL projection with
  different redaction has a different valid HMAC.
- A projection hash is useful for equality/deduplication but is not a substitute for a
  keyed integrity value.
- Key derivation remains domain-separated from other device-key uses. Key material
  is never placed in config, logs, errors, or destination payloads.
- If the key is unavailable, delivery and the mandatory local floor continue, but
  platform health and doctor report that records are unsigned. A future policy may
  make signing required, but v8 does not silently fail all audit writes solely due
  to boot-order/key availability.
- Key rotation must change `integrity_key_id`; verification tooling must identify
  records whose prior key is unavailable rather than labeling them corrupt.
- Provide local verification by record ID/range and machine-readable results without
  exposing redacted content.
- Local verification reads `projected_record_json`, recomputes `projection_hash` and,
  when a matching integrity key is available, the HMAC. It reports bounded status
  and reason codes only; it never returns the stored body as part of a verification
  result. Bounded range results explicitly report `truncated: true` when more rows
  matched than were returned, so callers cannot mistake a limited page for a
  complete attestation.

Per-record HMAC does not prove that a row was never deleted and does not make SQLite
an append-only ledger. Normal retention intentionally deletes history. A chained or
externally anchored tamper-evident audit ledger is outside this scope and must not be
claimed by product documentation.

## 11. At-Rest Protection and Capacity

- v8 guarantees redaction, strict filesystem permissions, and path trust checks; it
  does not claim application-level database encryption unless an encrypted SQLite
  backend is separately implemented and tested.
- Product documentation should recommend platform disk encryption for hosts that
  retain sensitive local history or raw judge bodies.
- `retention_days: 0` is intentionally unbounded and must produce a lint/doctor
  capacity warning unless the operator explicitly acknowledges it.
- Doctor/TUI report database file size, free filesystem capacity, last successful
  write, last reaper result, and estimated growth where sufficient history exists.
- A disk-full or quota failure changes SQLite health to failed, emits the safest
  possible stderr/platform signal, and follows mandatory local-integrity failure
  behavior. It must not cause remote exporters to receive a raw fallback record.
- Automatic deletion remains age-based; v8 does not invent an undocumented
  size-based deletion order that could remove recent compliance history.
