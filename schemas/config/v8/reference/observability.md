# DefenseClaw v9 observability configuration reference

<!-- GENERATED FILE. DO NOT EDIT. -->

Current source files declare `config_version: 9`.
This reference is generated from `schemas/config/v8/defenseclaw-config.schema.json`.
The JSON Schema is the source of truth; this document and the adjacent exhaustive
YAML are presentation artifacts checked for drift in CI.

```text
producer -> bucket/signal -> collect -> sample -> route -> redact -> export
                                  \-> mandatory local SQLite audit floor
```

An enabled destination with neither `send` nor `routes` receives every bucket and
every signal its kind supports, unredacted. Configure `send` for one concise policy
or ordered `routes` for selector-specific policy. Collection gates run first.

## Destination kinds

| Kind | Supported signals | Source fields |
|---|---|---|
| `jsonl` | logs | `name`, `kind`, `enabled`, `path`, `rotation`, `batch`, `send`, `routes` |
| `console` | logs | `name`, `kind`, `enabled`, `batch`, `send`, `routes` |
| `prometheus` | metrics | `name`, `kind`, `enabled`, `listen`, `path`, `send`, `routes` |
| `splunk_hec` | logs | `name`, `kind`, `enabled`, `endpoint`, `token_env`, `token_credential`, `index`, `source`, `sourcetype`, `sourcetype_overrides`, `tls`, `timeout_ms`, `network_safety`, `batch`, `send`, `routes`, `local_stack` |
| `http_jsonl` | logs | `name`, `kind`, `enabled`, `endpoint`, `method`, `bearer_env`, `bearer_credential`, `headers`, `tls`, `timeout_ms`, `network_safety`, `batch`, `send`, `routes` |
| `otlp` | logs, traces, metrics (Galileo preset: traces) | `name`, `kind`, `preset`, `enabled`, `protocol`, `endpoint`, `headers`, `logger_name`, `tls`, `timeout_ms`, `network_safety`, `signal_overrides`, `batch`, `send`, `routes` |

## Complete source field catalog

`<name>` denotes a user-selected map key; `[]` denotes an array item.
Constraints that span fields are enforced by the compiler in addition to JSON Schema.

| Source path | Type | Default | Allowed / constant | Description |
|---|---|---|---|---|
| `observability.bucket_catalog_version` | constant | `1` | `1` |  |
| `observability.resource` | object |  |  |  |
| `observability.resource.attributes` | object |  |  |  |
| `observability.resource.attributes.<name>` | string |  |  | User-named entry. |
| `observability.trace_policy` | object |  |  |  |
| `observability.trace_policy.sampler` | string | `"parentbased_always_on"` | `always_on, always_off, traceidratio, parentbased_always_on, parentbased_always_off, parentbased_traceidratio` |  |
| `observability.trace_policy.sampler_arg` | string |  |  |  |
| `observability.trace_policy.semantic_profile` | constant | `"defenseclaw-genai-rich-v1"` | `"defenseclaw-genai-rich-v1"` |  |
| `observability.trace_policy.limits` | object |  |  |  |
| `observability.trace_policy.limits.max_attributes_per_span` | integer | `128` |  |  |
| `observability.trace_policy.limits.max_events_per_span` | integer | `64` |  |  |
| `observability.trace_policy.limits.max_links_per_span` | integer | `32` |  |  |
| `observability.trace_policy.limits.max_attributes_per_event` | integer | `32` |  |  |
| `observability.trace_policy.limits.max_attribute_value_bytes` | integer | `16384` |  |  |
| `observability.trace_policy.limits.max_projected_span_bytes` | integer | `262144` |  |  |
| `observability.trace_policy.limits.max_stacktrace_bytes` | integer | `32768` |  |  |
| `observability.trace_policy.limits.max_message_items` | integer | `128` |  |  |
| `observability.metric_policy` | object |  |  |  |
| `observability.metric_policy.export_interval_seconds` | integer | `60` |  |  |
| `observability.metric_policy.temporality` | string | `"delta"` | `delta, cumulative` |  |
| `observability.defaults` | object |  |  |  |
| `observability.defaults.collect` | object |  |  |  |
| `observability.defaults.collect.logs` | boolean | `true` |  |  |
| `observability.defaults.collect.traces` | boolean | `true` |  |  |
| `observability.defaults.collect.metrics` | boolean | `true` |  |  |
| `observability.defaults.redaction_profile` | constraint |  |  |  |
| `observability.buckets` | object |  |  |  |
| `observability.buckets.<name>` | object |  |  | User-named entry. |
| `observability.buckets.<name>.collect` | object |  |  |  |
| `observability.buckets.<name>.collect.logs` | boolean | `true` |  |  |
| `observability.buckets.<name>.collect.traces` | boolean | `true` |  |  |
| `observability.buckets.<name>.collect.metrics` | boolean | `true` |  |  |
| `observability.buckets.<name>.redaction_profile` | constraint |  |  |  |
| `observability.redaction_profiles` | object |  |  |  |
| `observability.redaction_profiles.<name>` | object |  |  | User-named entry. |
| `observability.redaction_profiles.<name>.extends` | string |  | `sensitive, content, strict` | Required. |
| `observability.redaction_profiles.<name>.detectors` | array |  |  |  |
| `observability.redaction_profiles.<name>.field_classes` | object |  |  |  |
| `observability.redaction_profiles.<name>.field_classes.metadata` | string |  | `preserve, detect, whole, hash, remove` |  |
| `observability.redaction_profiles.<name>.field_classes.identifier` | string |  | `preserve, detect, whole, hash, remove` |  |
| `observability.redaction_profiles.<name>.field_classes.content` | string |  | `preserve, detect, whole, hash, remove` |  |
| `observability.redaction_profiles.<name>.field_classes.reason` | string |  | `preserve, detect, whole, hash, remove` |  |
| `observability.redaction_profiles.<name>.field_classes.evidence` | string |  | `preserve, detect, whole, hash, remove` |  |
| `observability.redaction_profiles.<name>.field_classes.error` | string |  | `preserve, detect, whole, hash, remove` |  |
| `observability.redaction_profiles.<name>.field_classes.path` | string |  | `preserve, detect, whole, hash, remove` |  |
| `observability.redaction_profiles.<name>.field_classes.credential` | string |  | `preserve, detect, whole, hash, remove` |  |
| `observability.connectors` | object |  |  |  |
| `observability.connectors.<name>` | object |  |  | User-named entry. |
| `observability.connectors.<name>.webhooks` | array |  |  |  |
| `observability.connectors.<name>.webhooks[].name` | string |  |  |  |
| `observability.connectors.<name>.webhooks[].url` | string |  |  | Required. |
| `observability.connectors.<name>.webhooks[].type` | string | `"generic"` | `slack, pagerduty, webex, generic` | Required. |
| `observability.connectors.<name>.webhooks[].secret_env` | string |  |  |  |
| `observability.connectors.<name>.webhooks[].room_id` | string |  |  |  |
| `observability.connectors.<name>.webhooks[].min_severity` | string |  | `INFO, LOW, MEDIUM, HIGH, CRITICAL` |  |
| `observability.connectors.<name>.webhooks[].events` | array |  |  |  |
| `observability.connectors.<name>.webhooks[].timeout_seconds` | integer | `10` |  |  |
| `observability.connectors.<name>.webhooks[].cooldown_seconds` | integer |  |  |  |
| `observability.connectors.<name>.webhooks[].enabled` | boolean | `false` |  |  |
| `observability.tokenomics` | object |  |  | Per-call model usage records, cost and the local usage aggregate. Off by default; an absent block is the pre-1.0.10 behaviour. |
| `observability.tokenomics.enabled` | boolean | `false` |  | Master switch. Off: no usage record, no store, no goroutine. |
| `observability.tokenomics.record_routing_provenance` | boolean | `true` |  | Put requested and selected model, route decision and profile on each usage record. |
| `observability.tokenomics.roles` | array |  |  | Call roles to record. Empty or absent: all. |
| `observability.tokenomics.native_otel_import` | object |  |  |  |
| `observability.tokenomics.native_otel_import.claudecode` | boolean | `true` |  | Import per-call usage from the Claude Code OTLP stream (cross-check only while the proxy carries the connector). |
| `observability.tokenomics.native_otel_import.codex` | boolean | `true` |  | Import per-call usage from the Codex OTLP stream (cross-check only while the proxy carries the connector). |
| `observability.tokenomics.cost` | object |  |  |  |
| `observability.tokenomics.cost.compute` | boolean | `true` |  | Compute cost from observability.pricing. |
| `observability.tokenomics.cost.currency` | constant | `"USD"` | `"USD"` |  |
| `observability.tokenomics.cost.keep_reported` | boolean | `true` |  | Keep a per-call provider or agent reported cost and mark its basis as reported. |
| `observability.tokenomics.local_store` | object |  |  |  |
| `observability.tokenomics.local_store.enabled` | boolean | `false` |  | Keep an hourly usage aggregate in <data_dir>/model_usage/model_usage.db for the usage API and status. |
| `observability.tokenomics.local_store.retention_days` | integer | `30` |  |  |
| `observability.tokenomics.local_store.granularity` | constant | `"hour"` | `"hour"` |  |
| `observability.tokenomics.metrics` | object |  |  |  |
| `observability.tokenomics.metrics.labels` | array |  |  | Labels on defenseclaw.model.cost and defenseclaw.model.tokens. A closed set: identity labels are refused. |
| `observability.pricing` | object |  |  | Versioned price table. The gateway prices only from this table; no price is compiled into a binary. Managed hosts take it from the admin config in the signed bundle. |
| `observability.pricing.version` | string |  |  | Table version stamped on every record. Required when models are listed. |
| `observability.pricing.models` | array |  |  |  |
| `observability.pricing.models[].provider` | string |  |  | Required. |
| `observability.pricing.models[].model` | string |  |  | Required. Exact model id, or a prefix ending in * (longest prefix wins). |
| `observability.pricing.models[].input_per_mtok` | number |  |  | Required. USD per million input tokens (uncached). |
| `observability.pricing.models[].output_per_mtok` | number |  |  | Required. USD per million output tokens (reasoning included unless reasoning_per_mtok is set). |
| `observability.pricing.models[].cache_read_per_mtok` | number |  |  | USD per million cache-read input tokens. Absent: priced at input_per_mtok. |
| `observability.pricing.models[].cache_write_per_mtok` | number |  |  | USD per million cache-creation input tokens. Absent: priced at input_per_mtok. |
| `observability.pricing.models[].reasoning_per_mtok` | number |  |  | USD per million reasoning output tokens. Absent: priced at output_per_mtok. |
| `observability.pricing.ai_defense` | object |  |  |  |
| `observability.pricing.ai_defense.per_call_usd` | number |  |  |  |
| `observability.pricing.unknown_model` | constraint | `"omit"` | `omit, fallback` | omit: a model without a price entry has no cost. fallback: price it with fallback. |
| `observability.pricing.fallback` | object |  |  |  |
| `observability.pricing.fallback.input_per_mtok` | number |  |  | USD per million input tokens (uncached). |
| `observability.pricing.fallback.output_per_mtok` | number |  |  | USD per million output tokens (reasoning included unless reasoning_per_mtok is set). |
| `observability.pricing.fallback.cache_read_per_mtok` | number |  |  | USD per million cache-read input tokens. Absent: priced at input_per_mtok. |
| `observability.pricing.fallback.cache_write_per_mtok` | number |  |  | USD per million cache-creation input tokens. Absent: priced at input_per_mtok. |
| `observability.pricing.fallback.reasoning_per_mtok` | number |  |  | USD per million reasoning output tokens. Absent: priced at output_per_mtok. |
| `observability.local` | object |  |  |  |
| `observability.local.path` | string |  |  | Defaults dynamically to <data_dir>/audit.db. |
| `observability.local.judge_bodies_path` | string |  |  | Defaults dynamically to <data_dir>/judge_bodies.db. |
| `observability.local.retention_days` | integer | `7` |  | Positive values reap eligible local event, evidence, judge-body, and correlation history older than the UTC cutoff a minute after startup readiness and every six hours. The same window bounds AI discovery scan history in <data_dir>/inventory.db, which the gateway prunes about hourly (always keeping the latest scan) and compacts. Zero retains history forever and requires a persistent capacity warning. SQLite can reuse freed pages, but the audit database file does not shrink automatically. The maximum is the largest whole-day period representable as a Go time.Duration. |
| `observability.local.max_store_mb` | integer | `0` |  | Opt-in size cap for the audit database in MiB. 0 (the default) keeps retention by days only. A value from 64 to 1048576 (1 to 63 are refused) makes each retention run also delete the oldest history, through the same path as retention_days, until the used pages of the audit database are under the cap; the newest hour is always kept. Releases before 1.0.6 refuse this key: remove it before going back with defenseclaw upgrade --version (defenseclaw rollback restores the previous configuration). |
| `observability.local.keep_rejected_records` | boolean | `false` |  | Opt-in. When true, each record the v8 schema gate refuses (a field value outside its family contract) is also kept in the rejected_records table of the audit database: time, signal, family, event name, reason code, the failing field and a copy of its fields redacted with, per field class, the stricter of the sensitive profile and the local profile of the record's bucket (at most 16 KiB per record; larger copies keep only the field names). Until the gateway redacts it, the copy is held in its memory only. The gateway writes them off the producer path through a bounded queue that drops and counts when full; each run of the store (from turning it on, or a reload that keeps it on, to the next) keeps at most rejected_records_max_rows rows. retention_days and max_store_mb prune the table with the other history. false (the default) only counts refused records and starts no writer. Read them with defenseclaw audit rejected. Not used on Secure Client. Releases before 1.0.10 refuse this key: remove it before going back with defenseclaw upgrade --version (defenseclaw rollback restores the previous configuration). Those releases also neither prune nor show the table, while their max_store_mb pass counts its pages: before going back, keep the store on with rejected_records_max_rows: 100 until the gateway has applied it (it trims the table at once), then remove both keys (or, with the gateway stopped, delete the rows with sqlite3 audit.db 'DELETE FROM rejected_records'). |
| `observability.local.rejected_records_max_rows` | integer | `10000` |  | Row cap of the rejected-record store (keep_rejected_records): the writer deletes the oldest rows past it in small batches, at once when a reload lowers it, and one run of the store queues at most this many rows. Ignored while keep_rejected_records is false. Releases before 1.0.10 refuse this key. |
| `observability.destinations` | array |  |  |  |
| `observability.destinations[].name` | constraint |  |  | Required. |
| `observability.destinations[].kind` | constant |  | `"jsonl"` | Required. |
| `observability.destinations[].enabled` | boolean | `true` |  |  |
| `observability.destinations[].path` | string |  |  | Required. |
| `observability.destinations[].rotation` | object |  |  |  |
| `observability.destinations[].rotation.max_size_mb` | integer | `50` |  |  |
| `observability.destinations[].rotation.max_backups` | integer | `5` |  |  |
| `observability.destinations[].rotation.max_age_days` | integer | `30` |  |  |
| `observability.destinations[].rotation.compress` | boolean | `true` |  |  |
| `observability.destinations[].batch` | object |  |  |  |
| `observability.destinations[].batch.max_queue_size` | integer | `2048` |  | Maximum projected records retained by this destination queue. |
| `observability.destinations[].batch.max_queue_bytes` | integer | `67108864` |  | Maximum immutable projected payload bytes retained by this destination queue. |
| `observability.destinations[].send` | object |  |  |  |
| `observability.destinations[].send.signals` | constant |  | `["logs"]` | Required. |
| `observability.destinations[].send.buckets` | one of |  |  | Required. |
| `observability.destinations[].send.redaction_profile` | constraint |  |  |  |
| `observability.destinations[].routes` | array |  |  |  |
| `observability.destinations[].routes[].name` | string |  |  | Required. |
| `observability.destinations[].routes[].signals` | constant |  | `["logs"]` | Required. |
| `observability.destinations[].routes[].selector` | object |  |  | Required. |
| `observability.destinations[].routes[].selector.buckets` | one of |  |  |  |
| `observability.destinations[].routes[].selector.sources` | one of |  |  |  |
| `observability.destinations[].routes[].selector.connectors` | one of |  |  |  |
| `observability.destinations[].routes[].selector.actions` | one of |  |  |  |
| `observability.destinations[].routes[].selector.event_names` | one of |  |  |  |
| `observability.destinations[].routes[].selector.min_severity` | string |  | `INFO, LOW, MEDIUM, HIGH, CRITICAL` |  |
| `observability.destinations[].routes[].action` | string | `"send"` | `send, drop` |  |
| `observability.destinations[].routes[].redaction_profile` | constraint |  |  |  |
| `observability.destinations[].listen` | string |  |  | Required. |
| `observability.destinations[].endpoint` | string |  |  | Required. |
| `observability.destinations[].token_env` | string |  |  | Required unless token_credential is set. |
| `observability.destinations[].token_credential` | string |  |  | Protected credential of a standalone enterprise deployment, stored with enterprise secret set. It resolves only in that profile. |
| `observability.destinations[].index` | string |  |  |  |
| `observability.destinations[].source` | string |  |  |  |
| `observability.destinations[].sourcetype` | string |  |  |  |
| `observability.destinations[].sourcetype_overrides` | object |  |  | Maps registered audit producer keys to Splunk sourcetypes. Registration and UTF-8 byte length are compiler-validated. |
| `observability.destinations[].sourcetype_overrides.<name>` | string |  |  | User-named entry. |
| `observability.destinations[].tls` | object |  |  |  |
| `observability.destinations[].tls.insecure_skip_verify` | boolean | `false` |  |  |
| `observability.destinations[].tls.ca_cert` | string |  |  |  |
| `observability.destinations[].timeout_ms` | integer | `10000` |  |  |
| `observability.destinations[].network_safety` | object |  |  |  |
| `observability.destinations[].network_safety.allow_private_networks` | boolean | `false` |  |  |
| `observability.destinations[].network_safety.allow_cgnat` | boolean | `false` |  |  |
| `observability.destinations[].batch.max_export_batch_size` | integer | `512` |  | Maximum records in one outbound request. |
| `observability.destinations[].batch.max_export_batch_bytes` | integer | `8388608` |  | Hard ceiling for one fully encoded outbound request. |
| `observability.destinations[].batch.scheduled_delay_ms` | integer | `5000` |  | Maximum normal batching delay in milliseconds. |
| `observability.destinations[].local_stack` | object |  |  | Written only by local Splunk setup: the record that DefenseClaw started the local Splunk container this destination sends to. Every Splunk destination without it is remote. |
| `observability.destinations[].local_stack.marker` | constant |  | `"defenseclaw-local-splunk"` | Required. |
| `observability.destinations[].local_stack.container_id` | string |  |  | Required. Full ID of the Splunk container local setup started. |
| `observability.destinations[].method` | string | `"POST"` | `POST, PUT, PATCH` |  |
| `observability.destinations[].bearer_env` | string |  |  |  |
| `observability.destinations[].bearer_credential` | string |  |  | Protected credential of a standalone enterprise deployment, stored with enterprise secret set. It resolves only in that profile. |
| `observability.destinations[].headers` | object |  |  |  |
| `observability.destinations[].headers.<name>` | one of |  |  | User-named entry. |
| `observability.destinations[].headers.<name>.env` | string |  |  | Required. |
| `observability.destinations[].headers.<name>.credential` | string |  |  | Required. Protected credential of a standalone enterprise deployment, stored with enterprise secret set. It resolves only in that profile. |
| `observability.destinations[].preset` | constant |  | `"galileo"` |  |
| `observability.destinations[].protocol` | string | `"grpc"` | `grpc, grpc/protobuf, http, http/protobuf` |  |
| `observability.destinations[].logger_name` | string |  |  | OTel log instrumentation-scope name. Valid only when this destination selects logs. |
| `observability.destinations[].tls.insecure` | boolean | `false` |  |  |
| `observability.destinations[].signal_overrides` | object |  |  |  |
| `observability.destinations[].signal_overrides.logs` | object |  |  |  |
| `observability.destinations[].signal_overrides.logs.endpoint` | string |  |  |  |
| `observability.destinations[].signal_overrides.logs.path` | string |  |  |  |
| `observability.destinations[].signal_overrides.traces` | object |  |  |  |
| `observability.destinations[].signal_overrides.traces.endpoint` | string |  |  |  |
| `observability.destinations[].signal_overrides.traces.path` | string |  |  |  |
| `observability.destinations[].signal_overrides.metrics` | object |  |  |  |
| `observability.destinations[].signal_overrides.metrics.endpoint` | string |  |  |  |
| `observability.destinations[].signal_overrides.metrics.path` | string |  |  |  |
| `observability.destinations[].send.signals` | array |  |  | Required. |
| `observability.destinations[].routes[].signals` | array |  |  | Required. |

## Exhaustive YAML

See [`observability.yaml`](./observability.yaml). It intentionally disables every
optional destination while demonstrating all destination kinds, selectors, secret
references, redaction controls, and local-retention controls.
