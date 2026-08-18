# DefenseClaw v8 observability configuration reference

<!-- GENERATED FILE. DO NOT EDIT. -->

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
| `splunk_hec` | logs | `name`, `kind`, `enabled`, `endpoint`, `token_env`, `index`, `source`, `sourcetype`, `sourcetype_overrides`, `tls`, `timeout_ms`, `network_safety`, `batch`, `send`, `routes` |
| `http_jsonl` | logs | `name`, `kind`, `enabled`, `endpoint`, `method`, `bearer_env`, `headers`, `tls`, `timeout_ms`, `network_safety`, `batch`, `send`, `routes` |
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
| `observability.trace_policy.compatibility_aliases` | boolean | `true` |  |  |
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
| `observability.local` | object |  |  |  |
| `observability.local.path` | string |  |  | Defaults dynamically to <data_dir>/audit.db. |
| `observability.local.judge_bodies_path` | string |  |  | Defaults dynamically to <data_dir>/judge_bodies.db. |
| `observability.local.retention_days` | integer | `90` |  | Zero retains event, evidence, and judge-body history forever and requires a persistent capacity warning. The maximum is the largest whole-day period representable as a Go time.Duration. |
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
| `observability.destinations[].token_env` | string |  |  | Required. |
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
| `observability.destinations[].method` | string | `"POST"` | `POST, PUT, PATCH` |  |
| `observability.destinations[].bearer_env` | string |  |  |  |
| `observability.destinations[].headers` | object |  |  |  |
| `observability.destinations[].headers.<name>` | one of |  |  | User-named entry. |
| `observability.destinations[].headers.<name>.env` | string |  |  | Required. |
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
