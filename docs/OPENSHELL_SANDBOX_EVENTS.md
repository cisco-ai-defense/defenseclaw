# OpenShell sandbox events

The NVIDIA OpenShell 0.1 integration emits canonical v8 telemetry only. The
authoritative definitions live in the telemetry registry
([`schemas/telemetry/v8/operations.yaml`](../schemas/telemetry/v8/operations.yaml)
and [`security.yaml`](../schemas/telemetry/v8/security.yaml)); this page maps
them for readers. Producers go through the typed `audit.SandboxTelemetry`
interface in [`internal/audit/sandbox_v8.go`](../internal/audit/sandbox_v8.go),
which never accepts a family name or free-form attributes. See
[SANDBOX.md](SANDBOX.md) for the architecture.

The producers are complete, but nothing calls them yet: the sandbox manager,
the `WatchSandbox` watcher and the egress proxy's event sink are not wired
up. When they are, the process builds one `audit.NewSandboxRecorder` and
shares it, because the recorder tracks each sandbox's phase for the active
gauge. On daemon start the reconciler must record a lifecycle event for every
existing sandbox so the gauge is republished.

## Sandbox correlation (`correlation.sandbox`)

Every sandbox record carries these attributes when they are known. Empty
values are omitted, never inferred. They are never metric labels.

| Attribute | Meaning |
| --- | --- |
| `defenseclaw.sandbox.id` | OpenShell sandbox ID; absent until the gateway accepted the sandbox |
| `defenseclaw.sandbox.name` | DefenseClaw sandbox name; required on every record except gateway-wide health |
| `defenseclaw.sandbox.runtime` | `openshell` |
| `defenseclaw.sandbox.driver` | OpenShell compute driver: `docker`, `podman`, `vm`, `k8s` |
| `defenseclaw.sandbox.image.digest` | Workload image digest (`sha256:<64 hex>`) |
| `defenseclaw.sandbox.policy.version` | OpenShell policy revision in force; omitted when unknown, never reported as 0 |
| `defenseclaw.sandbox.profile` | `open`, `balanced`, or `strict` |
| `defenseclaw.sandbox.pack` | Policy pack name |
| `defenseclaw.sandbox.phase` | Lifecycle phase (below) |
| `defenseclaw.sandbox.workdir.mode` | `mount` or `copy` |

Phases are the OpenShell `SandboxPhase` values (`provisioning`, `starting`,
`ready`, `stopping`, `stopped`, `completed`, `error`, `deleting`, `unknown`)
plus two DefenseClaw-only bookends: `creating` (before the gateway accepts the
sandbox) and `deleted` (after it is gone).

## Families

| Producer | Audit action | Family | Bucket | Mandatory |
| --- | --- | --- | --- | --- |
| `RecordSandboxLifecycle` | `sandbox-lifecycle` | `log.sandbox.lifecycle` | `agent.lifecycle` | No |
| `RecordSandboxWorkspace` | `sandbox-workspace` | `log.sandbox.workspace` | `enforcement.action` | State changes and flagged changes (below) |
| `RecordSandboxEgress` | `sandbox-egress` | `log.egress.allowed`, `log.egress.blocked` | `network.egress` | Blocked (`enforced_outcome`) |
| `RecordSandboxApproval` | `sandbox-approval` | `log.approval.requested`, `log.approval.resolved` | `compliance.activity` | Resolved (`approval_resolution`) |
| `RecordSandboxPolicy` | `sandbox-policy` | `log.policy.updated` | `compliance.activity` | Always (`control_plane_mutation`) |
| `RecordSandboxHealth` | `sandbox-health` | `log.subsystem.lifecycle`, `.ready`, `.degraded`, `.restored` | `platform.health` | Always (`durable_health_transition`) |
| `RecordSandboxFinding` | `sandbox-finding` | `log.finding.observed` | `security.finding` | No |

A mandatory record is delivered whatever a route's collection settings say.

### Lifecycle

One record per observed or initiated phase change. It carries the new phase,
`defenseclaw.sandbox.phase.previous`, `defenseclaw.sandbox.lifecycle.trigger`
(`create`, `start`, `stop` and `delete` for DefenseClaw-initiated changes,
`watch` for a gateway status update, `reconcile` for drift the controller
found), `defenseclaw.sandbox.exit_code` once the main process exited
(128 plus the signal number for a signal), and the OpenShell condition behind
the change (`defenseclaw.sandbox.condition.type`, `.status`, `.reason`,
`.message`). Condition tokens that do not fit their registered shape are
dropped, and the message is cut to 1,024 bytes.

The outcome is `completed` for `ready`, `stopped`, `completed` and `deleted`,
`failed` for `error` and `unknown`, and `attempted` otherwise. Severity
defaults to HIGH for `error`, MEDIUM for `unknown`, and INFO otherwise.

### Workspace

One record per `snapshot`, `undo`, `mask`, `review`, `upload` or `pull`
(`defenseclaw.sandbox.workspace.operation`, also reported as
`defenseclaw.enforcement.effective_action`). It carries the snapshot kind
(`git` or `filesystem`; callers report the workspace package's non-git
`copy` snapshot as `filesystem`), the snapshot ref, the pull mode (`apply`,
`branch` or `patch`), counts of files, added and removed lines, flagged files
and bytes, and up to 64 workspace-relative paths. The paths are file names
from the project, so each destination's redaction profile governs them.

The result is `applied`, `completed`, `failed`, `no_change`, `partial` or
`skipped`. It defaults to `applied` for undo, mask and pull and to
`completed` for the rest; `failed` and `partial` may carry a failure class.

Two kinds of record are mandatory:

- a state change (`enforcement_state_change`): an undo, a mask, or a pull in
  `apply` or `branch` mode, unless its result is `no_change` or `skipped`. A
  `failed` or `partial` result still counts, because part of the change may
  have been written. A `patch` pull writes only the patch file and is not a
  state change;
- any record with a flagged file count above zero (`enforced_outcome`): the
  session changed files that can run code on the host.

Severity defaults to HIGH for `failed`, MEDIUM when files were flagged, and
INFO otherwise.

### Egress

One record per decision, from the DefenseClaw egress proxy
(`defenseclaw.network.source` `dc-egress-proxy`) or from OpenShell's own
network boundary (`openshell`). It carries the destination as
`defenseclaw.network.target_ref`, `server.address` and `server.port`, the
dialed address (`defenseclaw.network.resolved_ip`), `url.scheme` when known,
`defenseclaw.network.decision` (`allow` or `block`) with `.blocked`, a stable
`.decision_code`, a bounded `.reason`, and the source policy summary
(`.policy_outcome`). Only OpenShell's HTTP events can add the origin-form
path of a plain-HTTP request (`defenseclaw.network.target_path`); the
DefenseClaw proxy never records URL paths. Blocked decisions default to
MEDIUM, allowed ones to INFO. Each record also increments
`defenseclaw.egress.events`.

### Approvals

A rare ask: an OpenShell draft proposal (`defenseclaw.sandbox.approval.kind`
`network_rule`) or a host-port consent (`host_port`). Both stages carry
`defenseclaw.approval.id`, the destination as `server.address` and
`server.port`, `defenseclaw.approval.dangerous` for triage-classified risky
reach (private, IP-literal or credentialed destinations), and a bounded
`defenseclaw.guardrail.reason`.

A resolution adds `defenseclaw.approval.result` (`approved`, `denied`,
`expired`, `cancelled`, reported as the outcomes `approved`, `denied`,
`timed_out` and `cancelled`), `defenseclaw.approval.actor_type` (`operator`,
`automatic` for triage, or `policy`) and, for an approval only,
`defenseclaw.sandbox.approval.scope` (`sandbox` for this sandbox, `always`
for future sandboxes too). A request must not carry a resolution.

### Policy changes

`defenseclaw.admin.operation` is one of `sandbox.policy.apply` (render and
apply the profile policy), `sandbox.policy.rule_add` (merge an approved draft
or host-port rule), `sandbox.policy.rule_remove`, `sandbox.egress.unblock`,
and `sandbox.egress.block`. The record carries the new OpenShell revision as
`defenseclaw.admin.revision` and the previous one as
`defenseclaw.admin.current_revision`, the policy hash as
`defenseclaw.admin.after_summary` (`sha256:<hex>`), the actor, the origin
(`api`, `cli`, `internal` or `triage`), a bounded target, a registered reason
code, and a change count. The outcome is `applied`, or `no_change` for a
no-op.

### Health

`defenseclaw.health.subsystem` is `openshell`. States map to families:

| State | Family | Outcome | Severity |
| --- | --- | --- | --- |
| `starting` | `log.subsystem.lifecycle` | `attempted` | INFO |
| `stopped` | `log.subsystem.lifecycle` | `completed` | INFO |
| `ready` | `log.subsystem.ready` | `completed` | INFO |
| `restored` | `log.subsystem.restored` | `completed` | INFO |
| `degraded`, `failed` | `log.subsystem.degraded` | `failed` | HIGH |

A stable error code (typically an `OPENSHELL_*` gateway error code) goes in
`defenseclaw.schema.error_code`, the summary in
`defenseclaw.health.error_summary`. A health record about the integration as a
whole (for example the watch stream) has no sandbox name.

### Findings

`defenseclaw.finding.category` is `sandbox.<kind>`:

| Kind | Meaning | Default rule ID |
| --- | --- | --- |
| `ocsf_finding` | An OpenShell OCSF `FINDING` event | `SANDBOX-OCSF-FINDING` |
| `binary_drift` | A harness binary whose hash left its pin | `SANDBOX-BINARY-DRIFT` |
| `tamper_attempt` | An attempt to alter hooks or managed config | `SANDBOX-TAMPER-ATTEMPT` |
| `hook_silence` | Harness activity with no hook traffic | `SANDBOX-HOOK-SILENCE` |
| `large_upload` | A large upload to a first-seen host | `SANDBOX-LARGE-UPLOAD` |

A finding requires a severity (INFO, LOW, MEDIUM, HIGH or CRITICAL). A
missing finding ID is generated; confidence, when reported, is in (0, 1].

### Hook decisions and other rows

Hook decisions (`log.compat.hook_decision`) accept the same correlation
group, so a sandboxed hook verdict can be joined to its sandbox. The gateway
fills `defenseclaw.sandbox.id` and `defenseclaw.sandbox.name` from the sandbox
binding that authenticated the hook (`audit.CorrelationEnvelope.SandboxID` and
`SandboxName`); the other correlation attributes are not set there, and the
hook metrics never carry them. Generic compatibility audit rows from a
sandbox, such as Codex notify and inspect calls, carry `sandbox_id` and
`sandbox_name` in their body instead.

## Metrics

| Metric | Labels | Notes |
| --- | --- | --- |
| `defenseclaw.sandbox.transitions` (counter) | `defenseclaw.connector.source`, `defenseclaw.sandbox.phase.from`, `defenseclaw.sandbox.phase.to` | Emitted with a lifecycle record whose phase changed |
| `defenseclaw.sandbox.active` (gauge) | `defenseclaw.connector.source` | Sandboxes provisioning, starting, ready, or stopping, per connector |
| `defenseclaw.egress.events` (counter) | `defenseclaw.metric.decision` (`allow`, `block`), `defenseclaw.metric.source` (`openshell`, `dc-egress-proxy`) | The existing egress metric |

The local-observability profile projects `defenseclaw.connector.source` as
the `connector` label and the egress attributes as `decision` and `source`.
Sandbox identities are never labels.

The recorder keeps the last recorded phase of each sandbox name and uses it as
the previous phase when the caller gives none. It publishes the active gauge
under the same lock as the log, so gauge points reach the runtime in the
order the phases changed. A lifecycle call that fails leaves the tracked
phase unchanged, so the caller can retry it. When the previous phase is not
known, a transition is counted only if it enters `creating`: a restarted
daemon reconciling running sandboxes, or a repeated `deleted`, does not count
a sandbox twice.

## Agent-chosen values

The sandboxed agent picks destinations, file names, finding targets, and its
session and agent IDs. None of these values can make the producer drop the
record:

- An egress or approval host has its port split off (the port is used when
  none was given separately). It is lowercased and IDNA-encoded
  (`bücher.example` becomes `xn--bcher-kva.example`), and IP literals lose
  their brackets and zone. If the host still does not canonicalize, egress
  records it as `defenseclaw.network.target_ref` `invalid-host` with
  `server.address` absent, and an approval omits it. An out-of-range port is
  omitted.
- An egress path keeps only its origin-form path; the query and fragment are
  dropped.
- Workspace paths: invalid UTF-8 is replaced and NUL bytes are dropped.
  Absolute paths, drive-qualified paths, and paths that leave the workspace
  are skipped. Each path is cut to 1024 bytes. The list keeps at most the
  first 64 paths, and stops earlier once the JSON-encoded array (quotes,
  commas, and escapes included) would pass 16 KiB. The counts still describe
  every file.
- A finding `target_ref` is cut to its registered 256 bytes; one that is not
  an identifier is omitted.
- The session and agent IDs come from the correlation envelope, which the
  agent fills through its session header and hook payload. Egress and
  approval records carry them as `gen_ai.conversation.id` and
  `gen_ai.agent.id` only when they are registered identifiers (trimmed, at
  most 256 bytes); any other value is omitted.

## Retired legacy events

The legacy standalone sandbox's events were retired with it: the
`init-sandbox` audit action and the `defenseclaw.openshell.exit` metric
(`metric.defenseclaw.openshell.exit` family, with its
`defenseclaw.metric.command` attribute) are no longer emitted. See
[SANDBOX.md](SANDBOX.md#hosts-that-still-have-the-legacy-install) for how to
remove a legacy install.
