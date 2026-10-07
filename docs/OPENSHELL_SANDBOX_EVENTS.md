# OpenShell sandbox events

The NVIDIA OpenShell 0.1 integration emits canonical v8 telemetry only. The
authoritative definitions live in the telemetry registry
([`schemas/telemetry/v8/operations.yaml`](../schemas/telemetry/v8/operations.yaml)
and [`security.yaml`](../schemas/telemetry/v8/security.yaml)); this page maps
them for readers. Producers go through the typed `audit.SandboxTelemetry`
interface in [`internal/audit/sandbox_v8.go`](../internal/audit/sandbox_v8.go),
which never accepts a family name or free-form attributes. See
[SANDBOX.md](SANDBOX.md) for the architecture.

The gateway sidecar builds one `audit.NewSandboxRecorder` per process and
shares it: the sandbox manager (through `manager.Options.Telemetry`) and the
sandbox runtime both write to it. One recorder is required because it tracks
each sandbox's phase for the active gauge. On daemon start the manager's
reconcile pass records a lifecycle event (trigger `reconcile`) for every
existing sandbox, so the gauge is republished.

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
| `defenseclaw.sandbox.binding.id` | The DefenseClaw ingress binding the sandbox's hooks and egress proxy credential authenticate with (`sb_<hex>`; never the token) |

Phases are the OpenShell `SandboxPhase` values (`provisioning`, `starting`,
`ready`, `stopping`, `stopped`, `completed`, `error`, `deleting`, `unknown`)
plus two DefenseClaw-only bookends: `creating` (before the gateway accepts the
sandbox) and `deleted` (after it is gone).

## Families

| Producer | Audit action | Family | Bucket | Mandatory |
| --- | --- | --- | --- | --- |
| `RecordSandboxLifecycle` | `sandbox-lifecycle` | `log.sandbox.lifecycle` | `agent.lifecycle` | No |
| `RecordSandboxWorkspace` | `sandbox-workspace` | `log.sandbox.workspace` | `enforcement.action` | State changes and flagged changes (below) |
| `RecordSandboxEgress` | `sandbox-egress` | `log.egress.allowed`, `log.egress.blocked`, `log.egress.completed`, `log.egress.failed` | `network.egress` | Blocked (`enforced_outcome`) |
| `RecordSandboxApproval` | `sandbox-approval` | `log.approval.requested`, `log.approval.resolved` | `compliance.activity` | Resolved (`approval_resolution`) |
| `RecordSandboxPolicy` | `sandbox-policy` | `log.policy.updated` | `compliance.activity` | Always (`control_plane_mutation`) |
| `RecordSandboxHealth` | `sandbox-health` | `log.subsystem.lifecycle`, `.ready`, `.degraded`, `.restored` | `platform.health` | Always (`durable_health_transition`) |
| `RecordSandboxFinding` | `sandbox-finding` | `log.finding.observed` | `security.finding` | No |
| `RecordSandboxActivity` | `sandbox-activity` | `log.sandbox.process`, `log.sandbox.ssh`, `log.sandbox.inference` | `tool.activity`, `compliance.activity`, `model.io` | No |
| `RecordSandboxProcess` | `sandbox-process` | `log.sandbox.process_tree` | `agent.lifecycle` | No |

The manager stamps every record with what it knows of the sandbox and the
producer does not: the launching host account as `user.id`,
`defenseclaw.user.id_kind` and `defenseclaw.user.name` (the daemon's own
user, which the sandbox's binding stores too) on egress, approval, finding,
process, SSH and inference records, and on egress, approval, process and
inference records the harness session the sandbox's hooks last named as
`gen_ai.conversation.id` (it wins over the request envelope's session; a
new session starts without one until its first hook).

`RecordSandboxPolicy` records name the changed host or egress pattern in `defenseclaw.admin.target_ref`: a wildcard such as `*.example.com` is recorded as `suffix:example.com`, a leading `::` as `0::` (`::/0` becomes `0::/0`), and a name whose first label starts with `_` as `host:` plus the name (`_x.example` becomes `host:_x.example`), because a reference must start with a letter or digit.

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

One record per `snapshot`, `undo`, `mask`, `review`, `upload`, `pull` or
`quarantine` (`defenseclaw.sandbox.workspace.operation`, also reported as
`defenseclaw.enforcement.effective_action`). It carries the snapshot kind
(`git` or `filesystem`; callers report the workspace package's non-git
`copy` snapshot as `filesystem`), the snapshot ref, the pull mode (`apply`,
`branch` or `patch`), counts of files, added and removed lines, flagged files
and bytes, and up to 64 workspace-relative paths. The paths are file names
from the project, so each destination's redaction profile governs them.

DefenseClaw itself records a `quarantine` (initiator `defenseclaw`) when a
new nested git repository appears in a live-mounted project during a session
and it renames that repository's `.git` entry. The record names the
repository's folder, counts one file and one flagged file, and is `failed`
(failure class `rename_failed`) when the rename did not happen. The
`nested_repo` finding of the same detection is listed under Findings.

The result is `applied`, `completed`, `failed`, `no_change`, `partial` or
`skipped`. It defaults to `applied` for undo, mask, pull and quarantine and to
`completed` for the rest; `failed` and `partial` may carry a failure class.

Two kinds of record are mandatory:

- a state change (`enforcement_state_change`): an undo, a mask, a quarantine,
  or a pull in `apply` or `branch` mode, unless its result is `no_change` or
  `skipped`. A `failed` or `partial` result still counts, because part of
  the change may have been written. A `patch` pull writes only the patch
  file and is not a state change;
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
(`.policy_outcome`). OpenShell reports an allowed connection (naming the
process) and then each HTTP request it inspects on it: the connection and
its first request are one record, each later request on it a record of its
own, and every denied request is recorded. Only OpenShell's HTTP events can
add the origin-form path of a plain-HTTP request
(`defenseclaw.network.target_path`); the DefenseClaw proxy never records
URL paths. Blocked decisions default to
MEDIUM, allowed ones to INFO. Each record also increments
`defenseclaw.egress.events`.

OpenShell's denials are recorded as they come (decision code
`SANDBOX_EGRESS_OPENSHELL_DENIED`), including the connections it closes on a
policy reload ("policy generation is stale") and the denials of this
install's own ingress and egress ports; those two are not counted in the
sandbox's blocked requests and are not shown as blocks on the activity feed.
A denied connection to a host port is recorded with `server.address`
`host.openshell.internal`, not OpenShell's synthetic address. A sandbox
whose policy turned its web egress off while it ran is refused by the proxy
with category `egress_off` (decision code `SANDBOX_EGRESS_EGRESS_OFF`).
OpenShell's allowed connections to a host port other than this install's
own (a `--host-port` service, a local model endpoint) are recorded as
allowed with `server.address` `host.openshell.internal`.

An OpenShell record names the process that made the connection:
`defenseclaw.sandbox.process.executable` and `defenseclaw.sandbox.process.pid`.
Both are what the process claims, display text the workload chooses.

The end of every tunnel or forwarded request the proxy allowed is a second
record: `log.egress.completed` with `defenseclaw.network.bytes_up`,
`.bytes_down` and `.duration_ms` (decision code `SANDBOX_EGRESS_ALLOWED`),
or `log.egress.failed`. A failed end is either one the proxy cut short (the
large-upload block, the idle timeout, a refused TLS server name or content,
or a recheck): outcome `cancelled`, with the byte counts, `.duration_ms`
and decision code `SANDBOX_EGRESS_TERMINATED` (`.reason` says why a recheck
ended it); or one where DNS, the connect, TLS or the upstream failed and
the sandbox got a 502 (outcome `failed`) or 504 (`timed_out`), with
`.duration_ms` and the bounded error (decision code
`SANDBOX_EGRESS_UPSTREAM_FAILED`). None counts toward
`defenseclaw.egress.events`: the decision did.

### Activity

OpenShell's OCSF records of what runs in a sandbox and what reaches into
it. A workload can start processes, and a client open SSH sessions, as fast
as it likes, so the manager paces each sandbox's process and SSH records (a
burst of 200, then 20 a second); the daemon log says how many the pacing
held back. Model calls are not paced.

| Family | From | Carries | Outcome |
| --- | --- | --- | --- |
| `log.sandbox.process` | `PROC:LAUNCH`, `PROC:TERMINATE` | `defenseclaw.sandbox.process.event` (`start`, `exit`), `.source` (`ocsf`), `.pid`, `.executable`, `.command_line` (start only), `.exit_code` (exit only) | `attempted` for a start, `completed` for exit code 0, `failed` otherwise |
| `log.sandbox.ssh` | `SSH:*` (`sandbox connect`, `exec`, uploads and pulls) | `defenseclaw.sandbox.ssh.activity` (`LISTEN`, `OPEN`, ...), `.auth`, the peer address as `client.address` | `allowed`, `blocked` (OpenShell denied it) or `completed` |
| `log.sandbox.inference` | `API:INFERENCE` | `gen_ai.provider.name`, `gen_ai.request.model`, `defenseclaw.sandbox.inference.status`, `.latency_ms`, `.operation`; never model content | `failed` for a status other than `Success`, else `completed` (the status is optional) |

The command line is the agent's argument vector, so it is content class: each
destination's redaction profile governs whether it leaves the host. Before
that, the manager replaces the values of arguments that name secrets and
keeps at most 1,024 bytes of it, as for the process tree.

### Approvals

A rare ask: an OpenShell draft proposal (`defenseclaw.sandbox.approval.kind`
`network_rule`) or a host-port consent (`host_port`). OpenShell drafts no
proposal for `host.openshell.internal`, so the manager raises the host-port
ask of a port the run declared with `--host-port` itself, on the sandbox's
first denied connection to it; approving it adds a policy rule (reason code
`approval`). Both stages carry
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

The sandbox manager's reason codes are `approval` (a rule added by an
approved proposal), `egress_unblock` (an unblock), `admin_policy` (an
approved rule removed because the administrator's policy now refuses it),
`egress_blocklist` (an approved rule removed because a block list or the
blocklist feed now refuses its destination), `approval_required` (a rule
DefenseClaw approved on its own removed because the policy now leaves it to
the user), `policy_unresolved` (an approved rule removed because no policy
can be resolved for the sandbox) and `rule_resolves_to_host` (an approved
rule removed because its destination now resolves to this machine). A pass that removes several rules writes one
record per rule, with the rule name as the target.

### Health

`defenseclaw.health.subsystem` is `openshell`. States map to families:

| State | Family | Outcome | Severity |
| --- | --- | --- | --- |
| `starting` | `log.subsystem.lifecycle` | `attempted` | INFO |
| `stopped` | `log.subsystem.lifecycle` | `completed` | INFO |
| `ready` | `log.subsystem.ready` | `completed` | INFO |
| `restored` | `log.subsystem.restored` | `completed` | INFO |
| `degraded`, `failed` | `log.subsystem.degraded` | `failed` | HIGH |

A stable error code goes in `defenseclaw.schema.error_code`: an `OPENSHELL_*`
gateway error code in lower case (`openshell_admin_violation`), because the
field holds only stable tokens. The summary goes in
`defenseclaw.health.error_summary`. A health record about the integration as a
whole (for example the watch stream) has no sandbox name.

Two `degraded` records are the manager's own:

- `openshell_egress_auth_failed`: the egress proxy refused requests that
  presented an invalid proxy credential (malformed, unknown, revoked or
  wrong; a request with none is the normal first leg of the handshake). The
  credential names no sandbox. The first refusal of a streak is one
  `degraded` record at once; the gateway log counts the later ones at most
  once a minute, with the last destination; and a minute without a refusal
  ends the streak with one `restored` record (same error code).
- `openshell_telemetry_failed`: the recorder refused a sandbox record. The
  first refusal of a streak is recorded (through the same recorder, so a
  runtime that is down refuses this too) and logged; every refusal is
  counted in `GET /api/v1/sandbox/status` (`telemetry_failures`,
  `telemetry_error`) and on `defenseclaw sandbox status`.

### Findings

`defenseclaw.finding.category` is `sandbox.<kind>`:

| Kind | Meaning | Default rule ID |
| --- | --- | --- |
| `ocsf_finding` | An OpenShell OCSF `FINDING` event | `SANDBOX-OCSF-FINDING` |
| `hook_silence` | Harness activity with no hook traffic | `SANDBOX-HOOK-SILENCE` |
| `hook_tamper` | A tool that ran without a DefenseClaw verdict: a `PostToolUse` whose `PreToolUse` was denied or never arrived | `SANDBOX-HOOK-TAMPER` |
| `large_upload` | A large upload to a first-seen host | `SANDBOX-LARGE-UPLOAD` |
| `nested_repo` | A repository that appeared inside a live-mounted project during a session | `SANDBOX-NESTED-REPO` |
| `shadow_ai` | An AI API the sandbox reached (MEDIUM) or tried to reach (LOW) that is neither its model provider nor its harness's vendor: a catalogued AI provider or an inference-shaped host. At most once per provider and severity per session: a refusal and then a contact raise one of each; the target is the host | `SANDBOX-SHADOW-AI` |

A finding requires a severity (INFO, LOW, MEDIUM, HIGH or CRITICAL). A
missing finding ID is generated; confidence, when reported, is in (0, 1].

### Process tree

Only for a sandbox whose process tree is on (the pack's
`observe.process_tree: true`, or `sandbox run --process-tree`; off in every
built-in pack). DefenseClaw samples the sandbox's `/proc` every 5 seconds
while it runs (15 on the vm driver once a sample takes over a second) and
adds OpenShell's `PROC` launch and terminate records. One record when a
process joins the tree and one when it exits:
`defenseclaw.sandbox.process.event` (`start`, `exit`), `.source` (`sample`,
`ocsf`), `.pid`, `.parent_pid` (absent while only OpenShell reported the
process, which names no parent), `.name` (comm), `.executable`,
`.command_line` (the first 16 arguments, joined, the values of arguments that
name secrets replaced, at most 1,024 bytes), `.working_directory`,
`.exit_code` (when OpenShell reported it) and `.lineage` (the names of up to
32 ancestors, the parent first). The command line, working folder and
lineage are content and the executable a path: each destination's redaction
profile governs them. Like the other sandbox records they carry the binding,
the launching host user and the session the hooks last named. At most 200
records at once and 10 a second per sandbox; the daemon log says how many it
held back. A process that starts and ends between two samples, and that
OpenShell does not report, has no record. An OpenShell launch makes both a
`log.sandbox.process` record (what ran) and, with the tree on, a
`log.sandbox.process_tree` start (the tree's membership, with the parent and
lineage once a sample saw them).

With the tree on, `sandbox destinations` and its API name the lineage of the
process that made each connection (`lineage`, the process first).

### AI discovery inside a sandbox

What the AI discovery of a sandbox finds in it reaches the AI discovery
families (`ai_component.discovered`, `.changed`, `.observed`, `.removed`)
with the sandbox's `defenseclaw.sandbox.id` and `defenseclaw.sandbox.name`;
the rest of the sandbox correlation group is not set there.

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
| `defenseclaw.egress.events` (counter) | `defenseclaw.metric.decision` (`allow`, `block`), `defenseclaw.metric.source` (`openshell`, `dc-egress-proxy`), `defenseclaw.connector.source` (the sandbox's harness connector) | The existing egress metric; one point per decision, none for an end |

The local-observability profile projects `defenseclaw.connector.source` as
the `connector` label (on the egress metric too) and the egress attributes
as `decision` and `source`.
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
  their brackets and zone. A name whose first label starts with `_`
  (`_x.example`) is recorded as `defenseclaw.network.target_ref`
  `host:_x.example` with `server.address` absent, since neither field may
  start with `_`; an approval omits it. If the host still does not
  canonicalize, egress records it as `defenseclaw.network.target_ref`
  `invalid-host` with `server.address` absent, and an approval omits it. An
  out-of-range port is omitted.
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
- A process record's name, executable, command line, working folder and
  lineage are the workload's: each is cut to its registered bound, and
  invalid UTF-8 is omitted rather than failing the record.
- The session and agent IDs come from the correlation envelope, which the
  agent fills through its session header and hook payload, and the session
  from the sandbox's last hook. Egress and approval records carry them as
  `gen_ai.conversation.id` and `gen_ai.agent.id`, and process and inference
  records the session as `gen_ai.conversation.id`, only when they are
  registered identifiers (trimmed, at most 256 bytes); any other value is
  omitted.
- An actor's or process's executable is cut to 4096 bytes and its process
  ID kept only in 1 to 4194304; an executable that is not UTF-8 is omitted.
  A process command line is cut to 4096 bytes (the manager sends at most
  1,024). SSH and inference tokens
  (activity, auth, status, operation, model) that are not identifiers are
  omitted, and an SSH peer that is not an IP address is.

## Retired legacy events

The legacy standalone sandbox's events were retired with it: the
`init-sandbox` audit action and the `defenseclaw.openshell.exit` metric
(`metric.defenseclaw.openshell.exit` family, with its
`defenseclaw.metric.command` attribute) are no longer emitted, and the gateway
no longer reports a degraded `sandbox` health subsystem for a host that still
has the legacy config (the upgrade to 1.0 resets that config). See
[SANDBOX.md](SANDBOX.md#hosts-that-still-have-the-legacy-install).
