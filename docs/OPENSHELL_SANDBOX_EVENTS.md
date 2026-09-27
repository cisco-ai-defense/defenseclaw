# OpenShell sandbox events

The NVIDIA OpenShell 0.1 integration emits canonical v8 telemetry only. The
authoritative definitions live in the telemetry registry
([`schemas/telemetry/v8/operations.yaml`](../schemas/telemetry/v8/operations.yaml)
and [`security.yaml`](../schemas/telemetry/v8/security.yaml)); this page maps
them for readers. Producers go through the typed
`audit.SandboxTelemetry` interface in
[`internal/audit/sandbox_v8.go`](../internal/audit/sandbox_v8.go), which never
accepts a family name or free-form attributes.

## Sandbox correlation (`correlation.sandbox`)

Every sandbox-originated log carries these attributes when they are known.
They are never metric labels.

| Attribute | Meaning |
| --- | --- |
| `defenseclaw.sandbox.id` | OpenShell sandbox ID |
| `defenseclaw.sandbox.name` | DefenseClaw sandbox name |
| `defenseclaw.sandbox.runtime` | `openshell` |
| `defenseclaw.sandbox.driver` | OpenShell compute driver: `docker`, `podman`, `vm`, `k8s` |
| `defenseclaw.sandbox.image.digest` | Workload image digest (`sha256:…`) |
| `defenseclaw.sandbox.policy.version` | OpenShell policy revision in force |
| `defenseclaw.sandbox.profile` | `open`, `balanced`, or `strict` |
| `defenseclaw.sandbox.pack` | Policy pack name |
| `defenseclaw.sandbox.phase` | Lifecycle phase (below) |
| `defenseclaw.sandbox.workdir.mode` | `mount` or `copy` |

Phases are the OpenShell `SandboxPhase` values (`provisioning`, `starting`,
`ready`, `stopping`, `stopped`, `completed`, `error`, `deleting`, `unknown`)
plus `creating` (before the gateway accepts the sandbox) and `deleted`.

## Families

| Producer | Audit action | Family | Notes |
| --- | --- | --- | --- |
| `RecordSandboxLifecycle` | `sandbox-lifecycle` | `log.sandbox.lifecycle` (agent.lifecycle) | Phase, previous phase, trigger, exit code, OpenShell condition |
| `RecordSandboxWorkspace` | `sandbox-workspace` | `log.sandbox.workspace` (enforcement.action) | Snapshot, undo, mask, review, upload, pull |
| `RecordSandboxEgress` | `sandbox-egress` | `log.egress.allowed` / `log.egress.blocked` | `defenseclaw.network.source` is `openshell` or `dc-egress-proxy`; blocked is mandatory |
| `RecordSandboxApproval` | `sandbox-approval` | `log.approval.requested` / `log.approval.resolved` | `defenseclaw.sandbox.approval.kind` and `.scope`; resolution is mandatory |
| `RecordSandboxPolicy` | `sandbox-policy` | `log.policy.updated` | Control-plane mutation (mandatory) |
| `RecordSandboxHealth` | `sandbox-health` | `log.subsystem.lifecycle`, `.ready`, `.degraded`, `.restored` | Subsystem `openshell` |
| `RecordSandboxFinding` | `sandbox-finding` | `log.finding.observed` | Category `sandbox.<kind>`: OCSF finding, binary drift, tamper attempt, hook silence, large upload |

Hook decisions (`log.compat.hook_decision`) accept the same correlation group
so a sandboxed hook verdict can be joined to its sandbox. The gateway fills
`defenseclaw.sandbox.id` and `defenseclaw.sandbox.name` from the sandbox
binding that authenticated the hook (`audit.CorrelationEnvelope.SandboxID` and
`SandboxName`); the hook metrics never carry them.

## Metrics

| Metric | Labels |
| --- | --- |
| `defenseclaw.sandbox.transitions` (counter) | `defenseclaw.connector.source`, `defenseclaw.sandbox.phase.from`, `defenseclaw.sandbox.phase.to` |
| `defenseclaw.sandbox.active` (gauge) | `defenseclaw.connector.source`; sandboxes provisioning, starting, ready, or stopping |
| `defenseclaw.egress.events` (counter) | Existing egress metric; `source` is `openshell` or `dc-egress-proxy` |

## Retired legacy events

The legacy standalone sandbox's events were retired with it: the
`init-sandbox` audit action and the `defenseclaw.openshell.exit` metric
(`metric.defenseclaw.openshell.exit` family, with its
`defenseclaw.metric.command` attribute) are no longer emitted.

See [SANDBOX.md](SANDBOX.md) for how to remove a legacy install.
