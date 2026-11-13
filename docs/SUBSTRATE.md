# DefenseClaw on Agent Substrate

Design record for the Agent Substrate integration shipped in DefenseClaw 1.0.10. User documentation is in
[docs-site/content/docs/substrate](../docs-site/content/docs/substrate); this page records why it is built the way it is.
The telemetry contract is in [`schemas/telemetry/v8`](../schemas/telemetry/v8) and
[OPENSHELL_SANDBOX_EVENTS.md](OPENSHELL_SANDBOX_EVENTS.md) (the sandbox records Substrate reuses).

> TODO(substrate): this record follows the build plan. Anything that changed during the build is marked in
> `~/dc-eh/plans/agent-substrate/lanes/a7/PROGRESS.md`; reconcile this file with the merged code before the PR is marked ready.

## Goal

Protect every DefenseClaw connector agent that runs as an [Agent Substrate](https://ate.dev) actor in Kubernetes, interactive or
unattended, the way DefenseClaw protects OpenShell sandboxes on a host.

- Hooks stay in the sandbox. Decisions are made outside it.
- Substrate's egress is the only way out of a sandbox. It adds a signed actor token on calls to DefenseClaw and swaps placeholders for
  real secrets only on the hosts each secret is bound to.
- Every model call goes through the DefenseClaw proxy, so routing, guardrails and cost accounting cover every agent, keyed to a
  verified actor and person.
- Stateful findings (tool chains, intent, asks) work across stateless gateway replicas.

Supported: Agent Substrate `>=1.0.0 <1.1.0`, Kubernetes 1.34 or later, kind, GKE and EKS, OpenShell behaviour unchanged.

## Decisions

| # | Decision |
|---|---|
| D2 | Model traffic always goes through the DefenseClaw proxy |
| D3 | The launcher creates actors in launcher atespaces and attributes them to the person |
| D6 | Routing and tokenomics come from the 1.0.10 routing and tokenomics streams, unchanged |
| D7 | gVisor is the default sandbox class |
| D8 | Interactive agents follow the profile's fail mode. Unattended runs fail closed |
| D9 | The callout reads bodies only for MCP and listed hosts, up to 1 MiB, when body mode is detected |
| D10 | DefenseClaw never replaces another callout |
| D11, D13 | A horizontal autoscaler serves stateless work. Stateful steps run on a leader. SQLite, no Postgres port |
| D12 | Unattended asks are denied by default |
| D14 | No secret value in an actor |
| D15 | Separate actor and admin listeners and Services |

## Components

One image, `defenseclaw-gateway`, several subcommands.

| Component | Subcommand | Notes |
|---|---|---|
| Gateway, actor listener | `serve --substrate` | Service `defenseclaw-actor`, the only DefenseClaw host in an actor's egress policy |
| Gateway, admin listener | `serve --substrate` | Service `defenseclaw-admin`, for the launcher, the fleet view and bundles; never in an egress policy |
| Gateway leader | `serve --substrate` | One replica holds a lease and the store volume; serves chain, intent, ask and registration RPCs |
| Controller | `substrate-controller` | Admission, egress policy rendering, drift, idle suspend, inventory, kit skew |
| Egress callout | `substrate-extproc` | Envoy ext_proc service registered with Substrate's egress gateway |
| Actor kit | in the template image | A static hook binary, a terminal relay and the connector settings; no keys, no policy |
| Launcher | `defenseclaw substrate ...` | Laptop or CI; contexts, OIDC sign-in, attach |

## Trust boundaries

- **B1, actor to DefenseClaw.** Untrusted. Only the Substrate-injected token counts, and only with a live actor UID.
- **B2, DefenseClaw to Substrate.** DefenseClaw's own service account with the OpenFGA roles it needs and no more.
- **B3, administrators.** Chart values and signed bundles checked against trust anchors in an admin-only Secret.
- **B4, Substrate.** Trusted for the sandbox, the egress gateway and the identity CA. Cluster administrators, node root and sandbox
  escapes are out of scope.

## Flows

**Admission.** `template build` adds the kit, runs the scans and signs an attestation. The controller admits only an attested digest
that a profile allows. Otherwise the actor has no egress policy, which is default deny, and a `template_unverified` event.

**Create and resume.** Policy is written before the first resume, forks included. Each resuming actor gets its generation checked. A
late policy only delays access.

**Hook.** Agent hook, resident hook binary, egress (adds the token), actor listener. The gateway verifies the token and the live UID,
finds the registration and profile, and runs the hook engine with surface `substrate`. Stateful steps go to the leader.

**Model.** `/llm/<provider>` on the actor Service resolves the caller from the token, applies routing and the guardrails, adds the key,
forwards, checks the response and records usage.

**Other egress.** Allowed hosts go through the callout: block-list feeds, secrets in URLs and headers, ask hosts and, for MCP, body
mode. An `observed_egress` step goes into the actor's chain window.

**Asks.** Raised by the callout or the gateway and answered in the session or in `approvals`. Admin limits apply. An approval updates
the policy, and the held request retries for about ten seconds. Unattended asks follow D12.

**Lifecycle.** Registration is keyed by actor UID. A fork gets a new registration and inherits chain windows but not asks. A revert
adds a mutation barrier. Delete leaves a tombstone and removes the snapshots.

**Idle.** The controller suspends an actor after `idle_suspend_after` without hook, model, relay, egress or CPU activity, never with a
pending ask and never for `--task` runs unless the profile says so.

## Stateful findings

| State | On Substrate |
|---|---|
| Tool chains: the current call plus up to 8 earlier ones per verified session, 30 minutes | The leader serves `Observe` over an internal RPC; followers forward; a per-partition lock orders parallel calls |
| Root scope | Keyed by the verified actor UID: every call lands in the session and the actor window, so rotating session IDs can't empty it |
| Intent (in memory per process) | In the leader store. For `--task` runs the launcher registers the task text at create, a verified source |
| Asks, approvals, pending outcomes | Leader store |
| Horizon | Running time only; suspend pauses the clock |
| Fork | The child inherits the parent's windows as a copy with a lineage link |
| Revert | A mutation barrier is inserted; findings are kept |
| Outage | Unattended and managed fail closed. Open source interactive records a gap marker |

Leader failover moves the lease and reattaches the volume (about 30 seconds). Stateless checks continue; stateful steps follow the fail mode.

## Failure modes

| Failure | Behaviour |
|---|---|
| One gateway replica down | Nothing visible |
| Leader down | Stateless checks continue; stateful steps follow the fail mode until the new leader is up |
| All replicas down | Hooks follow D8; model calls fail with a clear message; policies stay |
| Controller down | Existing actors keep their policy; new actors have no network; idle suspend pauses |
| Callout down | Closed in managed mode, configurable in open source; `doctor` red |
| Control API down | The live-UID cache holds 60 seconds, then refuse; asks wait |
| Pool full | Parking, then the launcher says the cluster is full and retries |

## Config

The additive `substrate` section of the DefenseClaw config (schema v8, Go and Python parity). The reference is
[docs-site/content/docs/substrate/reference.mdx](../docs-site/content/docs/substrate/reference.mdx). Profiles gain
`sandbox.runtimes`, `sandbox_class`, `idle_suspend_after`, `unattended_asks`, `actor_secrets` and
`profile_assignments[].match.substrate`. `SandboxAdminConfig` is the renamed sandbox section, with `OpenShellAdminConfig` kept as an alias.

## Secrets

An actor holds none. Model keys are added by the proxy. Service credentials are `ate-secret://` references that Substrate's egress
gateway injects on bound hosts only. Per-person secrets are keyed by the OIDC subject. A profile's `actor_secrets` can expose a
short-lived value with exact-value matching. See the user page for the configuration.

The secrets admin API (`secrets set`, `secrets set --mine`) writes Kubernetes sources (`ate-secret://k8s.io/...`) with the
gateway's ServiceAccount. The chart gives it the Role `defenseclaw-gateway-secrets` in each source namespace: create, plus get and
patch by name, or on every Secret of the namespace when the Secret name holds `{person}`. Keep per-person sources in a namespace of
their own. The gateway changes only the Secrets it created (label `app.kubernetes.io/managed-by: defenseclaw`); any other Secret of
that name gets 409 `secret_not_managed_by_defenseclaw`. A source in the release or Substrate namespace fails the chart render.

## Telemetry

Registry version 4 of the v8 telemetry registry (no v9). All additions are listed in
`~/dc-eh/plans/agent-substrate/lanes/a7/PROGRESS.md` and shown to users in
[Sandbox telemetry](../docs-site/content/docs/observability/sandbox-telemetry.mdx):

- enums widened: `defenseclaw.user.id_kind` (`oidc_subject`), `defenseclaw.sandbox.runtime` (`substrate`),
  `defenseclaw.sandbox.driver` (`gvisor`, `microvm`), the sandbox phases and the lifecycle triggers;
- the `defenseclaw.sandbox.substrate.*` group and `ate.actor.uid` in `correlation.sandbox`;
- resource attributes `k8s.cluster.name` and `k8s.namespace.name` (the pinned OpenTelemetry snapshot was refreshed for exactly these);
- `defenseclaw.network.body_inspected` and `defenseclaw.network.body_over_cap` on egress records;
- `log.secret.injected`, and eight `defenseclaw.substrate.*` metrics with no identity labels;
- the Grafana board `defenseclaw-substrate` and the chart's alert rules.

Not yet in the registry (owned elsewhere): `log.model.usage` and `defenseclaw.model.cost` from the tokenomics stream, and the tool-chain
event families from the chain store.

## Delivery

A signed gateway image and signed per-connector kit images, digest-pinned, from the release workflow. A signed Helm chart
(`deploy/helm/defenseclaw-substrate`): the two Services, the HPA and PDB, the leader and its volume, the controller, the callout,
network policies, the OpenFGA bootstrap Job, hooks for upgrade, rollback and delete, an optional PrometheusRule and a local
observability stack. `defenseclaw substrate setup` writes the Substrate install overlay and refuses when another callout is registered.
Upgrades roll under the PDB with the config and store migrated first; a rollback across a store schema change is refused and names the
backup. Uninstall removes DefenseClaw's egress policies first, so nothing is left open.

## Tests

Unit and golden tests per package. Live cells run on a real Substrate cluster (kind, EKS) with real agents and Bedrock models through
the real path, listed in the test plan `substrate-1`. A model refusal is recorded as n/a, never a pass.

## Not in scope

Agent frameworks and custom harnesses, desktop and IDE apps, the ACP guard, OpenClaw and ZeptoClaw as actors, live workspace folders,
process lineage and the kernel feed, Edge Connector, Secure Client, and a hosted control plane.
