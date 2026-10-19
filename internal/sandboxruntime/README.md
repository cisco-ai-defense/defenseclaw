# Shared sandbox contracts

DefenseClaw owns policy, approvals, agent hooks, credentials, workspace review
and audit. A runtime adapter supplies qualified execution and transport beneath
that control plane. The current OpenShell controller remains compatible;
these declarations do not enable AXIS or start background work.

`ResolveExecutionPolicy` accepts a stable validated configuration snapshot and
the existing pack resolver inputs. It projects common sandbox policy, applies
repository and administrative restrictions, then freezes every shared setting
and the resolved run into one immutable identity. Its host authority snapshot
ID and generation must rotate when broker routing or host facts change.

`ResolveHostRun` captures an opaque host resolution for both provider planning
and `BindResolvedExecutionPolicy`. They use independent copies of the same
projected config, flags, violations and private evaluator, without reopening
pack files or resolving host facts again. Binding requires the exact captured
execution options, including authority generation, harness, terminal and offline
requirements. An old handle cannot be stamped with a new generation. The owner
must still capture the config and authority together under its launch/rotation
transaction. Neither this handoff nor its planning copy qualifies a provider.
The existing immutable egress decider is shared; its process-wide local-address
guard retains its existing refresh behavior rather than becoming a frozen
address snapshot. OpenShell `Manager.Create` now uses `packs.ResolveRun` for one
owned policy/configuration tuple through image selection, token delivery,
workspace planning and initial undo setup. Later live-policy refresh and start
still deliberately resolve current policy. The gateway's optional native launch owner now captures one actual Config/N
publication and binds one owned run-specific policy. The native controller
factory and qualified runtime catalog remain unavailable.

The private resolver remains the egress authority. Inspection JSON omits its
private evaluator state and cannot reconstruct an executable policy. It still
contains host-confidential workspace paths and policy provenance. Keep the
snapshot and component values inside trusted host admission/adapters; guests,
external APIs, logs and telemetry need a separate redacted projection. An adapter must
route authorized traffic through DefenseClaw's broker; copying a flattened
allowlist into MXC does not reproduce approvals or administrative enforcement.
Explicit offline execution is separate from the `strict` profile.

Before execution, the host must independently qualify exact runtime and harness
artifacts and require the policy's capabilities. `AdmitPolicy` also requires a
trusted translation receipt bound to that runtime, harness, policy digest and
every policy component. Missing, duplicated, changed or unknown components
refuse admission. Evidence from a workload or API client is never authoritative.
Admission also compares the current trusted host authority binding. The caller
must serialize authority rotation with admission and launch, or condition the
launch on that generation; retaining an older policy handle grants no exception.

`LaunchGate` supplies that serialization for the future adapter. It reads the
owner's actual authority source at registration and dispatch, and rejects a
binding that differs from the last successful transaction. Every writer must
enter `Rotate` or `RotatePublished` before changing those facts; checking a
callback alone cannot close an unsynchronized writer's race. Rotation must
revoke affected live grants/workloads and publish its new, increasing generation
before success.
`RotatePublished` accepts the exact binding returned by the existing host
publisher when it assigns a generation during the transaction; never predict
that publisher's counter. Decide no-op changes before entering the callback.
An incomplete transition, cancellation during it or failed owned cleanup closes
the gate. The Sidecar reload commit now uses this transaction when a native owner is
installed: revocation precedes token/v8 changes, Config and Generation
publication, and the commit tail. Candidate failures and unchanged asset
reloads stay outside it. First-token writers share one helper and refuse
missing-token publication after owner installation. Installation requires a
paired Config/N and resolved startup token before ConfigManager starts; an
unpaired or tokenless current publication refuses authority. The Sidecar and
process-wide scanner/provider generation must be the same publication; an
out-of-band global replacement closes native admission. Its opaque binding
also detects a changed resolved gateway token, including environment
overrides, using a private per-owner HMAC key rather than exposing a token
fingerprint. A deliberate token change needs an advancing actual publication.
The revocation callback must not reenter ConfigManager or LaunchGate while their locks are
held. No controller installs this owner in the customer path yet, and managed
daemons still need their own adoption transaction.

Trusted preparation resources register a private one-use handle with copied
runtime/receipt evidence and the complete launch specification. Dispatch checks
admission again and passes the frozen literal argv, environment, workspace and
broker binding to the trusted adapter. Cancellation, launch error or a different
observed full session identity invokes bounded owned-handle cleanup. A copied
or serialized handle cannot grant a second dispatch. The host controller must
reserve session identities uniquely, abort abandoned preparations and own all
successful workloads. These helpers do not yet wire a production AXIS adapter,
establish private workspace custody or qualify a provider's actual enforcement.
The optional backend contract uses this same prepare/receipt flow for both
create and restart; it exposes no direct provision/start bypass around the gate.

A receipt checks structural consistency. It grants no process launch,
credential, workspace path or lifecycle authority. The controller must still
enforce session ownership, current policy generation, credential binding and
the adapter's actual enforcement evidence on every relevant operation. No
refusal may silently select a different backend or execute on the host.
