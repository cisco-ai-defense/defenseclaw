# Deployment modes, feature switches, bundle-at-once, upgrade and downgrade

Open this when: your change behaves differently per deployment mode, adds a switch, adds a managed (`enterprise.*`) key, touches the lifecycle, guardian, enumerator, MDM wrappers or packaging, or applies config, policy and assets together.

## The modes

| Mode | Who owns config | Gateway | Switch off by |
|---|---|---|---|
| OSS per-user | the user (`config.yaml` in their home) | per user, runs as that user | config keys, `defenseclaw setup`, guardrail and connector commands, the TUI |
| Standalone managed | administrator (`deployment_mode: managed_enterprise`, `enterprise.profile: standalone`) | machine-wide root or SYSTEM services | the closed `enterprise.*` switches; nothing in a user config can turn off a managed protection |
| Enterprise via MDM | same as standalone, delivered by wrappers in `packaging/mdm` | same | same, driven by `ensure` on each check-in |
| Secure Client profile | frozen path, config_version 8 only | separate | not extended by new features |

Mode and profile come from pinned service environment variables; a conflicting config fails to load.

## Requirements

IDs live only in `reference/checklist.md`. These rows add detail and carry no IDs.

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| Gate managed-only behavior on the resolved mode and profile (`cfg.StandaloneEnterprise()`, `cfg.SecureClientIntegration()`, `managed.IsManagedEnterprise`), never on a user-writable key or user-controlled env var. | A standard user's config must not opt out of the managed gate. | `go test ./internal/managed ./internal/config -run 'Profile\|Managed\|Pin'` | `internal/managed/managed.go`, `internal/managed/profile.go`, `internal/config/enterprise.go` |
| A new `enterprise.*` key is accepted only under `managed_enterprise` and, unless explicitly a Secure Client key, only on the standalone profile. Add it to the struct, the validator (closed `oneOf` lists), `enterpriseBlockEmpty`, the schema and the docs. | An unvalidated key becomes a silent no-op for an administrator. | `go test ./schemas ./internal/config`; `make check-schemas` | `internal/config/enterprise.go`, `schemas/embed_test.go` |
| Each managed knob has a secure built-in default, resolved as connector override, then enterprise default, then built-in. Empty means secure. Loosening needs an explicit named value (`allow`, `report`, `off`, `verify_only`). | An unconfigured fleet must be protected. | `go test ./internal/config -run 'PolicyFor\|Enterprise'` | `internal/config/enterprise.go` (`@sym:builtinConnectorPolicy`, `@sym:PolicyFor`) |
| Outside Secure Client, managed hook paths fail closed: hook error, unreachable gateway, stale guardian authorization, unregistered SID or unverified agent version deny or refuse, and managed Codex, Claude Code and standalone Devin have no fail-open override. Under Secure Client (`cfg.SecureClientIntegration()`) delivery when the gateway is unreachable follows `guardrail.hook_fail_mode`, default `open` with an explicit `closed` kept; stale authorization, unregistered SID and integrity failures still deny. Only stop and session-end events are neutral. | Managed hosts must never silently allow what policy denies; only Secure Client opts into open delivery. | `go test ./internal/managed ./internal/gateway -run 'Guardian\|FailClosed'` | `internal/managed/hook_guardian.go`, `internal/enterpriseunix/payload.go`, `docs-site/content/docs/enterprise/configure/machine-policy.mdx` |
| Enrollment defaults protect: unenrolled users are inspected, root is inspected unless exempted, surfaces with an unverified hook contract are reported or refused. A refused surface is written to the refused-surfaces record so the gateway refuses its calls. | An enumerator that skips an agent must not leave it unguarded. | `go test ./internal/enterprisehooks -run 'Enumerat\|Refus'` | `internal/enterprisehooks/enumerator_unix.go`, `internal/enterprisehooks/unprotected_agents.go` |
| A connector on a managed host needs a route decision per OS in `RouteFor`. The default arm is `unsupported`, so a missing connector is silently unmanaged. Use the add-connector skill for the full list. | The host would report success while the agent is uncovered. | `go test ./internal/enterprisepolicy ./internal/enterprisehooks` | `internal/enterprisepolicy/types.go`, `.claude/skills/defenseclaw-add-connector/reference/enterprise.md` |
| Do not touch Secure Client paths when adding standalone features. Put Windows standalone branches behind the standalone profile checks and tell reviewers in the PR when `packaging/windows` or `packaging/macos` changed. | That profile must stay byte-identical; its invariance check runs outside CI. | `pytest cli/tests/test_windows_enterprise_standalone_contract.py`; `go test ./internal/enterprisehooks -run 'SecureClient\|PlatformMinimum'` | `internal/managed/profile.go` |
| Managed hosts refuse local writers with a stated reason and a non-zero exit. Every new CLI or TUI writer goes through `config_writer`. `upgrade` and `rollback` refuse beside a managed install. | A local edit would diverge from enforced policy. | `pytest cli/tests -k 'managed and (refus or config_writer)'` | `cli/defenseclaw/config_writer.py`, `cli/defenseclaw/commands/cmd_upgrade.py`, `scripts/install.sh` |
| Managed config holds no secrets: credentials are protected credentials named in `enterprise.inspection.*.credential`, and environment secret references are refused. | Inline keys end up in MDM scripts, logs and backups. | `go test ./internal/config -run 'Secret\|Credential\|Inline'` | `internal/config/enterprise.go`, `packaging/mdm/README.md` |
| Everything the managed gateway loads (config, data dir, policy dir, every rule-pack dir) must be administrator-owned and service-readable, with pack digests pinned. Ensure checks packs before restarting the gateway. | A user-writable pack or Rego module is a bypass. | `go test ./internal/config ./internal/enterpriseunix -run 'PolicyInput\|RulePack'` | `internal/enterpriseunix/packtrust.go`, `internal/config/enterprise.go` |
| DefenseClaw never writes host-wide Linux kernel or sysctl settings. Status and verify report the current user namespace and ptrace settings as observed facts. Every invoked Linux or macOS machine-policy hook compares the policy files it sees with content digests pinned in the trusted runtime descriptor; a missing, unreadable or changed view raises a `managed_hook` alert while the call is still inspected under the managed policy, and only a hook with no trusted descriptor refuses. Linux also refuses a private user namespace and a tracer. Host hardening is an optional administrator step using the administrator's own tools. | An agent that hides its managed policy before launch may omit the hook entirely; application control is needed to close that residual route. A private policy view must never turn an invoked hook into an allow. | `go test ./internal/enterpriseunix ./internal/cli ./internal/enterprisepolicy -run 'LinuxLifecycleNeverChangesHostKernel\|LinuxStatusUsesCurrentKernelFactsWithoutBootMarkers\|StandaloneHookAlertsOnUnprovenPolicyView\|PolicyViewDigest'` | `internal/enterpriseunix/userns.go`, `internal/enterpriseunix/userns_test.go`, `internal/cli/hook_trusted_state_unix.go`, `internal/enterprisepolicy/policy_view_digest.go` |
| Managed listeners stay on loopback (gateway API on 127.0.0.1). A new listener needs a managed-mode loopback validator. | A non-loopback bind exposes every user's policy surface. | `go test ./internal/config -run 'Listener\|Loopback'` | `internal/config/config.go` |
| A managed device must not write raw prompts or model output to disk. New trace or capture features need the same refusal or an explicit admin opt-in. | A machine-wide service would collect every user's prompts. | `go test ./internal/config -run 'Trace\|Enterprise'` | `internal/config/enterprise.go` |
| A feature present in only some modes says so in code and docs and reports a reason code when requested but unavailable. Never ignore a key silently. | An administrator who writes a key that does nothing believes they are protected. | `go test ./internal/config -run 'Tetragon\|ManagedIPC\|PeerAuth'` | `internal/config/enterprise.go`, `internal/config/managed.go` |
| A new per-user surface (installer, updater, auto-start, daemon) must detect the managed descriptor and refuse beside a managed install. | A per-user gateway beside a managed one is an unmanaged enforcement point. | `pytest cli/tests/test_upgrade_shim.py -k 'install_sh or managed'`; `pytest cli/tests/test_windows_enterprise_standalone_contract.py -k refuses_a_managed_host` | `scripts/install.sh`, `internal/managed/runtime_descriptor.go` |
| MDM-facing behavior goes through the generic contract in `packaging/mdm` (result schema, documented exit codes, detect and uninstall scripts, stdin or admin-only-file secrets, pinned artifact trust). Vendor kits stay thin wrappers. | The same wrapper runs on every check-in and must be idempotent and machine-readable. | `pytest cli/tests/test_enterprise_packaging.py`; `python scripts/check_enterprise_lifecycle_result.py <result.json> --platform linux` on a real lifecycle result | `packaging/mdm/contract/lifecycle-result.schema.json`, `packaging/mdm/contract/exit-codes.md` |
| Packaging parity: a new installed file, binary or service goes into every channel (Linux deb/rpm via `.goreleaser.yaml` and `packaging/linux`, macOS pkg, Windows Setup, the wheel via `_bundle-data`) and into the lifecycle's required or optional binary lists with a sha256, non-empty, non-writable check. | One missing channel fails closed or leaves an agent unprotected on that OS. | `make packaging-linux-enterprise`; `make lint` (assemble parity) | `.goreleaser.yaml`, `internal/enterpriseunix/payload.go`, `packaging/windows/payload.go` |
| A managed artifact that gains a feature gets a verify counterpart that fails on artifacts rendered before the feature, so the guardian re-renders after an upgrade. | An upgrade that leaves old hook scripts leaves the new protection off while status reads healthy. | `go test ./internal/enterprisehooks/... ./internal/enterpriseunix -run 'Verify\|Guardian'` | `internal/enterpriseunix/verify.go`, `internal/enterprisehooks/guardianstate/state.go` |
| The enumerator and guardian never follow a user-controlled path with privilege: homes bounded to configured roots, no-follow regular-file readers, agent binaries only in administrator-owned locations. | A symlink or junction in a user home becomes a privileged read or write. | `go test ./internal/enterprisehooks -run 'Home\|Untrusted\|Bounded'` | `internal/enterprisehooks/home_bounded_unix.go` |
| Use file-name and build-tag pairs (`_windows.go`, `_unix.go`, `_other.go`) for OS code and build for all three OSes. Do not add a product build tag as a feature switch. | One binary must serve every mode. | `GOOS=windows go build ./...`, same for `darwin` and `linux` | `internal/enterprisehooks/*_windows.go` |
| Document managed behavior in `docs-site/content/docs/enterprise` and the matching threat model; keep sample admin configs in `testdata/enterprise-configs` loadable. | Admins copy the sample; a test loads it. | `go test ./internal/enterpriseunix -run SampleConfig` | `internal/enterpriseunix/sample_config_test.go` |
| Seed user-editable assets (observability stack, registries under `bundles/`) once and refresh only through an explicit atomic path that preserves operator edits. | A seeded copy that is never refreshed silently lags the shipped version. | `pytest cli/tests/test_bundle_refresh.py` | `cli/defenseclaw/bundle_refresh.py`, `bundles/` |

## Bundle-at-once

Config, policy, rule packs, assets, secrets and binaries apply as one unit with rollback and a deterministic digest. A feature that needs a second out-of-band step breaks managed deployments.

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| Apply managed state only through the lifecycle transaction: lock, intent, snapshot, stage, apply, reload, activate in dependency order, verify, then commit or restore. An interrupted transaction rolls back first on the next run. No second writer for a managed file. | Partial application leaves a half-new policy. | `go test ./internal/enterpriseunix -run 'Rollback\|Recover\|Transaction'`; `GOOS=windows go vet ./internal/enterprisehooks` | `internal/enterpriseunix/doc.go`, `internal/enterpriseunix/lifecycle.go` |
| A hot config apply is allowed only when nothing else differs and no changed key is restart-required. A rejected reload keeps the previous policy and warns. The running policy digest must be visible. | A hot apply of a restart key leaves running state different from committed config. | `go test ./internal/enterpriseunix -run 'Hot\|AppliedPolicy\|PolicyOmitted'` | `internal/enterpriseunix/hotapply.go`, `internal/enterpriseunix/policystate.go` |
| Any new signed policy bundle format must: carry config, policy, rule packs and assets together; compute one deterministic digest over canonical content; verify the signature before any file is staged; apply atomically; restore the prior state on any failure; and report the applied digest. It must reuse the lifecycle transaction rather than add a writer. | Without these, a reload can mix old and new policy. No bundle format exists on main today; the lifecycle transaction is the only unit. | review against `internal/enterpriseunix/lifecycle.go`; add apply, failure and rollback tests | `internal/enterpriseunix/lifecycle.go`, `internal/config/validate_candidate.go` |

## Upgrade and downgrade

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| Downgrade is explicit and reversible. Lifecycle refuses an older payload without `--allow-downgrade`. A migration keeps a write-once backup a rollback needs. Do not extend state files an older release decodes strictly (`deployment.json`); add a new file. | Package managers can unpack older files after a failed removal; older releases fail on unknown fields. | `go test ./internal/enterpriseunix -run 'Downgrade\|Rollback'`; the enterprise upgrade CI lanes run `scripts/check_enterprise_upgrade_config.py --before <cfg> --after <cfg>` | `internal/enterpriseunix/lifecycle.go`, `internal/enterpriseunix/policystate.go`, `packaging/linux/apt-downgrade-guard.sh` |

## Where it lives

`internal/config/enterprise.go`, `internal/managed/`, `internal/enterpriseunix/`, `internal/enterprisehooks/`, `internal/enterprisepolicy/`, `packaging/`, `cmd/defenseclaw-enterprise-setup`, `docs-site/content/docs/enterprise/`.

## How to verify

Unit tests above, then the enterprise install and upgrade jobs on disposable hosts (see `reference/testing.md`). Check each OS: Linux, macOS, Windows.

## Common mistakes

- Reading the mode from a config key a user can write.
- Leaving a connector out of `RouteFor`.
- Validating packs only after restarting the gateway.
- Extending `deployment.json`.
- Adding a file to one package channel only.
- Hand-writing machine-policy files outside the lifecycle.
- Making a Secure Client file differ while "only touching Windows standalone".
