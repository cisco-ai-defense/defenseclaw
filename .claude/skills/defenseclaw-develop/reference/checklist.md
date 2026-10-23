# Requirement checklist

IDs are defined only in this file; the area reference files carry detail rows and no IDs. Tiers: MUST (`M-`) blocks merge. SHOULD (`S-`) is expected; skipping needs a one-line reason in the PR. MAY (`O-`) is optional. Read only the sections for the areas you touch: `grep -n -- '-CFG-' .claude/skills/defenseclaw-develop/reference/checklist.md`.

Each item: rule, why (the failure it prevents), then the check and the evidence paths. Source and tests win over this list.

## CFG: configuration

- [ ] **M-CFG-1** Declare every new key in the closed schema first; never only in a struct. Why: an undeclared key is rejected on load, and two shapes drift.
  Check: `go test ./internal/config`. Evidence: `schemas/config/v8/defenseclaw-config.schema.json` (the `v8` directory holds the current shape), `internal/config/schema_v8.go`.
- [ ] **M-CFG-2** Mirror the key in the Go struct, the Go default and the Python dataclass, with matching defaults. Why: a key known to one side is dropped on a save round trip or never read.
  Check: `pytest cli/tests/test_config_save_roundtrip.py cli/tests/test_config_sandbox_profiles_parity.py`. Evidence: `internal/config/config.go`, `internal/config/defaults.go`, `cli/defenseclaw/config.py`.
- [ ] **M-CFG-3** A pure addition needs a loader default only. A rename, removal or semantic change needs a migration step and a coordinated version bump on both sides (stop and ask first). Why: a one-sided bump locks out upgrades.
  Check: `pytest cli/tests/test_migrations.py`. Evidence: `cli/defenseclaw/migrations.py`, `internal/config/migrate_v9.go`, `internal/config/config.go`.
- [ ] **M-CFG-4** Implement a migration once, in Go; Python and the CLI call it. Keep a write-once backup of the old file. Why: two implementations disagree on what moved.
  Check: `go test ./internal/config -run MigrateV9`. Evidence: `internal/config/migrate_v9.go`, `cli/defenseclaw/config_inspect.py`.
- [ ] **M-CFG-5** `config set` and `config unset` never change `config_version`; only a migration does. Why: relabelling a file corrupts the backup logic.
  Check: `pytest cli/tests/test_cmd_config.py`. Evidence: `cli/defenseclaw/commands/cmd_config.py` (`@sym:_refuse_config_version`).
- [ ] **M-CFG-6** Write `config.yaml` only through the shared writer (lock, sha256 compare, validate, atomic write, generation bump). Why: a bypass loses concurrent edits and skips validation.
  Check: `go test ./internal/config/configwrite` and `pytest cli/tests/test_config_writer.py`. Evidence: `cli/defenseclaw/config_writer.py`, `internal/config/configwrite/configwrite.go`.
- [ ] **M-CFG-7** Classify each key as hot or restart-required. A restart-required key goes in both restart lists and the docs. Why: otherwise the CLI saves it and the running gateway silently keeps the old value.
  Check: `go test ./internal/config/configwrite`, then compare `@sym:restartKeys` in `internal/config/configwrite/configwrite.go` with `@sym:RESTART_KEYS` in `cli/defenseclaw/config_writer.py` by hand (no parity test exists). Evidence: `internal/config/configwrite/configwrite.go` (`@sym:restartKeys`), `cli/defenseclaw/config_writer.py`, `internal/gateway/config_manager.go`.
- [ ] **M-CFG-8** Store a reference to a credential (`*_env` name or credential reference), never the value. Extend masking for any new sensitive field. Why: `config show` and logs must not print secrets.
  Check: `pytest cli/tests/test_cmd_config.py`. Evidence: `internal/config/secret_ref_v8.go`, `cli/defenseclaw/commands/cmd_config.py` (`@sym:_SECRET_FIELDS`).
- [ ] **M-CFG-9** No second source for a setting: no new hidden env var, flag or side file that overrides `config.yaml`. Why: it breaks provenance in `config get --effective` and managed control.
  Check: grep the diff for `Getenv` and `os.environ`. Evidence: `docs-site/content/docs/reference/configuration/source-of-truth.mdx`.
- [ ] **M-CFG-10** Register every `DEFENSECLAW_*` variable with a managed policy, then regenerate the docs. Security opt-outs are `ignore` or `tighten_only` and surface in doctor. Why: a codebase-coverage test fails on an unregistered name; an inherited variable must not weaken a managed host.
  Check: `python scripts/gen_envvars_docs.py --check` and `go test ./internal/envvars`. Evidence: `internal/envvars/registry.json`, `cli/tests/test_envvars_codebase_coverage.py`.
- [ ] **M-CFG-11** Pin any file a setting points to (rule pack, policy asset) by sha256 digest in the config. A mismatch keeps the previous generation. Why: a changed file must not take effect silently.
  Check: `go test ./internal/config -run 'Candidate|Digest'`. Evidence: `internal/config/validate_candidate.go`, `internal/config/config_v9_types.go`.
- [ ] **S-CFG-1** A retired key fails with the replacement and the migrate command; `config set` refuses it. Test the error text. Why: a silent fallback hides a misconfiguration from the operator.
  Check: `pytest cli/tests/test_cmd_config_v8.py`. Evidence: `cli/defenseclaw/observability/v8_config.py`.
- [ ] **S-CFG-2** Observability config changes regenerate the reference (`python scripts/generate_observability_v8_reference.py --write`); never hand-edit the generated reference. Why: `make check` rejects drift between schema, reference and packaged data.
  Check: `python scripts/generate_observability_v8_reference.py --check`. Evidence: `scripts/generate_observability_v8_reference.py`, `schemas/config/v8/reference/`.
- [ ] **S-CFG-3** Test the writer and loader with a UTF-8 BOM, CRLF line endings and an unchanged re-apply. Why: each was a past regression.
  Check: `pytest cli/tests/test_config_writer.py`. Evidence: `cli/tests/test_config_save_roundtrip.py`.

## POL: policy and guardrails

- [ ] **M-POL-1** Change an admission decision in Rego and its Go twin together, with the agreement test. Why: when OPA fails the Go fallback decides; a mismatch changes verdicts silently.
  Check: `make rego-test` and `go test ./internal/policy -run Admission`. Evidence: `policies/rego/admission.rego`, `internal/policy/fallback.go`, `internal/policy/engine_test.go`.
- [ ] **M-POL-2** Rego reads only `input.*`; new inputs go through the config-compiled input. No `data.json` source. Why: a stale `data.*` read sees nothing and can fail open.
  Check: `go test ./internal/policy -run Prepare`. Evidence: `internal/policy/engine.go` (`@sym:checkNoLegacyData`), `internal/policy/compiled.go`.
- [ ] **M-POL-3** A policy load error never becomes an empty policy; a failed reload keeps the previous modules. Why: an unreadable directory would allow everything.
  Check: `go test ./internal/policy`. Evidence: `internal/policy/engine.go`.
- [ ] **M-POL-4** A new bundled policy file is also copied into the Python data tree by the Makefile and embedded by Go where needed. Why: wheel installs would lag and CLI and gateway would disagree.
  Check: `pytest cli/tests/test_rego_policies.py`. Evidence: `Makefile`, `policies/assets.go`.
- [ ] **M-POL-5** Changing rule-pack format, precedence or validation updates the Go loader and the Python overlay together; validate with the Go loader. Why: the CLI scan and the gateway would enforce different rules.
  Check: `go test ./internal/guardrail` and `pytest cli/tests/test_scanner_rulepack.py`. Evidence: `internal/guardrail/rulepack.go`, `cli/defenseclaw/scanner/rulepack.py`.
- [ ] **M-POL-6** A finding blocks only with a code-owned same-rule proof; regex-only, custom, partial or unproven matches stay detection-only. Use the never-matching `a^` fallback for semantic-only rules. Why: it prevents false-positive interruptions of benign work.
  Check: `go test ./internal/gateway ./internal/guardrail ./internal/actionfacts`. Evidence: `docs/GUARDRAIL_RULE_PACKS.md`, `internal/guardrail/capability.go`.
- [ ] **M-POL-7** After editing default rule YAML, regenerate the compiled catalog and commit it. Why: the Go fallback would differ from the shipped pack.
  Check: `make check-guardrail-catalog` (fix with `make generate-guardrail-catalog`). Evidence: `cmd/generate-guardrail-catalog/main.go`.
- [ ] **M-POL-8** The pack digest covers every component file and the manifest; a new component type joins the digest and the inventory check. Why: an uncovered file can change without changing the pin.
  Check: `go test ./internal/guardrail -run RulePack`. Evidence: `internal/guardrail/rulepack.go`.
- [ ] **M-POL-9** Admission order is fixed (block, allow, first-party, scan, verdict). A scan error is never "allowed". New admission paths use the same engine. Why: two admission paths with different order can admit what the other blocks.
  Check: `make rego-test`. Evidence: `policies/rego/admission.rego`, `internal/policy/admission.go`.
- [ ] **M-POL-10** First-party allow entries are content-bound, not name-trusted. Why: a folder named like a first-party skill could switch off scanning.
  Check: `go test ./internal/policy -run FirstParty`. Evidence: `internal/policy/first_party_verify.go`.
- [ ] **M-POL-11** Every new failure mode (gateway down, missing token, bad response) resolves through the effective fail mode, with a test and a docs entry. Why: a failure path that opens silently is a policy bypass.
  Check: `go test ./internal/gateway/... -run FailMode`. Evidence: `docs-site/content/docs/reference/configuration/fail-modes.mdx`, `cli/defenseclaw/fail_mode.py`.
- [ ] **S-POL-1** Add hard negatives (previews, help, loopback, failed results, mismatched identities) with every new blocking rule. Why: name heuristics are not proof of production.
  Check: `go test ./internal/gateway -run 'ProtectiveProfile|BenignNeighbors'`. Evidence: `benchmarks/fixtures/`, `policies/guardrail-use-cases/`.
- [ ] **S-POL-2** Measure attack recall on attack data and false-positive rate on separate benign data. Why: an attack-only fixture cannot show noise.
  Check: steps in `benchmarks/README.md`. Evidence: `benchmarks/datasets.lock.json`.

## ID: identity and profiles

- [ ] **M-ID-1** Only verified identity selects a profile (kernel or credential verified uid or SID plus OS directory facts). Never headers, payloads, env or claimed session facts. Why: a client-supplied identity would pick a looser profile.
  Check: `go test ./internal/gateway -run GuardrailProfile`. Evidence: `internal/gateway/guardrail_profile.go`, `internal/useridentity/directory.go`.
- [ ] **M-ID-2** No lenient fallback in matching: refuse when an assignment needs an identity fact the OS has not confirmed, naming that fact; otherwise use only proven matches or the default. A stale name matches nobody, and names compare through the shared normalizers. Why: a failed lookup that lands in a looser profile is a bypass.
  Check: `go test ./internal/gateway ./internal/useridentity`. Evidence: `internal/useridentity/principal.go`.
- [ ] **M-ID-3** Policy visibility is own-only for users and admin-only otherwise, enforced server side (loopback plus token, or privileged peer). Any new endpoint, status field or telemetry attribute naming a policy, profile, digest, group or account is gated and tested per caller class. Why: a field that names another account's policy, group or digest discloses it to every local user.
  Check: `go test ./internal/gateway -run 'PolicyBlockOnlyToAnAdministrator|PolicyPrivacy|ProfileExplain'`. Evidence: `internal/gateway/health_policy_privacy_test.go`.
- [ ] **M-ID-4** A new profile attribute is added to the validator, the derivation precedence, the digest view and the Python twin. `enabled` and `hook_fail_mode` stay out of profiles. Why: a missing digest field keeps the same digest after a change.
  Check: `go test ./internal/config -run GuardrailProfile` and `pytest cli/tests/test_guardrail_profiles.py`. Evidence: `internal/config/guardrail_profiles.go`.
- [ ] **M-ID-5** The policy digest is canonical, deterministic and secret-free; test stability and change detection. Why: it is stamped on decisions and telemetry.
  Check: `go test ./internal/config -run Digest`. Evidence: `internal/config/guardrail_profiles_test.go`.
- [ ] **M-ID-6** Sandbox and OpenShell profile settings may only tighten the admin floor. Why: a profile that loosens it, or a looser default profile, is a gap during a directory outage.
  Check: `go test ./internal/config -run 'Tighten|Sandbox'`. Evidence: `internal/config/openshell_tighten.go`.
- [ ] **M-ID-7** A new identity source reads OS facts only (never an IdP API or identity credentials), marks each fact verified or claimed, and states per-OS limits. Why: the product promise is no IdP calls.
  Check: `go test ./internal/useridentity ./internal/unixidentity`. Evidence: `docs-site/content/docs/enterprise/identity/authentication.mdx`.
- [ ] **M-ID-8** Agent identity IDs stay deterministic; changing a namespace or input needs a migration (stop and ask). Why: assignments and audit trails key on them.
  Check: `go test ./internal/agentidentity`. Evidence: `internal/agentidentity/agentidentity.go`.
- [ ] **M-ID-9** Profiles and identity routes stay unreachable under the Secure Client profile. Why: it must stay byte-identical.
  Check: `go test ./internal/config ./internal/managed -run SecureClient`. Evidence: `internal/managed/profile.go`.

## DEP: deployment modes, switches and bundles

- [ ] **M-DEP-1** Gate managed-only behavior on the resolved deployment mode and profile, never on a user-writable key or user environment. Why: a per-user config must not opt out of the managed gate.
  Check: `go test ./internal/managed ./internal/config -run 'Profile|Managed|Pin'`. Evidence: `internal/managed/profile.go`, `internal/config/enterprise.go`.
- [ ] **M-DEP-2** New `enterprise.*` keys are validated against closed lists, appear in the schema, default to the secure value, and loosen only by a named value (`off`, `report`, `allow`), never by absence. Why: an unvalidated key is a silent no-op for an admin.
  Check: `go test ./schemas ./internal/config`. Evidence: `internal/config/enterprise.go`.
- [ ] **M-DEP-3** Managed hook paths fail closed: errors, an unreachable gateway or stale guardian state deny. Only stop and session-end events are neutral. Why: empty hook binaries once allowed every call.
  Check: `go test ./internal/managed ./internal/gateway -run 'Guardian|FailClosed'`. Evidence: `internal/managed/hook_guardian.go`.
- [ ] **M-DEP-4** Managed hosts refuse local writers with a reason and exit code 3. Every new CLI or TUI writer goes through the config writer. Why: a local edit would diverge from what the gateway enforces.
  Check: `pytest cli/tests -k 'managed and refus'`. Evidence: `cli/defenseclaw/config_writer.py`, `cli/defenseclaw/commands/cmd_config.py` (`@sym:MANAGED_EXIT_CODE`), `cli/defenseclaw/commands/cmd_upgrade.py`.
- [ ] **M-DEP-5** Apply config, policy, packs, secrets, drop-ins and binaries as one unit through the lifecycle transaction (stage, apply, verify, commit or restore). No second writer for a managed file. Why: partial application leaves a half-new policy.
  Check: `go test ./internal/enterpriseunix -run 'Rollback|Recover|Transaction'`. Evidence: `internal/enterpriseunix/doc.go`, `internal/enterpriseunix/lifecycle.go`.
- [ ] **M-DEP-6** Everything a feature needs ships inside the applied unit: assets are digest-pinned, validated before swap, and a failed candidate keeps the previous generation and reports why. No second out-of-band step. Why: a feature needing a manual follow-up breaks managed rollouts.
  Check: `go test ./internal/config -run Candidate` and `go test ./internal/gateway -run Reload`. Evidence: `internal/config/validate_candidate.go`, `internal/gateway/config_manager.go`.
- [ ] **M-DEP-7** A new installed file, binary or service is added to every channel (Linux packages, macOS pkg, Windows Setup, Python wheel) and to the lifecycle binary lists with a hash check. Why: one missing channel yields a host that verifies on one OS only.
  Check: `make packaging-linux-enterprise`, `pytest cli/tests/test_enterprise_packaging.py` and `go test ./internal/enterpriseunix -run 'Binar|Payload'`; no test checks every channel, so list each channel you touched in the PR. Evidence: `.goreleaser.yaml`, `internal/enterpriseunix/payload.go`, `packaging/windows/payload.go`.
- [ ] **M-DEP-8** Everything the managed gateway loads (config, policy tree, every rule-pack directory) must be administrator-owned and checked before the restart. Why: a user-writable pack is a policy bypass.
  Check: `go test ./internal/enterpriseunix -run 'RulePackTreeTrust|VendorRulePackDrift'`. Evidence: `internal/enterpriseunix/packtrust.go`.
- [ ] **M-DEP-9** Managed listeners stay on loopback; any new listener needs a managed-mode validator. Why: a machine-wide service must not expose every user's policy surface.
  Check: `go test ./internal/config -run 'Listener|Loopback'`. Evidence: `internal/config/config.go`.
- [ ] **M-DEP-10** State per mode (OSS, standalone, Secure Client) where a feature exists. A requested but unavailable feature reports a reason code, never silently does nothing. Why: an admin who writes a no-op key believes they are protected.
  Check: `go test ./internal/config -run 'Tetragon|ManagedIPC'`. Evidence: `docs-site/content/docs/enterprise/configure/machine-policy.mdx`.
- [ ] **M-DEP-11** A hot config apply is allowed only when nothing else differs and no changed key is restart-required; a rejected reload keeps enforcing the previous policy. Why: running policy would differ from committed config.
  Check: `go test ./internal/enterpriseunix -run 'Hot|AppliedPolicy|PolicyOmitted'` and `go test ./internal/config/configwrite -run ManagedRestartRequired`. Evidence: `internal/enterpriseunix/hotapply.go`.
- [ ] **M-DEP-12** A per-user surface (installer, updater, auto-start, daemon) refuses beside a managed install. Why: a per-user gateway is a second, unmanaged enforcement point.
  Check: `pytest cli/tests/test_upgrade_shim.py -k 'install_sh or managed'` and `pytest cli/tests/test_windows_enterprise_standalone_contract.py -k refuses_a_managed_host`. Evidence: `scripts/install.sh`, `internal/managed/runtime_descriptor.go`.
- [ ] **M-DEP-13** A managed host never writes raw prompts or model output to disk; new trace or capture features refuse or need explicit admin opt-in. Why: a root service would collect every user's prompts.
  Check: `go test ./internal/config -run 'Trace|Enterprise'`. Evidence: `docs-site/content/docs/enterprise/plan/threat-model.mdx`.
- [ ] **M-DEP-14** State and test the off switch in every mode: OSS (a `config.yaml` key that setup, the CLI and the TUI can flip), standalone and MDM-managed (an `enterprise.*` closed-list value `off` that no user config can override), Secure Client (unreachable). A test turns it off in each mode and asserts the feature does nothing and starts nothing. Why: a feature without a managed off switch cannot be staged or withdrawn across a fleet.
  Check: `go test ./internal/config -run 'Enterprise|Managed'` plus the feature's off-path test. Evidence: `internal/config/enterprise.go`, `docs-site/content/docs/enterprise/configure/configuration.mdx`.
- [ ] **M-DEP-15** A connector on a managed host needs a route decision per OS in `RouteFor`; the default arm is `unsupported`, so a missing connector is silently unmanaged. Why: the host would report success while the agent is uncovered.
  Check: `go test ./internal/enterprisepolicy ./internal/enterprisehooks`. Evidence: `internal/enterprisepolicy/types.go`, `.claude/skills/defenseclaw-add-connector/reference/enterprise.md`.
- [ ] **M-DEP-16** A managed artifact that gains a feature gets a verify counterpart that fails on artifacts rendered before the feature, so the guardian re-renders after an upgrade. Why: an upgrade that leaves old hook scripts leaves the new protection off while status reads healthy.
  Check: `go test ./internal/enterprisehooks/... ./internal/enterpriseunix -run 'Verify|Guardian'`. Evidence: `internal/enterpriseunix/verify.go`, `internal/enterprisehooks/guardianstate/state.go`.
- [ ] **M-DEP-17** A new bundle or digest format carries config, policy, rule packs and assets together, has one deterministic digest over canonical content, verifies its signature before staging any file, applies through the lifecycle transaction, restores the previous state on failure, and reports the applied digest. Stop and ask first. Why: a partial apply mixes old and new policy.
  Check: apply, failure and rollback tests next to `internal/enterpriseunix/lifecycle.go`. Evidence: `internal/enterpriseunix/lifecycle.go`, `internal/config/validate_candidate.go`.

## REQ: external requirements

- [ ] **M-REQ-1** A new external requirement (Docker, VM, local model, GPU, extra, system package, OS version, egress) is optional and off by default unless the core guardrail path cannot run without it. Why: it must not break hosts that never asked for it.
  Check: review the diff of `pyproject.toml`, `packaging/` and install scripts. Evidence: `cli/defenseclaw/commands/cmd_doctor.py` (`@sym:_check_sandbox`).
- [ ] **M-REQ-2** Never install or download silently: show a plan, ask or require a flag, pin by version and sha256, refuse on mismatch. Doctor only prints fixes. Why: unreviewed downloads are a supply-chain hole.
  Check: `go test ./internal/openshell -run 'Installer|Digest'`. Evidence: `internal/openshell/version.go`, `internal/openshell/install.go`.
- [ ] **M-REQ-3** On managed hosts check and report a requirement, never install it; publish the result as a root-owned record and refuse the dependent feature with a stable code and a fix line. Why: a user-writable record would mark a host ready.
  Check: `go test ./internal/openshell -run Prerequisites`. Evidence: `internal/openshell/prerequisites.go`.
- [ ] **M-REQ-4** Add a detection check with a stable ID that ends in pass, warn, fail or skip with a copy-paste fix (sudo marked), never a traceback. Surface it in `defenseclaw doctor` (and `status` when operators act on it). Why: operators learn what is missing before it fails.
  Check: `defenseclaw doctor --json` on a host without the requirement. Evidence: `internal/openshell/doctor.go`, `cli/defenseclaw/commands/cmd_doctor.py`.
- [ ] **M-REQ-5** Document the requirement in `docs-site` in a "You need" table (versions, disk, rights, first-start caveats) and in the install prerequisites. Why: it is the operator's only pre-flight list.
  Check: `grep -rn '<name>' docs-site/content/docs`. Evidence: `docs-site/content/docs/get-started/install.mdx`, `docs-site/content/docs/how-to/sandboxes/set-up-on-linux.mdx`.
- [ ] **M-REQ-6** Test the missing case: binary, daemon, KVM, key or platform absent, asserting severity, reason code and fix text. Why: only the happy path gets tested otherwise.
  Check: `pytest cli/tests/test_cmd_doctor_sandbox.py` and `go test ./internal/openshell/...`. Evidence: `internal/openshell/doctor_test.go`.
- [ ] **M-REQ-7** Refuse unsupported platforms by name in code even when config says enabled; never silently downgrade a required backend. Why: a config copied from another OS must not read as active.
  Check: `go test ./internal/openshell -run SelectDriver`. Evidence: `internal/openshell/driver_select.go`.
- [ ] **M-REQ-8** Bump a pinned external artifact (version, URL, digest) together, with tests. Why: a partial bump makes setup refuse its own installer.
  Check: `go test ./internal/openshell -run Version`. Evidence: `internal/openshell/version.go`.
- [ ] **M-REQ-9** A new outbound destination is off until enabled, named in the docs, covered by an offline test, and, when the URL is user-configured or partially trusted (webhooks, scanners, registries, proxy passthrough), dialled through `internal/netguard` (dial-time IP validation, no redirects, no inline credentials). Why: a configurable URL becomes SSRF into loopback, link-local or cloud metadata, and air-gapped hosts must keep working.
  Check: `go test ./internal/netguard/...`; grep the diff for `http.Client{` without a netguard dialer. Evidence: `internal/netguard/netguard.go` (`@sym:IsHardDeniedIP`, `@sym:RejectInlineCredentials`), `internal/netguard/egress_route.go`.
- [ ] **M-REQ-10** Give every external requirement one tier and use the same word in code, doctor and docs. Required: the core guardrail path cannot run without it; install fails fast and names it. Recommended: a feature degrades without it (the LLM judge, a local vLLM server); doctor warns and never fails. Optional: an opt-in feature (Docker or a MicroVM for sandboxes); doctor skips while the feature is off and fails only when it is enabled and missing. Why: operators and agents cannot otherwise tell a hard dependency from a suggestion.
  Check: the docs-site "You need" table has a Tier column, and a doctor test asserts the severity for each tier. Evidence: `cli/defenseclaw/commands/cmd_doctor.py`, `docs-site/content/docs/get-started/install.mdx`.
- [ ] **S-REQ-1** Pick severity by who is hurt: fail only when the enabled feature cannot work, warn when degraded, skip when off or not applicable. Why: mis-severity blocks healthy hosts or hides broken ones.
  Check: read against `cli/tests/test_cmd_doctor_sandbox.py`. Evidence: `cli/defenseclaw/commands/cmd_doctor.py`.
- [ ] **S-REQ-4** Optional third-party services get their own doctor row: skip when off, warn when enabled without a key, fail only on a rejected credential. Why: offline hosts stay green.
  Check: compare with `@sym:_check_virustotal`. Evidence: `cli/defenseclaw/commands/cmd_doctor.py`.

## SBX: sandbox

- [ ] **M-SBX-1** Sandboxes stay off until `openshell.enabled` is set; the doctor section skips when off. Why: no cost or requirement for users who never asked.
  Check: `pytest cli/tests/test_cmd_doctor_sandbox.py`. Evidence: `cli/defenseclaw/commands/cmd_doctor.py`.
- [ ] **M-SBX-2** Driver choice (docker, vm, auto, fallback) is an explicit setting with a typed refusal; a required MicroVM never falls back to Docker; macOS never uses Docker. Why: a silent downgrade weakens required isolation.
  Check: `go test ./internal/openshell -run SelectDriver`. Evidence: `internal/openshell/driver_select.go`.
- [ ] **M-SBX-3** Keep the Python `sandbox` commands in lockstep with the Go command tree and its golden file. Why: the two CLIs drift.
  Check: `go test ./internal/cli ./internal/openshell/sandboxcli`. Evidence: `internal/cli/testdata/sandbox_commands.json`, `docs-site/content/docs/reference/sandboxes/cli.mdx`.
- [ ] **M-SBX-4** Built-in and custom sandbox packs load through the strict pack loader; keep `@sym:BuiltinPackNames` ordered loosest to strictest; a change to a built-in pack or egress feed updates the embedded copy and its test. Why: a leniently loaded pack or a stale feed changes sandbox posture silently.
  Check: `go test ./policies/sandbox/... ./internal/openshell/packs/...`. Evidence: `policies/sandbox/packs.go`, `policies/sandbox/egress/embed_test.go`, `docs-site/content/docs/reference/sandboxes/policy.mdx`.
- [ ] **M-SBX-5** Sandbox traffic leaves only through the DefenseClaw egress proxy and the rendered OpenShell policy; credentialed endpoints (hook ingress, LLM) are reachable only through their scoped rules. Why: a direct route bypasses egress policy and telemetry.
  Check: `go test ./internal/openshell/egress/... ./internal/openshell/policy/...`. Evidence: `internal/openshell/egress`, `internal/openshell/policy`, `docs-site/content/docs/reference/sandboxes/network.mdx`.
- [ ] **M-SBX-6** Each sandbox authenticates with its own binding (random bearer stored only as a hash, scoped to one connector's hook routes); managed registrations and saved decisions stay scoped to the caller's uid; relayed calls use the sandboxrelay contract. Why: a shared or unscoped credential lets one sandbox or user act as another.
  Check: `go test ./internal/sandboxauth/... ./internal/sandboxreg/... ./internal/sandboxrelay/...`. Evidence: `internal/sandboxauth`, `internal/sandboxreg`, `internal/sandboxrelay`.
- [ ] **M-SBX-7** Any feature that lets sandboxed code write into the mounted project keeps the nested-repository guard. Why: a planted `.git` config runs code on the host.
  Check: `go test ./internal/openshell/nestguard/...`. Evidence: `internal/openshell/nestguard`.

## SCN: scanners, judges and local models

- [ ] **M-SCN-1** Scanners are pinned wheels resolved from the managed environment first, then PATH. Doctor probes the launcher with a bounded `--version`; the missing case fails with a repair hint. Do not ask users to install scanners separately. Why: PATH must not shadow the managed scanner, and a stale launcher on PATH can run a different scanner version.
  Check: `pytest cli/tests/test_cmd_doctor.py -k scanner`. Evidence: `cli/defenseclaw/scanner_binary.py`, `cli/defenseclaw/commands/cmd_doctor.py`.
- [ ] **S-SCN-1** The LLM judge is recommended but never a hard dependency. Accept local OpenAI-compatible servers (vLLM, Ollama, LM Studio) without a key, route through the shared `llm:` block, surface serving requirements as a doctor or settings hint, and give the judge its own doctor row (skip when off, warn when the key is missing or the server is unreachable). Why: judge-less hosts stay healthy and a silent judge outage shows up.
  Check: run doctor with the judge off, a bad key and an unreachable local server. Evidence: `cli/defenseclaw/config.py` (`@sym:_LOCAL_LLM_PROVIDERS`), `cli/defenseclaw/commands/cmd_doctor.py` (`@sym:_check_llm_reachable`), `cli/defenseclaw/scanner/settings.py` (`@sym:VLLM_SERVE_HINT`).

## TST: testing

- [ ] **M-TST-1** Run the pre-PR gates for the areas touched: `make lint`, `make test`, `make ts-test`, `make rego-test`, `make check`. `make test` does not cover the others; `make telemetry-check` is separate. `make test` runs Go tests only for `internal/gateway` and `test/`; also run `go test -race ./internal/<pkg>/...` for every Go package you touched, or `make go-test-cov`. Why: they mirror the required CI checks.
  Check: the commands themselves. Evidence: `docs/TESTING.md`, `CONTRIBUTING.md`, `Makefile`.
- [ ] **M-TST-2** Ship a test that fails without the change, in the same PR. Why: unpinned fixes regress.
  Check: revert the production change locally and watch the test fail. Evidence: `CONTRIBUTING.md`.
- [ ] **M-TST-3** Go tests are race-clean and never depend on sleeps for ordering. Why: every Go shard runs `-race`.
  Check: `go test -race -count=1 ./internal/<pkg>`. Evidence: `Makefile`.
- [ ] **M-TST-4** Python tests use the isolation fixtures: no real home, network, gateway or host discovery. Why: tests must not mutate a developer or CI profile.
  Check: `pytest cli/tests/<module>`. Evidence: `cli/tests/conftest.py`.
- [ ] **M-TST-5** When you change CI logic or file classification, update the classifier and its test together. Why: a wrong rule silently skips a required gate.
  Check: `pytest cli/tests/test_ci_changes.py`. Evidence: `scripts/ci_changes.py`.
- [ ] **M-TST-6** Regenerate a Go golden only with `DEFENSECLAW_UPDATE_GOLDEN=1` for the one affected test, then review the diff. Why: goldens encode security contracts.
  Check: `git diff` after regeneration. Evidence: `policies/kernel/kernel_test.go`.
- [ ] **M-TST-7** Installer, migration, upgrade, rollback or gateway-startup changes run the install lifecycle scenarios, including the 0.8.x upgrade scenarios. Why: they are the only gate for rollback and migration failures.
  Check: `scripts/test-install-lifecycle.sh --assets <dir> --previous-assets <dir>`. Evidence: `docs/TESTING.md`, `scripts/test-install-lifecycle.sh`.
- [ ] **M-TST-8** Enterprise package, Setup, guardian and lifecycle changes pass the enterprise install jobs, run only on disposable hosts. Why: the jobs install and remove system services as root.
  Check: CI job `Enterprise Required`. Evidence: `scripts/test-enterprise-unix-install.sh`, `.github/workflows/ci.yml`.
- [ ] **M-TST-9** Windows-affecting code gets Windows-native validation and platform-specific test file pairs. Why: ACLs, services and paths differ.
  Check: `GOOS=windows go vet ./...`. Evidence: `.github/workflows/windows-native.yml`.
- [ ] **M-TST-10** A green synthetic or contract job is not certification. Support claims for a connector or OS need interactive verification on each claimed OS, recorded in the PR Test Plan. Why: CI runners lack real agents, identities and MDM.
  Check: Test Plan lists host, commands and observed results. Evidence: `.github/workflows/connector-live-e2e.yml`.
- [ ] **M-TST-11** Connector changes run `make connector-matrix-test`. Why: the matrix runs on every PR.
  Check: `make connector-matrix-test`. Evidence: `test/e2e/connectormatrix.go`.
- [ ] **M-TST-12** A new managed file, or a new managed branch in a shared file, is listed in `.github/managed-paths.txt`. Why: the manifest decides which pull requests run the managed lanes; an unlisted file skips them.
  Check: `make check-managed-paths`. Evidence: `scripts/check_managed_paths.py`.
- [ ] **S-TST-1** Iterate with the cheapest focused test, then run the full gate once. Gateway tests need an explicit `-timeout`. Why: the package exceeds the default deadline.
  Check: `make test-file FILE=<module>`. Evidence: `docs/TESTING.md`.
- [ ] **S-TST-2** TUI tests: unit-test models first, at most two Pilot tests per new screen at 80x24, no sleeps, no copy assertions. Why: Pilot tests are slow and brittle.
  Check: `make tui-test`. Evidence: `cli/tests/tui/test_smoke.py`, `.claude/skills/defenseclaw-tui/SKILL.md`.

## PERF: performance and size

- [ ] **M-PERF-1** Every new feature has an off switch and costs nothing when off: no goroutine, watcher, timer, listener or disk scan unless enabled; a test or benchmark shows the off path. Why: laptops and multi-user hosts pay for idle features.
  Check: `go test ./internal/observability/runtime -bench Disabled -run '^$'`. Evidence: `internal/gateway/api.go`.
- [ ] **M-PERF-2** The hook path is one bounded local call: no discovery, subprocess spawn, config scan or heavy init in the hook binaries. Do expensive work in the gateway. Why: it runs on every tool call.
  Check: `go test ./internal/gateway/connector/hookexec/... ./cmd/defenseclaw-hook/...`. Evidence: `cmd/defenseclaw-hook/main.go`, `internal/gateway/connector/hookexec/hookexec.go`.
- [ ] **M-PERF-3** Derive a hook's budget from the agent's registered timeout minus the response grace; retries must fit inside it. Set the registered timeout and the budget together. Why: the agent kills a hook that overruns.
  Check: `go test ./internal/gateway/connector/hookexec/ -run 'Timeout|Deadline'`. Evidence: `internal/gateway/connector/hookexec/hookexec.go`.
- [ ] **M-PERF-4** Bound every input (hook stdin, API body, OTLP body); new endpoints use the body-limit middleware. Why: unbounded bodies exhaust memory.
  Check: `go test ./internal/gateway -run 'BodyLimit|Oversize'`. Evidence: `internal/gateway/api.go`.
- [ ] **M-PERF-5** Keep admission control on hook endpoints: per-caller rate and in-flight limits and a global cap that answers 429 immediately rather than queueing. Do not raise limits without a load measurement. Why: a late answer is worse than a refusal.
  Check: `go test ./internal/gateway -run 'HookCaller|RateLimit'`. Evidence: `internal/gateway/hook_caller_limits.go`.
- [ ] **M-PERF-6** Never queue the judge on the hook path; skip it at capacity and fall back to the deterministic verdict. Why: a queued call stalls the agent.
  Check: `go test ./internal/gateway -run HookJudge`. Evidence: `internal/gateway/inspect.go`.
- [ ] **M-PERF-7** New CEL or semantic rules stay inside the static and runtime cost limits; regexes are RE2-safe. Raise a limit only with a test and a justification. Why: packs evaluate on every call.
  Check: `go test ./internal/guardrail/semantic/...`. Evidence: `internal/guardrail/semantic/limits.go`.
- [ ] **M-PERF-8** Keep the audit store single-writer: no long transactions, no writes bypassing the store, retention in small batches with the default of 7 days. Why: long writes starve hooks.
  Check: `go test ./internal/audit -run 'Retention|Busy'`. Evidence: `internal/audit/store.go`, `internal/audit/retention_v8.go`, `internal/config/observability_v8_types.go` (`@sym:ObservabilityV8DefaultRetentionDays`).
- [ ] **M-PERF-9** Telemetry destinations use bounded, byte-aware queues; a full queue drops and counts, never blocks. Why: a slow collector must not stall hooks.
  Check: `go test ./internal/observability/... -bench . -run '^$'`. Evidence: `internal/config/observability_v8_compile.go`.
- [ ] **M-PERF-10** Root or SYSTEM work done for users runs as a short-lived child with resource limits, deadlines and a failure breaker. Why: one user's directory must not consume a host.
  Check: `go test ./internal/cli -run 'EnterpriseHookWorker|AIDiscoveryPass'`. Evidence: `internal/cli/enterprise_hooks_worker_unix.go`.
- [ ] **M-PERF-11** Keep release binaries lean (`CGO_ENABLED=0`, `-trimpath`, stripped) and the Windows hook launcher under its size ceiling; no heavy dependency in the hook binaries. Why: the hook is exec'd per call.
  Check: run `scripts/build-release-assets.sh` before and after and `ls -l` the hook binaries; the Windows launcher size step (8 MiB) runs in CI. Evidence: `scripts/build-release-assets.sh`, `.github/workflows/windows-native.yml`.
- [ ] **S-PERF-2** Report size deltas for anything you ship: each changed release binary, the wheel and any package, measured with `ls -l` or `du` before and after, in the PR body. Do not commit datasets, corpora or generated blobs; datasets are downloaded and pinned in `benchmarks/datasets.lock.json`. Why: every byte ships to each laptop and managed host, and only the Windows launcher has a CI ceiling.
  Check: `git diff --stat` shows no large new binary or data file. Evidence: `benchmarks/README.md`, `.github/workflows/windows-native.yml`.
- [ ] **S-PERF-1** Do not add work that scales with profile or user count on each config load; decode once and keep allocation assertions. Why: 1,000 profiles once slowed every reload.
  Check: `go test ./internal/config -run Profiles`. Evidence: `internal/config/guardrail_profiles_test.go`.

## OBS: observability and audit

- [ ] **M-OBS-1** Define audit actions once in Go and mirror them in Python and the schema; production code uses typed constants, not raw strings. Why: downstream consumers rely on the enum.
  Check: `make check-audit-actions check-audit-no-raw-literals`. Evidence: `internal/audit/actions.go`, `cli/defenseclaw/audit_actions.py`.
- [ ] **M-OBS-2** Add gateway error codes as typed constants mirrored in Python. Why: Go and Python sets must match.
  Check: `make check-error-codes`. Evidence: `internal/gatewaylog/error_codes.go`, `cli/defenseclaw/gateway_error_codes.py`.
- [ ] **M-OBS-3** Every state change (config apply, policy reload, mode change, refusal) emits an audit event with actor and result. Why: operators reconstruct what changed from the log.
  Check: `go test ./internal/gateway -run Config`. Evidence: `internal/gateway/config_change_audit.go`.
- [ ] **M-OBS-4** Start telemetry changes in the registry, run `make telemetry-generate`, commit the generated outputs, never hand-edit them. Why: CI rejects stale generated output.
  Check: `make telemetry-check`. Evidence: `schemas/telemetry/v8`, `scripts/generate_telemetry_registry.py`.
- [ ] **M-OBS-5** Do not reintroduce the retired v7 runtime outside the upgrade and recovery boundaries. Why: the hard-cut gate fails.
  Check: `make check-observability-v8-hard-cut`. Evidence: `scripts/check_observability_v8_hard_cut.py`.
- [ ] **M-OBS-6** Redact once at the projection boundary through redaction profiles; state the privacy class and effective profile of any new field or destination. Why: dashboards are not a redaction boundary.
  Check: `go test ./internal/redaction ./internal/observability`. Evidence: `docs-site/content/docs/reference/observability/redaction.mdx`.
- [ ] **M-OBS-7** Dashboard and provider-shape changes keep source and packaged copies in sync. Why: queries on missing metrics render plausible zeros.
  Check: `make check-grafana-dashboards check-provider-coverage`. Evidence: `scripts/check_grafana_dashboards.py`, `test/testdata/llm-endpoints.json`.

## DOC: documentation

- [ ] **M-DOC-1** Put operator behavior in `docs-site/content/docs`; keep repo Markdown for contributor and implementation material. Why: the website is canonical.
  Check: review the diff; `cd docs-site && npm run build`. Evidence: `CONTRIBUTING.md`, `docs-site/README.md`.
- [ ] **M-DOC-2** Every `defenseclaw ...` and `defenseclaw-gateway ...` command in docs parses against the real CLI. Why: gates fail on invented flags.
  Check: `python scripts/check_docs_cli_commands.py`. Evidence: `cli/tests/test_docs_cli_commands.py`.
- [ ] **M-DOC-3** Internal links resolve and new pages are listed in the section navigation. Why: unlisted pages are invisible.
  Check: `cd docs-site && npm run validate-links`. Evidence: `docs-site/content/docs/meta.json`.
- [ ] **M-DOC-4** Never hand-edit generated docs (env-var reference, `docs-site/data/policy-*.json` assets); run the generator. Why: CI diffs them.
  Check: `python scripts/gen_envvars_docs.py --check`. Evidence: `docs-site/content/docs/reference/configuration/env-vars.mdx`.
- [ ] **S-DOC-1** Add a `CHANGELOG.md` entry under Unreleased for operator-visible changes, leading with the symptom and the fix. Why: it is the development rollup.
  Evidence: `CHANGELOG.md`.
- [ ] **S-DOC-2** Pin new connector or platform claims with a test. Why: an unpinned claim drifts from the code without failing any test.
  Check: `pytest cli/tests/test_windows_release_claims.py`. Evidence: `docs-site/data/capability-matrix.json`.

## SEC: security

- [ ] **M-SEC-1** No credentials in config, logs, audit rows, telemetry, fixtures or PR text. Write secret-bearing files through the safe-file helper with private modes. Why: leaks survive in backups and MDM scripts.
  Check: `pytest cli/tests/test_secure_write_permissions.py`. Evidence: `internal/safefile`, `docs-site/content/docs/reference/configuration/keys.mdx`.
- [ ] **M-SEC-2** Privileged discovery code (root or SYSTEM) never follows user-controlled paths: bounded homes, no-follow, regular files, size caps. Why: a symlink in a home becomes a privileged read.
  Check: `go test ./internal/enterprisehooks -run 'Home|Bounded'`. Evidence: `internal/enterprisehooks/home_bounded_unix.go`.
- [ ] **M-SEC-3** Pin GitHub Actions by commit SHA, keep workflow permissions read-only at workflow scope, and keep PR-controlled code away from elevated tokens. Why: the workflow lint job and the Pages deploy depend on it.
  Check: CI job `Workflow Lint`. Evidence: `.github/workflows/ci.yml`, `.github/actionlint.yaml`.
- [ ] **M-SEC-4** Fix dependency advisories by raising the version floor, never by adding audit ignores. Why: the audit jobs fail on advisories.
  Check: CI audit jobs. Evidence: `pyproject.toml`, `extensions/defenseclaw/package-lock.json`.
- [ ] **M-SEC-5** Report vulnerabilities privately per the security policy, never in a public issue or PR. Evidence: `SECURITY.md`.
- [ ] **S-SEC-1** Add the license header to new source files. Why: the app target enforces it. Evidence: `scripts/macos_license_headers.py`.

## PKG: packaging and upgrade

- [ ] **M-PKG-1** The 0.8.x to 1.x upgrade keeps working: configs older than the supported floor convert with `defenseclaw migrate`, and the runtime refuses them with that one instruction. Why: operators upgrade in place.
  Check: `pytest cli/tests/test_migrations.py cli/tests/test_enterprise_upgrade_v9.py` and `go test ./internal/config -run MigrateV9`. Evidence: `scripts/check_enterprise_upgrade_config.py` (CI enterprise upgrade lanes run it with --before and --after), `cli/defenseclaw/migrations.py`, `scripts/defenseclaw-upgrade.sh`.
- [ ] **M-PKG-2** Upgrade, downgrade and rollback are explicit and reversible; downgrades are refused without the explicit flag; files older releases read strictly are not extended. Why: managed rollbacks must work.
  Check: `go test ./internal/enterpriseunix -run 'Downgrade|Rollback'`. Evidence: `internal/enterpriseunix/lifecycle.go`.
- [ ] **M-PKG-3** Change versions only with `make set-version VERSION=X.Y.Z`; keep `make check-version-sync` green. Why: any disagreeing version source fails the gate.
  Check: `make check-version-sync`. Evidence: `scripts/stamp-version.sh`.
- [ ] **M-PKG-4** Source-checkout install targets are for development only and never run under sudo-owned checkouts or beside a managed install. Why: they are not an operator path.
  Check: `make help`. Evidence: `scripts/refuse-sudo-user-checkout.sh`, `scripts/install-dev.sh`.
- [ ] **M-PKG-5** Keep `go.mod` free of a `toolchain` directive and keep the cross-shell parity checks green. Why: OSS builds and byte-identical Windows builds depend on it.
  Check: `make lint`. Evidence: `scripts/check-go-mod-no-toolchain.sh`, `scripts/check-repro-flags-parity.sh`.
- [ ] **M-PKG-6** Remove the dead and legacy code you touch (retired keys, unreachable fallbacks, stale shims). Keep a shim only for a supported upgrade and state until when in the PR body. Retired connector names appear only in the legacy migration modules, `CHANGELOG.md`, the upgrade guide and the manual test plan; build them from fragments in tests. Why: stale shims hide lenient behavior.
  Check: grep the touched key across `cli/`, `internal/`, `docs-site/`, `scripts/`. Evidence: `cli/tests/test_retired_connector_names.py`, `internal/legacyconnector/legacyconnector.go`.
- [ ] **S-PKG-1** Leave publishing to the Release workflow; changes to it get a dry run. Why: a mistake there affects every operator.
  Evidence: `.github/workflows/release.yaml`, `docs/RELEASE_RUNBOOK.md`.
- [ ] **S-PKG-2** Keep `.claude/skills` the only copy of a skill and expose it under `.agents/skills` by a relative symlink (`defenseclaw-tui` is the model); replace a duplicated directory (today `defenseclaw-add-connector`) with a symlink when you touch it. Why: duplicates drift.
  Check: `ls -l .agents/skills`.
- [ ] **M-PKG-7** Change the audit SQLite schema only by appending an entry to the ordered migration list in `internal/audit/store.go`; never edit, reorder or remove an entry. Each migration is additive for the previous reader, idempotent, safe on a partial schema, and counted by `@sym:PendingMigrations` so a long one runs before gateway readiness. Test it against a database written by the previous release. Why: rollback reopens the file with an older reader, and a long in-place migration stalls hooks at start.
  Check: `go test ./internal/audit -run Migration`. Evidence: `internal/audit/store.go`, `internal/audit/pending_migrations.go`.

## PR: pull request hygiene

- [ ] **M-PR-1** Complete every section of the PR template, with exact commands and observed results in the Test Plan. Evidence: `.github/pull_request_template.md`.
- [ ] **M-PR-2** Every follow-up links a GitHub issue; write None otherwise. Why: no action item lives only in a PR body.
- [ ] **M-PR-3** Paste `reference/pr-block.md` into the PR description before the first commit and keep it current. Why: requirements are cheaper before coding.
- [ ] **M-PR-4** Stage explicit paths; never commit scratch files, build outputs, local state or secrets. Why: stray files accumulate in checkouts. Check: `git status --short` before `git add`.
- [ ] **M-PR-5** If the change alters an architecture rule, update this skill in the same PR (`reference/maintenance.md`). Check: `make skill-check`.
- [ ] **M-PR-6** Land every layer of a change in the same PR: schema, Go and Python mirrors, migration, docs-site page, tests per mode, packaging channels and audit or telemetry. No "docs or tests in a follow-up". Why: a release cut between two PRs ships a half feature. Check: the PR block lists each layer as done or n.a. with a reason.
- [ ] **O-PR-1** Expect one review group for all paths; do not assume per-area owners. Evidence: `.github/CODEOWNERS`.
