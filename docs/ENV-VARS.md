# DefenseClaw environment variables

Canonical list of every `DEFENSECLAW_*` env var consumed by the
codebase, generated from `internal/envvars/registry.json`.

> **Edit policy:** Do not hand-edit the auto-generated block below.
> Edit `internal/envvars/registry.json` and run
> `python3 scripts/gen_envvars_docs.py` to regenerate.

The CI gate at `cli/tests/test_envvars_codebase_coverage.py` fails
if any callsite references a `DEFENSECLAW_*` var not declared in
the registry — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
workflow.

Active overrides are also surfaced live by `defenseclaw doctor`
(the "Security Overrides" section).

<!-- AUTOGEN-BEGIN: env-vars -->
<!-- The block below is auto-generated from `internal/envvars/registry.json` via `scripts/gen_envvars_docs.py`. Edit the JSON, not this file. -->

## Security opt-outs

| Env var | Impact | Default | Accepted values | Purpose | Security concern | Consumers |
| --- | --- | --- | --- | --- | --- | --- |
| `DEFENSECLAW_ALLOW_CGNAT` | **HIGH** | `unset` (CGNAT blocked) | `1`, `unset` | Allow RFC 6598 carrier-grade NAT addresses (100.64.0.0/10, used by Tailscale and similar overlays) through the SSRF / private-IP guards. | CGNAT egress guard — prevents SSRF into shared carrier-grade NAT / overlay-network address space (e.g. another tenant's Tailscale node). | `internal/netguard/netguard.go:94` — cgnatAllowed() omits 100.64.0.0/10 from the reserved-CIDR list when set<br>`cli/defenseclaw/webhooks/writer.py:415` — _cgnat_allowed() gates webhook URL validation for CGNAT IPs<br>`cli/defenseclaw/registries/ssrf.py:52` — _cgnat_allowed() gates registry/manifest SSRF resolution for CGNAT |
| `DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT` | **HIGH** | `unset` (fail-closed in action mode) | `1`, `unset` | Bypass the action-mode fail-closed checks for unverified hook contracts and hook-contract lock drift during connector setup, allowing enforcing hooks to be installed against agent versions outside the verified contract matrix. | Hook contract verification — prevents installing an enforcing hook whose request/response contract has drifted from the verified matrix (a silent guardrail bypass). | `internal/gateway/sidecar.go:1417` — Blocks connector setup on an unverified hook contract in action mode unless set<br>`internal/gateway/sidecar.go:1422` — Blocks connector setup on hook-contract lock drift in action mode unless set<br>`cli/defenseclaw/commands/cmd_setup.py:2499` — Python setup path mirrors the gateway drift/contract enforcement |
| `DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS` | **HIGH** | `unset` (SSRF guard enforced) | `1`, `unset` | Skip SSRF validation for MCP scan target URLs, permitting loopback, private, link-local, and cloud-metadata destinations. | MCP scan-target SSRF guard — prevents a scan request from reaching IMDS / loopback / private hosts. | `internal/scanner/mcp.go:56` — validateMCPScanTargetURL() returns early without SSRF checks when set |
| `DEFENSECLAW_CODEX_LOOPBACK_TRUST` | **HIGH** | `unset` (fail-closed) | `1`, `unset` | Restore legacy loopback-trusts-any-bearer behavior for the Codex connector. | Per-bearer Codex authentication on loopback — prevents same-host user-to-user impersonation when multiple users share an OS account. | `internal/gateway/connector/codex.go:310` — Authenticate() falls back to legacy behavior when set; emits a [SECURITY] log line |
| `DEFENSECLAW_DEV` | low | `unset` | `1`, `true`, `unset` | Mark the process as a developer build. | — | `internal/redaction/credentials.go:173` — isCredentialScrubDevMode reads this var |
| `DEFENSECLAW_DISABLE_AWS_HTTP1_SHIM` | **medium** | `unset` (shim active for Bedrock) | `1`, `unset` | Disable the AWS Bedrock HTTP/1 monkey-patch the OpenClaw plugin installs to make Bedrock traffic visible to the guardrail proxy. | — | `extensions/defenseclaw/src/aws-sdk-http1-for-guardrail.ts:265` — JS shim bails out when set |
| `DEFENSECLAW_DISABLE_REDACTION` | **HIGH** | `unset` (redaction enabled) | `1`, `true`, `unset` | Disable all PII / credential redaction across every sink (audit DB, JSONL, OTel, Splunk, webhooks). | — | `internal/redaction/redaction.go:111` — DisableAll() reads this env var<br>`cli/defenseclaw/commands/redaction_status.py:42` — Python status reporter<br>`cli/defenseclaw/commands/cmd_setup.py:3158` — Setup flow surfaces this in onboarding |
| `DEFENSECLAW_DUMP_RAW_SECRETS` | **HIGH** | `unset` | `1`, `unset` | E2E test toggle ONLY. | — | `scripts/test-e2e-full-stack.sh:1038` — Dumps raw secrets in diagnostic output for test debugging |
| `DEFENSECLAW_FAIL_MODE` | **medium** | (value from guardrail.hook_fail_mode in config.yaml) | `open`, `closed`, `unset` | Per-shell override of guardrail.hook_fail_mode. 'open' allows on transport errors; 'closed' blocks. | — | `internal/gateway/connector/hooks/inspect-tool.sh:43` — Read by every inspect-*.sh hook |
| `DEFENSECLAW_FORCE_AWS_HTTP1_SHIM` | low | `unset` (shim only on Bedrock) | `1`, `unset` | Force the AWS HTTP/1 shim to install even on non-Bedrock setups. | — | `extensions/defenseclaw/src/aws-sdk-http1-for-guardrail.ts:272` — JS shim forces install when set |
| `DEFENSECLAW_JSONL_DISABLE` | low | `unset` (JSONL enabled) | `1`, `true`, `unset` | Disable the gateway.jsonl audit tier. | — | `internal/gateway/sidecar.go:226` — Gateway boot reads this kill switch<br>`internal/gateway/jsonl_kill_switch.go` — Definition site |
| `DEFENSECLAW_OPENSHELL_ALLOW_UNPINNED` | **medium** | `unset` (fail-closed) | `1`, `unset` | Accept a mutable OCI tag (e.g. 'latest') when installing openshell-sandbox instead of requiring a content-addressed digest or sha256 pin. <br>**Fix:** Pin via DEFENSECLAW_OPENSHELL_ARCH_DIGEST or DEFENSECLAW_OPENSHELL_BINARY_SHA256. | Pinned-digest sandbox install — prevents tag-mutation supply-chain attacks where an upstream tag is silently re-pointed at a malicious image. | `scripts/install-openshell-sandbox.sh:159` — Skips integrity verification when set |
| `DEFENSECLAW_OPENSHELL_ARCH_DIGEST` | — | `unset` | `sha256:<hex>`, `unset` | Pin the openshell-sandbox install to a specific platform manifest digest (sha256:...). | Pinned-digest sandbox install — content-addressed verification of the OCI manifest before extraction. | `scripts/install-openshell-sandbox.sh:151` — Verifies OCI manifest digest against this pin |
| `DEFENSECLAW_OPENSHELL_BINARY_SHA256` | — | `unset` | `64-char hex sha256`, `unset` | Pin the final extracted openshell-sandbox binary to a specific sha256. | Pinned-digest sandbox install — sha256 verification of the extracted binary. | `scripts/install-openshell-sandbox.sh:157` — Marker check (presence enables sha256 verification path)<br>`scripts/install-openshell-sandbox.sh:250` — Verifies extracted binary sha256 against this pin |
| `DEFENSECLAW_OTEL_TLS_INSECURE` | **HIGH** | `unset` (TLS verified) | `true`, `1`, `unset` | Disable TLS certificate verification on the OTel exporter. | — | `internal/config/config.go:2300` — viper.BindEnv binds this to otel.tls.insecure |
| `DEFENSECLAW_POLICY_VALIDATE_ALLOW_NO_OPA` | **medium** | `unset` (validation requires OPA) | `1`, `unset` | Accept a policy file as 'validated' even when OPA / Rego is not installed. | — | `cli/defenseclaw/commands/cmd_policy.py:1135` — Policy validate command bypass |
| `DEFENSECLAW_PREPAIR_TRUST_DEVICE_KEY` | **HIGH** | `unset` (fail-closed) | `1`, `unset` | Bypass the provenance-sentinel check during 'defenseclaw setup sandbox' pre-pairing. <br>**Fix:** Restart the gateway once after upgrading; LoadOrCreateIdentity auto-writes the .provenance sentinel and the env var is no longer needed. | Provenance-sentinel verification — prevents acceptance of an unauthenticated device.key file (e.g. a copy left on disk by a prior install or attacker). | `cli/defenseclaw/commands/cmd_setup_sandbox.py:1759` — _pre_pair_device gates the provenance fail-closed branch on this var |
| `DEFENSECLAW_REVEAL_PII` | **medium** | `unset` (PII redacted everywhere) | `1`, `true`, `unset` | Reveal PII in operator-facing logs only (CLI stdout, TUI). | — | `internal/redaction/redaction.go:90` — Reveal() reads this env var |
| `DEFENSECLAW_SANDBOX_FORCE_REGEX_CLEANUP` | **medium** | 0 (no regex sweep) | `1`, `0`, `unset` | Opt into the legacy broad regex cleanup of sandbox/openshell network namespaces when no saved namespace file exists. | Namespace cleanup scope — a broad regex sweep can delete unrelated network namespaces on a shared host. | `cli/defenseclaw/commands/cmd_setup_sandbox.py:1258` — Embedded pre-sandbox script reads it before namespace cleanup<br>`cli/defenseclaw/commands/cmd_setup_sandbox.py:1481` — Embedded cleanup-sandbox script reads it |
| `DEFENSECLAW_SCHEMA_VALIDATION` | **medium** | on | `off`, `unset` | Disable the runtime JSON-schema gate that validates event payloads before they hit sinks. | — | `internal/gateway/sidecar.go:243` — Gateway boot reads and toggles the schema gate |
| `DEFENSECLAW_STRICT_AVAILABILITY` | — | `unset` (transport failures fail-open) | `1`, `unset` | Opt-IN to fail-closed on transport errors during hook execution. | — | `internal/gateway/connector/hooks/_hardening.sh:250` — Hook hardening sourced by every *-hook.sh |
| `DEFENSECLAW_TEST` | low | `unset` | `1`, `true`, `unset` | Mark the process as running under tests. | — | `internal/redaction/credentials.go:176` — isCredentialScrubDevMode reads this var |
| `DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN` | **HIGH** | `unset` (fail-closed) | `1`, `true`, `unset` | Make the plugin-side tool-inspect hook fail-open (allow tool) when the gateway is unreachable. | — | `extensions/defenseclaw/src/index.ts:98` — OpenClaw plugin tool-inspect handler |
| `DEFENSECLAW_TRUSTED_PROXY_CIDRS` | **medium** | `unset` (X-Forwarded-For ignored) | `comma-separated CIDRs or IPs`, `unset` | Comma-separated CIDRs (or bare IPs) of reverse-proxy peers whose X-Forwarded-For header is trusted for client-IP attribution in logs. | Client-IP attribution — trusting forwarded headers from an untrusted peer lets a caller spoof the source IP recorded in auth-failure and audit logs. | `internal/gateway/requestctx.go:369` — isTrustedProxyPeer() trusts X-Forwarded-For only from these peers |
| `DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED` | **HIGH** | `unset` (fail-closed) | `1`, `unset` | Skip checksum / signature verification during 'defenseclaw upgrade' or scripts/upgrade.sh. | Upgrade-artifact integrity — prevents installing a tampered tarball/wheel pulled from a hijacked release CDN or MITM. | `cli/defenseclaw/commands/cmd_upgrade.py:318` — Python upgrade path checks this before downloading without a checksum<br>`scripts/upgrade.sh:263` — Shell upgrade path checks this before proceeding without verification |
| `DEFENSECLAW_UPGRADE_TARBALL_SHA256` | — | `unset` | `64-char hex sha256`, `unset` | Operator-provided sha256 pin for the gateway tarball downloaded by `defenseclaw upgrade`. | Operator-supplied checksum pin for upgrade artifacts — defense-in-depth alongside the sidecar .sha256 file. | `cli/defenseclaw/commands/cmd_upgrade.py:341` — Python upgrade verifier<br>`scripts/upgrade.sh:225` — Shell upgrade verifier |
| `DEFENSECLAW_UPGRADE_WHL_SHA256` | — | `unset` | `64-char hex sha256`, `unset` | Operator-provided sha256 pin for the Python CLI wheel downloaded by `defenseclaw upgrade`. | Operator-supplied checksum pin for upgrade artifacts — defense-in-depth alongside the sidecar .sha256 file. | `cli/defenseclaw/commands/cmd_upgrade.py:358` — Python upgrade verifier<br>`scripts/upgrade.sh:226` — Shell upgrade verifier |
| `DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST` | **medium** | `unset` (SSRF guard blocks private IPs) | `1`, `unset` | Relax the webhook SSRF guard to permit RFC1918 / loopback / link-local destinations. | — | `internal/gateway/webhook.go:139` — Webhook sender SSRF gate<br>`internal/gateway/webhook.go:563` — Webhook validate-on-add SSRF gate<br>`cli/defenseclaw/webhooks/writer.py:412` — Python writer validate-on-add |

## Credentials & secrets

| Env var | Impact | Default | Accepted values | Purpose | Security concern | Consumers |
| --- | --- | --- | --- | --- | --- | --- |
| `DEFENSECLAW_GATEWAY_TOKEN` | **HIGH** | `unset` | `bearer-token`, `unset` | Bearer token hooks present to the gateway API. | — | `internal/gateway/connector/hooks/inspect-tool.sh:30` — Hooks present this header<br>`internal/cli/sidecar.go:43` — Sidecar references in setup messages |
| `DEFENSECLAW_LLM_KEY` | **HIGH** | `unset` | `LLM API key string`, `unset` | Canonical env-var name for the unified LLM key. | — | `cli/defenseclaw/credentials.py` — Credentials registry default for llm.api_key_env |
| `DEFENSECLAW_LLM_KEY_ENV` | low | DEFENSECLAW_LLM_KEY | `any env-var name` | Indirection: name of the env var to read the LLM key from. | — | `cli/defenseclaw/credentials.py` — Credentials registry indirection |
| `DEFENSECLAW_LLM_MODEL` | low | (value from llm.model in config.yaml) | `provider/model-id`, `unset` | Override the configured LLM model id at runtime. | — | `cli/tests/test_config.py:667` — Tested override path |
| `DEFENSECLAW_LLM_MODEL_ENV` | low | DEFENSECLAW_LLM_MODEL | `any env-var name` | Indirection: name of the env var to read the LLM model from. | — | `cli/defenseclaw/credentials.py` — Credentials registry indirection |
| `DEFENSECLAW_LOCAL_PASSWORD` | **HIGH** | `unset` | `any-string`, `unset` | Password for the local Splunk daemon basic-auth surface. | — | `internal/cli/daemon.go:212` — Daemon reads from .env |
| `DEFENSECLAW_LOCAL_USERNAME` | **medium** | `unset` | `any-string`, `unset` | Username for the local Splunk daemon basic-auth surface. | — | `internal/cli/daemon.go:211` — Daemon reads from .env |
| `DEFENSECLAW_MASTER_KEY` | **HIGH** | (derived at boot from device.key) | `sk-dc-<hex>` | Bearer derived from device.key (PBKDF2). | — | `internal/gateway/proxy.go:3338` — deriveMasterKey |
| `DEFENSECLAW_PD_KEY` | **medium** | `unset` | `pagerduty-key`, `unset` | Alias for DEFENSECLAW_PD_ROUTING_KEY. | — | `cli/defenseclaw/commands/cmd_setup_webhook.py:166` — Alternative PD key var |
| `DEFENSECLAW_PD_ROUTING_KEY` | **medium** | `unset` | `pagerduty-routing-key`, `unset` | PagerDuty routing key default for webhook entries. | — | `cli/defenseclaw/commands/cmd_setup_webhook.py:166` — Webhook setup default |
| `DEFENSECLAW_PROXY_TOKEN` | low | `unset` | `any-string`, `unset` | Test-harness proxy bearer. | — | `scripts/test-proxy-sandbox.py:940` — Test proxy bearer |
| `DEFENSECLAW_REGISTRY_TOKEN` | **medium** | `unset` | `registry-token`, `unset` | Default registry auth env var (e.g. | — | `cli/defenseclaw/commands/cmd_registry.py:133` — Registry default auth_env |
| `DEFENSECLAW_SIEM_SECRET` | **medium** | `unset` | `any-string`, `unset` | SIEM webhook secret default. | — | `cli/defenseclaw/commands/cmd_setup_webhook.py:166` — Webhook setup default |
| `DEFENSECLAW_SKILLSSH_TOKEN` | **medium** | `unset` | `registry-token`, `unset` | Example registry-specific token env var. | — | `cli/defenseclaw/commands/cmd_registry.py:334` — Registry example token |
| `DEFENSECLAW_SKILL_SCANNER_LLM_KEY` | **HIGH** | `unset` | `LLM API key string`, `unset` | Override the LLM key used by the skill scanner only. | — | `cli/defenseclaw/credentials.py` — Credentials registry |
| `DEFENSECLAW_SPLUNK_HEC_TOKEN` | **HIGH** | `unset` | `HEC token`, `unset` | Alternative HEC token consulted by the Python sink wiring when the canonical splunk_hec.token_env points to a different var. | — | `cli/defenseclaw/commands/cmd_setup.py:4911` — Python Splunk wiring fallback |
| `DEFENSECLAW_WEBEX_TOKEN` | **medium** | `unset` | `webex-bot-token`, `unset` | Webex bot token default for webhook entries. | — | `cli/defenseclaw/commands/cmd_setup_webhook.py:166` — Webhook setup default |
| `DEFENSECLAW_WEBHOOK_SECRET` | **medium** | `unset` | `any-string`, `unset` | Generic webhook HMAC secret default. | — | `cli/defenseclaw/commands/cmd_setup_webhook.py:166` — Webhook setup default |

## Paths & runtime layout

| Env var | Impact | Default | Accepted values | Purpose | Security concern | Consumers |
| --- | --- | --- | --- | --- | --- | --- |
| `DEFENSECLAW_API_ADDR` | low | (templated value from gateway.api_port at hook install time) | `host:port`, `unset` | Sidecar API address that hooks dial. | — | `internal/gateway/connector/hooks/inspect-tool.sh:42` — Hooks dial this |
| `DEFENSECLAW_BIN` | low | (discovered via PATH lookup) | `any-absolute-path` | Override path to the defenseclaw CLI binary. | — | `internal/scanner/plugin_test.go:177` — Plugin test harness<br>`scripts/setup-llm.sh:51` — LLM setup script |
| `DEFENSECLAW_CUSTOM_PROVIDERS_PATH` | low | `unset` | `any-absolute-path`, `unset` | Path to a custom providers YAML file consulted before the embedded catalog. | — | `internal/configs/embed.go:71` — Go embedded-providers loader |
| `DEFENSECLAW_DIR` | low | (templated at install time) | `any-absolute-path` | Used in generated openshell-sandbox shell wrappers to locate the DefenseClaw install dir from inside the sandbox. | — | `cli/defenseclaw/commands/cmd_setup_sandbox.py:1202` — Sandbox shell wrappers reference this |
| `DEFENSECLAW_GATEWAY_BIN` | low | (discovered via PATH lookup) | `any-absolute-path` | Override path to the defenseclaw-gateway binary. | — | `cli/defenseclaw/gateway.py:315` — Python gateway-process spawner |
| `DEFENSECLAW_HOME` | — | ~/.defenseclaw | `any-absolute-path` | Override the canonical data dir (default ~/.defenseclaw). | — | `internal/config/defaults.go:62` — Go default-resolver<br>`cli/defenseclaw/config.py:98` — Python config loader<br>`cli/defenseclaw/connector_paths.py:1305` — Connector path resolver<br>`scripts/install.sh:50` — Installer reads this<br>`scripts/upgrade.sh:49` — Upgrader reads this<br>`internal/gateway/connector/hooks/inspect-tool.sh:9` — Hooks read this |
| `DEFENSECLAW_INSTALL_DIR` | low | $HOME/.local/bin | `any-absolute-path` | Directory where CLI symlinks are placed by install.sh / setup-llm.sh. | — | `scripts/setup-llm.sh:59` — Install location for setup-llm |
| `DEFENSECLAW_OVERLAY_ROOT` | low | `unset` | `any-absolute-path`, `unset` | Extra provider-catalog overlay dir merged on top of the built-in catalog. | — | `cli/defenseclaw/commands/cmd_setup_provider.py:115` — Provider setup overlay loader |
| `DEFENSECLAW_SIDECAR_URL` | low | http://127.0.0.1:18790 | `any-http-url` | Target URL for the bundled CodeGuard skill (skills/codeguard/main.py) to call into the sidecar. | — | `skills/codeguard/main.py:35` — Skill sidecar URL |
| `DEFENSECLAW_VENV` | — | ${DEFENSECLAW_HOME}/.venv | `any-absolute-path` | Path to the DefenseClaw uv venv. | — | `scripts/install.sh:51` — Installer venv path<br>`scripts/upgrade.sh:50` — Upgrader venv path |
| `MIGRATION_DEFENSECLAW_HOME` | — | (set by upgrade.sh) | `any-absolute-path` | Passed by scripts/upgrade.sh to the migration step. | — | `scripts/upgrade.sh:376` — Upgrade-time migration runner |

## Telemetry (OTel)

| Env var | Impact | Default | Accepted values | Purpose | Security concern | Consumers |
| --- | --- | --- | --- | --- | --- | --- |
| `DEFENSECLAW_JUDGE_PERSIST_QUEUE_SIZE` | — | `unset` (config guardrail.judge_persist_queue_depth, default 1024) | `positive integer`, `unset` | Emergency boot-time override for the async judge-persistence queue depth. | — | `internal/gateway/sidecar.go:364` — Overrides cfg.Guardrail.JudgePersistQueueDepth at sidecar boot |
| `DEFENSECLAW_OTEL_ENABLED` | — | (value from otel.enabled in config.yaml) | `true`, `false`, `1`, `0`, `unset` | Master toggle for the OTel exporter. | — | `internal/config/config.go:2297` — viper.BindEnv otel.enabled |
| `DEFENSECLAW_OTEL_ENDPOINT` | — | (value from otel.endpoint) | `any-otlp-endpoint`, `unset` | Default OTLP endpoint (host:port[/path]). | — | `internal/config/config.go:2298` — viper.BindEnv otel.endpoint |
| `DEFENSECLAW_OTEL_LOGS_ENDPOINT` | — | (value from otel.logs.endpoint) | `any-otlp-endpoint`, `unset` | Per-signal override for logs endpoint. | — | `internal/config/config.go:2307` — viper.BindEnv otel.logs.endpoint |
| `DEFENSECLAW_OTEL_LOGS_PROTOCOL` | — | (value from otel.logs.protocol) | `http/protobuf`, `grpc`, `unset` | Per-signal override for logs protocol. | — | `internal/config/config.go:2308` — viper.BindEnv otel.logs.protocol |
| `DEFENSECLAW_OTEL_LOGS_URL_PATH` | — | (value from otel.logs.url_path) | `any-url-path`, `unset` | Per-signal override for logs URL path. | — | `internal/config/config.go:2309` — viper.BindEnv otel.logs.url_path |
| `DEFENSECLAW_OTEL_METRICS_ENDPOINT` | — | (value from otel.metrics.endpoint) | `any-otlp-endpoint`, `unset` | Per-signal override for metrics endpoint. | — | `internal/config/config.go:2304` — viper.BindEnv otel.metrics.endpoint |
| `DEFENSECLAW_OTEL_METRICS_PROTOCOL` | — | (value from otel.metrics.protocol) | `http/protobuf`, `grpc`, `unset` | Per-signal override for metrics protocol. | — | `internal/config/config.go:2305` — viper.BindEnv otel.metrics.protocol |
| `DEFENSECLAW_OTEL_METRICS_URL_PATH` | — | (value from otel.metrics.url_path) | `any-url-path`, `unset` | Per-signal override for metrics URL path. | — | `internal/config/config.go:2306` — viper.BindEnv otel.metrics.url_path |
| `DEFENSECLAW_OTEL_PROTOCOL` | — | (value from otel.protocol) | `http/protobuf`, `grpc`, `unset` | Default OTLP protocol (http/protobuf or grpc). | — | `internal/config/config.go:2299` — viper.BindEnv otel.protocol |
| `DEFENSECLAW_OTEL_TRACES_ENDPOINT` | — | (value from otel.traces.endpoint) | `any-otlp-endpoint`, `unset` | Per-signal override for traces endpoint. | — | `internal/config/config.go:2301` — viper.BindEnv otel.traces.endpoint |
| `DEFENSECLAW_OTEL_TRACES_PROTOCOL` | — | (value from otel.traces.protocol) | `http/protobuf`, `grpc`, `unset` | Per-signal override for traces protocol. | — | `internal/config/config.go:2302` — viper.BindEnv otel.traces.protocol |
| `DEFENSECLAW_OTEL_TRACES_URL_PATH` | — | (value from otel.traces.url_path) | `any-url-path`, `unset` | Per-signal override for traces URL path (when using HTTP). | — | `internal/config/config.go:2303` — viper.BindEnv otel.traces.url_path |
| `DEFENSECLAW_RUN_ID` | — | auto-generated UUID at gateway boot | `any-string`, `unset` | Correlation ID stamped on every event for cross-sink joins. | — | `internal/gatewaylog/runid.go:58` — Go reader<br>`internal/audit/store.go:2390` — Audit store reader<br>`internal/gateway/sidecar.go:114` — Sidecar boot<br>`cli/defenseclaw/logger.py:172` — Python logger reader<br>`cli/defenseclaw/db.py:739` — Python DB reader<br>`scripts/test-e2e-full-stack.sh:54` — E2E test runner default |
| `DEFENSECLAW_TELEMETRY_ENABLED` | — | `unset` | `1`, `0`, `unset` | Local-observability-stack-only toggle. | — | `bundles/local_observability_stack/docker-compose.yml:17` — Compose-file env reference |
| `DEFENSECLAW_TRACEPARENT` | — | `unset` (no traceparent forwarded) | `W3C traceparent string`, `unset` | W3C traceparent header value propagated from the agent/hook environment into outbound hook HTTP requests and the Codex telemetry bridge, enabling distributed-trace correlation. | — | `internal/cli/hook.go:137` — Native hook reads it (precedence over TRACEPARENT / OTEL_TRACEPARENT)<br>`internal/gateway/connector/hooks/_hardening.sh:661` — Bash hook trace-context extraction<br>`internal/gateway/connector/codex.go:975` — Codex telemetry bridge forwards it on outbound curls |
| `DEFENSECLAW_TRACESTATE` | — | `unset` (no tracestate forwarded) | `W3C tracestate string`, `unset` | W3C tracestate header value propagated alongside traceparent for vendor-specific trace baggage on hook and Codex telemetry outbound requests. | — | `internal/cli/hook.go:142` — Native hook reads it alongside traceparent<br>`internal/gateway/connector/hooks/_hardening.sh:674` — Bash hook trace-context extraction<br>`internal/gateway/connector/codex.go:976` — Codex telemetry bridge forwards it on outbound curls |

## Debug / verbose logging

| Env var | Impact | Default | Accepted values | Purpose | Security concern | Consumers |
| --- | --- | --- | --- | --- | --- | --- |
| `DEFENSECLAW_DEBUG` | low | `unset` | `1`, `unset` | Gateway client logs every request/response frame to stderr. | — | `internal/gateway/client.go:80` — Client struct gates verbose logging on this var |
| `DEFENSECLAW_JUDGE_TRACE` | **medium** | `unset` | `1`, `true`, `unset` | LLM judge logs every prompt + response. | — | `internal/gateway/llm_judge.go:62` — Judge debug toggle |
| `DEFENSECLAW_LLM_DEBUG` | **medium** | `unset` | `1`, `true`, `unset` | Python LLM bridge logs per-request prompt + response bodies. | — | `cli/defenseclaw/llm.py:110` — LLM bridge _DEBUG flag |
| `DEFENSECLAW_PERSIST_JUDGE` | **medium** | `unset` | `1`, `true`, `unset` | Persist every judge prompt + response to disk under data_dir. | — | `internal/gateway/sidecar.go:134` — Gateway boot enables judge persistence |
| `DEFENSECLAW_SIDECAR_DIAG` | low | `unset` | `1`, `true`, `unset` | Extra sidecar boot-time diagnostics (config dump, env presence). | — | `internal/cli/sidecar.go:212` — sidecarDiagEnabled helper |
| `DEFENSECLAW_TUI_SKIP_FIRST_RUN_PROMPT` | — | `unset` (prompt shown on a TTY) | `1`, `true`, `yes`, `unset` | Skip the interactive first-run setup wizard prompt when launching the TUI, proceeding directly without asking whether to run setup. | — | `cli/defenseclaw/tui/__init__.py:53` — Gates the interactive first-run setup prompt |
| `DEFENSECLAW_WEBHOOK_DEBUG` | **medium** | `unset` | `1`, `unset` | Webhook dispatcher dumps full request bodies (including secrets) to stderr. | — | `internal/gateway/webhook.go:146` — Webhook sender debug field |

## Discovery & probes

| Env var | Impact | Default | Accepted values | Purpose | Security concern | Consumers |
| --- | --- | --- | --- | --- | --- | --- |
| `DEFENSECLAW_ANTHROPIC_PROBE_MODEL` | — | claude-3-5-haiku-latest | `any-anthropic-model-id` | Override the model used by 'defenseclaw doctor' to probe Anthropic API key validity. | — | `cli/defenseclaw/commands/cmd_doctor.py:659` — Doctor's Anthropic probe |
| `DEFENSECLAW_TRUSTED_BIN_PREFIXES` | **medium** | `unset` (built-in defaults only) | `os.pathsep-separated absolute paths (':' POSIX, ';' Windows)`, `unset` | Extra trusted binary prefixes for AI Discovery's binary probing, separated by os.pathsep (':' on POSIX, ';' on Windows). | Tight binary-discovery trust list — prevents PATH-shadow elevation where a malicious binary in a user-writable dir gets probed and treated as a real agent runtime. 'trusted-paths add' refuses world-writable and non-absolute directories unless --force. | `cli/defenseclaw/inventory/agent_discovery.py:289` — Agent discovery binary probe<br>`cli/defenseclaw/commands/cmd_setup.py:1587` — setup trusted-paths CLI and inline trust prompt persistence |

## Hook-internal (do not override)

| Env var | Impact | Default | Accepted values | Purpose | Security concern | Consumers |
| --- | --- | --- | --- | --- | --- | --- |
| `DEFENSECLAW_AGENT_ID` | — | (set by plugin / hooks) | `any-string` | Agent identity propagated through correlation headers and OTel attributes. | — | `internal/cli/scan_v7.go:69` — Go reader<br>`extensions/defenseclaw/src/__tests__/agent_identity.test.ts:61` — JS plugin reader (tested) |
| `DEFENSECLAW_AGENT_INSTANCE_ID` | — | (set by plugin / hooks) | `any-string` | Per-instance agent identifier; used to disambiguate concurrent runs of the same agent. | — | `internal/cli/scan_v7.go:70` — Go reader |
| `DEFENSECLAW_AGENT_NAME` | — | (set by plugin / hooks) | `any-string` | Human-readable agent name propagated via correlation headers. | — | `extensions/defenseclaw/src/index.ts:315` — JS plugin header emit |
| `DEFENSECLAW_BAKED_HOOK_PATH` | **medium** | empty (default PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin) | `colon-separated absolute paths`, `unset` | Baked into the installed _hardening.sh helper at hook-generation time. | Hook PATH lockdown — a mis-baked value that widens PATH could re-admit attacker-writable directories to hook execution. | `internal/gateway/connector/hooks/_hardening.sh:149` — defenseclaw_harden_env() uses it to set the locked-down hook PATH |
| `DEFENSECLAW_CLIENT` | — | (set by plugin) | `any-string` | Client name (e.g. openclaw-plugin) stamped on the X-DefenseClaw-Client correlation header. | — | `extensions/defenseclaw/src/policy/enforcer.ts:156` — Enforcer header |
| `DEFENSECLAW_DAEMON` | — | (set by daemon launcher; child only) | `1` | Sentinel set by the daemon launcher in the child process so it knows it's the daemon. | — | `internal/daemon/daemon.go:35` — EnvDaemon constant |
| `DEFENSECLAW_DATA_DIR` | — | `unset` (set by the daemon on child processes) | `absolute data-directory path` | Marker injected by the daemon launcher into the spawned gateway child process environment, recording which data directory that child belongs to. | — | `internal/daemon/daemon.go:307` — Written into the gateway child env to tag the owning data directory |
| `DEFENSECLAW_GATEWAY_ADDR` | — | 127.0.0.1:<api_port> | `loopback host:port`, `unset` | Gateway API address for the Windows native Go hook entrypoint. | Loopback-only enforcement — a non-loopback gateway address is rejected so a hook cannot be redirected to an off-box collector. | `internal/cli/hook.go:94` — Primary env resolution of the hook's gateway API address<br>`internal/cli/hook.go:97` — Sidecar .hookcfg fallback for the same key |
| `DEFENSECLAW_HOOK_CONNECTOR` | — | (set by hooks) | `claudecode`, `codex`, `openclaw`, `zeptoclaw`, `inspect`, `...` | Internal label identifying which connector's hook is executing. | — | `internal/gateway/connector/hooks/inspect-tool.sh:22` — Each hook exports this |
| `DEFENSECLAW_HOOK_CWD` | — | (set by hooks) | `absolute-path` | Resolved CWD exported by hooks; used by sanitizeHookCWD to bound git operations. | — | `internal/gateway/connector/hooks/_hardening.sh:99` — Hook hardening |
| `DEFENSECLAW_HOOK_HOME` | — | (set by hooks) | `absolute-path` | Hardened HOME exported by hooks to insulate them from operator HOME. | — | `internal/gateway/connector/hooks/_hardening.sh:76` — Hook hardening |
| `DEFENSECLAW_HOOK_MAX_BODY` | low | 1048576 | `positive integer` | Request-body cap (in bytes) for hooks. | — | `internal/gateway/connector/hooks/_hardening.sh:346` — Body-cap enforcement |
| `DEFENSECLAW_HOOK_NAME` | — | (set by hooks) | `inspect-tool`, `inspect-request`, `...` | Internal label identifying which hook is executing. | — | `internal/gateway/connector/hooks/inspect-tool.sh:23` — Each hook exports this |
| `DEFENSECLAW_HOOK_PATH` | — | (set by hooks) | `colon-separated paths` | Hardened PATH exported by hooks (system-only) so a hostile workspace can't shadow git/curl/etc. | — | `internal/gateway/connector/hooks/_hardening.sh:88` — Hook hardening |
| `DEFENSECLAW_HOOK_PATH_TRUSTED` | — | `unset` (always stripped before PATH lockdown) | `unset` | Companion name to DEFENSECLAW_HOOK_PATH that an agent process might set. | Hook PATH lockdown — stripped so an agent-supplied 'trusted' flag cannot re-enable an attacker-controlled PATH. | `internal/gateway/connector/hooks/_hardening.sh:148` — unset DEFENSECLAW_HOOK_PATH_TRUSTED during env hardening (anti-consumed) |
| `DEFENSECLAW_OPENCLAW_MAIN` | low | (set by plugin bootstrap) | `absolute-path` | Sentinel read by the OpenClaw plugin bootstrapper to locate its main module. | — | `extensions/defenseclaw/src/aws-sdk-http1-for-guardrail.ts:163` — Plugin bootstrap sentinel |
| `DEFENSECLAW_PLUGIN_AGENT_ID` | — | (set by plugin) | `any-string` | Plugin-side agent ID. | — | `extensions/defenseclaw/src/__tests__/agent_identity.test.ts:71` — JS plugin reader (tested) |
| `DEFENSECLAW_SIDECAR_INSTANCE_ID` | — | (auto-generated by gateway) | `uuid-or-similar` | Sidecar instance ID; auto-generated by the gateway at boot, propagated via headers. | — | `internal/cli/scan_v7.go:71` — Go reader |

## Splunk-bridge bundle

| Env var | Impact | Default | Accepted values | Purpose | Security concern | Consumers |
| --- | --- | --- | --- | --- | --- | --- |
| `DEFENSECLAW_HEC_TOKEN` | **HIGH** | (set in .env.example) | `hec-token` | Splunk-bridge HEC token. | — | `bundles/splunk_local_bridge/env/.env.example:12` — Bridge .env |
| `DEFENSECLAW_HEC_URL` | — | (set in .env.example) | `any-hec-url` | Splunk-bridge bundle: HEC endpoint URL. | — | `bundles/splunk_local_bridge/env/.env.example:11` — Bridge .env |
| `DEFENSECLAW_INDEX` | — | defenseclaw_local | `splunk-index-name` | Splunk-bridge target index. | — | `bundles/splunk_local_bridge/env/.env.example:13` — Bridge .env |
| `DEFENSECLAW_INTEGRATION_ENABLED` | — | false | `true`, `false` | Splunk-bridge integration toggle. | — | `bundles/splunk_local_bridge/env/.env.example:16` — Bridge .env |
| `DEFENSECLAW_O11Y_DASHBOARD_NAME_PREFIX` | — | empty (no prefix) | `string`, `unset` | Prefix label applied to the Splunk Observability dashboard groups, dashboards, and detectors created by the Terraform setup command. | — | `cli/defenseclaw/commands/cmd_setup_splunk_o11y_dashboards.py:137` — --name-prefix Click option bound to this env var |
| `DEFENSECLAW_REF` | — | unknown | `any-string` | Splunk-bridge bundle git ref label. | — | `bundles/splunk_local_bridge/env/.env.example:17` — Bridge .env |
| `DEFENSECLAW_SOURCE` | — | defenseclaw | `any-source-string` | Splunk-bridge source label. | — | `bundles/splunk_local_bridge/env/.env.example:15` — Bridge .env |
| `DEFENSECLAW_SOURCETYPE` | — | defenseclaw:json | `splunk-sourcetype` | Splunk-bridge sourcetype. | — | `bundles/splunk_local_bridge/env/.env.example:14` — Bridge .env |
| `DEFENSECLAW_SPLUNK_O11Y_DASHBOARDS_WORK_DIR` | — | <data_dir>/splunk_o11y_dashboards/terraform | `absolute directory path`, `unset` | Terraform working directory for Splunk Observability dashboard provisioning. | — | `cli/defenseclaw/commands/cmd_setup_splunk_o11y_dashboards.py:113` — --work-dir Click option bound to this env var |
| `DEFENSECLAW_TERRAFORM_PLUGIN_DIR` | — | `unset` (no -plugin-dir passed to terraform init) | `absolute directory path`, `unset` | Optional Terraform provider plugin directory for offline / cached provider installs when running 'defenseclaw setup splunk-o11y-dashboards'. | — | `cli/defenseclaw/commands/cmd_setup_splunk_o11y_dashboards.py:92` — --plugin-dir Click option bound to this env var |

## Test fixtures (test-only)

| Env var | Impact | Default | Accepted values | Purpose | Security concern | Consumers |
| --- | --- | --- | --- | --- | --- | --- |
| `DEFENSECLAW_FAKE_CLAUDE_LIST` | — | `unset` | `comma-separated mock responses`, `unset` | Test-only stub: comma-separated list of responses the fake claude CLI returns. | — | `internal/gateway/connector/codeguard_native_test.go:90` — Test stub |
| `DEFENSECLAW_FAKE_CLAUDE_LOG` | — | `unset` | `absolute-path`, `unset` | Test-only stub: path the fake claude CLI logs invocations to. | — | `internal/gateway/connector/codeguard_native_test.go:116` — Test stub |
| `DEFENSECLAW_TEST_KEY` | — | `unset` | `any-string`, `unset` | Placeholder LLM key used in test fixtures only. | — | `cli/tests/test_llm_env.py` — Test fixture |
| `DEFENSECLAW_TEST_KEY_NOTSET_12345` | — | `unset` | `unset` | Placeholder env var name used to assert 'unset' behavior in tests. | — | `cli/tests/test_llm_env.py` — Test fixture for unset assertions |
| `DEFENSECLAW_TEST_LLM_KEY` | — | `unset` | `any-string`, `unset` | Placeholder LLM key used in some test setups when DEFENSECLAW_LLM_KEY needs an alternate target. | — | `cli/tests/test_llm_env.py` — Test fixture |

<!-- AUTOGEN-END: env-vars -->

## When in doubt

Run `defenseclaw doctor`. It walks the same env-var resolution
code paths as the running gateway and surfaces effective values
plus any active opt-outs.
