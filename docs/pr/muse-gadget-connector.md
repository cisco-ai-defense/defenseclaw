<!--
Every future action item must have a GitHub issue before it appears in this PR
body. List linked issues under "Open Issues / Follow-ups". If there are no
follow-ups, write "None".
-->

## Problem

Meta's Muse Gadget SDK lets an AI assistant (Muse) remotely execute shell commands (`system.run`), read/write files (`file.read`, `file.write`), and tunnel IP traffic (`/link-tunnel`) on ESP32 microcontrollers and Linux single-board computers. These gadgets have no pre-execution governance layer: every `link.invoke` from the Muse cloud runs unconditionally on the device. A compromised or prompt-injected Muse session can exfiltrate credentials, install persistence, pivot through the local network, or brick the device — with no audit trail.

## Current Situation

DefenseClaw's edge-connector already runs an 8-stage evaluation pipeline on IoT devices and communicates with the cloud gateway over MQTT. However, it has no awareness of the Muse Gadget SDK protocol: it cannot map Muse's `link.invoke` commands to capability flags, decode the Muse wire format, or apply Muse-specific policy (command rate limits, protected paths, capability-sequence correlation). The gateway connector registry ships 14 built-in connectors — none for Muse.

The `feature/defenseclaw-lite-phase1` base branch provides the edge-connector C library, IPC socket server, MQTT bridge, and fleet manager that this PR builds on.

## Solution

Add a full-stack Muse Gadget SDK connector spanning three layers:

### Gateway Connector (Go)

A `hookOnlyConnector` registered as the 15th built-in connector (`"muse"`). The hook profile wires a Muse-specific `Decode` callback that extracts `tool_name`, `tool_args`, `device_id`, `session_id`, `direction`, and `content` from the Muse hook payload vocabulary, and a `Respond` callback that renders the `{"decision": "block"|"allow", "reason": "..."}` envelope the gadget-side hook bridge expects. Both callbacks are wired into `hookOnlyConnector.HookProfile()` via the standard `if c.name == "muse"` dispatch.

The hook shell script is a full Go template with `{{.Managed}}`, `{{.Sandbox}}`, and per-user branches matching the production patterns of existing connectors (devin, copilot, cursor). Default fail mode is closed — appropriate for IoT devices where fail-open means unguarded shell execution.

Config root is `~/.config/musegadget/` (per-user, no root required). Windows is declared unsupported since Muse targets Linux and ESP32.

### Edge-Connector Bridge (C + Python)

`muse_bridge.h` is a header-only C bridge that maps the four Muse commands to DefenseClaw capability flags (`system.run` → `DCLAW_CAP_EXEC_SHELL`, `file.read` → `DCLAW_CAP_READ_FS`, `file.write` → `DCLAW_CAP_WRITE_FS`, `device.health` → `DCLAW_CAP_SENSOR_READ`) and populates a `dclaw_tool_request_t` for the evaluation pipeline. Both public functions (`muse_command_to_caps`, `muse_build_request`) are NULL-safe and bounds-checked.

`muse_executor_hook.py` is the Linux-side Python hook that Muse gadget operators import into their Executor. It communicates with the edge-connector process exclusively via JSON-RPC over a Unix socket (`/tmp/defenseclaw.sock`) — no ctypes FFI, avoiding all ABI-coupling risks. Unrecognized commands are blocked (fail-closed). The socket is closed in a `finally` block, responses are capped at 64 KB, and content is truncated with UTF-8 safety.

### Policy

`muse-gadget.yaml` is a dedicated IoT policy with:
- Capability-sequence correlation rules (e.g. `net_fetch` → `exec_shell` blocks lateral movement, `read_fs` → `net_fetch` blocks exfiltration, `exec_shell` → `write_fs` → `exec_shell` blocks staged payloads)
- Per-command rate limits (system.run: 30/min, file.write: 20/min)
- Protected paths (`/etc/shadow`, `/var/lib/musegadget/sdk_token`, `/boot/`, `/sys/`, `/proc/`)
- Muse-specific secret patterns (`mgst_` tokens, `sdk_token`, `device_token`)
- Plain substring `blocked_patterns` for destructive commands (`rm -rf /`, `dd if=/dev`, `mkfs`, `wget`, `curl`, `nc -l`, `ncat`, `socat`)

`strict.yaml` gains an `iot_extensions.muse_gadget` block with the same sequence correlation rules and `hatch.metaaivm.com` in the firewall allowlist.

## Architecture Diagram

```
Meta Muse Cloud ──Noise XX WebSocket──→ Linux Gadget / ESP32
                                            │
                                ┌───────────┴───────────┐
                                │  Muse Executor         │
                                │  receives link.invoke: │
                                │  system.run, file.read │
                                │  file.write, health    │
                                └───────────┬───────────┘
                                            │
                              ┌─────────────┴─────────────┐
                   Linux path │                           │ ESP32 path
                              ▼                           ▼
                ┌──────────────────────┐   ┌──────────────────────┐
                │ muse_executor_hook.py│   │  muse_bridge.h       │
                │ JSON-RPC over Unix   │   │  direct C call to    │
                │ socket IPC           │   │  dclaw_evaluate()    │
                └──────────┬───────────┘   └──────────┬───────────┘
                           │                          │
                           ▼                          ▼
                ┌────────────────────────────────────────────────┐
                │         DefenseClaw Edge Connector              │
                │  8-stage pipeline: validate → rate-limit →      │
                │  content-scan → deny-list → destination-check → │
                │  sequence-correlate → cache → cloud-escalate    │
                │  Local verdict: <5μs                            │
                └───────────────────┬────────────────────────────┘
                                    │ MQTT (optional cloud escalation)
                                    ▼
                ┌────────────────────────────────────────────────┐
                │         DefenseClaw Gateway                     │
                │  /api/v1/muse/hook endpoint                     │
                │  museProfileDecode → policy eval →              │
                │  museProfileRespond                             │
                └────────────────────────────────────────────────┘
```

## What Changed (Where & How)

| File | Summary |
| --- | --- |
| `internal/gateway/connector/muse.go` | New `hookOnlyConnector` constructor, per-user config root at `~/.config/musegadget/`, path override test seam |
| `internal/gateway/connector/muse_hook_profile.go` | `museProfileDecode` extracts Muse-specific fields from hook payload; `museProfileRespond` renders decision envelope |
| `internal/gateway/connector/hook_only.go` | +4 lines: wire `Decode` and `Respond` callbacks for `c.name == "muse"` |
| `internal/gateway/connector/registry.go` | +1 line: `NewMuseConnector()` in `newBuiltinConnectors()` |
| `internal/gateway/connector/platform_support.go` | +4 lines: `"muse"` → `PlatformUnsupported` on Windows |
| `internal/gateway/connector/hooks/muse-hook.sh` | Full Go template with `{{.Managed}}`, `{{.Sandbox}}`, and per-user branches; fail-closed default |
| `internal/gateway/connector/muse_test.go` | 17 tests: metadata, capabilities, config paths, decode, respond, registry, platform support, VerifyClean, HookProfile wiring |
| `edge-connector/src/muse/muse_bridge.h` | Header-only C bridge: `muse_command_to_caps()` and `muse_build_request()` with NULL guards |
| `edge-connector/src/muse/muse_executor_hook.py` | Python IPC-only hook: fail-closed for unknown commands, 64KB response cap, UTF-8-safe truncation, socket in `try/finally` |
| `edge-connector/src/muse/__init__.py` | Package marker |
| `edge-connector/tests/test_muse_bridge.c` | 15 C tests: command mapping, request building, content truncation, NULL safety |
| `policies/muse-gadget.yaml` | Dedicated IoT policy: sequence correlation, rate limits, protected paths, blocked patterns |
| `policies/strict.yaml` | +44 lines: `iot_extensions.muse_gadget` block and `hatch.metaaivm.com` in firewall allowlist |

## Breaking Changes

None. Additive only — new connector, new policy file, new edge-connector module. No existing connector behavior, API, or config format is modified.

## Open Issues / Follow-ups

None.

## Test Plan

**Go unit tests (17/17 pass):**

```
$ go test ./internal/gateway/connector/ -run "TestMuse" -v -count=1

=== RUN   TestMuseConnectorMetadata             --- PASS
=== RUN   TestMuseConnectorHookCapabilities     --- PASS
=== RUN   TestMuseConnectorSetCredentials       --- PASS
=== RUN   TestMuseConfigRootLinux               --- PASS
=== RUN   TestMuseConfigRootDarwin              --- PASS
=== RUN   TestMuseConfigRootOverride            --- PASS
=== RUN   TestMuseConfigPathOverride            --- PASS
=== RUN   TestMuseProfileDecode                 --- PASS
=== RUN   TestMuseProfileDecodeMinimal          --- PASS
=== RUN   TestMuseProfileRespondBlock           --- PASS
=== RUN   TestMuseProfileRespondAllow           --- PASS
=== RUN   TestMuseRegisteredInDefaultRegistry   --- PASS
=== RUN   TestMusePlatformSupportWindows        --- PASS
=== RUN   TestMusePlatformSupportLinux          --- PASS
=== RUN   TestMusePlatformSupportDarwin         --- PASS
=== RUN   TestMuseVerifyCleanOnFreshDataDir     --- PASS
=== RUN   TestMuseHookProfileDecodeWired        --- PASS
PASS
ok      github.com/defenseclaw/defenseclaw/internal/gateway/connector   0.291s
```

**E2E connector tests (all pass, including Muse in SetCredentials matrix):**

```
$ go test ./test/e2e/ -run "TestConnector|TestRegistry" -v -count=1

--- PASS: TestConnectorLifecycle_Matrix (2.11s)
--- PASS: TestRegistryBuiltinConnectors (0.00s)
--- PASS: TestRegistryAvailableMetadata (0.00s)
--- PASS: TestRegistryGetUnknown (0.00s)
--- PASS: TestConnectorVerifyCleanOnFreshDataDir (0.00s)
--- PASS: TestConnectorToolInspectionModes (0.00s)
--- PASS: TestConnectorSubprocessPolicies (0.00s)
--- PASS: TestConnectorSetCredentials (0.00s)
    --- PASS: TestConnectorSetCredentials/muse (0.00s)
PASS
ok      github.com/defenseclaw/defenseclaw/test/e2e     2.907s
```

**Go vet:**

```
$ go vet ./internal/gateway/connector/
(clean — no output)
```

**C bridge tests (15/15 pass):**

```
$ cc -I./include -I./build/include -o /tmp/test_muse_bridge tests/test_muse_bridge.c && /tmp/test_muse_bridge

Muse bridge tests:
  test_command_to_caps_system_run                   PASS
  test_command_to_caps_file_read                    PASS
  test_command_to_caps_file_write                   PASS
  test_command_to_caps_device_health                PASS
  test_command_to_caps_unknown                      PASS
  test_command_to_caps_empty                        PASS
  test_command_to_caps_null                         PASS
  test_build_request_system_run                     PASS
  test_build_request_file_read                      PASS
  test_build_request_file_write                     PASS
  test_build_request_unknown_command                PASS
  test_build_request_device_health                  PASS
  test_build_request_content_truncation             PASS
  test_build_request_null_req                       PASS
  test_build_request_null_command                   PASS

15 passed, 0 failed
```

**Python syntax:**

```
$ python3 -c "import ast; ast.parse(open('edge-connector/src/muse/muse_executor_hook.py').read()); print('OK')"
OK
```

**Manual testing (not yet executed):**

- Deploy edge-connector on Raspberry Pi alongside Muse Gadget SDK
- Verify `system.run` commands are intercepted and blocked per muse-gadget.yaml policy
- Verify `file.read` of `/etc/shadow` is blocked by protected_paths
- Verify capability sequence `read_fs` → `net_fetch` triggers block
