# DefenseClaw — Hook Connector Contract

This document is the public, version-controlled contract for integrating any
hook-capable agent harness with DefenseClaw **without writing a native (Go)
connector**. It defines two layers that build on each other:

- **Tier 1 — the hook wire contract.** A stable HTTP request/response and
  exit-code contract. Any harness that can run a script (or an HTTP call) on a
  lifecycle event can self-integrate against this contract with no DefenseClaw
  code at all. This tier is *spec only*: you implement the small client side.
- **Tier 2 — the declarative connector manifest.** A single data file
  (`hook-connector-manifest.json`, validated by
  [`schemas/hook-connector-manifest.json`](../schemas/hook-connector-manifest.json))
  that teaches DefenseClaw how to discover, install, decode, evaluate, and
  respond for a harness. Dropping a manifest auto-registers a full connector —
  discovery, config patching, the `/api/v1/<name>/hook` route, verdict
  rendering, and teardown — with **no new Go code per harness**.

Both tiers describe the *same* runtime pipeline. Tier 1 is what the harness
sends and receives on the wire; Tier 2 is how DefenseClaw is configured to
produce and interpret that wire traffic on behalf of a harness that cannot
hand-roll it.

> Status: design contract. This file and the JSON Schema define the target
> behavior; the engine that consumes manifests is implemented separately.

---

## 1. Which tier do I want?

| You are… | Use | Why |
| --- | --- | --- |
| A harness author who can ship a hook/script that calls an HTTP endpoint | Tier 1 | Self-contained; you own the client; DefenseClaw needs nothing. |
| An operator who wants DefenseClaw to *manage* (install, verify, remove, decode, render) a harness's hooks for you | Tier 2 | DefenseClaw does the wiring; you ship a manifest, not code. |
| DefenseClaw maintainers adding a first-party harness with no special behavior | Tier 2 (embedded) | New harness ships as embedded data, not a new connector package. |

Tier 2 is strictly more capable and is what powers managed connectors. Tier 1
exists so a harness can integrate even when nobody has written a manifest for
it yet.

---

## 2. Tier 1 — the hook wire contract

### 2.1 Endpoint

```
POST http://127.0.0.1:18970/api/v1/<connector>/hook
```

- `<connector>` is the connector name (built-in name, or a manifest `name`).
- The gateway binds to loopback by default. The address is discoverable from
  the gateway-written hook environment / token files; do not hardcode a remote
  host.
- A generic, connector-agnostic alias is also defined for harnesses that
  self-wire without a manifest:

```
POST http://127.0.0.1:18970/api/v1/hook        (connector via ?connector=<name> or X-DefenseClaw-Connector header)
```

When the connector cannot be resolved, the gateway falls back to a generic
profile (flat decode, generic render) so the call still produces a valid
verdict.

### 2.2 Request headers

| Header | Required | Purpose |
| --- | --- | --- |
| `Content-Type: application/json` | yes | Body is a single JSON object. |
| `Authorization: Bearer <token>` | yes when a token exists | Gateway hook token. Read from the gateway-provisioned hook token file / env. Loopback calls without a token are accepted with a logged warning to keep first-run UX working, but a token is the supported posture. |
| `X-DefenseClaw-Client: <name>-hook/<v>` | yes | CSRF / origin marker. Mutating hook calls require a recognized client marker. |
| `traceparent` / `tracestate` | optional | W3C trace context. When present and the contract advertises `supports_traceparent`, the gateway continues the remote trace instead of minting a new root span. |
| `X-DefenseClaw-Session-Id` | optional | Stable session correlation when the payload has no session id. |
| `X-DefenseClaw-Run-Id`, `X-DefenseClaw-Agent-Id` | optional | Additional correlation dimensions surfaced on telemetry. |

### 2.3 Request body — canonical fields

The body is the harness's own event JSON. DefenseClaw normalizes it into a
canonical request. For a **flat** payload, populate any of the accepted keys
below (first non-empty wins); for a non-flat payload, a Tier-2 `decode.field_map`
maps your shape onto these canonical fields.

| Canonical field | Accepted source keys (flat payload) | Meaning |
| --- | --- | --- |
| event | `hook_event_name`, `hookEventName`, `event_type`, `event`, `type` | Lifecycle event name. |
| session_id | `session_id`, `sessionId`, `conversation_id`, `task_id`, `thread_id` | Session/conversation correlation. |
| turn_id | `turn_id`, `turnId`, `step_id` | Per-turn correlation. |
| tool_name | `tool_name`, `toolName`, `command_name`, `name` | Tool/command about to run or just ran. |
| tool_input | `tool_input`, `tool_args`, `arguments`, `args`, `input` | Tool arguments / command body. |
| content | `prompt`, `user_prompt`, `message`, `text`, `content` | Prompt or message text for prompt-class events. |
| cwd | `cwd`, `working_directory` | Working directory, if provided. |
| model | `model`, `model_id` | Model identifier, if provided. |

Events are classified into surfaces — **prompt** (user prompt submitted),
**tool_call** (a tool/command is about to run), **tool_result** (a tool/command
just completed), and **event_content** (generic) — which selects what the
gateway inspects.

### 2.4 Response body — canonical verdict

`200 OK` with a JSON object:

```jsonc
{
  "action": "allow",            // allow | block | alert | confirm (post-capability-gating)
  "raw_action": "block",        // pre-downgrade action (e.g. before observe-mode allow)
  "would_block": true,          // true when the verdict represents a block posture
  "severity": "HIGH",           // CRITICAL|HIGH|MEDIUM|LOW|INFO|WARN|ERROR|NONE
  "mode": "action",             // action | observe
  "reason": "…redacted human-readable reason…",
  "additional_context": "…optional extra context to surface to the agent…",
  "evaluation_id": "…",         // correlation id for the decision
  "<response_field>": { … }     // harness-native output map (see 2.6); key name is per-connector
}
```

`<response_field>` (e.g. `hook_output`, `codex_output`) carries the object the
harness actually understands. A Tier-1 self-integrator can ignore the canonical
fields and read only `<response_field>`, or vice versa.

### 2.5 Action semantics and capability gating

| action | Meaning | Gating |
| --- | --- | --- |
| `allow` | Proceed. | Always permitted. |
| `block` | Stop the pending action. | Only enforced on events the connector declares blockable; otherwise downgraded to `allow` with `would_block=true`. |
| `confirm` | Ask a human to approve. | Only when the connector advertises native ask **and** the event is ask-capable; otherwise downgraded to `alert`. |
| `alert` | Surface a warning, proceed. | Always permitted. |

The gateway never asks a harness to do something it cannot do: a manifest's
`capabilities` (`can_block`, `can_ask_native`, `ask_events`, `block_events`)
are the ceiling. `raw_action` preserves the pre-gating intent for audit.

### 2.6 Exit-code styles

Hook scripts translate a `200 OK` into stdout + a process exit code that the
harness understands. Five styles cover the known harness families:

| Style | stdout | Exit code | Used when |
| --- | --- | --- | --- |
| `hook_echo` | echo `<response_field>` JSON verbatim | `0` | The decision is fully encoded inside the JSON (harness reads JSON, not exit code). |
| `hook_echo_decision` | echo `<response_field>` JSON | `2` if its decision is deny/block, else `0` | Harness reads JSON *and* exit code. |
| `action_stderr` | none | `2` on block (reason to stderr), else `0` | Harness keys purely off exit code + stderr. |
| `claude_code` | vendor JSON | vendor codes | Claude Code's documented hook protocol. |
| `codex` | vendor JSON | vendor codes | Codex's documented hook protocol. |

On non-2xx or transport failure, the hook applies its **fail mode**:

- Fail-open (default): exit `0` (allow) so a gateway outage never bricks the
  agent.
- Fail-closed: exit non-zero (deny) — only when the connector
  `supports_fail_closed` and the operator opted in
  (`DEFENSECLAW_FAIL_MODE=closed`).
- Strict availability (`DEFENSECLAW_STRICT_AVAILABILITY=1`): treat an
  unreachable gateway as fail-closed regardless of the per-event fail mode.

### 2.7 Minimal Tier-1 flow

```
 harness            hook client                gateway
   │ lifecycle event   │                          │
   │──────────────────▶│ read event JSON (stdin)  │
   │                   │ POST /api/v1/<name>/hook  │
   │                   │  Authorization: Bearer …  │
   │                   │  X-DefenseClaw-Client: …  │
   │                   │──────────────────────────▶│ normalize → classify
   │                   │                           │ evaluate policy/guardrail
   │                   │                           │ gate by capabilities
   │                   │◀──────────────────────────│ 200 {action, <response_field>}
   │                   │ render per exit_style      │
   │◀──────────────────│ stdout + exit code         │
   │ enforce/proceed   │                            │
```

---

## 3. Tier 2 — the declarative connector manifest

A manifest is pure data; DefenseClaw interprets it with a constrained engine.
There is **no executable code** in a manifest and no plugin `.so` to load — the
engine only ever does data-shaped operations (read/patch known config files,
map fields by dotted path, fill output templates). This is the key safety
difference from native Go plugins.

### 3.1 What a manifest replaces

Adding a harness today touches many code sites. A manifest folds all of them
into one file:

| Native connector site | Manifest section |
| --- | --- |
| `NewXConnector()` + `registry.RegisterBuiltin` | `name`, `kind` (auto-registered) |
| Agent discovery / version probe | `discovery` |
| `HookContract` row in `hook_contracts.json` | `contract` |
| `HookCapability` (block/ask events, scope) | `capabilities` |
| `patchXHooks()` config writer | `wiring` |
| `HookProfile.Decode` | `decode` |
| `HookProfile.Respond` + `hookexec` style + `response_field` | `response` |
| Per-connector `X-hook.sh` | `wiring.entry_template` + generic hook template |

### 3.2 Loading model

Two sources, one engine:

```
 ┌─────────────────────────────┐        ┌─────────────────────────────────┐
 │ Embedded (first-party)      │        │ Drop-in (third-party / operator) │
 │ shipped with the gateway    │        │ ~/.defenseclaw/connectors/*.json │
 │ implicitly trusted          │        │ trust depends on provenance      │
 └──────────────┬──────────────┘        └────────────────┬─────────────────┘
                │           manifest loader (validate, gate, register)        │
                └───────────────────────────┬────────────────────────────────┘
                                             ▼
                              one manifest connector per file
                       (Connector + HookEndpoint + capability + paths)
                                             ▼
                          identical runtime path as native connectors
                         (discovery → setup → /hook → verdict → teardown)
```

- **Embedded** manifests are baked into the gateway binary and are trusted the
  same way built-in connectors are.
- **Drop-in** manifests load from an operator-controlled directory (default
  `~/.defenseclaw/connectors/`). They are subject to the full security gate in
  §4 and default to observe mode unless verified.

### 3.3 Manifest sections

See [`schemas/hook-connector-manifest.json`](../schemas/hook-connector-manifest.json)
for the authoritative field list. Summary:

- `name`, `display_name`, `description`, `kind: "hook"` — identity. `name` is
  the `/api/v1/<name>/hook` route and must not collide with a built-in.
- `discovery` — `version_probe`, `binary_names`, `config_globs`,
  `trusted_bin_prefixes`: how to detect the harness on a host.
- `contract` — `contract_id`, `agent_version` bounds, `hook_script_version`,
  `supports_traceparent`, `events`, `aid_surfaces`: the versioned compatibility
  surface and drift-lock identity.
- `capabilities` — `can_block`, `can_ask_native`, `ask_events`,
  `block_events`, `supports_fail_closed`, `scope`: the enforcement ceiling.
- `wiring` — `targets`, `install_events`, `layout`, `container_key`, `matcher`,
  `entry_template`, `ownership`, `extra_keys`: the config-patch recipe used by
  Setup / verify / Teardown.
- `response` — `response_field`, `exit_style`, `default_block_reason`,
  `templates`: how a verdict renders into harness-native output and exit code.
- `decode` — `field_map`, `event_aliases`: optional normalizer for non-flat
  payloads.
- `provenance` — publisher/sha256/signature for drop-in trust.

### 3.4 Wiring layouts

Every known harness's hook config falls into one of four shapes. The
`layout` enum selects the shape; `entry_template` is the leaf object inserted.

```
flat_map            container[event] = [ entry, … ]
                    e.g. { "hooks": { "PreToolUse": [ {type:"command", command:"…"} ] } }

grouped_matcher     container[event] = [ { matcher, hooks: [ entry, … ] } ]
                    e.g. { "hooks": { "PreToolUse": [ {matcher:"*", hooks:[{…}]} ] } }

top_level_grouped   root[event]      = [ { matcher, hooks: [ entry, … ] } ]
                    (same as grouped_matcher but with no container key)

nested_named        root[<owner_key_prefix><event>] = { event: [ { matcher, hooks:[entry] } ] }
                    e.g. { "defenseclaw-opencode-PreToolUse": { "PreToolUse": [ {matcher:"*", hooks:[{…}]} ] } }
```

`ownership.match` (and `ownership.owner_key_prefix` for `nested_named`) lets
Setup be idempotent and lets Teardown remove only DefenseClaw's entries from a
file that may contain unrelated hooks.

### 3.5 Substitution tokens

String values in `wiring.entry_template`, `wiring.extra_keys`, and
`response.templates[].output` support a fixed token set. No general expression
language — just these literal substitutions:

| Token | Expands to | Valid in |
| --- | --- | --- |
| `${hook_command}` | Platform-correct hook invocation (installed script on Unix; `defenseclaw hook --connector <name>` on Windows) | wiring entry/extra |
| `${api_addr}` | Gateway host:port | wiring entry/extra |
| `${fail_closed}` | `true`/`false` per resolved fail mode | wiring entry/extra |
| `${reason}` | Verdict reason text | response output |
| `${additional_context}` | Extra context for the agent | response output |
| `${tool}` | Tool/command name | response output |
| `${event}` | Canonical event name | response output |
| `${severity}` | Verdict severity | response output |

Substitution is **type-preserving when a value is exactly one token**: a value
of `"${fail_closed}"` emits a JSON boolean (`true`/`false`), not the string
`"true"`. Tokens embedded inside a larger string always render as text.

### 3.6 Response templates

`response.templates` is an ordered list; the first rule whose `when` matches the
gated `action` (and optionally `event`) wins. Its `output` object is rendered
(tokens substituted) and returned under `response_field`. If no template
matches, or `templates` is omitted, the built-in generic renderer is used.

### 3.7 Decode

For flat payloads, omit `decode`. For nested payloads, `decode.field_map` maps
each canonical field to a dotted path (`toolCall.args`).

`decode.event_aliases` is **classification-only**: it tells the surface
classifier that a harness-native event behaves like a known one (for example
`pre_prompt` → `UserPromptSubmit`) so DefenseClaw inspects the right surface. It
does **not** rename the event used for capability gating or wiring —
`capabilities.block_events`, `capabilities.ask_events`, and
`wiring.install_events` always use the harness-native event names.

---

## 4. Security and trust model

Drop-in manifests can patch local config files and shape security decisions, so
they are treated as untrusted input and run through a defense-in-depth gate.
Embedded first-party manifests skip the trust checks (they ship in the signed
binary) but still pass schema validation.

### 4.1 Threat model

- A malicious/compromised drop-in manifest tries to **shadow a built-in**
  connector to intercept its hooks.
- A manifest tries to **write outside** the user's home/workspace (path
  traversal) or into the DefenseClaw data dir.
- A manifest declares capabilities it should not have, or tries to silently run
  in enforcing mode unverified.
- A manifest file is tampered with after the operator placed it.

### 4.2 Controls

| Control | Enforcement |
| --- | --- |
| Schema validation | Every manifest must validate against `hook-connector-manifest.json` before registration; invalid manifests are rejected and audited. |
| Name-collision guard | A drop-in `name` matching a built-in (or already-registered manifest) is refused — built-ins cannot be shadowed. |
| Config-path allowlist | `wiring.targets` must resolve under `$HOME` or the selected workspace; targets resolving into the DefenseClaw data dir or absolute system paths are rejected. |
| File ownership/permissions | The drop-in directory and manifest files must be owned by the user and not group/world-writable. |
| Provenance verification | A drop-in may declare `provenance` (sha256 + detached signature). Signatures are verified against configured trusted keys. |
| Observe-mode default | An **unverified** drop-in manifest is forced to observe mode (decisions logged, never enforced) unless the operator explicitly opts into enforcement. |
| Capability ceiling | The gateway never blocks/asks beyond declared `capabilities`; `raw_action` records the intended action for audit. |
| Audit emission | Manifest load, rejection, mode downgrade, and every hook decision emit audit events with the connector dimension. |

### 4.3 Trust tiers

| Source | Schema-validated | Path/permission gated | Signature required for enforce | Default mode |
| --- | --- | --- | --- | --- |
| Embedded (first-party) | yes | n/a | no | action |
| Drop-in, verified provenance | yes | yes | yes | action (operator-confirmed) |
| Drop-in, unverified | yes | yes | n/a | observe |

---

## 5. Parity with native connectors

A manifest must be able to reproduce an existing native hook connector exactly.
The mapping below is the parity checklist (each native structure ↔ manifest
section):

- `Connector` interface (`Name`/`Setup`/`Teardown`/`VerifyClean`) ↔ `name` +
  `wiring`.
- `HookEndpoint` route `/api/v1/<name>/hook` ↔ auto-registered from `name`.
- `HookProfile` (`Decode`/`MapVerdict`/`Respond`, `ResponseFieldName`,
  `SupportsTraceparent`) ↔ `decode` + `capabilities` + `response` + `contract`.
- `HookCapability` (block/ask events, scope, fail-closed) ↔ `capabilities`.
- `HookContract` (version bounds, script version, events, AID surfaces) ↔
  `contract`.
- `hookexec` decision style ↔ `response.exit_style`.

The acceptance bar: re-expressing a built-in (for example `cursor`) as a
manifest yields byte-identical installed config, the same wire verdicts, and the
same exit codes as the native connector.

---

## 6. Worked examples

- [`examples/cursor.manifest.yaml`](hook-connector-contract/examples/cursor.manifest.yaml)
  — re-expresses the existing `cursor` connector as a manifest (parity target).
- [`examples/opencode.manifest.yaml`](hook-connector-contract/examples/opencode.manifest.yaml)
  — a net-new harness (OpenCode) integrated purely via manifest, exercising
  `decode`, `nested_named` wiring, and `provenance`.

> Examples are authored in YAML for readability; the on-disk and embedded form
> is JSON validated by the schema. YAML and JSON are 1:1 here.

---

## 7. Non-goals (this contract version)

- Manifests do not carry executable code, regexes-as-policy, or arbitrary
  expressions — only the fixed token substitutions in §3.5.
- Manifests do not configure proxy (LLM-interception) connectors; those remain
  code-backed.
- Native OTLP emission wiring stays code-backed; `contract.native_otlp` is
  descriptive only in this version.
- Per-harness bespoke approval UIs beyond the `confirm`/ask capability are out
  of scope.
