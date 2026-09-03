# End-user identity in v8 telemetry: branch testing plan

Branch: `feature/identity-fabric-telemetry` (not for merge)
Base: `origin/main` at `74fddaee`

## What this branch does

DefenseClaw already reports *what* happened on an endpoint — which agent ran,
which tool it called, which MCP servers are configured. It does not report *who
did it*. On a multi-user endpoint every record is attributed to the machine, so
an operator can see that an agent exfiltrated a file but not whose account was
driving it.

This branch adds the end user as a first-class attribute on v8 telemetry:

| Attribute | Meaning |
| --- | --- |
| `user.id` | Windows SID, or POSIX uid |
| `defenseclaw.user.id_kind` | `windows_sid` or `posix_uid`, so a consumer never has to infer which from the shape |
| `defenseclaw.user.name` | bare OS account name, never `DOMAIN\user` |
| `defenseclaw.user.email` | the account the agent is signed into, when the agent stores one locally |

An earlier revision of this branch wrote Astrix-shaped records to a per-user
disk spool, because AI Defense had no ingest for them. That is gone. The
records now travel on the existing v8 contract, which already reaches AI
Defense through the `managedaid` destination, so there is no new transport to
build and no staging buffer to drain.

## Where identity comes from, and why it can't come from the gateway

The gateway cannot ask the OS who the user is. Under a managed install it runs
as a service account — LocalSystem on Windows, a daemon account on macOS — so
`os/user.Current()` returns the service principal, and every event on a
multi-user endpoint would be attributed to one identity that never touched an
agent. The prior code did exactly this; fixing it is part of the branch.

Only the hook runs inside the real user's session, so the hook reports the
identity and the gateway consumes it:

| Transport | Used by | How identity travels |
| --- | --- | --- |
| bundled `.sh` that `curl`s the gateway | all ten `hooks/*-hook.sh` | `defenseclaw_user_identity_args` in `_hardening.sh` emits `X-DefenseClaw-User-Id` / `X-DefenseClaw-User-Name` curl arguments |
| native `<exe> hook --connector <name>` | Windows, and the `.ps1` hooks | `hookexec.setUserIdentityHeaders` reads the thread/process token SID |
| in-process plugin POST | `amp-plugin.ts`, `opencode-plugin.js`, `omnigent-policy.py` | each sets the same two headers from its own runtime (`os.userInfo()`, `getpass.getuser()`) |

Every connector transport reports identity. That is worth stating explicitly
because the first cut covered only codex, claude-code, and cursor, and the
seven other shell hooks plus the three plugin transports shipped with no
identity at all — which, like the bash 3.2 bug below, looked identical to
working correctly from the outside. The gateway side needed no change for any
of them: `CorrelationMiddleware` reads these headers on every loopback route,
not per connector.

The plugin transports guard against a negative uid, because `os.userInfo().uid`
and `os.getuid()` do not exist on Windows and the `-1` the runtime reports
there belongs to neither identifier namespace.

Precedence in the gateway is deliberate. Headers come from the hook process and
are preferred. The hook *payload* is agent-controlled and is consulted only as a
fallback, for connectors that report a user natively (Cursor). Under an
unmanaged install — and only then — the gateway falls back to its own OS
identity, because there it really is running as the person using it.

None of this is authentication. The gateway's loopback listener is reachable by
any local process, so these are attribution join keys, not authenticated
assertions. They must never drive an authorization decision.

### The email

`internal/useridentity` reads the signed-in account from each connector's own
local state:

| Connector | Source |
| --- | --- |
| Claude Code | `oauthAccount.emailAddress` in `~/.claude.json` |
| Codex | the `email` claim in the ID token in `~/.codex/auth.json` (signature deliberately unverified — we hold no issuer key, and this is evidence, not an assertion) |
| Cursor | `user_email` in the hook payload; Cursor keeps no local account file |

Absent is a normal outcome and is preferred over a guess. The address is never
synthesized from `username@domain`, git config, environment variables, or a
Windows UPN. On a host where Codex keeps credentials only in the OS credential
store, there is nothing to read and the field is simply omitted.

For inventory, the gateway resolves the address **per profile directory**, not
for itself, so a scan of five user profiles reports five different accounts.
When an explicit home is supplied, `CODEX_HOME` / `CLAUDE_CONFIG_DIR` from the
reader's own environment are ignored — honoring them would attribute the
gateway operator's account to every profile it scanned.

## Where the records go

Two families carry identity, and they have different delivery guarantees.

**Hook lifecycle** (`agent.lifecycle`, `tool.activity`, `guardrail.evaluation`)
— near-real-time, one record set per session start and per tool call. These
buckets are *not* force-collected under `managedaid`, so whether they reach AI
Defense depends on operator collection config.

**Inventory** (`ai.discovery`) — the existing 5-minute sidecar discovery scan,
now attributing each MCP row to the profile it was read from. `ai.discovery` is
force-collected in managed enterprise, so per-user MCP attribution reaches AI
Defense without operator action. Note that `emitEndpointInventory` is gated on
managed enterprise and does not run on an unmanaged install.

`defenseclaw.user.email` is classified `identifier` / `sensitive` and is
preserved in plaintext by the `managedaid` projection. **This needs privacy
sign-off before the branch is merged.**

---

# Part 1 — macOS

## Step 1 — Unit tests

```bash
git fetch origin && git checkout feature/identity-fabric-telemetry

go test ./internal/useridentity/...
go test ./internal/gateway/ -run 'Identity|UserEmail|InventoryHomeOwner|AttributeEachHome|DaemonsOwnProfile'
go test ./internal/gateway/connector/ -run 'IdentityHeaders|UserIdentityArgs'
```

`TestIdentityHeadersSurviveTheSystemShellsReader` is the one to watch. It runs
each shipped hook's own reader block against the helper under `/bin/bash`
specifically, not whatever bash is first on `PATH`. See "the bash 3.2 trap"
below for why that distinction is the whole test.

## Step 2 — A live gateway with a file sink

There is no environment variable that turns on file output in v8; it is a
config destination. Use an isolated home so nothing touches your real install.

```bash
mkdir -p /private/tmp/dc-idfab/home /private/tmp/dc-idfab/confighome
go build -o /private/tmp/dc-idfab/defenseclaw ./cmd/defenseclaw
cp -R policies /private/tmp/dc-idfab/home/policies

cat > /private/tmp/dc-idfab/config.yaml <<'YAML'
config_version: 8
gateway:
  host: 127.0.0.1
  port: 18899
observability:
  destinations:
    - name: local-jsonl
      kind: jsonl
      path: /private/tmp/dc-idfab/home/telemetry.jsonl
YAML

export DEFENSECLAW_HOME=/private/tmp/dc-idfab/home
export DEFENSECLAW_CONFIG=/private/tmp/dc-idfab/config.yaml
/private/tmp/dc-idfab/defenseclaw &
```

Use `/private/tmp`, not `/tmp`: `/tmp` is a symlink on macOS and the device
identity loader refuses an indirect data directory.

First boot synthesizes a gateway token into `$DEFENSECLAW_HOME/.env` and then
exits with `config reload requires gateway restart for: gateway`. Copy that
token into `gateway.token` in the config and start it again; after that it
stays up. The `ws://127.0.0.1:18899` connect failures in the log are expected —
there is no OpenClaw gateway — and do not affect hook events.

Confirm the sink is live:

```bash
curl -s http://127.0.0.1:18970/health \
  | python3 -c 'import json,sys; print([d["name"] for d in json.load(sys.stdin)["telemetry"]["details"]["destinations"]])'
```

## Step 3 — Render the real hooks

Hook endpoints reject any request whose contract does not match the installed
runtime lock, so you cannot hand-craft one with `curl`. Render the real hooks
into a sandbox config home instead:

```bash
for c in codex claudecode cursor; do
  /private/tmp/dc-idfab/defenseclaw connector reconcile \
    --connector "$c" --config-home /private/tmp/dc-idfab/confighome --json
done
```

`--config-home` is hidden but supported, and it is what keeps this off your
real `~/.codex`, `~/.claude.json`, and `~/.cursor`.

## Step 4 — Drive the hooks

Invoke them exactly as the agent does — the argument form is in the rendered
`confighome/config.toml` (Codex) and `confighome/hooks.json` (Cursor).

```bash
H=/private/tmp/dc-idfab/home/hooks

echo '{"hook_event_name":"SessionStart","session_id":"mac-codex-1","model":"gpt-5-codex","cwd":"'"$PWD"'","source":"startup"}' \
  | "$H/codex-hook.sh" --event SessionStart --hook-contract codex-hooks-v4

echo '{"hook_event_name":"PreToolUse","session_id":"mac-codex-1","tool_name":"mcp__github__create_issue","tool_input":{"title":"demo"}}' \
  | "$H/codex-hook.sh" --event PreToolUse --hook-contract codex-hooks-v4

echo '{"hook_event_name":"SessionStart","session_id":"mac-claude-1","cwd":"'"$PWD"'","source":"startup","model":"claude-sonnet-4-6"}' \
  | "$H/claude-code-hook.sh"

echo '{"hook_event_name":"sessionStart","session_id":"mac-cursor-1","cursor_version":"3.10.17","user_email":"you@example.com"}' \
  | "$H/cursor-hook.sh"

echo '{"hook_event_name":"beforeShellExecution","conversation_id":"mac-cursor-1","command":"git status","user_email":"you@example.com"}' \
  | "$H/cursor-hook.sh"
```

Then read the identity columns:

```bash
python3 - <<'PY'
import json
for line in open('/private/tmp/dc-idfab/home/telemetry.jsonl'):
    line = line.strip()
    if not line:
        continue
    d = json.loads(line)
    b = d.get('body', {})
    if not b.get('user.id'):
        continue
    print(d['bucket'], d['event_name'], b.get('user.id'),
          b.get('defenseclaw.user.id_kind'), b.get('defenseclaw.user.name'),
          b.get('defenseclaw.user.email'))
PY
```

## Observed output on macOS

Captured from the run above on macOS 15 (arm64), uid 501. Five records carry
identity per session-start-plus-one-tool-call sequence. The account name and
address throughout this section are fixtures standing in for whatever the
capturing account was; the uid and the field structure are as observed.

```text
bucket                 event                        user.id  id_kind    name    email
agent.lifecycle        session_start                501      posix_uid  dcuser  dcuser@example.com
guardrail.evaluation   hook_decision                501      posix_uid  dcuser  dcuser@example.com
tool.activity          tool_start                   501      posix_uid  dcuser  dcuser@example.com
tool.activity          tool.invocation.requested    501      posix_uid  dcuser  dcuser@example.com
guardrail.evaluation   hook_decision                501      posix_uid  dcuser  dcuser@example.com
```

A full `agent.lifecycle` / `session_start` body from Codex:

```json
{
  "defenseclaw.agent.lifecycle.event": "session_start",
  "defenseclaw.agent.lifecycle.state": "active",
  "defenseclaw.agent.root.id": "agent-c7a0b1646aac54a8",
  "defenseclaw.agent.type": "codex",
  "defenseclaw.session.root.id": "mac-codex-1",
  "defenseclaw.session.source": "startup",
  "defenseclaw.user.email": "dcuser@example.com",
  "defenseclaw.user.id_kind": "posix_uid",
  "defenseclaw.user.name": "dcuser",
  "gen_ai.agent.name": "codex",
  "gen_ai.conversation.id": "mac-codex-1",
  "gen_ai.provider.name": "openai",
  "gen_ai.request.model": "gpt-5-codex",
  "user.id": "501"
}
```

Per connector, the identity fields observed were:

| Connector | `user.id` | `id_kind` | `name` | `email` |
| --- | --- | --- | --- | --- |
| codex | `501` | `posix_uid` | `dcuser` | `dcuser@example.com` (from the `auth.json` ID token) |
| claudecode | `501` | `posix_uid` | `dcuser` | *absent* |
| cursor | `501` | `posix_uid` | `dcuser` | `dcuser@example.com` (from the payload) |

The absent Claude Code address is correct behavior, not a defect: this host's
`~/.claude.json` has no `oauthAccount` block, so there is nothing to read and
the field is omitted rather than guessed.

The Cursor row is the useful one to check, because it proves the precedence
rule. Cursor's payload carries `user_email`, and without the headers the
gateway derives a pseudonymous `user-<hash>` id from it. Seeing `501` /
`posix_uid` / `dcuser` there means the hook's headers arrived and won, while
the payload still supplied the address the OS cannot know.

## The bash 3.2 trap

The first implementation read the helper's output with `mapfile`. `mapfile` is
bash 4; macOS ships bash 3.2 as `/bin/bash`, which is what the hooks' shebang
resolves to. On every stock macOS endpoint the array stayed empty, no identity
headers were sent, and nothing failed: hooks ran, tool calls were allowed, the
gateway answered normally. The feature was simply absent.

It was invisible in testing for a second reason. On an unmanaged install the
gateway falls back to its own OS identity, which on a dev machine *is* the right
user — so the records looked correct. The bug would only have surfaced in
managed enterprise, where that fallback is deliberately disabled, which is the
one deployment the feature exists for.

The hooks now use a `while IFS= read -r` loop. Three tests pin it, and the two
shell ones run against `/bin/bash` explicitly rather than the first bash on
`PATH`, since on a Homebrew machine those are different versions and the PATH
one would pass.

`TestIdentityHeadersSurviveTheSystemShellsReader` discovers its subjects by
globbing `hooks/*-hook.sh` rather than reading a list. The hand-maintained list
is what let seven hooks ship with no reader at all: the three that had one
passed, and a hook that reports nothing is indistinguishable from a hook that
reports correctly. It also asserts each hook actually expands
`IDENTITY_HEADER_ARGS` into its request, since collecting the arguments and
never passing them to `curl` fails just as quietly.

Note the same `mapfile` guard still wraps W3C **trace** header propagation in
all ten hooks (`TRACE_HEADER_ARGS`). That is pre-existing on `main`, not
introduced here, and it means `traceparent` / `tracestate` are also not
propagated from macOS hooks. It is the identical mechanical fix — replace
`mapfile -t` with the same read loop — but it changes trace behavior rather
than adding a field, so it is deliberately left out of this branch.

---

# Part 2 — Windows

The Windows SID path is the surface with no runtime coverage. It compiles and
is vet-clean for `windows/amd64`, but the token lookup in
`useridentity.currentIdentity` and the ProfileList lookups in
`identityForHome` / `homeForID` have never executed.

## Step 1 — Prove the platform code runs

```powershell
git fetch origin
git checkout feature/identity-fabric-telemetry

go test ./internal/useridentity/... -v
```

`TestCurrentReportsAClassifiableIdentity` is the gate: it asserts the reported
id classifies as the kind it claims. On Windows expect a `S-1-5-21-…` SID and
`windows_sid`. If this fails, the token lookup is wrong and nothing else is
worth running.

`TestForHomeAndHomeForIDRoundTrip` exercises the ProfileList mapping in both
directions — SID to profile directory and back. It skips rather than fails when
no profile resolves, so read the output, not just the exit code.

## Step 2 — Standalone hook run as `dcstd`

Build as the admin account, then run as the standard user so the SID belongs to
a non-admin. Repeat Part 1 steps 2–4 with Windows paths; the Windows hook is
the native executable rather than a shell script, so identity comes from
`hookexec` and there is no `_hardening.sh` involved.

Confirm the SID the records carry matches the account:

```powershell
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
```

Expect `user.id` to be that SID, `defenseclaw.user.id_kind` to be
`windows_sid`, and `defenseclaw.user.name` to be the bare account name with no
`DOMAIN\` prefix.

## Step 3 — Two users, one endpoint

This is the case the feature exists for and the one macOS cannot exercise well.
Drive agent sessions as two different accounts and confirm each record carries
that account's SID — not the installing admin's, and not the service account's.

## Step 4 — Enterprise-managed run

Install per the enterprise flow (`packaging/windows/install-enterprise.ps1`),
then drive real sessions as `dcstd` with the installed hooks.

Check specifically:

- Hook records carry the invoking user's SID even though the gateway runs as
  LocalSystem. This is the misattribution fix. Treat `S-1-5-18` in any record
  as a failure and stop to investigate rather than recording it as the
  fallback: the OS-identity fallback is disabled under a managed install, so
  the service principal cannot arrive that way. Its presence means the header
  path did not work *and* something else put the gateway's own identity on the
  record — the attribution path itself is wrong, not just less precise.
- `ai.discovery` inventory rows attribute each MCP server to the profile it was
  read from. On a two-user endpoint the same server name configured by both
  users must appear twice with different `user.id` values.
- No inventory row is attributed to the service account. The first inventory
  pass reads the daemon's own home and is deliberately skipped under managed
  enterprise; a row naming the service principal means that gate failed.

## Step 5 — Cursor on Windows

Cursor's Windows transport uses the generated PowerShell adapter and
`--input-file` rather than native stdin, which is a different path into
`hookexec`. Confirm identity headers are still set.

---

## What to check in every record

- `user.id` present with an `id_kind` that matches its shape. An id the gateway
  cannot classify is emitted without a kind rather than being labelled
  `posix_uid` — a consumer that joined an arbitrary string as a uid would
  silently merge unrelated users.
- `defenseclaw.user.name` is the bare account name. A `DOMAIN\user` value means
  the Windows lookup stopped stripping the qualifier.
- `defenseclaw.user.email` absent is fine and expected on many hosts. Present
  but wrong is not: it must match the account the connector is actually signed
  into.
- No record carries the service account under a managed install.
- MCP inventory rows are attributed per profile, and two users' same-named
  servers stay distinct.

## Known gaps

- **`agent.lifecycle` is not force-collected by `managedaid`.** Hook lifecycle
  identity reaches AI Defense only if the operator's collection config includes
  that bucket. `ai.discovery` is force-collected, so inventory attribution is
  unconditional. Worth deciding whether hook identity should be promoted.
- **The email is plaintext at the AI Defense sink.** Classified `identifier` /
  `sensitive`, preserved by the `managedaid` projection. Needs privacy sign-off.
- **The email is attribution evidence, not attestation.** Any process running as
  the user can write the connector config it is read from.
- **Only three connectors have an email source at all.** `codex` reads the
  `email` claim from `~/.codex/auth.json`, `claude-code` reads
  `oauthAccount.emailAddress` from `~/.claude.json`, and `cursor` forwards
  `user_email` from its payload. Every other connector reaches the `default`
  branch of `EmailForConnector` and resolves nothing, and the three that are
  wired can still legitimately resolve nothing — Codex keeping credentials only
  in the OS keychain, or a Claude Code install on API-key rather than OAuth
  auth, both yield no address. The attribute is omitted in that case and the
  record is still emitted; the uid or SID and the account name carry the
  attribution. Cursor's payload-only source also means its email is absent from
  the periodic inventory, which has no payload to read.
- **`emitEndpointInventory` is managed-enterprise-only**, so the inventory half
  of this branch cannot be exercised on an unmanaged macOS install. It is
  covered by unit tests instead
  (`TestPerConnectorMCPEntriesAttributeEachHomeToItsOwner`).
- **Windows profile ownership comes from ProfileList**, so
  `TestPerConnectorMCPEntriesAttributeEachHomeToItsOwner` skips there — a temp
  directory has no registry entry. The Windows path needs the step 4 run to be
  considered covered.
- **Pre-existing, not from this branch:** the `mapfile` guard on trace headers
  (above), and a regex in `schemas/telemetry/v8/registry.yaml` for
  `url_host` under `defenseclaw.inventory.mcp_identifier` whose double-escaped
  backslash rejects bracketed IPv6 hosts that the Go producer accepts.
