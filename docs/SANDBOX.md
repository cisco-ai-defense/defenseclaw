# OpenShell sandbox architecture

This page is for contributors. It explains how DefenseClaw runs a coding
harness such as Claude Code or Codex inside an NVIDIA OpenShell 0.1 sandbox:
what OpenShell enforces, what DefenseClaw adds, how traffic gets in and out,
how the project folder is shared and taken back, and which measured OpenShell
behaviours the code is built around. The code is the authority; each section
names the package to read.

The operator guide for the sandbox commands will live on the
[published sandbox page](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/)
(`docs-site/content/docs/setup/sandbox.mdx`). Today that page covers only the
removal of the legacy 0.0.x sandbox. Telemetry details are in
[OPENSHELL_SANDBOX_EVENTS.md](OPENSHELL_SANDBOX_EVENTS.md).

## Build status

The integration is being built in layers. The packages in the
[code map](#code-map) exist with unit tests, the daemon runs the sandbox
manager, hook ingress and egress proxy when `openshell.enabled` is on, and
the `defenseclaw-gateway sandbox` command tree (setup, doctor, run and the
lifecycle, approval, workspace, policy, pack, image, wrapper and teardown
commands) drives it through the REST API under `/api/v1/sandbox/`. The
surfaces are in place: the Python `defenseclaw sandbox` Click stubs mirror
the Go tree (pinned in `internal/cli/testdata/sandbox_commands.json`) and
exec `defenseclaw-gateway sandbox`, `defenseclaw doctor` has a Sandbox
section, the TUI has a Sandboxes panel (key 7) and the sandbox setup wizard
in Setup slot 13, and the macOS app shows sandboxes in the menu bar,
Overview and a Sandboxes panel. Still to come:

- **MCP import and per-run configuration for the other harnesses.** Only
  Claude Code and Codex bring the user's MCP servers along and get per-run
  managed configuration (see
  [per-sandbox managed configuration](#per-sandbox-managed-configuration)).
- **Harnesses.** `claudecode`, `codex`, `opencode`, `copilot`, `amp`,
  `cursor`, `kiro` and `devin` have harness specs and sandbox artifacts. The
  Amp, Cursor Agent and Devin images stay unverified until a probe runs with a
  vendor account (see [Sandboxed connectors](#sandboxed-connectors)).

## Why OpenShell

The goal is to let a developer run a harness in its skip-permissions mode
without putting the machine at risk. That needs a boundary the agent cannot
argue or code its way around.

- **OpenShell** runs the harness in a workload container with no network, a
  Landlock filesystem policy, seccomp, and a non-root user. A supervisor
  outside the workload is the only way out. It applies per-endpoint,
  per-binary network rules and swaps credential placeholders for real values
  only on the endpoints they are bound to. Because these limits sit in the
  kernel and in the supervisor, static binaries, raw system calls and
  obfuscated commands are expected to meet them too. That was not tested
  separately (see [not measured](#not-measured)).
- **Qpoint qcontrol**, the alternative considered, hooks functions inside the
  agent process. That gives visibility and soft control, but the agent still
  runs with the user's full privileges, and in-process hooks can be bypassed.

The planned side-by-side bake-off was only half run: OpenShell 0.1.1 was
measured (see [platform behaviours](#platform-behaviours-to-design-around)),
but qcontrol was never installed or measured. The choice rests on how the two
work. Reopen it if a qcontrol run shows something OpenShell cannot do.
qcontrol may still be added later as an optional event source.

## Who enforces what

OpenShell supplies the boundary. DefenseClaw supplies the judgment and the
parts of the boundary that depend on the project.

| Concern | OpenShell enforces | DefenseClaw adds |
| --- | --- | --- |
| Network | The workload has no network; the supervisor is the only path out and applies per-endpoint, per-binary rules | The egress proxy for web traffic: blocklist feed, SSRF guard, per-destination decisions, byte counts |
| Files | Landlock; only bind-mounted host paths are visible | Which host paths are mounted, secret masks, read-only git state, snapshot and undo, change review |
| Identity | The process identity the policy names | Runs as your uid in mount mode (as `sandbox` in copy mode) and builds a per-uid image |
| Credentials | Placeholders resolve only on bound endpoints, for bound binaries | Per-sandbox binding tokens, provider profiles pinned to the harness binary; LLM traffic never passes through DefenseClaw |
| Agent actions | None | Hooks feed the existing guardrail pipeline: rule packs, CEL, the judge, HITL |
| Hook integrity | Root-owned, read-only system paths | Managed hook config in the image, fail-closed hooks, a build-time hook-fire probe, hook tamper and hook silence detection |
| Visibility | OCSF events over `WatchSandbox` | Parse, correlate by sandbox, emit v8 telemetry |

## Components

Ports are shown for the default `gateway.api_port` of 18970.

```text
 Host (one user)                          OpenShell 0.1, docker driver
+--------------------------------+       +--------------------------------+
| DefenseClaw daemon             |       | openshell-gateway              |
|   :18970 main API              |       |   systemd user service :17670  |
|   :18971 sandbox hook ingress  |       |                                |
|   :18972 egress proxy          |       | per sandbox:                   |
+--------------------------------+       |   supervisor (host network)    |
      ^              ^                   |     policy, credentials, OCSF  |
      | hooks, OTLP  | web traffic       |   workload (no network,        |
      +------+-------+                   |     Landlock, seccomp,         |
             |                           |     non-root)                  |
   supervisor relays                     |     harness + sandbox hooks    |
   host.openshell.internal               +--------------------------------+
   to host 127.0.0.1
```

The OpenShell client (`openshell.Dial`) talks to the gateway over gRPC with
mTLS through the OpenShell Go SDK. The upstream `openshell` CLI is used only
where the SDK has no transport: terminal attach, file upload and download,
port forwarding, gateway registration and install.

## Networking

Networking needs no veth pairs, iptables rules or root. DefenseClaw listens
on loopback only.

### Listeners

| Listener | Config key | Default | Reached by |
| --- | --- | --- | --- |
| Main API | `gateway.api_port` | 18970 | Host clients only; never exposed to a sandbox |
| Sandbox hook ingress | `openshell.ingress_port` (0 means `api_port + 1`) | 18971 | Sandbox hooks and harness OTLP exporters |
| Egress proxy | `openshell.egress_port` (0 means `api_port + 2`) | 18972 | Every web client in the sandbox |

Both sandbox listeners refuse anything but a loopback address. With
`openshell.enabled` on, config validation refuses sandbox ports that collide
with each other, with `gateway.api_port` or with `guardrail.port`, and derived
ports past 65535.

### host.openshell.internal

Inside the workload, `host.openshell.internal` resolves to a synthetic address
(`198.18.0.2`) that the supervisor relays to host `127.0.0.1`. The host
service sees the client as `127.0.0.1`. So on the sandbox listeners a loopback
source proves nothing: every request is authenticated by its own credential,
and the main API's loopback carve-outs never apply because sandbox traffic
never reaches the main listener.

### Paths out of the workload

```text
 workload process
   |
   |-- hook POST ---> host.openshell.internal:18971
   |                    provider rule: bearer placeholder swapped for the
   |                    real binding token, relayed to 127.0.0.1:18971
   |
   |-- web ---------> host.openshell.internal:18972  (HTTPS_PROXY)
   |                    rule defenseclaw_egress: tcp, tls skip, any binary
   |                    raw relay to 127.0.0.1:18972, the proxy decides
   |
   |-- LLM API -----> provider host, for example api.anthropic.com:443
   |                    (NO_PROXY) provider rule swaps the key placeholder
   |
   '-- anything else: denied by OpenShell, which files a draft proposal
```

The harness spec builds the environment passed to `openshell sandbox create
--env` (`harness.Spec.Env`):

- `DEFENSECLAW_EGRESS_URL` is
  `http://<user>:<secret>@host.openshell.internal:<egress_port>`, and
  `DEFENSECLAW_EGRESS_BYPASS` lists `host.openshell.internal` plus the
  provider hosts of the harness's credential profile, so hooks reach the
  ingress directly and LLM calls stay on OpenShell's provider rules. The
  strict profile sets no proxy. `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`
  (and their lowercase forms) and `NODE_USE_ENV_PROXY=1` are passed too, but
  OpenShell 0.1.1 drops them at create, so the workload gets them from the
  shell fragment below.
- `DEFENSECLAW_SANDBOX_ID` and `DEFENSECLAW_SANDBOX_NAME` identify the
  sandbox. The ID is also meant to tell a nested DefenseClaw launch that it
  already runs sandboxed.
- The connector's startup variables (see [overlay images](#overlay-images)).

One shell fragment (`egressEnvScript` in
`internal/openshell/harness/shellenv.go`) exports `HTTPS_PROXY`,
`HTTP_PROXY`, `NO_PROXY` (and their lowercase forms) and
`NODE_USE_ENV_PROXY=1` from those two variables, only for a well-formed
`http://` URL and in place of any proxy settings the caller's environment
carries. It runs wherever a process starts in a DefenseClaw image:

| Start | How it gets the proxy |
| --- | --- |
| The harness (`sandbox run`, `sandbox connect`, a vendor login) | Its root-owned launcher, `/usr/local/lib/defenseclaw/bin/<connector>-launch`, runs the fragment first. Every tool the harness runs inherits it. |
| A `sandbox connect --shell` shell, or `openshell sandbox exec` with its default login shell | `/etc/profile` sources the root-owned `/etc/profile.d/defenseclaw-sandbox.sh`. |
| `defenseclaw-gateway sandbox exec` | OpenShell starts it without a login shell, so the CLI runs the command through the root-owned `/usr/local/lib/defenseclaw/bin/sandbox-env`, which also drops the shell start-up and Node loader variables the launchers drop. |

The profile fragment and `sandbox-env` also put
`/usr/local/lib/defenseclaw/shims` first on `PATH`. It holds a shim named
after the harness command (`claude`, `codex`, `opencode`, `copilot`, …) that
starts the launcher, so typing the harness name in a connect or exec shell
gets the launcher's protections too. The community base image's
`~/.bashrc` resets `PATH` after the profile ran, so for bash the profile also
defines and exports a function of the harness command's name that runs the
shim; it survives the reset and reaches child bash shells (the launchers run
under `bash -p`, which imports no functions; dash drops exported functions,
so a `sh` started in between loses it). OpenShell runs a login-shell exec
as `bash -lc` and a `--no-login-shell` one as `bash -c`. What none of them
covers: a program
started by its absolute path (`/usr/local/bin/<command>`), a child started
with an emptied environment (`env -i`), `openshell sandbox exec
--no-login-shell` used directly, and a harness run nested inside a tool
call, which inherits the proxy but skips the launcher's per-start checks.
The daemon's own `sandbox exec` probes run without the fragment and need no
proxy.

A client that ignores `HTTPS_PROXY` and connects directly is denied by
OpenShell, which then files a draft policy proposal. `internal/openshell/triage`
judges each proposal against the sandbox's own proxy decider, because
approving one adds a direct OpenShell rule that bypasses the proxy:

- What the proxy refuses and no unblock lifts is rejected: the
  administrator's lists, the block list, the blocklist feed, this machine,
  link-local and metadata addresses.
- A public IP literal in the open mode is rejected until it is unblocked.
- Doors into your machine or network ask: host ports, private addresses and
  intranet names.
- Everything else follows the pack's approvals mode.
- Every destination name is resolved with the proxy's own dial-time rules
  (`egress.LookupHost` and `Decider.CheckAddrs`). A name that resolves to
  this machine, link-local, metadata or reserved addresses is rejected. A
  name that resolves to a private network asks, or is rejected when
  `openshell.admin.allow_unblock` is `false`. A name that does not exist or
  has no address is rejected. A lookup that times out or fails temporarily
  (SERVFAIL, an unreachable resolver) rejects nothing: the proposal stays
  pending and the next pass decides it.
- The batcher repeats the whole check, with fresh DNS answers, right before
  it applies an approval. When that check cannot be made (a failing lookup,
  or a sandbox policy that does not resolve), an automatic approval is
  triaged again later, and your own approval is retried three times, then
  comes back to you as a pending ask. The proposal is not rejected.
- Every reconcile, about every 5 minutes, removes approved rules whose
  names now resolve to this machine.
- A proposal's `allowed_ips` are judged as whole ranges against the same
  guard (`packs.Effective.AllowedIPReach`), because with `allowed_ips` set
  OpenShell skips its own private-address check for the rule and the name
  may later resolve to any address in them. A range that holds one of this
  machine's own interface addresses is rejected, however public. A range on
  a public subnet this machine sits on asks, like a private range.
- OpenShell's own SSRF check still applies to approved rules without
  `allowed_ips` (loopback, link-local and internal ranges), but it does not
  know this machine's own public addresses. DefenseClaw checks the name at
  triage, right before it applies the approval, and on every reconcile, one
  lookup each time. A name whose DNS answers alternate between a public
  address and one of this machine's public addresses can pass all of these
  checks. The approved rule then reaches the services this machine serves on
  that public address, for as long as the rule exists. The proxy has no such
  gap, because it checks every DNS answer at dial time. This matters only on
  a machine with a public address on an interface (a VPS or bare-metal host,
  or a global IPv6 address). There, bind host services to loopback, or keep
  agents from adding direct rules on their own: set
  `openshell.approvals.agent_proposals: false`, or use the `balanced`
  profile (it approves on its own only the curated allowlist) or `strict`
  (it approves nothing on its own). Approved names are not pinned to the
  addresses they resolved to, because OpenShell would then refuse a name as
  soon as its CDN moved it.

## Hook ingress

`internal/gateway/api_sandbox_ingress.go` serves a second listener with a
minimal route table:

- the hook path of each built-in connector (plugin connectors are excluded:
  a sandbox runs only a reviewed built-in harness);
- the Codex notify path;
- `/api/v1/inspect/tool`, `/request`, `/response` and `/tool-response`;
- OTLP over HTTP at `/v1/logs`, `/v1/metrics` and `/v1/traces`. The
  `/otlp/<source>/<token>/` form is not served, because it puts a credential
  in the URL.

Any other path answers 404 once the request is authenticated. There are no
admin routes, and the master gateway token, connector hook tokens and OTLP
path tokens are never accepted.

Each request passes these steps in order:

1. **Authenticate.** Exactly one `Authorization: Bearer` header must carry a
   live binding credential, or the answer is 401. OpenShell substitutes the
   credential into every header and the query string of a bound endpoint, so
   a credential anywhere else (another header, the host, the path, the query,
   percent- or Basic-encoded) answers 400: it would otherwise be echoed back
   or written to audit sinks.
2. **Trace, request ID, correlation.** Client-supplied request IDs are
   dropped and a new one is always minted. The user identity comes from the
   binding's host user; identity headers from the sandbox are removed.
3. **Authorize.** The path must belong to a route class the binding lists
   (`hook`, `notify`, `inspect`, `otlp`) and to the binding's one connector.
   Inspect calls name their connector in `X-DefenseClaw-Connector`; OTLP
   uploads in `x-defenseclaw-source`, which defaults to the binding's
   connector. A mismatch answers 403.
4. **Limit.** Per binding, hook, notify and inspect calls share a bucket of
   25 requests a second with a burst of 100 and at most 32 in flight. OTLP
   has its own bucket (10 a second, burst 50), at most 4 uploads in flight per
   binding and 16 across all bindings, and a 4 MiB body cap. Over a limit the
   answer is 429 with `Retry-After: 1`.
5. **Replay.** A hook or notify request may carry
   `X-DefenseClaw-Hook-Idempotency-Key`. A completed response is kept for two
   minutes, per binding, and a retry of the exact same request gets it back
   (marked `X-DefenseClaw-Idempotent-Replay`) instead of a second
   evaluation.

Hook handlers then treat a sandbox request differently from a host request
(`internal/gateway/sandbox_hook_scope.go`):

- The connector profile comes from the binding's reviewed hook contract and
  image harness version, never from the host's contract lock or version
  cache.
- A payload working directory is mapped through the binding's `FSView`. In
  mount mode `/work/<repo>` becomes the real host project path, and a path
  resolves only if it stays inside the project and is not a masked secret. In
  copy mode no path reaches the host filesystem.
- `~` means the sandbox HOME, `/sandbox`, never the host user's home.
- Tool results never earn the source-scope proofs that read the host tree.
- Session state is kept per binding, because session IDs are chosen by the
  agent.
- Nothing runs git or a subprocess scanner against the agent-writable tree on
  the host.
- A verdict that is not a plain allow carries a plain reason
  (`internal/gateway/sandbox_verdict_reason.go`), for example
  `Blocked by DefenseClaw rule <ID>: <title>. <what to do instead>`. It is
  built only from the static metadata of the deciding rules, looked up by rule
  ID in the connector's guardrail catalog and the built-in CodeGuard rules:
  the ID, the title, and a remediation for the rule's category (CodeGuard
  rules carry their own). A rule-pack title that its own rule or a secret
  rule would match is left out, and so are IDs no catalog knows. The reason
  never quotes matched content, whatever the redaction policy, so the agent
  can adapt instead of seeing `<redacted len=… sha=…>`. The same text becomes
  the sandbox's `last_blocked` and its `tool.blocked` activity entry; the
  audit sinks keep the source reason and redact it as before. Finding labels
  are left out of the response body; the rule IDs travel in `rule_ids`.

## Sandbox bindings and tokens

A binding (`internal/sandboxauth`) is one sandbox's authorization at the
ingress:

- **Credential.** `dcsb_` followed by 43 base64url characters (256 random
  bits). It is returned once when minted; the store keeps only its SHA-256.
  The main API refuses any credential with the `dcsb_` prefix in
  `Authorization`, `X-DefenseClaw-Token`, `X-DC-Auth` or an OTLP path token
  before any other credential check, so none of its loopback carve-outs can
  be reached with one.
- **Scope.** The sandbox ID and name, the one connector it may act for, the
  harness version and hook contract baked into its image, the policy profile,
  the route classes (hook and OTLP by default, plus notify for Codex), the
  workspace mode with its mounts and masks, and the host user.
- **Store.** `<data_dir>/sandboxes/bindings.json`, owner-only (0600 in a 0700
  directory), updated under an advisory lock with atomic replacement, at most
  1,024 bindings. Each process re-reads the file within a second, so a revoke
  written by another process applies within a second. Not supported on
  Windows.
- **Lifecycle.** `Mint`, `Rotate` (new credential, same binding), `Update`
  and `Revoke`. An optional TTL is re-applied on every rotation. The manager
  must revoke a binding when its sandbox is deleted, rotate it when the
  sandbox starts, and call `ForgetSandboxBinding` to drop the ingress's
  per-binding limiter, in-flight and replay state.

`openshell.token_delivery` selects how the manager hands the token to the
sandbox. With `provider` (the default) it becomes an OpenShell provider
credential created from the daemon's own ingress profile,
`defenseclaw-ingress-<ingress_port>`: variable `DEFENSECLAW_SANDBOX_TOKEN`,
sent as a bearer in `authorization`, bound to
`host.openshell.internal:<ingress_port>` with `protocol: rest`. The workload
only ever sees a placeholder, and the provider's rule is what lets the
sandbox reach the ingress. With `env` it is a plain variable the agent can
read; the sandbox has no ingress provider, and its policy opens the ingress
with a `defenseclaw_ingress` rule instead (same endpoint, every binary, no
substitution). The token then lives in the sandbox spec, which cannot change
after create, so it is not rotated on start.

Placeholders are revision-scoped (they change on every start), so nothing may
bake them into static files. The sandbox hooks read the variable on each
request, Claude Code's `otelHeadersHelper` prints the header on each export,
and the Codex launcher adds the OTLP header as `-c` flags at launch.

## Egress proxy

`internal/openshell/egress` is the general web path out of a sandbox. The
policy reaches it through one rule, `defenseclaw_egress`: host
`host.openshell.internal`, the egress port, `protocol: tcp` with `tls: skip`
(a raw relay), for every binary (`/**`). OpenShell's HTTP parser rejects a
CONNECT request addressed to another host, and it does not substitute
placeholders on a raw relay, so the proxy authenticates the sandbox itself.

### Authentication

Each sandbox gets its own proxy credential: a `dcx-` user name and a 256-bit
password, sent by clients as `Proxy-Authorization: Basic` from the userinfo of
`HTTPS_PROXY`. The proxy keeps only a SHA-256 of the password, one credential
per binding (registering a new one rotates the old one). The credential only
attributes traffic to a sandbox and rate-limits it; it grants nothing the
sandbox does not already have. A request without a credential gets a 407
challenge; a wrong one also records an `auth_failed` event.

The credential's principal also carries the sandbox's own `Decider`
(`Principal.Decider`). The manager builds it from that sandbox's resolved
pack and admin policy (`packs.Effective.EgressDecider`) and its unblocks. One
sandbox's block list, ports, mode or unblocks therefore never decide another
sandbox's traffic. The manager re-registers every credential with a rebuilt
decider after creates, deletes, configuration changes and reconciles.
Unblocks take effect at once, because the decider looks them up live. The
proxy's own decider (`Options.Decider`, `SetDecider`) is only the fallback
for a principal without one.

A sandbox whose policy stops resolving fails closed. This happens when its
custom pack is deleted or edited into one that no longer loads, or when the
configuration no longer accepts one of its run flags. The manager does not
keep serving it with the decider of its last good policy, because that
decider holds the administrator's lists as they were then. Instead:

- its proxy credential is revoked, so the proxy refuses the sandbox (407);
- triage leaves its proposals pending, and approvals report the error;
- each reconcile judges its approved OpenShell rules by the organization's
  policy alone: the administrator's constraints and DefenseClaw's own, under
  the default pack. When even that cannot be resolved (a broken required
  pack), every triaged rule is removed.

The feed, the log (`OPENSHELL_PACK_INVALID`) and a degraded health record
say so once. The credential comes back with a rebuilt decider as soon as
the policy resolves again.

### Request handling

- **CONNECT tunnels** carry HTTPS as opaque bytes. The proxy never terminates
  TLS, so certificate-pinning clients keep working. It reads the TLS server
  name (SNI) and ends a tunnel whose name it would block, so an allowed name
  or address cannot front for a blocked site on the same CDN.
- **Plain HTTP inside a tunnel** (Node's `fetch` tunnels `http://` URLs) is
  read request by request and forwarded only when each request's host is the
  tunnel's own host. After a WebSocket upgrade the bytes are relayed as they
  are; other upgrade offers are stripped so the tunnel stays inspected.
- **Other protocols** (SSH, databases) are relayed only on ports the operator
  added. On ports 80 and 443 they, and HTTP/2 without TLS, get a 400 inside
  the tunnel.
- **Absolute-form requests** (plain `http://`) are forwarded with hop-by-hop
  headers and the proxy credential stripped.

Blocked requests get a JSON 403 body that the agent can read: the host, the
category, a reason, whether it can be unblocked, and how to ask. Limits get a
429.

### Decision order

This is the one egress semantics. The policy layer (`packs`), the proxy,
triage, REST unblock and the activity feed all use it, because each asks the
same decider. `Decider.Decide` applies these layers in order, and the first
that decides wins:

1. **Guard.** The destination must be a valid host and port.
   - This machine and what only it reaches are never reachable
     (`host_internal`): loopback, its own addresses, `localhost`,
     `host.openshell.internal`, link-local and cloud metadata addresses, and
     reserved ranges.
   - Private networks are reachable only where an allow entry names them
     (`private_network`). These are RFC 1918, carrier-grade NAT and IPv6
     unique local addresses, the other hosts on this machine's subnets, and
     intranet names. The allow entry can come from `openshell.egress.allow`,
     the pack's `egress.allow` or `openshell.admin.egress_allow_only`.
   - The port must be on the port list (80 and 443 by default).
   - Guard blocks can't be unblocked.
2. **The administrator's lists.** `openshell.admin.egress_block` refuses
   (`admin_block`). A non-empty `openshell.admin.egress_allow_only` refuses
   everything outside it (`admin_allow_only`). Nothing but the administrator
   lifts either. The block message says "blocked by your organization's
   DefenseClaw policy".
3. **The block list**: the pack's `egress.block` plus `openshell.egress.block`
   (`operator_block`). It is checked before unblock decisions, so a host on
   it is not one-click unblockable. Reaching it takes removing the entry.
4. **Unblock decisions**, for one sandbox or for every sandbox ("always",
   saved to `openshell.egress.unblocked`). They are ignored when
   `openshell.admin.allow_unblock` is `false`.
5. **The allow list**: the pack's entries (the curated allowlist included)
   plus `openshell.egress.allow`. It exempts a host from the feed. When
   `allow_unblock` is `false`, the feed is checked first, so nothing lifts a
   feed entry.
6. **Blocklist feed.** A feed block is unblockable, unless `allow_unblock` is
   `false`.
7. **Allow-only entries** allow.
8. **Mode default.** Open mode (the `open` profile) allows host names. It
   blocks IP literals as `ip_literal`, because a literal would sidestep the
   name-based feed, until the literal is unblocked. Allowlist mode (the
   `balanced` profile) blocks the rest as `not_allowlisted`, which can also
   be unblocked. Neither block is unblockable when `allow_unblock` is
   `false`. The `strict` profile runs without the proxy.

`Decision.Unblockable`, the 403 body's `unblockable` and `how_to_unblock`,
blocked events and the feed's unblock action all follow steps 6 and 8.

Host names are resolved on the proxy side as fully qualified names, never
through the host's search domains. Every DNS answer passes the SSRF policy
just before the connection, and the dial targets the checked address, so DNS
rebinding between check and dial has nothing to exploit. A feed's IP and CIDR
entries and operator CIDR blocks also apply to the resolved address.

### Feeds

Both feeds are embedded from `policies/sandbox/egress/`. Host patterns are an
exact host or `*.` for every subdomain (not the apex).

- `blocklist.yaml` (`defenseclaw-blocklist`) lists services whose main use
  from an unattended agent is moving data to a place anyone can read or past
  network controls. Categories: `paste_site`, `file_drop`, `webhook_catcher`,
  `tunnel`, `anonymizer`.
- `allowlist.yaml` (`defenseclaw-allowlist`) is the allowlist-mode feed of a
  decider built without a policy. A sandbox's decider uses the balanced
  pack's `egress.allow` instead, as part of the allow list. A test keeps the
  two lists identical. Categories: `package_registry`, `source_hosting`,
  `toolchain`, `documentation`. CONNECT tunnels are opaque, so the proxy cannot tell a
  download from an upload: every listed host with a write API (GitHub, GitLab,
  the registries' publish endpoints) can receive data too. The balanced
  profile narrows destinations; it is not an exfiltration barrier for those
  hosts.

`FirewallBlockPatterns` carries over only outbound TCP deny rules with a
destination that cover the proxy's ports. The host firewall's default action
and allowlist scope what the DefenseClaw host itself may reach and are not
applied to sandboxes.

### Byte counts and large uploads

The `Counter` keeps bytes up and down per tunnel and per destination. When
the bytes sent to a destination this sandbox had not contacted before cross
the large-upload threshold (`large_upload_mb`, 25 MiB in the `open` pack), it
raises a `large_upload` event once. Uploads to first-seen hosts are also
totalled per registrable domain and per resolved address (per /64 for IPv6),
so rotating subdomains or domains that point at one server does not reset the
count. `CounterOptions.BlockLargeUploads` can also cut the tunnel; no
configuration key selects it yet.

### Limits

At most 1,024 client connections in total; per binding 256 connections, 256
concurrent tunnels or requests, and 50 new ones a second with a burst of 200.
Headers must arrive within 10 seconds, and an idle tunnel closes after 10
minutes.

### Events

The proxy reports `allowed`, `blocked`, `closed`, `failed`, `auth_failed` and
`large_upload` events to an `EventSink`. Events never carry credentials, URL
paths or query strings. The sink that turns them into `log.egress.allowed`
and `log.egress.blocked` records (source `dc-egress-proxy`) and
`sandbox.large_upload` findings is part of the manager.

### Relation to the pack posture

`packs.Effective` is the single source of the egress policy.
`Effective.EgressOptions` is the only translation from the resolved posture
to `egress.DeciderOptions`:

- the network mode;
- the ports;
- the built-in feed when the policy has it;
- the administrator's block and allow-only lists;
- the block list;
- the allow list, which already holds the curated allowlist when the
  profile needs it, so the proxy's own allowlist feed is not used;
- `NoUnblock` for `openshell.admin.allow_unblock: false`;
- the sandbox's unblocks.

The rest of the package asks the decider this builds:

- `Effective.EgressDecider` builds each sandbox's proxy decider.
- `Effective.DecideEgress` reports the decider's verdict before any unblock,
  as a `packs` rule name.
- `Allow(ActionUnblock)` accepts only what that verdict lets an unblock lift.
- `Allow(ActionApprove)` checks the guard and the feed with it.

No feed matcher is passed around: the policy uses the proxy's own feed.
`internal/openshell/manager/egress_semantics_test.go` drives the policy
layer, a live proxy, REST unblock and triage with the same inputs and pins
that they agree.

## Provider credentials and LLM traffic

LLM traffic never goes through DefenseClaw. OpenShell adds a
`_provider_<name>` rule for every provider attached to a sandbox, and only
those rules substitute credential placeholders. `internal/openshell/profiles`
renders the provider profiles, which the manager imports the first time a
sandbox needs one (`defenseclaw sandbox setup` imports the ingress profile
ahead of time):

| Profile | Credential | Sent as | Endpoint |
| --- | --- | --- | --- |
| `defenseclaw-ingress-<ingress_port>` | `DEFENSECLAW_SANDBOX_TOKEN` | bearer | `host.openshell.internal:<ingress_port>` |
| `defenseclaw-anthropic` | `ANTHROPIC_API_KEY` | `x-api-key` | `api.anthropic.com:443` |
| `defenseclaw-claude-oauth` | `CLAUDE_CODE_OAUTH_TOKEN` | bearer | `api.anthropic.com:443` |
| `defenseclaw-claude-bedrock-mantle-<region>` | `ANTHROPIC_API_KEY` | `x-api-key` | `bedrock-mantle.<region>.api.aws:443` |
| `defenseclaw-openai` | `OPENAI_API_KEY` | bearer | `api.openai.com:443` |
| `defenseclaw-codex-bedrock-mantle-<region>` | `BEDROCK_MANTLE_API_KEY` | bearer | `bedrock-mantle.<region>.api.aws:443` |
| `defenseclaw-opencode-anthropic` | `ANTHROPIC_API_KEY` | `x-api-key` | `api.anthropic.com:443` |
| `defenseclaw-opencode-openai` | `OPENAI_API_KEY` | bearer | `api.openai.com:443` |
| `defenseclaw-opencode-bedrock-mantle-<region>` | `BEDROCK_MANTLE_API_KEY` | `x-api-key` | `bedrock-mantle.<region>.api.aws:443` |
| `defenseclaw-copilot-github` | `COPILOT_GITHUB_TOKEN` | bearer | `api.github.com:443` and the Copilot API hosts |
| `defenseclaw-copilot-anthropic` | `COPILOT_PROVIDER_API_KEY` | `x-api-key` | `api.anthropic.com:443` |
| `defenseclaw-copilot-bedrock-mantle-<region>` | `COPILOT_PROVIDER_API_KEY` | `x-api-key` | `bedrock-mantle.<region>.api.aws:443` |
| `defenseclaw-amp` | `AMP_API_KEY` | bearer | `ampcode.com:443` |
| `defenseclaw-cursor` | `CURSOR_API_KEY` | bearer | `api2.cursor.sh:443`, `api3.cursor.sh:443`, `repo42.cursor.sh:443` |
| `defenseclaw-kiro` | `KIRO_API_KEY` | bearer | `q.us-east-1.amazonaws.com:443`, `runtime.us-east-1.kiro.dev:443`, `management.us-east-1.kiro.dev:443`, `prod.us-east-1.auth.desktop.kiro.dev:443` |
| `dc-cred-<hash>` | the `--credential` variable | bearer | the host and port it is bound to |

The Copilot GitHub-token, Amp, Cursor and Kiro endpoint sets come from the
pinned CLIs, not from a live run (no account was available). Devin CLI has no
provider profile: it authenticates with an interactive login inside the
sandbox.

An in-sandbox vendor login (`cursor-launch login`, `kiro-launch login
--use-device-flow`, `devin-launch auth login --force-manual-token-flow`;
`HarnessSpec.Login`) runs through the harness launcher, which exports the
egress proxy, so its traffic goes through the proxy (OpenShell refuses a
connection around it). The login stores a long-lived vendor account token in
the sandbox HOME. Unlike a provider placeholder, the workload can read that
token and send it out through any destination the profile allows, and a kept
sandbox reuses it. Prefer the API-key provider profile where there is one
(`defenseclaw-cursor`, `defenseclaw-kiro`); Devin has none, so log out or
delete the sandbox after use.

LLM profiles are pinned to the realpaths of the harness binaries that the
image probe recorded, so no other program in the sandbox can use the key; an
inference credential usable by every binary is refused. The ingress profile
allows every binary: hooks post with `curl`, and the harness itself exports
OTLP. There is no egress profile: the proxy credential travels in
`HTTPS_PROXY`, which OpenShell cannot substitute on a raw relay.

Provider profiles are global to the OpenShell gateway, so every DefenseClaw
daemon (every data dir) on it shares them, and updating one re-points every
sandbox whose providers use it. A profile's id therefore names everything its
endpoints depend on:

- The ingress profile is one per ingress listener. A second daemon on other
  ports (a dev daemon next to the usual one), or the same daemon after a port
  change, imports its own and never rewrites another's endpoint. Daemons that
  use the same port in turn share an identical profile.
- A Bedrock Mantle profile is one per region, so sandboxes using different
  regions never share an endpoint.
- The Anthropic, Claude OAuth and OpenAI profiles have fixed endpoints and are
  shared. The one thing they accumulate is the binaries of every image that
  used them, and that list only grows, so an update never takes a binary away
  from a running sandbox. An update names the resource version it replaces:
  when another daemon updated or imported the profile first, the manager
  merges again from what the gateway holds.
- A `dc-cred-<hash>` profile hashes the variable, host and port it binds, all
  it holds, so sharing it is safe too.

Everything else DefenseClaw creates on the gateway is its own: sandboxes and
providers (`<sandbox>-ingress`, `<sandbox>-llm`, `<sandbox>-cred-<n>`) carry
the data dir's owner label, and a create never replaces a provider of that
name that another data dir (or a user) owns. Policy rules, `defenseclaw_egress`
among them, belong to one sandbox's policy, and the overlay image tags hash
the owner and the ingress port. Earlier releases imported one gateway-wide
`defenseclaw-ingress` profile, holding one daemon's port, and single-region
`defenseclaw-claude-bedrock-mantle` and `defenseclaw-codex-bedrock-mantle`
profiles. Sandboxes created then keep using them, and nothing updates them
any more.

`defenseclaw sandbox teardown` deletes this data dir's own ingress profiles
(the configured listener's and any its providers used), the legacy
`defenseclaw-ingress`, and the shared LLM and credential profiles, each only
when no other provider uses it. It never deletes another daemon's ingress
profile, and OpenShell refuses to delete a profile a provider still uses.

## Sandbox policy

`internal/openshell/policy` renders the typed OpenShell `SandboxPolicy`. The
output is deterministic and golden-tested (`internal/openshell/policy/testdata`),
because every policy reload closes connections.

- **Landlock** is `hard_requirement`: a kernel without the needed ABI refuses
  to start the sandbox instead of running it unconfined.
- **Read-only:** `/usr`, `/lib`, `/etc`, `/proc`, `/dev/urandom`, `/var/log`,
  `/opt`, the harness install roots and read-only context mounts.
- **Read-write:** `/tmp`, `/dev/null`, `/dev/ptmx`, `/dev/pts`, `/dev/tty`,
  `/sandbox` and the workdir (`/work/<repo>` in mount mode).
- **Process:** the numeric host uid and gid in mount mode (required), the
  image's `sandbox` user in copy mode. Root is refused.
- **Network:** `defenseclaw_egress` for the `open` and `balanced` profiles,
  nothing for `strict`. Credentialed endpoints are left to OpenShell's
  provider rules, except the ingress of a `token_delivery: env` sandbox,
  which has no ingress provider and gets `defenseclaw_ingress` in every
  profile. Extra rules (for example a consented host port) may not use
  the reserved `defenseclaw_` or `_provider_` prefixes. They may reach
  `host.openshell.internal` only on a consented host port, which can never be
  the ingress, egress, main API or OpenShell gateway port. Loopback names,
  wildcards that could match them, and IP literals in loopback, link-local,
  metadata, CGNAT or OpenShell's synthetic range are refused.

## Workspace

`internal/openshell/workspace` gives the harness the project folder and
nothing else, and lets the operator take back what the agent did.

### Mount mode

Mount mode is the default. `PlanMount` validates the launch folder and turns
it into docker-driver bind mounts:

| Mount | Target | Access |
| --- | --- | --- |
| The project | `/work/<repo>` | read-write |
| The git directory and up to 32 submodule git directories, each bound onto itself so it cannot be renamed away and replaced | same paths | read-write |
| In each of those, `config`, `config.worktree`, `hooks` and `commondir`; also a `core.hooksPath` inside the project, config include files, the worktrees admin directory and a `.git` pointer file | same paths | read-only |
| Each detected secret file or directory | same path | read-only empty file or directory |
| Each extra reference folder | beside the project under `/work` | read-only |

Missing protection targets (an empty `config` or `config.worktree` file, an
empty hooks directory, a `commondir` file that makes git use the git directory
itself) are created on the host so they can be bound, and removed again by
`ReleaseMount`. `config.worktree` is bound even when the project has none, so
the agent cannot plant one for host git to read. The manager must call
`ReleaseMount` when a sandbox is deleted, not when it stops, because a
restart reuses them.

The folder is refused outright when it:

- is reached through a symbolic link (the error names the real path), is not
  a directory, or is a top-level system directory;
- is part of the operating system (`/etc`, `/usr`, `/var/lib`, `/System`,
  `/Library`, `/opt/homebrew` and similar) or holds many projects or users
  (`/tmp`, `/home`, `/Users`, `/Volumes`, `/data` and similar);
- is your home directory or contains it;
- is inside, or contains, a credential or state directory under your home
  (`.ssh`, `.aws`, `.config`, `.gnupg`, `.kube`, `.docker`, `.azure`, the
  OpenShell and DefenseClaw state directories, `Library` and others, with
  their XDG equivalents), or the DefenseClaw data directory.

It needs copy mode instead (`NeedsCopyError`) when its git state cannot be
protected in place, for example when `.git` is a symbolic link, the git
directory lives outside the folder (a linked worktree or submodule checkout),
`core.worktree` is set, `core.hooksPath` is the project itself or leaves it
through a link, there are more than 32 submodule git directories, or there
are more than 256 secret files to mask. A secret scan that cannot finish
(more than 250,000 entries) refuses the mount.

### Secret masks

A file is masked when:

- its name matches a built-in credential name (`.env`, `.env.*`, keys and
  certificates, `.netrc`, `.npmrc`, `credentials.json`, `*.tfstate` and
  others) or it sits in a credential directory (`.ssh`, `.aws`, `.kube` and
  others). Templates such as `.env.example` stay visible;
- it matches a pack or `openshell.workdir.masks` glob; or
- the ClawShield secret rules find a critical-severity credential in it
  (files up to 256 KiB, at most 2,000 of them).

Unmask globs (the pack's templates, `openshell.workdir.unmask`) keep a path
visible. A tracked file whose name looks secret but whose content is exactly
the committed version stays visible, because the agent can read it from the
repository anyway, unless a pack or config glob names it. A masked file with
other hard links is flagged, because the same bytes may be visible under
another name.

### Snapshot and undo

`Snapshot` records the folder before the session.

- **Git projects.** The whole working tree, tracked and untracked (ignored
  files are left alone, but their paths are recorded), is committed into a
  DefenseClaw-owned shadow git directory,
  `<data_dir>/shadows/<project-key>.git`, under
  `refs/defenseclaw/pre/<name>`. The ref is also written into the project
  unless disabled. HEAD, the branch, other refs, the staging area and the git
  control files the agent could write are recorded.
- **The shadow's own objects.** The shadow keeps a private copy of the
  project's git object files, so the snapshot survives the agent deleting or
  rewriting `.git/objects`. Each file is cloned where the filesystem supports
  it (reflink, APFS `clonefile`) and byte-copied otherwise, up to 1 GiB of
  copies. Past that cap the rest is shared with the project through git
  alternates and the snapshot records a warning: if the session deletes or
  rewrites those objects, undo cannot bring back the history they hold. Hard
  links are never used, because a hard link shares the file the agent can
  rewrite.
- **Other folders.** A copy under `<data_dir>/snapshots/<name>/tree/`, using
  file clones where the filesystem supports them, capped at 1 GiB and 250,000
  entries. A larger folder is refused, because a partial snapshot would make
  undo delete what it left out.
- **Both.** A walk records the files that can run code on the host, the
  nested repositories that already exist, and fingerprints of dependency
  directories, so the review sees changes git ignores.

`Undo` needs the sandbox stopped first (the manager must stop it), and has a
preview mode. In a git project it:

- restores the working tree, HEAD and the branch, the staging area and the
  git control files the agent could write;
- resets branches and tags to their pre-session values (unless `KeepRefs` is
  set). First it saves every tip the session created or moved in the project,
  under `refs/defenseclaw/post-refs/<name>/<ref>` (for example
  `refs/defenseclaw/post-refs/<name>/refs/heads/main`), and its warnings list
  the saved refs;
- copies back pre-session commits whose objects were deleted during the
  session;
- removes the `.git` of each repository the session created inside the
  folder;
- keeps ignored files that existed before the session, even when the session
  removed the rule that ignored them. Up to 128 MiB of them are kept; past
  that cap the rest are removed like other new files (they remain in the
  post-session commit) and undo warns;
- removes files the session hid with changed ignore rules. They stay
  recoverable from `refs/defenseclaw/post-hidden/<name>` in DefenseClaw's
  shadow git directory, not in the project, so git run in the project does
  not see that ref.

Undo refuses to run when the project's git directory was replaced during the
session (`ErrGitDirReplaced`), because the new one may carry a planted
configuration. The error names the shadow git directory and the pre-session
commit, which stay available for inspecting the folder by hand.

In a folder without git, undo copies the snapshot back and removes the `.git`
of every repository the session created, including a new top-level `.git`.

The folder as the session left it is kept as a shadow commit, and as
`refs/defenseclaw/post/<name>` in the project where possible, so an undo can
itself be reverted.

Every git command DefenseClaw runs on the host goes through
`internal/gitsafe`, and every post-session operation that touches the working
tree runs against the shadow git directory, never the project's own `.git`.
A planted config, attributes file, `commondir` or hook in the project is
never consulted.

### End-of-session review

`Review` compares the folder with its snapshot without changing it. It
reports a diffstat and flags, most severe first, the changes that can run
code on your machine:

- **Critical:** a new nested git repository, a `.git` directory created in a
  folder that had no git, a replaced git directory (undo then refuses to run),
  a changed git control file inside the git directory that the agent can
  write (such as `info/attributes` or `objects/info/alternates`; undo restores
  it), a symbolic link that points outside the project (host tools follow it
  to your files), and a new or changed submodule URL in `.gitmodules`.
- **High:** changed npm lifecycle scripts (`postinstall` and the like), new
  filter, diff or merge drivers in `.gitattributes`, files that run
  implicitly (`.envrc`, editor tasks and settings, IDE run configurations,
  dev containers, git hook managers, package-manager config, Python tooling,
  build files), new executables or files made executable, and paths matching
  the pack's `workspace.review` globs.
- **Medium:** other npm scripts and dependency changes, CI definitions,
  container builds, version-manager files, a secret-like file created or
  changed, a changed dependency directory (packages installed in the
  sandbox run on the host when you use them), changed ignore rules that newly
  hide paths from the diff, and a git file that is read-only in the sandbox
  (such as `.git/config`, `config.worktree` or the hooks) but changed anyway,
  which means the change was made on the host.

Host-executable files that git ignores are found by re-walking the folder.
The ClawShield secret rules and CodeGuard also scan the changed files (files
up to 1 MiB, at most 2,000 of them).

### Planted nested repositories and the live guard

Mount mode cannot stop the agent from creating a new git repository inside
the project folder. Git reads a repository's own configuration whenever it
runs inside that repository, and some git settings (for example
`core.fsmonitor`) name a program git starts by itself. So an agent could leave
behind a nested repository that runs a program on your machine the next time
something on the host runs git inside that subfolder: you, your editor, or a
git-aware shell prompt.

The daemon therefore runs a nested-repository guard
(`internal/openshell/nestguard`) for every mounted sandbox while it is ready:

- Before the sandbox runs (at create and at every start), the manager records
  the `.git` entries the folder already holds. Those are never touched.
- While the sandbox runs, the guard watches the folder with inotify (on
  macOS, and when the watch limit is reached, it falls back to a bounded
  periodic scan). The moment a new `.git` entry appears at any depth,
  directory, file or symbolic link, including the top level of a folder that
  had no git, the guard renames it to `.git.defenseclaw-quarantine-<time>`.
  The rename walks the path with `O_NOFOLLOW` directory handles and never
  replaces an existing name, so a symbolic link the agent swaps in cannot
  redirect it. No git on the host ever reads the planted configuration.
- It also reports new gitlink (submodule) entries in the project's index;
  those are not changed.
- Each detection is kept on the sandbox record (`nested_repos` in the REST
  API), emitted as a `quarantine` `log.sandbox.workspace` record and a
  `sandbox.nested_repo` finding, and published on the activity feed, where
  the run UI, `sandbox activity` and the TUI show it. The end-of-session
  summary lists it again.

So running git in the project on the host is safe while the guard runs: a
repository the agent plants is quarantined before a host git command can use
it. The guard runs only while the sandbox is ready. It also quarantines a
repository you create in the folder yourself during a session (rename it
back when you are done). Review still flags the quarantined entry, and undo
removes it.

For untrusted repositories or tasks, use copy mode. There the agent's work
comes back as git objects in a verified bundle, which cannot carry another
repository's configuration, and nothing reaches the host folder until the
operator applies it.

### Copy mode

Copy mode is the choice for untrusted repositories or tasks. The agent works
on a copy, and changes come back only through a verified pull.

1. **Stage.** A git project becomes a sanitized shallow clone (depth
   `openshell.workdir.git_depth`, 200 by default; no hooks, config written by
   DefenseClaw, remotes without credentials) with the current working tree on
   top. A plain folder is copied with a hidden git directory kept at
   `/sandbox/.dc/git`. Secrets are held back by the mask rules, tracked files
   included, and the committed versions of held-back files are removed from
   the shipped history: the copy becomes a partial clone whose promisor
   remote has no URL, so asking git for one of those blobs fails instead of
   reading it. The size is checked first (`max_upload_mb`, 500 MiB in the
   `open` pack).
2. **Upload.** The copy goes to `/sandbox/work/<repo>`, which the sandbox user
   can write, and `refs/defenseclaw/baseline` marks the starting point. The
   upload creates the harness's workdir, so `sandbox run` creates the
   sandbox, uploads, sets the baseline, and only then probes the workdir and
   starts the harness; `connect --refresh` probes outside the workdir before
   it replaces the copy.
3. **Pull.** A capture in the sandbox writes `refs/defenseclaw/result` (HEAD
   plus uncommitted work) and streams it back as a git bundle, capped at 1 GiB
   by bytes received. The bundle is verified against the staged history,
   changes to held-back paths are dropped, and the result gets the same review
   as mount mode. Nothing in the project changes yet.
4. **Apply.** `apply` merges the result into the working tree three ways (git
   2.38 or newer; older git, or a conflict, falls back to a `dc/<name>`
   branch for git projects plus a patch file), `branch` creates `dc/<name>`,
   and `patch` writes a patch file. `branch` needs a git project; a plain
   folder cannot use it. Three gates apply:
   - A pull that was refused outright has no result, and nothing can apply
     it, not even as a patch.
   - Blocking reasons (a rewritten history, a new or changed remote, a
     submodule change) stop `apply` and `branch` until the operator forces
     them (`Force`).
   - A review with a high or critical flag or a critical secret stops `apply`
     and `branch` until the operator accepts the sensitive changes
     (`AcceptSensitive`), a separate confirmation.

   `patch` only writes the patch file, so the last two gates do not apply to
   it.

Mount plans and copy records supply the sandbox labels
`io.defenseclaw/project` (the first 128 bits of the SHA-256 of the folder's
real path, in hex) and `io.defenseclaw/workdir-mode`, so a later run can find
and resume the sandbox. A refresh refuses to replace a copy
whose last pull was never applied. Host git must be 2.29 or newer.

### Where state lives

```text
<data_dir>/snapshots/<name>/snapshot.json    snapshot record
<data_dir>/snapshots/<name>/tree/            non-git snapshot copy
<data_dir>/shadows/<project-key>.git         shadow git directory
<data_dir>/sandboxes/<name>/workspace/       mask files and mount state
<data_dir>/sandboxes/<name>/copy/            copy record, base.git, pulls
<data_dir>/sandboxes/bindings.json           ingress bindings
<data_dir>/sandboxes/images.json             overlay image records
<data_dir>/sandboxes/manager/<name>.json     the daemon's sandbox record
```

A mounted sandbox deleted with `--keep-snapshot`, or deleted outside
DefenseClaw, keeps its snapshot and a retained record: it stays listed with
phase `deleted`, `undo` and `review` still work on it, and `delete` drops the
snapshot. Until then its name cannot be reused.

Sandbox names follow the OpenShell rule (a DNS label: lowercase letters,
digits and `-`, at most 63 characters, starting and ending with a letter or
digit), and `git` is reserved.

## Overlay images

`internal/openshell/image` builds one image per harness, uid and ingress port
(and every other input) on top of the digest-pinned NVIDIA community base
(`ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63…`;
`openshell.image.base` overrides it and must also be digest-pinned).

### Build

The builder renders a deterministic context (a Dockerfile plus files whose
modes and owners are set in the tar headers) and streams it to
`docker build --pull=false -t <tag> -`. The Dockerfile:

1. Installs `jq` and `curl` if the base lacks them on the hook PATH
   (`/usr/bin:/bin:/usr/sbin:/sbin`).
2. Installs the harness at a version whose Linux hook contract is known. Any
   other version fails before the build starts. The default Claude Code pin,
   2.1.156, is relocated from the base image (other pins install from npm);
   Codex 0.146.0 replaces the base image's 0.117, which is outside every
   reviewed contract. Binaries move to root-owned
   `/opt/defenseclaw-harness/<harness>`, so a native installer's copy under
   `$HOME` never becomes the pinned binary.
3. Copies DefenseClaw's files root-owned and read-only under
   `/usr/local/lib/defenseclaw` (hooks in `hooks/`, launchers in `bin/`),
   the harness's managed configuration, and the user-owned first-run files
   under `/sandbox`.
4. Creates `/work` root-owned, chowns `/sandbox` to the run-as uid and gid,
   and switches to the `sandbox` user.

The tag is `defenseclaw/sandbox:<harness>-<hash>-u<uid>`, where `<hash>` is
the first 16 hex digits of a content hash over every input: the base digest,
harness and version, hook contract, uid and gid, ingress port, fail mode,
DefenseClaw version, the store owner and every file's bytes, mode and owner.

A probe run with `--network none` then checks the in-image bytes, modes and
owners and records the harness version and the realpaths and SHA-256 digests
of the required binaries in `<data_dir>/sandboxes/images.json`. The LLM
provider profiles pin the realpaths of the binaries that open model
connections. Each data directory has a random store owner that is part of
the hash and a label, so two data directories sharing one Docker daemon never
select or prune each other's images.

### Hook-fire verification

A hook script can be present and never run: Claude Code silently drops a
whole managed-settings drop-in that has one field it does not accept. So
`Build` ends with a hook-fire probe. It runs the harness headless in the new
image against a built-in mock LLM and a stand-in ingress on the image's baked
port, and requires that:

- an allowed tool call's side effect appears;
- a tool call the stand-in ingress blocks has no side effect;
- `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse` and `Stop`
  each arrive authenticated and with an idempotency key.

For both harnesses the allowed run is repeated with hostile user and project
settings planted: every known way to switch the managed hooks off or divert
them. The hooks must still fire, and none of the planted programs may run.
`HookFireOptions.RunFiles` mounts a sandbox's per-run files into every probe
container. `TestLiveRunConfig` (tag `openshell_integration`) uses it to prove
the per-run configuration below against the real harnesses.

Kiro CLI has no model endpoint a mock can stand in for; its own
scripted-response mode (`KIRO_MOCK_CHAT_RESPONSE`, with a placeholder
`KIRO_API_KEY`) replays the same scenarios instead, so its probe runs with no
mock server and no network. The probe writes the scenario's script into the
container before each run.

`Store.Current` selects only an image built from exactly the expected inputs
whose hooks were proven to fire. There is no fallback to an older image. An
image that fails the static checks is removed; one whose hooks do not fire
stays recorded as unverified and `Build` returns `ErrHooksNotFired`. Never
launch an unverified image.

On Linux the probe runs on the host network with the stand-in on
`127.0.0.2`, leaving `127.0.0.1:<ingress_port>` to a running daemon. Docker
Desktop uses a relay mode instead.

### Tamper tiers

Each connector publishes a tamper tier (`SandboxArtifacts.TamperTier`):

- **managed:** the hook registration lives in the harness's system policy,
  root-owned in the image, and user or project settings cannot switch it off.
  `claudecode`, `codex`, `copilot` and `cursor` are managed.
- **user:** the registration lives in a file the agent can edit, or code the
  agent or a repository adds runs beside the hooks. `opencode`, `amp`, `kiro`
  and `devin` are in this tier; the hook-silence finding is the backstop.
  [Sandboxed connectors](#sandboxed-connectors) has the details.

### Hook tamper detection

A sandbox hook is judgment inside the boundary. It runs as the workload's
uid, in the workload's PID namespace, and Claude Code treats a hook that dies
with anything but exit code 2 as a non-blocking error, so a workload that
kills its `PreToolUse` hook gets that tool call run without a DefenseClaw
verdict. The file and egress boundaries are enforced outside the sandbox and
do not depend on the hooks. The manager watches for the two ways a
compromised hook shows:

- **Hook silence** (`hook_silence`): the harness is active (OCSF process or
  network events, egress, native OTLP) for `HookSilence` without a single
  hook request.
- **Hook tamper** (`hook_tamper`, `internal/openshell/manager/hook_tamper.go`):
  a tool that ran without a verdict. Claude Code and Codex send the same
  per-call `tool_use_id` with a call's `PreToolUse` and its `PostToolUse`.
  Per binding, the manager records each `PreToolUse` decision and pairs it
  with the result. A `PostToolUse` whose `PreToolUse` was denied, or never
  arrived, raises a HIGH `hook_tamper` finding, a `finding` activity entry
  and a count in the sandbox's hook coverage (`tampered`,
  `last_tamper_at`). Claude Code's `PostToolUseFailure` and `PermissionDenied`
  close a call but never prove tamper: Claude can report a failure before
  `PreToolUse` ran. The pairing reads only events named exactly
  `PreToolUse` and `PostToolUse` that carry a per-call ID. Copilot CLI,
  Cursor Agent, Kiro CLI, OpenCode and Amp name their events differently, so
  for them hook silence is the backstop; their pre-tool events still count
  in the session summary's tool calls and blocks.

The pack's `hooks.on_tamper` picks the response: `stop` (the default in
`balanced` and `strict`) stops the sandbox once per session; `alert` (the
default in `open`) reports and leaves it running. The ledger is bounded per
binding (1024 open calls, 1024 finished or denied ones; oversized IDs are kept
as digests). An open call pushed out by newer ones is remembered as seen, so
a long-running tool is not flagged. Ledgers are dropped when the binding is
revoked or no sandbox holds it any more. "Never arrived" is only proved for a
session that started under the running daemon: after a daemon restart, a
running sandbox's ledger is partial until its next start, and only denials
seen since the restart count. The workload can still forge hook requests of
its own; the detector catches a killed or bypassed hook, not a workload that
imitates one.

### Hooks that do not reach DefenseClaw

Sandbox hooks fail closed, so a session whose hooks cannot reach the ingress
blocks every tool call while the harness may still exit 0
(`internal/openshell/manager/reach.go`). The manager flags a session (the
time since the sandbox last became ready) once, as a HIGH `hook_silence`
finding and a `finding` activity entry with reason `hooks_unreachable`, when:

- OpenShell refuses a hook's connection or request to the ingress port: the
  sandbox's policy does not allow it. This is reported at once, also after
  hooks that got through.
- OpenShell lets a hook connect but no authenticated request follows within
  15 seconds: the ingress does not answer, or the sandbox token did not reach
  the hook.
- The harness works (a model call, a local model endpoint, OTLP, egress) for
  `HookReachWindow` (30 seconds) without one authenticated hook.

An authenticated hook clears the flag (`hooks_restored` on the feed). The
sandbox's hook coverage carries `unreachable`, `unreachable_reason` and
`ingress_refused`, which `sandbox status`, `sandbox list` ("unreachable!")
and the "Sandbox hooks" check of `sandbox doctor` show. The run itself warns
live (the daemon's line, or its own once no hook arrived in the session's
first 45 seconds), ends the summary with "DefenseClaw hooks are not reaching
the daemon; every tool call is being blocked … Run: defenseclaw sandbox
doctor", and exits 69 when not one hook of the session got through (the
harness's own non-zero status wins). `sandbox logs` does the same for a
finished detached run with no hook since it started.

**Claude Code.** `/etc/claude-code/managed-settings.d/50-defenseclaw.json`
sets `allowManagedHooksOnly`, the hooks, an `otelHeadersHelper` that sends
OTLP to the ingress, the skip of the dangerous-mode prompt, and Claude's own
sandbox off (it cannot run inside OpenShell). Its managed `env` pins the
settings a hostile settings file could use to bypass the hooks:
`CLAUDE_CODE_SIMPLE=0` keeps the hooks (all but `SessionStart`) on in bare
mode, the hook-command prefix and shell overrides are emptied, `SHELL` is
`/bin/bash`, the Stop and SessionEnd hook limits keep Claude's defaults, and
loader and shell-startup variables are cleared. Startup variables that must
apply before the managed `env` does (`DISABLE_AUTOUPDATER=1`,
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`,
`CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL=1`) travel through
`sandbox create --env`. A pre-seeded `/sandbox/.claude.json` skips onboarding
and trusts `/work`, and the launcher re-approves the API key placeholder on
every start. Skip-permissions runs pass `--dangerously-skip-permissions`.

**Codex.** `/etc/codex/requirements.toml` sets `allow_managed_hooks_only`,
pins `features.hooks` on (without it a user setting can turn hooks off) and
holds the hook matrix. `/etc/codex/managed_config.toml` turns off the update
check, analytics and features that sync over the network, sets notify and
the OTLP exporters, and pins `BASH_ENV`, `ENV` and the loader variables to
empty in `shell_environment_policy.set`, which a user or trusted project
config could otherwise use to make every command source a file first.
Codex's own sandbox cannot nest inside OpenShell, so
skip-permissions runs pass `--dangerously-bypass-approvals-and-sandbox`, and
runs that keep the prompts pass `sandbox_mode="danger-full-access"` with
`approval_policy="on-request"`. The launcher exports `CODEX_API_KEY` from
`OPENAI_API_KEY`, trusts the exact working directory, stores the API key
login for interactive runs, and adds the OTLP authorization header.

### Per-sandbox managed configuration

What differs per run cannot live in the image. For every sandbox the manager
renders `connector.SandboxRunFiles` for the image's render target, writes the
files under `<data_dir>/sandboxes/<name>/run-config/` (owner-only directory,
files 0644) and bind-mounts each read-only at its in-sandbox path, in mount
and copy mode alike. Stop and start keep the files; delete removes them.

- **Claude Code:** `managed-settings.d/60-defenseclaw-run.json` sorts after
  the image's drop-in and wins over it. It pins every model-provider
  variable Claude reads (`CLAUDE_CODE_USE_*`, each provider's base URL,
  `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_CUSTOM_HEADERS`) to the run's value or
  empty, never a credential placeholder. In safe mode it sets
  `permissions.disableBypassPermissionsMode: "disable"` and
  `skipDangerousModePermissionPrompt: false`. With `mcp.project_servers:
  block` it sets `allowManagedMcpServersOnly` and `allowedMcpServers` by
  exact `serverCommand` or `serverUrl` (never `serverName`, which a
  repository could reuse). `/etc/claude-code/managed-mcp.json` lists the
  imported servers, putting Claude in its exclusive MCP mode. With `allow`
  the servers go to `/usr/local/lib/defenseclaw/run/claude-mcp-servers.json`
  instead, which the launcher merges into `~/.claude.json`. Every key is
  checked against the 2.1.156 settings schema, and the merge with the
  image's drop-in must keep the hook contract.
- **Codex:** Codex reads one `managed_config.toml` and one
  `requirements.toml`, so both are the image's documents with run keys
  added, mounted over the image's files and re-verified with the image
  verifier. `managed_config.toml` pins the run's model provider
  (`model_provider`, plus `openai_base_url` or a `model_providers` table) and
  defines the imported servers with `cwd` and `env_vars` pinned.
  `requirements.toml` gets `allowed_approval_policies` without `never`
  (`on-request` first; Codex falls back to the first entry) and
  `allowed_sandbox_modes` in safe mode. With `block` it also gets an
  `mcp_servers` allowlist by name and command or URL identity, empty when
  nothing is imported.

The imported servers come from `Options.MCP`: the gateway's
`sandboxMCPInventory` reads the harness's user-scope servers
(`config.ReadUserMCPServersForConnector`) and drops the ones DefenseClaw
blocks (block list or MCP asset policy). The manager leaves env values and
HTTP headers out, and skips disabled servers, servers on this machine,
transports the harness cannot run, and, for Codex with `block`, a server
whose name the repository's `.codex/config.toml` also defines. Codex matches
an allowlisted server by command only and merges a project table of the same
name key by key, so the repository could otherwise add environment
variables to it. The repository's own servers are listed in the create
response's one-line notice and in `Sandbox.MCP`.

Only Claude Code and Codex have per-run managed configuration
(`connector.SandboxRunConfigProvider`). For the other harnesses the run's
model provider comes from the credential profile's environment and launch
flags, a safe run relies on dropping the harness's bypass flags from the
launch (`harness.Spec.BypassArgs`; nothing managed refuses a bypass the
workload asks for later), and no MCP servers are brought along.

The run-as identity has one source, `Manager.runAs`: the image is built for
it, create refuses an image record with another uid/gid, and the policy runs
the workload as the record's numeric uid/gid in both workspace modes.

### Sandbox hook scripts

The sandbox variant of the hooks (`internal/gateway/connector/hooks/_sandbox.sh`
plus `{{if .Sandbox}}` branches) differs from the host hooks:

- The ingress address and request budgets are baked in. The fail mode is
  always closed; the image build refuses any other value, and the host
  `DEFENSECLAW_FAIL_MODE` override is never read.
- The only credential is `DEFENSECLAW_SANDBOX_TOKEN`. A missing or malformed
  token fails the hook closed (exit code 2); there is no fallback to a host
  token file or an unauthenticated request.
- Inherited variables the hooks do not read are dropped and `PATH` is pinned
  before any child process starts, because the workload shapes the hook
  environment. No Python interpreter is started.
- Requests use `curl -q --noproxy '*'` with 2 seconds to connect and 9
  seconds in total. A transport failure or a 502, 503 or 504 is retried once
  with the same idempotency key, and the retry gets its own 12-second limit,
  so one hook can wait about 21 seconds. Codex's `SessionEnd` gets 1 second
  per attempt, because Codex caps that hook at three seconds.

## Sandboxed connectors

Each connector below has an overlay image recipe (`internal/openshell/harness`)
and rendered hook artifacts (`SandboxArtifacts` in
`internal/gateway/connector`). The tamper tier says whether the agent or a
repository can switch the hooks off:

- **managed**: the hook registration is a root-owned system or managed
  policy that user and project settings cannot switch off;
- **user**: the agent or a repository can switch the hooks off, because the
  registration is a file in the image HOME that the agent can edit or delete
  (Amp), or because code they add runs in the same process as the hooks
  (OpenCode's plugins). For these connectors the hook-silence detector and
  OpenShell's egress enforcement are the backstop.

Every sandbox invocation starts the harness through a root-owned launcher
(`/usr/local/lib/defenseclaw/bin/<connector>-launch`). The launcher refuses
the switches that would run the harness without its hooks, puts the system
directories first on `PATH`, switches Node's compile cache off, exports the
egress proxy settings (see [paths out of the workload](#paths-out-of-the-workload)),
and drops `BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`, `CDPATH`, `GLOBIGNORE`,
`NODE_OPTIONS` and `NODE_PATH` from the harness environment. Harnesses run
hooks and tool commands through bash, which reads the file `BASH_ENV` names
before the command, so one `export` in a shell start-up file the agent can
edit would otherwise run inside every hook, or end it with exit 0 (allow).
Typing the harness command in a connect or exec shell starts the launcher
through the shim on `PATH`. Starting the pinned binary by its absolute path,
or as a nested run inside a tool call (where the system directories lead
`PATH`), skips the launcher and everything it does, apart from the
environment the nested run inherits.

A connector is **verified** when its image passes the hook-fire probe (the
harness runs headless against the built-in mock LLM, its hooks reach a
stand-in ingress with the sandbox token and an idempotency key, a blocked
tool call has no side effect, an allowed one has, hostile user and project
settings and a hostile launch environment change nothing, and the launcher
refuses to start beside the code it must refuse) and it has run end to end in
an OpenShell sandbox, where a tool call the real DefenseClaw gateway blocks
never runs.
An **unverified** connector has everything up to that run implemented. Its
images stay unverified, so they are never selected for a sandbox.

| Connector | Pinned harness | Hook registration in the image | Tier | Yolo flag | Credential profiles | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Claude Code | 2.1.156 (the base image's copy) | `/etc/claude-code/managed-settings.d/50-defenseclaw.json` | managed | `--dangerously-skip-permissions` | Anthropic API key, `CLAUDE_CODE_OAUTH_TOKEN`, Bedrock Mantle | verified |
| Codex | 0.146.0 (npm) | `/etc/codex/requirements.toml` | managed | `--dangerously-bypass-approvals-and-sandbox` | OpenAI API key, Bedrock Mantle | verified |
| OpenCode | 1.18.31 (npm, native sha256 pinned) | Root-owned plugin `/usr/local/lib/defenseclaw/opencode/defenseclaw.js`, registered in `/etc/opencode/opencode.json`; the launcher refuses to start beside any other plugin | user | `--auto` | Anthropic API key, OpenAI API key, Bedrock Mantle | verified |
| GitHub Copilot CLI | 1.0.88 (npm, native sha256 pinned) | `/etc/github-copilot/policy.d/50-defenseclaw.json`, with `allowManagedHooksOnly` in `/etc/github-copilot/managed-settings.json` | managed | `--yolo` | GitHub token (endpoints unverified), bring-your-own Anthropic key or Bedrock Mantle | verified |
| Amp | 0.0.1785334225-g9abe75 (npm, native sha256 pinned) | User-owned plugin `~/.config/amp/plugins/defenseclaw.ts` | user | `--dangerously-allow-all` | Amp API key (endpoints unverified) | unverified |
| Cursor Agent | 2026.07.23-e383d2b (release archive, sha256 measured by DefenseClaw) | Enterprise `/etc/cursor/hooks.json`, every event `failClosed` | managed | `--force` | Cursor API key (endpoints unverified), or `cursor-launch login` inside the sandbox (the session is readable by the workload) | unverified |
| Kiro CLI | 2.24.1 (release archive, vendor sha256) | Root-owned agent `/usr/local/lib/defenseclaw/kiro/defenseclaw.json`, alone in the directory the launcher forces `KIRO_AGENT_CONFIG_DIR` to | user | `--trust-all-tools` | Kiro Pro API key (endpoints unverified), or `kiro-launch login --use-device-flow` inside the sandbox (the token is readable by the workload) | verified (hooks and blocking; no real model) |
| Devin CLI | 3000.4.25 (release archive, vendor sha256) | User-owned `~/.config/devin/config.json`, hooks restored from a root-owned template on every start; workspace trust skipped | user | `--permission-mode dangerous` | `devin-launch auth login` inside the sandbox (the credential is readable by the workload) | unverified |

OpenCode and Copilot CLI ran end to end in OpenShell 0.1.1 sandboxes
(`TestLiveSandboxHookOnlyHarness` in `internal/gateway`), with the project
bind-mounted, the DefenseClaw hook ingress holding a real binding, and the
DefenseClaw egress proxy, once against the E2E mock model and once against
`anthropic.claude-haiku-4-5` on Bedrock Mantle through each harness's curated
Mantle profile (the key reached the model only as an OpenShell credential
placeholder). Every hook arrived authenticated with an idempotency key and
the allowed tool call ran. With the mock and the shell tool on DefenseClaw's
block list (what `POST /enforce/block` records), the next tool call got the
real gateway's block verdict and never ran (the marker file its redirect
would create stayed absent), and DefenseClaw's reason reached the model and
showed in the harness output (OpenCode prints it as the tool's error, Copilot
CLI as "Denied by preToolUse hook"). The default rules did not flag that
call, a read of `~/.ssh/id_rsa`. A tool call's plain `curl` (no `--proxy`)
reached example.org through the DefenseClaw proxy the launcher exported, the
proxy blocked webhook.site, and a connection that bypassed the proxy was
refused by OpenShell. Besides the model endpoint, OpenCode contacted
`models.opencode.ai` (its model catalog) and `registry.npmjs.org` (it
installs its plugin SDK into each config directory in the background; a
failure is only logged). Since the launcher exports the proxy, those
registry installs go through the DefenseClaw proxy and succeed. Copilot CLI
in offline bring-your-own-provider mode contacted nothing else.

Kiro CLI ran the same checks end to end in an OpenShell 0.1.1 sandbox
through its scripted-response mode, which replays the E2E scenarios in place
of the Kiro service (there is no model endpoint to point at a mock, and no
Kiro account was available for a real model). Every hook arrived
authenticated with an idempotency key, the allowed tool call ran, the
DCBLOCK call got the real gateway's block verdict and never ran (Kiro reports
the tool as failed; a scripted run has no model to hand the reason to), a
tool call's plain `curl` reached example.org through the proxy, the proxy
blocked webhook.site, and OpenShell refused a connection around the proxy.
Even in scripted mode Kiro called its service through the proxy:
`management.<region>.kiro.dev` for us-east-1, eu-central-1, us-gov-east-1 and
us-gov-west-1, `q.us-east-1.amazonaws.com` and
`desktop-release.q.us-east-1.amazonaws.com`.

The same runs check the shells the launchers do not start. In the shell
`openshell sandbox connect` attaches to, and in a login-shell
`openshell sandbox exec`, the proxy settings came from
`/etc/profile.d/defenseclaw-sandbox.sh` and the harness command was the
exported function that starts the launcher. A `--no-login-shell` command
through `sandbox-env` had the proxy and the shim. A plain `curl` reached
example.org through the DefenseClaw proxy in each, and a bare
`--no-login-shell` command had no proxy settings. OpenShell logged a few
`DENIED` lines for the egress proxy port itself (`L7 tunnel closed before
inspection because policy changed: policy generation is stale`): tunnels
the harness opened through the proxy right after start (OpenCode's
registry installs, Kiro's service calls), cut at the first settings poll.
The harness retried them.

Cursor Agent and Devin CLI images build and pass the static probe (pinned
version, binary realpaths and digests) but stay unverified: both CLIs need a
vendor account before any agent turn and fire no hook without one.

### Harness facts

These were measured on the pinned releases inside the community base image
(Linux arm64) in September 2026.

- **OpenCode 1.18.31.** The managed config directory is `/etc/opencode` on
  Linux. OpenCode reads it after every user, project and
  `OPENCODE_CONFIG_CONTENT` layer and merges plugin lists across layers, so a
  plugin registered there with a `file://` URL loads last, and
  `plugin: []` in user or project config cannot remove it. Throwing from
  `tool.execute.before` blocks the tool. `--pure` (or `OPENCODE_PURE=1`) runs
  with no external plugin at all, and `OPENCODE_TEST_MANAGED_CONFIG_DIR`
  replaces `/etc/opencode`. The DefenseClaw launcher refuses `--pure` and
  drops both variables. As with Claude Code's bare mode, an agent can still
  start a nested `opencode --pure` as a tool call. DefenseClaw sees that call
  but not the nested session's tools. `opencode run --auto` is the headless
  skip-permissions mode. The base image ships OpenCode 1.2.18, which is
  outside every hook contract. The image removes it.
- **OpenCode plugins share the process, so the tier is user.** OpenCode
  imports every plugin into the process the DefenseClaw plugin runs in: the
  `{plugin,plugins}/*.{js,ts}` files and `{tool,tools}` custom tools of every
  config directory (`~/.config/opencode`, each `.opencode` from the working
  directory up to the worktree root, `~/.opencode`, `OPENCODE_CONFIG_DIR`),
  the `plugin` entries of every user, project and environment config layer,
  a provider SDK package it does not bundle (or a `file://` one), and the
  plugins of a remote config that a `wellknown` login fetches. The DefenseClaw
  plugin reaches the ingress through the global `fetch`. In a test with the
  pinned release, a project plugin that loaded first replaced that `fetch`,
  so it could have answered `allow` for every tool call.
  `OPENCODE_DISABLE_PROJECT_CONFIG=1` does not help: the project plugin left
  the plugin list but its module was still imported. So
  the launcher refuses to start OpenCode, naming the file, while any of
  these is present (it checks every ancestor of the working directory and of
  any directory argument, and reads config the way OpenCode does: `{env:}`
  substituted, JSONC comments dropped). The hook-fire probe plants a
  fetch-replacing project plugin, a user plugin and a project config entry
  and requires the launcher to refuse each one. What the launcher cannot
  cover keeps the tier at user: a nested `opencode` run inside a tool call
  (or the pinned binary started directly), directories OpenCode opens after
  it starts (a server's per-request directory), code added while it runs,
  and the model catalog cache in `~/.cache/opencode`, which names provider
  packages too.
- **GitHub Copilot CLI 1.0.88.** Copilot loads hook documents from
  `/etc/github-copilot/policy.d/*.json` whatever `COPILOT_HOME` says, and runs
  them even with `disableAllHooks: true` in the user settings or config. With
  `allowManagedHooksOnly: true` in the device managed-settings file
  (`/etc/github-copilot/managed-settings.json`), user (`~/.copilot/hooks`) and
  repository (`.github/hooks`) hooks are dropped. Exit code 2 from a
  `preToolUse` hook denies the tool, and so does a
  `permissionDecision: "deny"` verdict on stdout. Exit code 2 from another
  event shows as a warning and does not stop the session. The executable
  extracts its JavaScript into `~/.cache/copilot/pkg` on first run. Unless
  auto-update is off, it prefers the newest package it finds in any cache
  under HOME, so the workload could make the next launch run other code. The image pre-extracts the pinned
  package into a root-owned cache, and the launcher sets
  `COPILOT_PKG_CACHE_HOME` to it with `COPILOT_AUTO_UPDATE=false`. The
  hook-fire probe plants newer packages in both user caches to prove they are
  ignored. Copilot runs every hook through `/bin/bash` (a `bash` earlier on
  `PATH` is ignored), and that shell reads `BASH_ENV` before the hook command;
  the hook script's own `bash -p` starts too late. The launcher drops
  `BASH_ENV` and the other shell start-up variables and leads `PATH` with the
  system directories, and the probe starts Copilot with a `BASH_ENV` (and
  `ENV`) file that ends the shell with exit 0 and a `PATH` of planted `bash`,
  `sh`, `curl` and `jq`, none of which may run. Bring-your-own-provider mode
  (`COPILOT_PROVIDER_BASE_URL`, `COPILOT_PROVIDER_TYPE=anthropic`) needs no
  GitHub login, and `COPILOT_OFFLINE=true` stops every other request. The
  GitHub-token profile's hosts (`api.github.com`, `api.githubcopilot.com` and
  the per-plan Copilot API hosts) come from the CLI, not from a live run: no
  Copilot-entitled account was available.
- **Amp 0.0.1785334225-g9abe75.** Amp loads plugins only from
  `~/.config/amp/plugins` and a project's `.amp/plugins`.
  `/etc/ampcode/managed-settings.json` cannot register one, so the tier is
  user. Amp ignores `AMP_DISABLE_PLUGINS` outside its development builds. The
  plugin loads before Amp contacts its service. Every run then starts with an
  authenticated `getUserInfo` call to `AMP_URL` (`https://ampcode.com` by
  default, JSON-RPC under `/api/internal?<method>`, bearer `AMP_API_KEY`), and
  all model traffic goes through that service. Without an Amp account key the
  run stops before any agent turn, and there is no local or
  bring-your-own model endpoint that a mock or Bedrock could serve. So hook
  firing at the ingress, blocking, and the service's endpoint set are
  unverified. The plugin's executable contract (token from the environment,
  an idempotency key, one retry, fail closed) is covered by unit tests.
- **Cursor Agent 2026.07.23-e383d2b.** Cursor's installer
  (`cursor.com/install`) downloads `agent-cli-package.tar.gz` for a date-hash
  build from `downloads.cursor.com`. Cursor publishes no digests, so
  DefenseClaw pins the SHA-256 of both Linux archives it downloaded. The
  pinned CLI reads `/etc/cursor/hooks.json` on Linux as its enterprise tier,
  ahead of team (`~/.cursor/managed`), user (`~/.cursor/hooks.json`) and
  project (`.cursor/hooks.json`) hooks, runs every matching hook and lets the
  enterprise response win. It stops with "Authentication required" before any
  agent turn without a Cursor login or `CURSOR_API_KEY`, sends model traffic
  to Cursor's service (`api2.cursor.sh` by default), and has no local model
  endpoint. Cursor also publishes an `agent-cli-local` build of the same
  release that runs without an account against an Anthropic- or
  OpenAI-compatible endpoint. The image does not ship it, but the hook
  behaviour was measured on it: with the enterprise file, `sessionStart`,
  `preToolUse`, `beforeShellExecution`, `afterShellExecution`, `postToolUse`
  and `sessionEnd` fire for a headless shell call (`beforeSubmitPrompt` and
  `stop` do not in print mode); a deny object or exit code 2 blocks the call;
  a hook that exits non-zero or prints no valid object lets the call run
  unless its entry sets `failClosed`, which the image sets on every entry;
  user and project `hooks.json` that answer allow run as well but do not
  override the enterprise deny; and a Claude settings `disableAllHooks`
  changes nothing. A project `.cursor/cli.json` with an unknown key stops the
  CLI at startup. `--sandbox disabled` switches Cursor's own sandbox off (it
  cannot nest), `--trust` skips the workspace prompt, and `--force` is the
  skip-permissions mode. Hook firing and blocking with the pinned build, and
  the `CURSOR_API_KEY` endpoint set, need a Cursor key. The `cursor-agent`
  wrapper sets `NODE_COMPILE_CACHE` to `~/.cache/cursor-compile-cache` when it
  is unset. Measured with the bundled Node 24.5.0: a second start reads the
  cache there, V8 accepts it, and it runs that code in place of the
  root-owned `index.js` chunks. So every launcher exports
  `NODE_DISABLE_COMPILE_CACHE=1` (Node then reports the cache disabled and
  reads nothing) and drops `NODE_OPTIONS` and `NODE_PATH`.
- **Kiro CLI 2.24.1.** Kiro's release manifest publishes SHA-256 digests for
  its headless Linux archives. `kiro-cli` is a front end that starts
  `kiro-cli-chat` from `PATH`; the launcher starts the pinned `kiro-cli-chat`
  directly. Kiro reads hooks from the agent it runs with, and picks the agent
  `--agent` names by the `name` field of any file in `~/.kiro/agents` or the
  working directory's `.kiro/agents` (not a parent's), a project file
  winning, so a file of any name (`a.json` sorts before `defenseclaw.json`)
  replaces the agent. `KIRO_HOME`, `KIRO_TEST_AGENTS_DIR` and
  `KIRO_AGENT_CONFIG_DIR` move the agents; with `KIRO_AGENT_CONFIG_DIR` set,
  Kiro reads agents from that directory alone (neither `~/.kiro/agents` nor
  the project's). `KIRO_CHAT_SHELL` and `AMAZON_Q_CHAT_SHELL` run every
  approved shell command through a program of the caller's choosing. There
  is no system settings tier, and Kiro still reads user and project settings
  and MCP servers, so the tier is user. Headless with `--agent defenseclaw`, the
  triggers `userPromptSubmit`, `preToolUse`, `postToolUse` and `stop` fire
  (`agentSpawn` fires only for the default agent). The matcher `*` matches
  every tool; `.*` matches none, so tool hooks with it never fire. Exit code
  2 from `preToolUse` blocks the tool (Kiro reports it as failed); any other
  exit code shows as a warning and the tool runs. A missing or unparseable
  agent file makes Kiro print only `failed to set agent` and run the tool
  with no hooks. So the DefenseClaw agent lives alone in root-owned
  `/usr/local/lib/defenseclaw/kiro`, which the launcher forces
  `KIRO_AGENT_CONFIG_DIR` to on every start (the sandbox env sets it too, for
  a `kiro-cli chat` started without the launcher); the hooks fire from that
  read-only directory, and the launcher refuses to start when the agent is
  missing. The launcher pins `HOME` and drops every `KIRO_*`, `Q_*`,
  `AMAZON_Q_*`, `ASBX_KIRO_*` and `KAS_*` variable except `KIRO_API_KEY` and
  `KIRO_MOCK_CHAT_RESPONSE`. `--v3` and `--agent-engine` select a different
  engine that was not measured, and `--cloud` runs the session in a remote
  sandbox; the launcher pins `--v2` and refuses those switches.
  The image settings select the DefenseClaw agent by default and set
  `telemetry.enabled false`, `app.disableAutoupdates true`,
  `chat.greeting.enabled false` and `chat.disableTrustAllConfirmation true`
  (an interactive `--trust-all-tools` start then asks nothing); all are valid
  2.24.1 settings and the hooks fire with them. `KIRO_MOCK_CHAT_RESPONSE` (a file of
  scripted turns) with any `KIRO_API_KEY` value runs a turn with no network
  or account; the hook-fire probe and the live run use it. The hostile-settings
  probe plants hookless agents named `defenseclaw` in `~/.kiro/agents`
  (`defenseclaw.json`, `a.json`) and the project (`defenseclaw.json`,
  `project.json`), and behind `KIRO_HOME`, `KIRO_AGENT_CONFIG_DIR` and
  `KIRO_TEST_AGENTS_DIR`, and a recording `KIRO_CHAT_SHELL`; every hook must
  still fire and the planted shell must not run. `kiro-launch login` runs
  `kiro-cli login` with the proxy exported. The user tier leaves open:
  `/agent` in an interactive session (it can switch to Kiro's built-in
  agent), project MCP servers, and a nested `kiro-cli-chat` started from a
  tool call, which skips the launcher. A real model through a Kiro Pro `KIRO_API_KEY` or
  a device-flow login is unverified.
- **Devin CLI 3000.4.25.** Devin's versioned release manifest publishes
  SHA-256 digests. Hooks come from `~/.config/devin/config.json` (`hooks`) or
  a project `.devin/hooks.v1.json`; there is no system hook tier, so the tier
  is user, and the launcher puts the DefenseClaw hooks back from a root-owned
  template on every start (keeping the other settings), drops
  `XDG_CONFIG_HOME` and refuses `--config`. Devin needs a Devin account login
  before any agent turn: `devin -p` stops with "Login canceled" without one,
  also with `ACP_BACKEND=openai` pointed at a mock, and the login is a browser
  or pasted-token flow (`devin auth login --force-manual-token-flow`), so
  hook firing, blocking and the endpoint set are unverified.
  `--permission-mode dangerous` approves every tool; `autonomous` requires
  Devin's own bubblewrap sandbox, which cannot nest. Devin fails open on any
  hook error other than exit code 2, and on a hook timeout, so the sandbox
  hook exits 2 on every failure and the image sets 30-second hook timeouts
  (the host's 10 seconds is shorter than two relay attempts). Devin's bundled
  docs say `--print` fails in an untrusted workspace, and Restricted Mode
  (trust declined at the first interactive prompt) runs without hooks. The
  launcher therefore always passes `--respect-workspace-trust false` (the
  pinned CLI accepts it before a prompt and before a subcommand such as
  `auth`) and refuses a caller `--respect-workspace-trust`. The trade-off: a
  trusted workspace loads the project's own `.devin/hooks.v1.json` beside the
  DefenseClaw hooks without asking, which the user tier already leaves open.
  The login check comes before the trust check, so the bypass is unverified
  in a real turn. The login credential lands in
  `~/.local/share/devin/credentials.toml`.

## Policy packs and admin constraints

`internal/openshell/packs` resolves the sandbox posture for one run. A pack
bundles it in one file: network mode (`open`, `allowlist` or `deny`, which map
to the `open`, `balanced` and `strict` profiles), approvals mode (`auto`,
`triage` or `manual`), egress feeds, block and allow lists, ports and the
large-upload threshold, workspace mode, masks, unmasks and review globs, the
harness skip-permissions default and allowlist, MCP import, host-port access
and blocked tools, the hook fail mode (only `closed`), and the response to
hook tamper (`hooks.on_tamper`: `stop` or `alert`).

The built-in packs are embedded from `policies/sandbox/<name>/pack.yaml`:

| Pack | Network | Approvals | Workspace | Skip-permissions | MCP import and host ports | Large upload |
| --- | --- | --- | --- | --- | --- | --- |
| `open` (default) | open web through the proxy, ports 80 and 443 | auto | mount | on | on | 25 MiB |
| `balanced` | curated allowlist, ports 80 and 443 | triage | mount | on | on | 10 MiB |
| `strict` | no proxy; provider hosts only | manual | copy | off | off | 5 MiB |

All three mask the same secret files and review the same host-executable
paths.

Custom packs are `<pack_dir>/<name>/pack.yaml` (default
`<data_dir>/policies/sandbox`) or an absolute path, loaded with the same strict
rules as guardrail rule packs. A pack's digest is `sha256:` over the file's
bytes.

A custom pack is trusted because you own it, and in mount mode the agent
writes the project as you. So the policy is never read from inside a
live-mounted project. The manager refuses to create a mount-mode sandbox
whose pack file or `pack_dir` is inside the project or holds it
(`pack_invalid`); the workspace also refuses to share such a folder. Every
later resolution checks again, because a configuration change can move the
pack. A running sandbox whose pack moved into its project fails closed (see
[Authentication](#authentication) under the egress proxy). Keep packs
outside the project, or run with `--copy`: a copy is not shared back while
the agent runs.

`packs.Resolve` layers the pack, then the user's `openshell` keys, then the
run inputs (`packs.Flags`, which the future run command will fill), and clamps
the result by `openshell.admin`. Along the way:

- A stricter profile never runs with looser approvals: `balanced` triages at
  least, and `strict` asks every proposal.
- Raising the profile above the pack's own network mode brings in the
  `balanced` pack's curated allowlist.
- Allow entries that cover every host or a whole top-level domain are
  ignored.
- Every refused loosening is returned as a `Violation` that names the key,
  the attempted value and the refusing constraint, and every setting records
  where its value came from (`Effective.Explain`). Refusals by
  `openshell.admin` (a required pack's floor included) say
  `blocked by your organization's DefenseClaw policy: <key>`. A pack or
  profile that refuses a runtime action says
  `not allowed by the <pack> sandbox pack: <key>` or
  `not allowed by the <profile> sandbox profile: <key>`. Ignored broad allow
  entries, reserved host ports and never-approved addresses have messages of
  their own.

`openshell.admin` holds the administrator's constraints: `required_pack` (its
posture becomes a floor) and `required_pack_digest`, `min_profile`,
`allow_yolo`, `allow_mount`, `allow_host_ports`, `allow_unblock`,
`allow_learn_mode`, `allowed_harnesses`, `egress_block` (cannot be unblocked),
`egress_allow_only` (forces an allowlist profile), `require_copy_for`,
`max_resources`, and `locked` (keys run inputs may not loosen). In a
`managed_enterprise` install the administrator owns `config.yaml`, so the
constraints are authoritative and a custom required pack must be an
administrator-owned file. Elsewhere they are enforced but advisory, because
the user can edit the file.

`Effective.Allow` checks runtime actions against the same policy: unblock,
approve, approve always, host port, mount, skip-permissions, learn mode and
harness.

- The administrator's block list and allow-only list apply to every unblock
  and approval.
- Neither lifts the block list (the pack's and `openshell.egress.block`).
- This machine, link-local, cloud metadata, multicast and reserved
  addresses are never unblocked or approved, and neither are the proxy
  guard's host-internal names. Private networks are never unblocked; they
  open only through an allow entry.
- With `allow_unblock: false`, an approval is also refused for a blocklist
  feed host and for a private network (an address or an intranet name).
- The checks ask the policy's own egress decider, so they need no feed
  matcher.
- What a name resolves to is triage's check (see
  [paths out of the workload](#paths-out-of-the-workload)).

No policy, input or approval ever opens these host ports to a sandbox:
DefenseClaw's API, sandbox ingress, egress proxy, guardrail proxy and model
router, the OpenShell gateway the run uses (17670 when unknown), and the
OpenClaw gateway (18789 by default).

## Telemetry

The sandbox emits v8 telemetry only, through the typed
`audit.SandboxTelemetry` interface (`internal/audit/sandbox_v8.go`). Every
record carries the `correlation.sandbox` attribute group, which never appears
on metrics.

| Source | Producer | Family |
| --- | --- | --- |
| Phase changes (initiated or watched) | `RecordSandboxLifecycle` | `log.sandbox.lifecycle`, `metric.defenseclaw.sandbox.transitions`, `metric.defenseclaw.sandbox.active` |
| Proxy and OpenShell network decisions | `RecordSandboxEgress` | `log.egress.allowed`, `log.egress.blocked`, `metric.defenseclaw.egress.events` |
| Draft proposals and host-port consents | `RecordSandboxApproval` | `log.approval.requested`, `log.approval.resolved` |
| Policy applies, rule changes, unblocks | `RecordSandboxPolicy` | `log.policy.updated` |
| Integration health | `RecordSandboxHealth` | `log.subsystem.*`, subsystem `openshell` |
| OCSF findings, binary drift, tamper, hook silence, large uploads | `RecordSandboxFinding` | `log.finding.observed` |
| Snapshot, undo, mask, review, upload, pull | `RecordSandboxWorkspace` | `log.sandbox.workspace` |

Hook decisions from a sandbox carry the sandbox ID and name taken from the
binding that authenticated them. Nothing calls the producers yet. The manager
must build one `audit.NewSandboxRecorder` for the process and share it with
the watcher, the egress proxy sink, approvals and workspace code, and on
daemon start emit a lifecycle event for every existing sandbox so the active
gauge is republished.

The watcher side exists. `internal/openshell/stream` follows one sandbox
through the raw `WatchSandbox` RPC on its own connection (the SDK's watch
follows status only): status, supervisor log lines, platform events, draft
notifications and warnings. It persists its cursor through a callback, turns
`OUT_OF_RANGE` after a gateway restart into a gap event and resubscribes, and
backs off on transport errors. `internal/openshell/ocsf` parses the OCSF
shorthand in log lines (classes `NET`, `HTTP`, `SSH`, `PROC`, `FINDING`,
`LIFECYCLE`, `CONFIG`, `API`, `EVENT`); a fixture corpus captured on a live
host backs its tests.

## Platform behaviours to design around

These were measured on one Linux arm64 host running OpenShell 0.1.1 (the
upstream installer, the docker driver and the `openshell-gateway` user
service) in September 2026, with Claude Code 2.1.156 and Codex 0.146.0.

### Network

| Behaviour | Design consequence |
| --- | --- |
| Any network policy update, even an unrelated rule, closes in-flight connections. So does the first settings poll, about 10 to 12 seconds after each sandbox start, and every global profile import. | Egress decisions live in the proxy, not in OpenShell rules. The policy renders deterministically. Profiles are imported once at setup. The manager must start the harness only after the first settings poll (about 15 seconds) and batch rare policy updates for moments when no hook is in flight (`sandboxauth.InFlight`, `openshell.approvals.debounce_ms`, 3,000 ms by default). |
| The relay drops about 0.3 to 0.7 percent of requests under concurrency, sometimes after the ingress acted. | Hooks retry once with an idempotency key, then fail closed; the ingress replays by key. |
| `host.openshell.internal` reaches host `127.0.0.1` and the host sees a loopback client. | Separate sandbox listeners that trust credentials, never the source address. |
| `protocol: tcp` alone on the proxy port is refused by the HTTP parser; `tcp` with `tls: skip` relays raw bytes. | The `defenseclaw_egress` rule uses `tcp` with `tls: skip`. |
| A binary glob of `/**` is accepted. A catch-all host `**.*.*` is accepted but covers only hosts with three or more labels. | The egress rule allows every binary; there is no catch-all host rule. |
| curl, Node `fetch` (with `NODE_USE_ENV_PROXY=1`), npm, pip, uv, git over HTTPS and Python urllib all honour `HTTPS_PROXY` through the relay. | The proxy environment covers the common tools. |
| `sandbox create --env` does not deliver the proxy variables: with `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` (and their lowercase forms) and `NODE_USE_ENV_PROXY` passed at create, none of them reach processes started with `sandbox exec`, while every other variable does and OpenShell adds its own CA bundle variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE` and others). Measured with OpenCode and Copilot CLI sandboxes, where the harness and hooks still reached the ingress and the mock model directly, and curl reached the DefenseClaw egress proxy only with an explicit `--proxy`. | DefenseClaw also passes the proxy URL and bypass list as `DEFENSECLAW_EGRESS_URL` and `DEFENSECLAW_EGRESS_BYPASS`, which do arrive, and one shell fragment exports the standard variables from them in every launcher, the login-shell profile and the `sandbox exec` wrapper (see [paths out of the workload](#paths-out-of-the-workload)). |
| `openshell sandbox exec` runs the command through `bash -lc` by default, sourcing `/etc/profile`, `/etc/profile.d` and the user's `~/.profile` (which in the community base sources a `~/.bashrc` that resets `PATH`); `--no-login-shell` runs it through `bash -c`. | DefenseClaw's own execs pass `--no-login-shell`; the proxy for interactive shells comes from `/etc/profile.d`, and `defenseclaw-gateway sandbox exec` wraps its command instead. |
| A direct connection to an unknown host is refused (`policy_dns_ineligible`, then `transparent_tcp_policy_denied`) and a draft proposal is filed. The metadata address is denied. | Non-proxy-aware clients surface as proposals for triage. |

### Credentials

| Behaviour | Design consequence |
| --- | --- |
| A placeholder is opaque and scoped to a policy revision (`openshell:resolve:env:v<revision>_<KEY>`); an unversioned one gets HTTP 500. | Hooks and OTLP helpers read the variable per request; launchers refresh first-run state on each start. |
| Placeholders are substituted in any header and in the query string on bound endpoints, including plain-HTTP `protocol: rest` endpoints, but not in bodies. | The ingress accepts the credential only in `Authorization` and refuses it anywhere else. |
| Provider profiles are imported one file at a time; their rules appear as `_provider_<name>`. | `Client.ImportProfiles` imports items one by one. |

### Images, mounts and harnesses

| Behaviour | Design consequence |
| --- | --- |
| Image `ENV` is not propagated; `sandbox create --env` is. `--from <local tag>` uses the local image. | Startup variables travel in `SandboxArtifacts.Env` and `harness.Spec.Env`. |
| Sandbox names are capped at 19 characters (`name exceeds maximum length`). | Test and probe names stay short. |
| Bind mounts need `allow_driver_config` and `enable_bind_mounts` for the docker driver and resource admission off in `gateway.toml`, then a gateway restart. | `GatewayConfigurator` plans the TOML-preserving edit, runs the gateway's preflight, backs up, restarts and rolls back if the gateway does not come up. |
| A read-only over-mount refuses writes, a bind-mounted file is effectively read-only, and an empty-file mask reads as empty. | Git internals and secrets are protected by the mounts themselves (Landlock cannot narrow a subtree of a read-write grant). |
| `process.run_as_user` sets the uid, and files written to a bind mount are owned by it on the host. | Mount mode runs as the host uid. |
| Content under `/sandbox` in the base image belongs to uid 998. | The overlay chowns `/sandbox` to the run-as uid; without it writes to `~/.claude` fail and `SessionStart` silently does not run. |
| Landlock hides `/dev` entries that are not listed. | `/dev/ptmx`, `/dev/pts` and `/dev/tty` are read-write for PTY tools. |
| Claude Code drops a whole managed-settings drop-in with one invalid field, silently. | The hook-fire probe gates every image. |
| Claude's bare mode disables hooks. | Managed `env` pins `CLAUDE_CODE_SIMPLE=0`, which restores every hook except `SessionStart` in bare mode, and the probe plants bare mode in hostile settings. |
| Codex's own sandbox cannot run inside OpenShell; `codex exec` authenticates with `CODEX_API_KEY`. | Launch flags turn it off; the launcher exports `CODEX_API_KEY`. |

### Not measured

These were not measured, so the design does not rely on a result for them:

- static binaries and programs that make raw system calls (the kernel
  limits are expected to hold for them, but no separate run checked);
- data leaving through DNS lookups;
- children started with an emptied environment (`env -i`);
- deleting files in the sandbox HOME (`/sandbox`, which is local to the
  sandbox).

### CLI and streams

| Behaviour | Design consequence |
| --- | --- |
| `sandbox exec` and `sandbox upload` hang while stdin is an open non-TTY pipe. | Non-interactive invocations read stdin from `/dev/null`. |
| The first `sandbox exec` after create occasionally returns nothing. | `WaitReady` waits for `Ready` and the `ConfigurationReady` condition. |
| Ending an exec stream does not stop the command in 0.1.1. | `Exec` wraps commands in `timeout(1)` inside the sandbox and retries only attempts whose stream never opened (plus unanswered attempts of idempotent commands). |
| `WatchSandbox` OCSF lines arrive at level `OCSF` with structured fields empty. The cursor looks like `v1:<uuid>:<20-digit sequence>`. A gateway restart drops the in-memory log buffer. | The shorthand text is parsed; an `OUT_OF_RANGE` cursor becomes a gap and a fresh subscription. |

## Supported platforms and versions

- OpenShell `>=0.1.1 <0.2.0`, checked against the CLI and the gateway. The
  installer code (`openshell.Installer`) runs the upstream installer from the
  v0.1.1 tag only after checking it against a pinned SHA-256. Releases before
  0.0.37 must be cleaned up with the old CLI first; later ones upgrade in
  place.
- A local gateway only, registered with mTLS. Remote gateways and plaintext,
  unauthenticated, OIDC or Cloudflare registrations are refused. So are a
  private key other users can access, world-writable or foreign-owned mTLS
  files and registration entries, and registration entries below the
  OpenShell config directory that are symbolic links. The CA and client
  certificate may be readable by others, and group-writable files and entries
  only produce a warning.
- Linux amd64 and arm64. macOS arm64 on Docker Desktop is a preview. Windows,
  WSL2 and Intel macOS are unsupported.
- The daemon and the gateway run as the same non-root user.
- `internal/openshell` doctor checks cover the platform, user, Landlock (ABI 3
  or newer), Docker (Engine 28 or newer, host networking, file sharing, disk),
  systemd linger, the gateway service, CLI, registration, mTLS files, gateway
  version and driver, global policy, bind mounts, OpenShell telemetry and the
  sandbox ports.

## Code map

| Concern | Source |
| --- | --- |
| OpenShell client, CLI, discovery, install, doctor, gateway config | [`../internal/openshell/`](../internal/openshell/) |
| `WatchSandbox` stream and OCSF parser | [`../internal/openshell/stream/`](../internal/openshell/stream/), [`../internal/openshell/ocsf/`](../internal/openshell/ocsf/) |
| Egress proxy | [`../internal/openshell/egress/`](../internal/openshell/egress/) |
| Egress feeds | [`../policies/sandbox/egress/`](../policies/sandbox/egress/) |
| Sandbox policy renderer | [`../internal/openshell/policy/`](../internal/openshell/policy/) |
| Provider profiles | [`../internal/openshell/profiles/`](../internal/openshell/profiles/) |
| Overlay images and hook-fire probe | [`../internal/openshell/image/`](../internal/openshell/image/) |
| Harness specs and launchers | [`../internal/openshell/harness/`](../internal/openshell/harness/) |
| Sandbox artifacts and hook scripts | [`../internal/gateway/connector/sandbox_artifacts.go`](../internal/gateway/connector/sandbox_artifacts.go), [`../internal/gateway/connector/hooks/_sandbox.sh`](../internal/gateway/connector/hooks/_sandbox.sh) |
| Workspace: mount, masks, snapshot, undo, review, copy | [`../internal/openshell/workspace/`](../internal/openshell/workspace/) |
| Policy packs and admin constraints | [`../internal/openshell/packs/`](../internal/openshell/packs/), [`../policies/sandbox/`](../policies/sandbox/) |
| Bindings, limiter, `FSView` | [`../internal/sandboxauth/`](../internal/sandboxauth/) |
| Hook ingress | [`../internal/gateway/api_sandbox_ingress.go`](../internal/gateway/api_sandbox_ingress.go), [`../internal/gateway/sandbox_hook_scope.go`](../internal/gateway/sandbox_hook_scope.go) |
| `openshell:` configuration | [`../internal/config/openshell.go`](../internal/config/openshell.go), [`../schemas/config/v8/defenseclaw-config.schema.json`](../schemas/config/v8/defenseclaw-config.schema.json) |
| Telemetry producers | [`../internal/audit/sandbox_v8.go`](../internal/audit/sandbox_v8.go) |
| `sandbox` commands (setup, run, lifecycle, pull, policy, images, teardown) | [`../internal/openshell/sandboxcli/`](../internal/openshell/sandboxcli/), [`../internal/cli/sandbox.go`](../internal/cli/sandbox.go) |
| Shell wrappers (`sandbox enable`/`disable`) | [`../internal/openshell/wrapper/`](../internal/openshell/wrapper/) |
| Nested-repository guard | [`../internal/openshell/nestguard/`](../internal/openshell/nestguard/), [`../internal/openshell/manager/guard.go`](../internal/openshell/manager/guard.go) |
| Python `sandbox` stubs and legacy cleanup | [`../cli/defenseclaw/commands/cmd_sandbox.py`](../cli/defenseclaw/commands/cmd_sandbox.py), [`../cli/defenseclaw/sandbox_legacy.py`](../cli/defenseclaw/sandbox_legacy.py) |
| Python sandbox API client (REST and the activity stream) | [`../cli/defenseclaw/gateway.py`](../cli/defenseclaw/gateway.py) |
| TUI Sandboxes panel, launch dialog and setup wizard | [`../cli/defenseclaw/tui/sandbox_panel.py`](../cli/defenseclaw/tui/sandbox_panel.py), [`../cli/defenseclaw/tui/services/sandbox_state.py`](../cli/defenseclaw/tui/services/sandbox_state.py), [`../cli/defenseclaw/tui/panels/setup.py`](../cli/defenseclaw/tui/panels/setup.py) |
| macOS app sandboxes (menu bar, Overview, panel) | [`../macos/DefenseClawMac/DefenseClawMac/DataLayer/SandboxModels.swift`](../macos/DefenseClawMac/DefenseClawMac/DataLayer/SandboxModels.swift), [`../macos/DefenseClawMac/DefenseClawMac/Features/SandboxesView.swift`](../macos/DefenseClawMac/DefenseClawMac/Features/SandboxesView.swift) |
| Legacy bind shim (Go, and its Python twin `legacy_standalone_api_host`) | [`../internal/config/legacy_openshell.go`](../internal/config/legacy_openshell.go), [`../cli/defenseclaw/config.py`](../cli/defenseclaw/config.py) |

## Testing

Unit tests need no OpenShell or Docker:

```bash
go test ./internal/openshell/... ./internal/sandboxauth/...
go test -run Sandbox ./internal/gateway/ ./internal/gateway/connector/ \
  ./internal/audit/
```

On macOS, `TestSandboxHooksScrubInheritedEnvironment` in
`internal/gateway/connector` currently fails: the hook request loses the
allowlisted trace context. Run the connector sandbox hook tests on Linux
until that is fixed.

Policy, provider-profile, sandbox-artifact and hook golden files are
regenerated with `DEFENSECLAW_UPDATE_GOLDEN=1`; review the diff.

Live tests carry the `openshell_integration` build tag and need a local
OpenShell 0.1.x gateway (with bind mounts enabled for the workspace tests):

```bash
go test -tags openshell_integration -run Live -v ./internal/openshell/
go test -tags openshell_integration -run TestLive -v \
  ./internal/openshell/workspace/
DEFENSECLAW_E2E_DATA_DIR="$HOME/dc-e2e" \
DEFENSECLAW_E2E_IMAGE_REPO=e-defenseclaw-sandbox \
  go test -tags openshell_integration -run TestLiveOverlay -v -timeout 60m \
  ./internal/openshell/image/
```

`DEFENSECLAW_OPENSHELL_GATEWAY` and `DEFENSECLAW_OPENSHELL_IMAGE` pick the
gateway registration and sandbox image for the workspace test;
`DEFENSECLAW_E2E_HOOKFIRE_RELAY_SINK` also verifies each overlay in relay mode.
The live tests create short-lived, prefixed sandboxes and delete them. Mock
model servers and harness scenarios for end-to-end runs are in
[`../test/e2e/openshell/`](../test/e2e/openshell/).

## Hosts that still have the legacy install

The legacy standalone integration targeted the `openshell-sandbox` 0.0.x
binary on Linux, for OpenClaw only, and its generated sandbox policy was never
enforced. It was removed. OpenClaw and ZeptoClaw use the `shims` subprocess
policy on every platform. Review the cleanup plan, then run it:

```bash
defenseclaw sandbox legacy-cleanup --dry-run
defenseclaw sandbox legacy-cleanup
```

Cleanup stops the systemd units itself but changes nothing else while any part
of the legacy sandbox still runs. Stop the non-systemd launcher first with
`sudo <data_dir>/scripts/run-sandbox.sh stop`. The
[published cleanup guide](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/)
lists every step, the opt-in `--remove-user` and `--remove-binary` removals,
and the follow-up commands.

Until cleanup runs, a config that still says `openshell.mode: standalone` with
a non-localhost `guardrail.host` keeps the gateway API bound to that host (an
explicit `gateway.api_bind` still wins). While `openshell.mode: standalone`
remains, `/health` reports the `sandbox` subsystem as `degraded`, and
`defenseclaw doctor` and `defenseclaw status` point at
`defenseclaw sandbox legacy-cleanup`.
