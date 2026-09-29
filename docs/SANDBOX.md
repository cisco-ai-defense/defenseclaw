# OpenShell sandbox architecture

This page is for contributors. It explains how DefenseClaw runs a coding
harness such as Claude Code or Codex inside an NVIDIA OpenShell 0.1 sandbox:
what OpenShell enforces, what DefenseClaw adds, how traffic gets in and out,
how the project folder is shared and taken back, and which measured OpenShell
behaviours the code is built around. The code is the authority; each section
names the package to read.

The operator guide for the sandbox commands is the
[published sandbox page](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/)
(`docs-site/content/docs/setup/sandbox.mdx`): setup, running a harness, the
session, the end-of-session review and undo, the run variations, MCP
servers, the shell wrapper, troubleshooting, and the legacy 0.0.x cleanup.
Telemetry details are in
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
- **Harnesses.** `claudecode`, `codex`, `opencode`, `copilot`, `kiro`,
  `hermes`, `openhands`, `omnigent`, `antigravity`, `amp`, `cursor` and
  `devin` have harness specs and sandbox artifacts. The `amp`, `cursor` and
  `devin` images stay unverified until a probe runs with a vendor account
  (see [Sandboxed connectors](#sandboxed-connectors)).
- **macOS.** A Mac runs sandboxes on OpenShell's MicroVM (`vm`) compute
  driver, since no sandbox can start on Docker Desktop, whose Linux VM kernel
  has no Landlock (see [compute drivers](#compute-drivers) and
  [macOS and Docker Desktop](#macos-and-docker-desktop)). Every run there
  works on a copy. OpenShell calls the driver experimental.

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
| Identity | The process identity the policy names (docker driver), or the gateway-wide `sandbox_uid`/`sandbox_gid` (vm driver) | Runs as your uid in mount and copy mode and builds a per-uid image; on the vm driver setup sets the gateway's identity to your uid and gid, and a check after each create and start refuses any other |
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

On a Mac the gateway is the `nvidia/openshell` Homebrew service (launchd),
and each sandbox is a MicroVM (libkrun on Apple's Hypervisor) instead of a
container; the rest of the picture is the same.

## Compute drivers

One OpenShell gateway runs one compute driver. DefenseClaw drives two:
`docker` (Linux, and any Docker host) and `vm`, OpenShell's MicroVM driver,
which a Mac runs sandboxes with. `internal/openshell/driver.go` holds the
one table of what differs, and code asks its fields (`HostMounts`,
`RunFilesInImage`, `SandboxLimits`, `GatewayIdentity`, `ImageRepository`),
not the driver's name or `runtime.GOOS`.

- **Which driver.** When the daemon connects it reads the driver from
  `GetGatewayInfo` (`openshell.GatewayDriver`) and refuses a gateway that
  reports none, several, or one DefenseClaw does not drive (podman,
  kubernetes). The status API reports it as `gateway.driver`, each sandbox
  record keeps the driver it was created on (empty in older records: docker),
  and a record is re-resolved with its own driver, never the connected
  gateway's. Setup and the doctor, before any gateway answers, read the
  configured driver from the effective `gateway.env` and `gateway.toml`.
  A connection outlives a gateway restart, which setup or `doctor --fix` can
  make onto the other driver: create, start and reconcile ask the gateway
  again, the status asks once its last answer is five seconds old, and a
  gateway that now runs another driver is connected to again.
- **No host mounts on vm.** libkrun attaches no shared folders, and the vm
  `driver_config` takes only `gpu_device_ids`. So every vm sandbox is in copy
  mode: the packs resolver clamps `workdir.mode` to copy with the constraint
  `openshell.gateway.compute_driver`, a create without a staged copy is
  answered with `CodeNeedsCopy`, and a template on a driver without host
  mounts never carries a `driver_config` (checked before anything is made,
  and again just before `CreateSandbox`). The CLI reads the driver from the
  status and stages a copy up front, refuses `--context`, and says that
  `--no-snapshot` does not apply.
- **Run files in a run image.** The per-run managed files of Claude Code and
  Codex cannot be bind-mounted, so on vm they are baked, root:root 0644, into
  a content-addressed run image (`defenseclaw.invalid/sandbox-run:<harness>-<base>-<digest>-u<uid>`)
  built on the verified overlay image. Hooks-only harnesses boot an alias of
  the overlay image (`defenseclaw.invalid/sandbox:…`), which shares its image
  ID. The files cannot change after create: a start whose render is stricter
  is refused, a looser one keeps the image. A copy's work stays in the
  sandbox and only a start reaches it (`pull` starts a stopped sandbox), so
  that refusal says to pull the work under the settings the sandbox was made
  with before deleting it and running it again. A value
  of a secret-bearing variable that came from `--env` is refused on vm,
  since it would sit in an image layer and in OpenShell's prepared-rootfs
  cache; so is a URL from `--env` with a user name, a password, or a query
  or fragment value. For the same reason an imported MCP server whose
  arguments or URL look like they carry a credential (a `--api-key VALUE`
  or `--token=VALUE` argument, a `NAME=VALUE` or `X-API-Key: VALUE`
  argument with a credential name, a Bearer value, a well-known token
  format, a URL query or fragment value) is left behind on vm, with a
  `--credential` hint.
- **Image names.** The vm driver reads images from the local Docker image
  store and falls back to a registry pull of the same name when it does not
  find one. Its references use a registry host under the reserved `.invalid`
  TLD (RFC 2606), which never resolves, so that fallback fails instead of
  fetching someone else's image. An image ID is not accepted as a reference.
- **Identity.** The vm driver runs every workload as the gateway's
  `[openshell.drivers.vm] sandbox_uid` and `sandbox_gid` (default 1000:1000)
  and ignores `process.run_as_user`; it rewrites the image's `sandbox`
  account to that identity. Setup writes the host uid and gid there, so the
  per-uid images, the hook-fire probe and the policy stay as they are.
- **Workload check.** After ready, at create and at every start, one exec
  (`/usr/bin/env -i`, every tool by absolute path) proves the uid and gid,
  a writable HOME, an empty `CapEff`, and the digests, owners and modes of
  the hook entrypoints and run files against what create recorded. Under
  an admin `max_resources` it also counts the processors and reads the
  memory the MicroVM got, since the running gateway can take other values
  than its files say (launchd's environment, a change since its restart). A
  mismatch rolls the create back or stops the started sandbox. It runs on
  the vm driver, where the workload's identity is the gateway's
  configuration. On docker it is off (`SkipWorkloadCheck` in the driver
  table) until a Linux live run has passed it.
- **Resources.** vm has no per-sandbox limits: every MicroVM gets the
  gateway-wide `vcpus`, `mem_mib` and `overlay_disk_mib`. `--cpu` and
  `--memory` are warned about and dropped, the record keeps the gateway-wide
  values, and an admin `max_resources` below them refuses the create.
- **Cost.** The first start of an image prepares a rootfs from it (about a
  minute, about 5 GB under `~/.local/state/openshell/vm-driver/images`,
  keyed by image ID and kept by OpenShell); a cached one starts in seconds.
  The pre-create `Explain` reports `vm_first_boot`, which the CLI turns into
  its "about a minute" note. `delete` keeps a sandbox's run image even when
  no other sandbox uses it, and `image prune` keeps every run image of an
  overlay image it keeps: the run image adds only its files' few layers to
  Docker, while a rebuilt one gets a new image ID, which the driver
  prepares another rootfs for (another minute and about 5 GB). So each
  posture's run image, and its prepared rootfs of about 5 GB, stays until
  its overlay image is superseded and pruned; the rootfs stays after that
  too, in OpenShell's cache, which the doctor's disk check reports.
- **Name resolution.** A MicroVM's `/etc/hosts` is empty (OpenShell 0.1.1:
  the driver makes the root disk from a `docker export`, whose init layer
  puts an empty file over the image's, and its guest init writes none), and
  its loopback DNS relay at `127.0.0.53` answers `localhost` with SERVFAIL.
  Antigravity CLI 1.2.12 exited at start there ("lookup localhost on
  127.0.0.53:53: server misbehaving"), and any dev server, local MCP server
  or test that resolves localhost failed the same way. The overlay images
  built for the vm driver (`BuildSpec.MicroVM`, which the daemon sets from
  the driver its gateway reports and `sandbox image build` from the
  daemon's gateway or the gateway configuration) answer localhost with a
  pinned `nss-myhostname` (see [Build](#build)): glibc programs, Node,
  Python and Go programs linked with cgo (agy is one) now resolve it. The
  images for the docker driver, whose sandboxes get Docker's `/etc/hosts`,
  are built as before, byte for byte. Go's own resolver (a Go binary built without cgo, or with
  `netgo`) and statically linked musl programs read `/etc/hosts` and DNS
  themselves and still cannot, until OpenShell writes `/etc/hosts`. The
  hook-fire probe runs every image for the vm driver with a MicroVM's name
  resolution too, and a driver without a hosts file (`HostsFile` in the
  driver table) boots only an image that passed that run. An image whose
  run settled nothing (it could not run, or the harness failed without a
  failed lookup of localhost) is checked again before the next sandbox on
  that driver boots it (`Record.MicroVMUnchecked`); `create` refuses an
  image that still did not pass, with the probe's reason, and every refusal
  names `defenseclaw sandbox image build <harness> --force`, which checks
  it again. A harness that exits at once in a sandbox where localhost
  does not resolve is named as such in the end-of-session summary, with
  what to do (a sandbox made before the images answered localhost is
  deleted and made again).
- **Stops.** A MicroVM stopped without a flush brings back empty what its
  workload wrote since the last one (OpenShell 0.1.1; `StopFlushes` is off
  for vm). The daemon's stop runs `sync` in the sandbox first. Every gateway
  restart that setup or the doctor makes (`GatewayConfigurator.Restart`, and
  the restart of an `Apply`) first runs it in every ready sandbox on the
  gateway, of every owner, and a sandbox that cannot be flushed refuses the
  restart. On vm, `doctor --fix` asks before a fix that restarts the gateway
  while sandboxes run on it, no by default, and `--yes` takes that default.
- **Switching.** A record made on the other driver is never started, gc'd or
  released as if it were this gateway's: `start` refuses it before any other
  check, and `delete` releases DefenseClaw's host state for it.

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

OpenShell relays `host.openshell.internal:<port>` to whatever listens on that
host port, and hands the ingress the sandbox's real token. So while the daemon
does not hold both sandbox listeners (another program took a port, or a
listener stopped), the manager refuses to create or start a sandbox, and the
subsystem health says why.

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
- `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME` and
  `GIT_COMMITTER_EMAIL` carry the identity the host's git uses for the
  project (`user.name` and `user.email`, the repository's before the
  user's), read by `sandbox run` (`sandboxcli.withGitIdentity`). The
  sandbox has none of the user's git configuration, so without them its git
  refuses to commit and looks up the container's host name to make up an
  address. `--env` overrides them. OpenShell's refusal of a lookup of the
  container's own host name (Docker's 12-hex-digit default) is audited but is
  neither a blocked site nor a feed line.

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

Ending a `sandbox exec` client does not stop its command: OpenShell 0.1.1
leaves a command running when its exec stream ends. So the CLI starts the
command under a session shell, `/bin/sh -c '"$@"; exit $?'
defenseclaw-exec-<32 hex digits> sandbox-env COMMAND...`, which runs it as
a child and keeps the session id in its argv. A client that is told to end
(SIGHUP, SIGTERM, and without a terminal the Ctrl-C the terminal sends the
whole job; with one, Ctrl-C reaches the command as a keystroke) runs one
more exec before it exits, `sandboxcli.reapScript`. It finds the session
shell by its `/proc/<pid>/cmdline`, collects every process below it by
`PPid`, and stops them as the sandbox user: SIGTERM, then SIGKILL after five
seconds. The mark is in argv because a sandbox process cannot read another
exec's `/proc/<pid>/environ` (Yama `ptrace_scope` 1), while it can read its
`cmdline` and `status` and signal it. A process that leaves the tree
(`setsid` and a double fork) keeps running until the sandbox stops.

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

- A proposal naming more than one destination host is rejected: approving
  it opens every endpoint, while an ask shows one destination, so each host
  must be its own proposal. An ask for several ports of one host names them
  all.
- Approving merges a proposal into the rule of its name, and a rule name is
  only a key: nothing ties `allow_<host>_<port>` to its host. A proposal
  whose rule already exists for another host (in OpenShell's current or
  candidate policy) is rejected, and the batcher applies one proposal per
  rule name in each policy revision, so the next one is checked against
  the rule the first one created.
- What the proxy refuses and no unblock lifts is rejected: the
  administrator's lists, the block list, the blocklist feed, this machine,
  link-local and metadata addresses.
- A public IP literal in the open mode is rejected until it is unblocked.
- A request the pinned harness binary itself makes around the proxy for
  something it does without (`harness.Spec.DirectFetches`: the Codex TUI's
  startup tip download from `raw.githubusercontent.com`) is rejected with
  reason `harness_background_fetch`; the same destination from any other
  binary is judged as usual.
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
- Approvals are applied in batches at quiet moments, because every policy
  reload closes the sandbox's open connections: the batcher waits until no
  hook request is in flight and none of the sandbox's egress proxy tunnels
  moved a byte for 2 seconds (an idle tunnel left open does not count), at
  most 2 minutes. The harness's own model stream runs over its provider's
  direct rule, which DefenseClaw does not see, so a reload during a long
  answer can still interrupt it.
- The batcher repeats the whole check, with fresh DNS answers, right before
  it applies an approval. When that check cannot be made (a failing lookup,
  or a sandbox policy that does not resolve), an automatic approval is
  triaged again later, and your own approval is retried three times, then
  comes back to you as a pending ask. The proposal is not rejected.
- Every reconcile, about every 5 minutes, looks every approved rule's
  names up again (`triage.RecheckResolved`) and removes rules whose names
  now resolve to this machine, to an address a block list or the
  administrator refuses, or to a private network while
  `openshell.admin.allow_unblock` is `false`. A rule DefenseClaw approved on
  its own whose name now resolves to a private network is removed too: only
  you approve a private network, and the agent's next direct connection
  asks you. A rule you approved yourself stays.
- Every configuration change and every reconcile removes approved rules
  the policy now refuses: destinations the administrator blocked or left off
  an allow-only list, and destinations a block list (yours or the pack's) or
  the blocklist feed now refuses with no unblock lifting it. Rules to host
  ports and private networks you approved stay.
- The daemon records who approved each rule (`approved_rules` in the
  sandbox record). A rule DefenseClaw approved on its own is removed once
  the policy would no longer approve it without asking
  (`triage.ApprovesAutomatically`): a stricter approvals or network mode (an
  administrator's `required_pack: strict` or `min_profile`), a destination
  taken off the allow list, an unblock taken back, or a port that is no
  longer an egress port. The agent's next direct connection asks you. Rules
  you approved yourself stay while the policy still lets you approve them.
  A rule counts as yours only while you approved everything in it: once
  DefenseClaw merges an approval of its own into it (another port or binary
  for the destination), before or after yours, it is recorded as approved
  on its own.
  `sandbox status` shows the posture the sandbox runs under now, and warns
  when it differs from the one it was created with, or when the policy now
  wants a copy of a project the sandbox mounts live (the mount stays until
  the sandbox stops; it cannot start again). Its violations are the clamps
  the current configuration applies, not the create-time ones. `yolo` and
  `launch.yolo` are the next launch's skip-permissions mode; `session_yolo`
  is the one the running session was launched with, and a warning says when
  the session still runs in skip-permissions mode after the policy turned it
  off (or uses a harness the policy no longer allows) until it ends.
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
and the Codex launcher exports the OTLP header as
`OTEL_EXPORTER_OTLP_{LOGS,TRACES,METRICS}_HEADERS`, which Codex's exporters
add to the managed exporters' headers. With `token_delivery: env` the value is
the token itself, so it never goes on a command line, which every process in
the sandbox can read (unlike another process's environment): the hooks hand
curl the `Authorization` header as configuration on a file descriptor, and
the managed config blanks the OTLP header variables for the commands Codex
runs.

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

A sandbox whose policy turns its web egress off while it runs (the deny
network mode, as an organization's required `strict` pack or a raised
`min_profile` sets, or a policy that no longer resolves) keeps its
credential, suspended (`CredentialStore.Suspend`): the proxy answers its
requests, and ends its open tunnels, with a 403 whose body has category
`egress_off` and names the reason, for example "your organization's required
sandbox pack (strict) turns web egress off for this sandbox
(openshell.admin.required_pack)", instead of the 407 an unknown credential
gets. The feed says so once per sandbox (`sandbox.lifecycle`, reason
`egress_off`). A sandbox created with the deny mode has no proxy at all.

The credential's principal also carries the sandbox's own `Decider`
(`Principal.Decider`). The manager builds it from that sandbox's resolved
pack and admin policy (`packs.Effective.EgressDecider`) and its unblocks. One
sandbox's block list, ports, mode or unblocks therefore never decide another
sandbox's traffic. The manager re-registers every credential with a rebuilt
decider after creates, deletes, configuration changes and reconciles.
Unblocks take effect at once, because the decider looks them up live. The
proxy's own decider (`Options.Decider`, `SetDecider`) is only the fallback
for a principal without one. After every such refresh, and whenever it
revokes a credential, the manager has the proxy decide its open tunnels and
in-flight requests again (`Proxy.Recheck`): the ones the sandbox's current
decider refuses, or whose credential is gone, are closed, so a tightening
reaches connections opened before it.

A sandbox whose policy stops resolving fails closed. This happens when its
custom pack is deleted or edited into one that no longer loads, or when the
configuration no longer accepts one of its run flags. The manager does not
keep serving it with the decider of its last good policy, because that
decider holds the administrator's lists as they were then. Instead:

- its proxy credential is suspended, so the proxy refuses the sandbox with a
  403 that says the policy cannot be resolved;
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
     reserved ranges. Cloud host services outside the link-local range count
     too (`egress.NeverReachPrefixes`): the Azure WireServer
     (`168.63.129.16`), the IPv6 metadata servers of Google Cloud
     (`fd20:ce::254`) and Oracle Cloud (`fd00:c1::a9fe:a9fe`), and the
     deprecated IPv6 site-local range `fec0::/10`. No allow entry opens
     them, and a proposal's `allowed_ips` that overlap them are rejected.
   - Private networks are reachable only where an allow entry names them
     (`private_network`). These are RFC 1918, carrier-grade NAT and IPv6
     unique local addresses, the other hosts on this machine's subnets, and
     intranet names. The allow entry can come from `openshell.egress.allow`,
     a custom pack's `egress.allow` or `openshell.admin.egress_allow_only`.
     DefenseClaw's curated allowlist (the balanced pack's `egress.allow`)
     admits its names but opens none of the private addresses they resolve
     to; an entry of your own for the same name does.
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

`sandbox unblock` refuses with the reason that applies, checked in this
order: a host on the administrator's lists or the block list (only the
list's owner opens it), this machine and what only it reaches (the refusal
names `--host-port`), a sandbox without the proxy (`strict`: its direct
connection requests ask instead, `defenseclaw sandbox approvals`), and only
then `openshell.admin.allow_unblock: false`. A host the sandbox's policy
already lets it reach is "not blocked".

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
- `allowlist.yaml` (`defenseclaw-allowlist`) is the allowlist-mode feed. It
  is the balanced pack's `egress.allow`, host for host (a test keeps the two
  lists identical), and a sandbox's decider applies it for the curated
  entries its policy has (`packs.Effective.EgressOptions`), so they never
  open a private network the way an operator allow entry does. Categories: `package_registry`, `source_hosting`,
  `toolchain`, `documentation`. CONNECT tunnels are opaque, so the proxy cannot tell a
  download from an upload: every listed host with a write API (GitHub, GitLab,
  the registries' publish endpoints) can receive data too. The balanced
  profile narrows destinations; it is not an exfiltration barrier for those
  hosts.

The deny rules of the host egress firewall (`firewall.config_file`,
`firewall.yaml` in the data directory) join every sandbox's block list, so
the proxy refuses those destinations and no unblock or approval opens them;
`sandbox policy explain` shows them under `egress.block`. Only outbound TCP
deny rules with a destination that cover the proxy's ports carry over
(`egress.FirewallBlockPatterns`). The host firewall's default action, allow
rules and allowlist scope what the DefenseClaw host itself may reach and are
not applied to sandboxes. A firewall configuration that cannot be read or
parsed fails the sandbox policy rather than dropping the denials.

### Byte counts and large uploads

The `Counter` keeps bytes up and down per tunnel and per destination. When
the bytes sent to a destination this sandbox had not contacted before cross
the large-upload threshold (`large_upload_mb`, 25 MiB in the `open` pack), it
raises a `large_upload` event once. The threshold is the sandbox's own: its
proxy credential carries the value of its resolved pack
(`Principal.LargeUploadBytes`) and follows configuration changes; the
counter's own value applies only to a principal without one. Uploads to first-seen hosts are also
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
| `defenseclaw-bedrock-mantle-openai-<region>` | `BEDROCK_MANTLE_API_KEY` | bearer | `bedrock-mantle.<region>.api.aws:443` (Hermes, OpenHands and OmniGent) |
| `defenseclaw-gemini` | `GEMINI_API_KEY` | `x-goog-api-key` | `generativelanguage.googleapis.com:443` (Antigravity) |
| `dc-cred-<hash>` | the `--credential` variable | bearer | the host and port it is bound to |

A Claude subscription (Pro or Max) signs in on this machine: `claude
setup-token` prints a long-lived token; exported as `CLAUDE_CODE_OAUTH_TOKEN`,
it reaches the sandbox only as the `defenseclaw-claude-oauth` placeholder.
Without a shared credential the run banner says so, and that a login inside
the sandbox stores a real token there (see below).

The Copilot GitHub-token, Amp, Cursor and Kiro endpoint sets come from the
pinned CLIs, not from a live run (no account was available). The Gemini
profile has not carried a real key either: Antigravity was verified against a
Gemini API mock only. Devin CLI has no provider profile: it authenticates
with an interactive login inside the sandbox.

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
  to start the sandbox instead of running it unconfined. This is why no
  Docker-driver sandbox starts on Docker Desktop (see
  [macOS and Docker Desktop](#macos-and-docker-desktop)); a MicroVM's own
  kernel has it.
- **Read-only:** `/usr`, `/lib`, `/etc`, `/proc`, `/dev/urandom`, `/var/log`,
  `/opt`, the harness install roots and read-only context mounts.
- **Read-write:** `/tmp`, `/dev/null`, `/dev/ptmx`, `/dev/pts`, `/dev/tty`,
  `/sandbox` and the workdir (`/work/<repo>` in mount mode).
- **Process:** on the docker driver, the numeric host uid and gid in mount
  mode (required), the image's `sandbox` user in copy mode. The vm driver
  ignores `run_as_user` and runs every workload as the gateway's
  `sandbox_uid`/`sandbox_gid`, which setup sets to the host uid and gid (see
  [compute drivers](#compute-drivers)). Root is refused.
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

Mount mode is the default on the docker driver; the vm driver has no host
mounts, so nothing in this section runs against it. `PlanMount` validates
the launch folder and turns it into docker-driver bind mounts:

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

One sandbox at a time mounts a folder live. The manager refuses a second
live mount of the same folder, or of a folder inside or around it (run that
one with `--copy`), because each sandbox's undo restores the whole folder and
each review would mix in the other's changes. Undo is also refused while
another sandbox mounting the folder may still run (a deleted sandbox whose
snapshot was kept does not block a new mount).

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
are more than 256 secret files to mask. The API answers such a create with
the `needs_copy` code, and `sandbox run` falls back to copy mode, saying why.
A secret scan that cannot finish (more than 250,000 entries) refuses the
mount.

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

Each start of a stopped sandbox is a new session and takes a fresh snapshot,
unless the folder still holds changes an earlier session made that were
neither undone nor accepted. Then the manager keeps the earlier snapshot, so
undo still reverts them (and everything since), and says so on the activity
feed. It keeps it too when it cannot compare the folder with the snapshot.
`sandbox start --new-snapshot` accepts the changes and takes a fresh one;
`--no-snapshot` always keeps the previous one.

`Undo` needs the sandbox stopped first (the manager must stop it), and has a
preview mode. A stop of a ready sandbox first sends SIGTERM to the harness's
processes (found by the install root their executable or script lies under)
and waits up to eight seconds for them to exit, so the harness ends its
session as after `/exit` and its `SessionEnd` hook reaches DefenseClaw; the
stop goes ahead whatever the sandbox answers. In a git project undo:

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
  the `.git` entries the folder already holds. Those are never touched. When
  the folder is too large for that scan to finish, a `.git` the guard finds
  later is left alone only if its change time is older than the scan, which
  the session cannot fake.
- While the sandbox runs, the guard watches the folder with inotify (on
  macOS, and when the watch limit is reached, it falls back to a bounded
  periodic scan). The moment a new `.git` entry appears at any depth,
  directory, file or symbolic link, including the top level of a folder that
  had no git, the guard renames it to `.git.defenseclaw-quarantine-<time>`,
  and again for every `.git` created later in the same folder. On a
  case-insensitive filesystem (macOS's default) `.GIT` and other spellings
  count, since git finds them as `.git`. The rename walks the path with
  `O_NOFOLLOW` directory handles and never replaces an existing name, so a
  symbolic link the agent swaps in cannot redirect it. The sandbox runs as
  your uid, so a folder the agent made read-only gets write permission back
  for the rename and its mode restored. No git on the host ever reads the
  planted configuration. A rename that keeps failing is reported once.
- The repositories that were there before are writable through the mount
  like the rest of the folder (only the project's own repository and its
  submodules are pinned read-only). The snapshot records the git config,
  hooks, `commondir`, attributes and `.git` pointer of up to 64 of them, and
  the end-of-session review flags every change to those as critical.
- It also reports new gitlink (submodule) entries in the project's index;
  those are not changed.
- Each detection is kept on the sandbox record (`nested_repos` in the REST
  API), emitted as a `quarantine` `log.sandbox.workspace` record and a
  `sandbox.nested_repo` finding, and published on the activity feed, where
  the run UI, `sandbox activity` and the TUI show it. The end-of-session
  summary lists it again. `git init` can recreate the `.git` the guard
  renamed while it was still writing it: a `.git` that comes back in the
  same folder within ten seconds is renamed too, but belongs to the same
  detection (its `also` names), so one repository creation is one entry.

So running git in the project on the host is safe while the guard runs: a
repository the agent plants is quarantined before a host git command can use
it. The guard runs only while the sandbox is ready. It also quarantines a
repository you create in the folder yourself during a session (rename it
back when you are done). The review shows each folder's quarantined
repository once, as a critical entry, and leaves its files (git's sample
hooks among them) out of the file counts, the scanners and the diff. Undo
removes it: the restore takes its files, and undo removes the empty
directory tree left of each quarantined name.

For untrusted repositories or tasks, use copy mode. There the agent's work
comes back as git objects in a verified bundle, which cannot carry another
repository's configuration, and nothing reaches the host folder until the
operator applies it.

### Copy mode

Copy mode is the choice for untrusted repositories or tasks, and the only
mode on the vm driver. The agent works on a copy, and changes come back only
through a verified pull, applied by git on the host as the host user: only
the executable bit crosses, and the in-sandbox uid never reaches the host.
Nothing is applied without a review: a session without a terminal, or with
`--yes`, leaves the work in the sandbox and names the pull.

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
digits and `-`, starting and ending with a letter or digit), and `git` is
reserved. OpenShell 0.1.1 creates sandboxes of at most 19 characters, so a
new name is held to that; the default is `<folder>-<rand4>`, the folder name
cut to fit, with the harness and DefenseClaw ownership carried as labels.

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
   (`/usr/bin:/bin:/usr/sbin:/sbin`). An image for the vm driver
   (`BuildSpec.MicroVM`) also installs `nss-myhostname`, asked right after
   `files` and before `dns` (`hosts: files myhostname dns`). It answers
   `localhost`, `localhost.localdomain`, `*.localhost` and the hostname
   with loopback addresses and does no network I/O, so localhost resolves
   in a MicroVM, whose `/etc/hosts` is empty (see
   [compute drivers](#compute-drivers)). The package is pinned next to the
   base image (`NSSMyhostnameDebs` in `internal/openshell/version.go`):
   Ubuntu 24.04's `libnss-myhostname` 255.4-1ubuntu8.17 for amd64 and
   arm64, downloaded from Ubuntu's snapshot archive (Launchpad's librarian
   as fallback), checked with `sha256sum -c` and installed with `dpkg -i`.
   It needs only the base's `libc6` and `libcap2`, so no package index is
   fetched, and two images with one content hash carry the same module.
   The build fails unless the module answers `localhost` with `127.0.0.1`.
   An image for the docker driver has no such step: its Dockerfile, content
   hash and tag are those of the images before it, and its build fetches
   nothing more than it did. `MicroVM` is part of the content hash only
   when set, and of `images.json` (`microvm`), so the two kinds of image of
   one harness never select or prune each other. (The digest-pinned base
   has `curl` but not `jq`, so every build still runs `apt-get update` and
   installs the archive's current `jq` there.)
2. Installs the harness at a version whose Linux hook contract is known. Any
   other version fails before the build starts. Claude Code 2.1.156 is
   relocated from the digest-pinned base image, and no other Claude Code
   version is pinned. Codex 0.146.0 replaces the base image's 0.117, which is
   outside every reviewed contract. An npm-installed harness (Codex,
   OpenCode, Copilot CLI, Amp) is downloaded once with `npm pack`, installed
   from that tarball only after its SHA-512 matches the pinned registry
   integrity, and its native executable must match a pinned sha256 per
   architecture. Binaries move to root-owned
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

- an allowed tool call's side effect appears (for Claude Code and Codex the
  stand-in answers its `PreToolUse` with the gateway's advisory `alert`
  verdict, so the run also proves an alert never blocks a tool);
- a tool call the stand-in ingress blocks has no side effect;
- `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse` and `Stop`
  each arrive authenticated and with an idempotency key.

For both harnesses the allowed run is repeated with hostile user and project
settings planted: every known way to switch the managed hooks off or divert
them. The hooks must still fire, and none of the planted programs may run.
`HookFireOptions.RunFiles` mounts a sandbox's per-run files into every probe
container. `TestLiveRunConfig` (tag `openshell_integration`, on branch
`test/openshell-live`; see [Testing](#testing)) uses it to prove the per-run
configuration below against the real harnesses.

The probe of an image for the vm driver (`BuildSpec.MicroVM`) ends with the
allowed run once more, with an OpenShell MicroVM's name resolution: an
`/etc/hosts` that names neither `localhost` nor the hostname (only the
stand-in ingress and, in relay mode, `host.docker.internal`), the guest's
`resolv.conf` pointed at a resolver no server answers at (the container's
own `127.0.0.53` in relay mode; the stand-in's address on the host network,
where `127.0.0.53` is systemd-resolved), and the image's own
`nsswitch.conf`. The two files are written to a new directory under the
system temp directory (`Builder.TempDir`, `os.TempDir()`: the user's
`$TMPDIR` under `/var/folders` on a Mac), which Docker Desktop shares by
default wherever the data dir is (a managed install's
`/opt/cisco/defenseclaw/runtime` is not shared), and removed with the
container; the doctor's file sharing check on a vm gateway is of that
directory. An image for the docker driver never runs this scenario. Its
verdict is kept apart (`MicroVMVerified`, `MicroVMProblem` and
`MicroVMInconclusive` in `images.json`) and never fails the probe; only an
interrupted probe fails. It is definitive only two ways: a pass, or a
harness that failed and printed a failed lookup of localhost
(`MicroVMProblem`, named with the line it printed): it resolves names on
its own, which the image cannot answer. Anything else settles nothing
(`MicroVMInconclusive`): a MicroVM run that could not run at all (a mount
Docker refused, a timeout, an address relay mode could not learn), or a
harness that exited or fired no hook without saying why. Such an image
stays unchecked for a MicroVM (`Record.MicroVMUnchecked`): `Build` probes
it again when it is next asked for it, which the daemon's create on the vm
driver does, and so does `sandbox image build`; a definitive problem stays
until `sandbox image build <harness> --force`. `sandbox image build` says
which of the two an image has.

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
  `claudecode`, `codex`, `copilot`, `cursor` and `omnigent` are managed.
- **user:** the registration lives in a file the agent can edit, or code the
  agent or a repository adds runs beside the hooks. `opencode`, `amp`, `kiro`,
  `devin`, `hermes`, `openhands` and `antigravity` are in this tier; the
  hook-silence finding is the backstop.
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
  network events of the harness's own binaries under its install root,
  egress, native OTLP) for `HookSilence` without a single hook request.
  Commands the harness did not start, such as the CLI's probe, a copy-mode
  upload or pull, or your own `sandbox exec`, do not count.
- **Hook tamper** (`hook_tamper`, `internal/openshell/manager/hook_tamper.go`):
  a tool that ran without a verdict. Per binding, the manager records each
  pre-tool decision and pairs it with the call's post-tool event. A
  post-tool event whose pre-tool event was denied, or never arrived, raises
  a HIGH `hook_tamper` finding, a `finding` activity entry and a count in
  the sandbox's hook coverage (`tampered`, `last_tamper_at`). The pairing
  reads each harness's own event names, exactly as the harness sends them:

  | Connector | Pre-tool | Proves the tool ran | Closes a call only | The call is named by |
  | --- | --- | --- | --- | --- |
  | Claude Code | `PreToolUse` | `PostToolUse` | `PostToolUseFailure`, `PermissionDenied` | `tool_use_id` |
  | Codex | `PreToolUse` | `PostToolUse` | | `tool_use_id` |
  | Cursor Agent | `preToolUse` | `postToolUse` | `postToolUseFailure` | `tool_use_id` |
  | OpenCode | `tool.execute.before` | `tool.execute.after` | | the plugin's `callID` |
  | Amp | `tool.call` | `tool.result` with status `done` | `tool.result` with another status | the plugin's `toolUseID` |
  | Kiro CLI | `preToolUse` | `postToolUse` | | session, tool name and tool input |
  | Copilot CLI, Devin CLI, Hermes, OpenHands, Antigravity, OmniGent | not paired | | | |

  A failure event closes a call but never proves tamper: Claude Code can
  report a failure before `PreToolUse` ran. Kiro CLI 2.24.1 sends no
  per-call ID, so the manager keys its calls by a digest of the call's
  session, tool name and canonical tool input, which Kiro sends unchanged
  with both events. Measured: Kiro sends `postToolUse` only for a tool that
  ran (not for one a `preToolUse` exit 2 blocked, nor for one its own
  permission check denied, which runs after `preToolUse`). Identical calls
  share a key, so the ledger counts open ones, and each call's own verdict
  decides: a retried call that DefenseClaw now allows is not tamper, and a
  repeat of a call DefenseClaw allowed with the same input is not reported.
  Copilot CLI and Devin CLI hooks carry no per-call ID either, and whether
  their post-tool events fire for a call a hook denied is not measured, so
  for them hook silence is the backstop. The same holds for Hermes,
  OpenHands, Antigravity and OmniGent until their hook payloads are
  measured. Every harness's pre-tool events
  count in the session summary's tool calls and blocks.

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
  hooks that got through. A connection OpenShell closes because the policy
  changed while it was open ("policy generation is stale"; every policy
  reload does that) is no refusal and only counts as an attempt. A
  transparent-mapping denial (`transparent_tcp_mapping_denied`), which
  OpenShell also answers while it republishes the host alias's mapping, is a
  refusal only when no authenticated request follows it within 15 seconds.
- OpenShell lets a hook connect but no authenticated request (hook, OTLP or
  notify) follows within 15 seconds: the ingress does not answer, or the
  sandbox token did not reach the hook.
- The harness calls its model for `HookReachWindow` (30 seconds) without one
  hook request reaching DefenseClaw. Only the harness's own model calls
  count: a connection its binary makes under a provider rule
  (`_provider_*`), or to a host port. Its start-up and onboarding traffic
  (update checks, telemetry, downloads, through the egress proxy or around
  it) comes before the first prompt fires a hook, so it starts no window,
  and neither does a model call in the session's first 20 seconds (the Codex
  TUI asks its model endpoint for the model list as it opens) or anything in
  a sandbox with no harness session. OTLP is no
  sign of work either: the Codex TUI exports it from its start and posts its
  first hooks only with the first prompt. Since no hook was seen failing,
  the warning then reads "No hook has reached DefenseClaw yet" (hook
  coverage `no_hook_yet`) rather than claiming tool calls are blocked.

An authenticated hook clears the flag (`hooks_restored` on the feed). The
sandbox's hook coverage carries `unreachable`, `unreachable_reason` and
`ingress_refused`, which `sandbox status`, `sandbox list` ("unreachable!")
and the "Sandbox hooks" check of `sandbox doctor` show. The run itself warns
live (the daemon's line, or its own once neither a hook nor authenticated
OTLP arrived in the session's first 45 seconds), ends the summary with
"DefenseClaw hooks are not reaching
the daemon; every tool call is being blocked … Run: defenseclaw sandbox
doctor", and exits 69 when not one hook of the session got through (the
harness's own non-zero status wins). `sandbox logs` does the same for a
finished detached run with no hook since it started.

A hook that does reach the ingress still fails closed when the answer is an
error: a route or connector the binding does not allow (403), the rate limit
(429), a malformed or oversized request (400, 413). The ingress reports every
authenticated hook or inspect post it answers outside 2xx, except a replay of
an answer already reported, and the sandbox's hook coverage counts them as
`hook_failed` with `last_hook_failure` (for example `HTTP 429 Too Many
Requests`). `sandbox list` ("4 calls, 1 blocked, 2 failed"), `sandbox status`
(the "Hook traffic" and "Hook error" rows) and the end-of-session summary ("1
hook call failed (blocked)") show them, and the feed gets a `hook.failed`
entry at once and then at most one every 10 seconds per sandbox, summing up
the failures in between. Tool calls and blocks count only verdicts, so a
failed pre-tool hook is not among them.

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
config could otherwise use to make every command source a file first; the
OTLP header variables and `NODE_OPTIONS`, which the launcher sets for Codex
alone, are blanked there too. Codex's own sandbox cannot nest inside
OpenShell, so skip-permissions runs pass
`--dangerously-bypass-approvals-and-sandbox`, and runs that keep the prompts
(`--safe`) pass `sandbox_mode="danger-full-access"` with
`approval_policy="untrusted"`, which asks before every command outside
Codex's read-only set and every edit. (`on-request` would ask only when the
model escalates out of a sandbox Codex no longer has, so harmless-looking
writes and test runs went through unasked.) `codex exec` cannot ask, so a
headless `--safe` run refuses those commands. The launcher exports
`CODEX_API_KEY` from `OPENAI_API_KEY`, trusts the exact working directory,
stores the API key login for interactive runs, exports the OTLP
authorization header, and passes Codex's Node wrapper
`NODE_OPTIONS=--disable-warning=UNDICI-EHPA` (Node otherwise prints its
EnvHttpProxyAgent warning at every start).

Two Codex behaviours need no user action but explain what the activity feed
shows:

- The Codex TUI downloads its startup tip
  (`raw.githubusercontent.com/openai/codex/main/announcement_tip.toml`) at
  every start with an HTTP client that ignores the proxy, whatever
  `tui.show_tooltips` says, and keeps it in memory only, so no managed
  setting or pre-seeded file prevents it (Codex 0.146
  `tui/src/tooltips.rs`). OpenShell refuses the connection and drafts a
  proposal; triage rejects it (`harness_background_fetch`) instead of
  opening a direct rule, whose policy reload would close the session's open
  connections, and Codex shows a built-in tip. OpenShell's denials of the
  download are audited but neither counted as blocked sites nor shown on
  the feed; the rejection's one line explains it.
- On Amazon Bedrock (`--llm bedrock`) the run pins `openai.gpt-oss-20b` in
  the managed config, because Mantle does not serve Codex's own default
  model (its requests fail with `validation_error: Invalid 'input'`). The
  banner's Model line names the model; `-- -m MODEL` picks another (a
  `-c model=` override does not, because the managed config wins over it).
  Mantle serves only function tools (`Invalid tools: unknown variant
  namespace` otherwise), so the managed config also pins
  `features.multi_agent = false` and `web_search = "disabled"`
  (`SandboxModelProvider.FunctionToolsOnly`): a Codex typed in `sandbox
  connect --shell` or started by the in-sandbox shim gets them too, not only
  the launches that carry the session flags.
  Mantle's Responses route rejects every turn after the first of a Codex
  conversation: Codex replays its earlier replies as assistant `message`
  items with `output_text` content, Mantle drops their `id` and `status`
  and then fails its own validation of them (`invalid_prompt`, 219
  validation errors, sent as an SSE `error` event after
  `response.in_progress`), which Codex reports as `stream disconnected
  before completion: stream closed before response.completed`. The same
  request with the reply as plain string content completes, so this is a
  Mantle limitation no provider setting avoids (Codex 0.146 has only
  `wire_api = "responses"` and no setting for how it serializes history).
  Start each task with `/new` in the TUI (or one `codex exec` per task);
  tool calls within one turn work. The launch banner of an interactive
  Codex session on Bedrock says so (`harness.CredentialProfile.Caveat`).

### Per-sandbox managed configuration

What differs per run cannot live in the image. For every sandbox the manager
renders `connector.SandboxRunFiles` for the image's render target. On the
docker driver it writes the files under
`<data_dir>/sandboxes/<name>/run-config/` (owner-only directory, files 0644)
and bind-mounts each read-only at its in-sandbox path, in mount and copy mode
alike. Stop and start keep the files; delete removes them. On the vm driver,
which has no mounts, the same bytes are baked root:root 0644 into the
sandbox's run image instead (see [compute drivers](#compute-drivers)), and a
start compares the render with the image's digest instead of rewriting.

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
  (`model_provider`, plus `openai_base_url` or a `model_providers` table),
  the provider's default `model` when it does not serve Codex's own
  (Bedrock Mantle: `openai.gpt-oss-20b`; only `-m` at launch overrides it),
  and defines the imported servers with `cwd` and `env_vars` pinned.
  `requirements.toml` gets `allowed_approval_policies` without `never`
  (`untrusted` first; Codex falls back to the first entry) and
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
response's one-line notice and in `Sandbox.MCP`. A server on this machine's
loopback over HTTP whose port the run accepted with `--host-port` comes
along, pointed at `host.openshell.internal:<port>`; it connects once you
approve the sandbox's ask for the port. For another loopback port, the
left-behind reason names the `--host-port` that would bring it; HTTPS servers
on this machine stay behind (their certificates name `localhost`).

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
- The bearer reaches curl as `--config` on a file descriptor, never on its
  command line (with `token_delivery: env` it is the token itself); the
  Codex notify bridge does the same.
- A reply must name one of the verdicts `allow`, `alert`, `block` or
  `confirm`; anything else fails closed. `alert` is advisory (`would_block`
  false, for example a HIGH rule in the default guardrail profile): the hook
  prints the harness notice the gateway rendered and the tool runs, as with
  the host hooks and the native hook runner.

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
`NODE_OPTIONS` and `NODE_PATH` from the harness environment. It drops the
dynamic loader's variables (every `LD_*`, `LD_PRELOAD`, `LD_AUDIT` and
`LD_LIBRARY_PATH` among them) and `GCONV_PATH` before it starts any
program, so a shared object named in a start-up file is never loaded into
its helpers, the harness or the hooks the harness runs. The Python
harnesses' launchers (Hermes, OpenHands, OmniGent) also drop every `PYTHON*`
variable: their uv entry points run the interpreter without `-I`, so a
`PYTHONPATH` exported from a start-up file would import a planted
`sitecustomize` module into the harness. Harnesses run
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
| Codex | 0.146.0 (npm, native sha256 pinned) | `/etc/codex/requirements.toml` | managed | `--dangerously-bypass-approvals-and-sandbox` | OpenAI API key, Bedrock Mantle | verified |
| OpenCode | 1.18.31 (npm, native sha256 pinned) | Root-owned plugin `/usr/local/lib/defenseclaw/opencode/defenseclaw.js`, registered in `/etc/opencode/opencode.json`; the launcher refuses to start beside any other plugin | user | `--auto` | Anthropic API key, OpenAI API key, Bedrock Mantle | verified |
| GitHub Copilot CLI | 1.0.88 (npm, native sha256 pinned) | `/etc/github-copilot/policy.d/50-defenseclaw.json`, with `allowManagedHooksOnly` in `/etc/github-copilot/managed-settings.json` | managed | `--yolo` | GitHub token (endpoints unverified), bring-your-own Anthropic key or Bedrock Mantle | verified |
| Amp | 0.0.1785334225-g9abe75 (npm, native sha256 pinned) | User-owned plugin `~/.config/amp/plugins/defenseclaw.ts` | user | `--dangerously-allow-all` | Amp API key (endpoints unverified) | unverified |
| Cursor Agent | 2026.07.23-e383d2b (release archive, sha256 measured by DefenseClaw) | Enterprise `/etc/cursor/hooks.json`, every event `failClosed` | managed | `--force` | Cursor API key (endpoints unverified), or `cursor-launch login` inside the sandbox (the session is readable by the workload) | unverified |
| Kiro CLI | 2.24.1 (release archive, vendor sha256) | Root-owned agent `/usr/local/lib/defenseclaw/kiro/defenseclaw.json`, alone in the directory the launcher forces `KIRO_AGENT_CONFIG_DIR` to | user | `--trust-all-tools` | Kiro Pro API key (endpoints unverified), or `kiro-launch login --use-device-flow` inside the sandbox (the token is readable by the workload) | verified (hooks and blocking; no real model) |
| Devin CLI | 3000.4.25 (release archive, vendor sha256) | User-owned `~/.config/devin/config.json`, hooks restored from a root-owned template on every start; workspace trust skipped | user | `--permission-mode dangerous` | `devin-launch auth login` inside the sandbox (the credential is readable by the workload) | unverified |
| Hermes Agent | 0.19.0 (PyPI, root-owned uv tool on a private CPython) | Managed layer `/etc/hermes/config.yaml` and `/etc/hermes/.env`; the launcher refuses a `.env`, plugin or `secrets` section in the Hermes home that would switch the hooks off, move the managed layer or load code beside them | user | `--yolo` | OpenAI API key, Anthropic API key, Bedrock Mantle (the curated profiles carried no real model in a sandbox) | verified (mock model) |
| OpenHands CLI | 1.16.0 (PyPI, root-owned uv tool on a private CPython) | User-owned `~/.openhands/hooks.json`, restored from a root-owned copy on every start; a project hooks file or a non-file hooks path is refused | user | `--always-approve` | OpenAI API key, Anthropic API key, Bedrock Mantle (the curated profiles carried no real model in a sandbox) | verified (mock model) |
| Antigravity CLI (agy) | 1.2.12 (release tarball, SHA-512 pinned) | User-owned `~/.gemini/config/hooks.json`, restored from a root-owned copy on every start; a non-file hooks path is refused | user | `--dangerously-skip-permissions` | Gemini API key (unverified with a real key) | verified (mock model) |
| OmniGent | 0.13.0 (PyPI, root-owned uv tool on a private CPython) | Server configuration `/etc/omnigent/config.yaml` through `OMNIGENT_CONFIG_HOME`; the launcher stops and stops reusing any recorded server or daemon started without it | managed | none (its policies decide) | Bedrock Mantle (default model `openai.gpt-oss-20b`), OpenAI API key (`--model` required), Anthropic API key (unverified) | verified (mock model) |

OpenCode and Copilot CLI ran end to end in OpenShell 0.1.1 sandboxes
(`TestLiveSandboxHookOnlyHarness` in `internal/gateway`, on branch
`test/openshell-live`), with the project
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

Hermes, OpenHands, Antigravity and OmniGent ran end to end through the
DefenseClaw daemon (`TestSandboxHookOnlyHarness` in `test/e2e/openshell`, on
branch `test/openshell-live`)
against the E2E mock model behind a `--credential` binding on
`host.openshell.internal`: hooks (OmniGent: policy events) reached the
ingress with the model key substituted, the marker command a test rule
blocks was denied with the rule's reason, and egress went through the proxy
with the blocklist and a sandbox unblock. Command rules also judge text these
harnesses send to a running process (OpenHands terminal input, agy
`send_command_input`, Hermes' `process` write and submit) as shell input;
Hermes' `execute_code` tool, whose Python command rules cannot read, is
turned off in the image. In an OmniGent sandbox a confirm verdict denies:
OmniGent's approval routes answer any process in the sandbox.

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
  every tool; `.*` matches none, so tool hooks with it never fire. The tool
  hooks' payloads carry `session_id`, `tool_name` and `tool_input` (and
  `tool_response` after the tool), but no per-call ID. Exit code
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
`<data_dir>/policies/sandbox`; `pack_dir` must be absolute or start with `~/`)
or an absolute path, loaded with the same strict rules as guardrail rule
packs. A pack's digest is `sha256:` over the file's
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

The manager (`watch.go`) turns the records into the feed and the counts:

- A denied connection counts once as a blocked request. OpenShell first
  refuses the name lookup (`NET:REFUSE … [reason:policy_dns_ineligible]`, no
  port and no process), answers it with a staged address and then denies
  the connection; the refusal is audited but neither counted nor shown.
  A record of the container's own host name (Docker's 12-hex-digit default)
  is treated the same.
- `CONFIG` records of the policy DNS (`Policy DNS mapped <name> …
  synthetic=<addr>`, `Policy DNS staged unapproved name <name> …`) map the
  synthetic addresses in 198.18.0.0/15 to their names, so a later record of
  a connection to such an address names its destination;
  `host.openshell.internal`'s address is handled as the host alias. The host
  alias's address and the ports its mapping covers are kept on the sandbox
  record (`host_alias`), because a restarted daemon's watch resumes past the
  mapping record; a synthetic address on DefenseClaw's own ingress or egress
  port, or on a declared `--host-port`, is the host alias's too.
- A connection OpenShell closed because the policy changed under it ("L7
  tunnel closed before inspection because policy changed: policy generation
  is stale"; every policy reload and provider update does that, the policy
  still allows it and the client connects again) is audited but neither
  counted as a blocked request nor shown as a block. Neither is a denial of
  this install's own ingress or egress port, nor a mapping denial of a host
  port the mapping covers (republished under the connection).
- OpenShell drafts no proposal for a denied connection to
  `host.openshell.internal`. The first one to a port the run declared with
  `--host-port` becomes a DefenseClaw `host_port` ask (`sandbox approvals`,
  the live notice), and approving it merges an
  `allow_host_openshell_internal_<port>` rule, which opens the port. A
  denied connection to another host port counts as blocked and gets one
  feed line per session (reason `host_port_closed`) that names the
  `--host-port` to run with. A rejected proposal for an address of this
  machine says how to reach the service through a host port instead.
- Every configuration change that moves a running sandbox's policy (pack,
  profile, network mode, approvals, skip-permissions, project mode, the
  organization's egress lists) puts one `sandbox.lifecycle` line on its feed
  (reason `policy_changed`), such as "your organization's sandbox policy
  changed: egress_block now includes example.com; applied to <name>".
- A hook verdict that let the tool call run but flagged it (an alert, or a
  block the event cannot enforce) is a `finding` on the feed (reason
  `hook_finding`) with the verdict's severity; the agent reads "Allowed but
  flagged by DefenseClaw rule …", not advice to try another approach.
- A record from before the daemon started is a replay; its feed event
  carries `replayed: true` and the CLI adds `(while DefenseClaw was down)`.
- The sandbox record keeps when the sandbox became ready (`ready_at`,
  OpenShell 0.1.1 reports no transition times), so a restarted daemon
  reports its uptime from then.
- The end-of-session summary reads the sandbox until its counts stop moving
  (at most three more reads, a second apart), because OpenShell reports the
  last denials a moment after the session ends.

## Platform behaviours to design around

These were measured on one Linux arm64 host running OpenShell 0.1.1 (the
upstream installer, the docker driver and the `openshell-gateway` user
service) in September 2026, with Claude Code 2.1.156 and Codex 0.146.0.

### Network

| Behaviour | Design consequence |
| --- | --- |
| Any network policy update, even an unrelated rule, closes in-flight connections. So does the first settings poll, about 10 to 12 seconds after each sandbox start, and every global profile import. | Egress decisions live in the proxy, not in OpenShell rules. The policy renders deterministically. Profiles are imported once at setup; a create that must import one (a new `--credential` host, a new image's binaries) first tells the running sandboxes and waits, up to 30 seconds, until none has a hook in flight. The manager must start the harness only after the first settings poll (about 15 seconds) and batch rare policy updates for moments when no hook is in flight (`sandboxauth.InFlight`, `openshell.approvals.debounce_ms`, 3,000 ms by default). |
| Any provider-profile change on the gateway, by any daemon, makes every running sandbox's supervisor report `Settings poll: config change detected [… policy_changed:false provider_env_changed:true]` within its next poll (measured: a `DeleteProviderProfile` from another daemon's sandbox delete, and an `ImportProviderProfiles` from another's create, each 5 to 12 seconds before), even for sandboxes that use none of the changed profiles. The supervisor then republishes its policy DNS mappings, which closes open connections ("policy generation is stale") and briefly denies new ones to the host alias. This is OpenShell's behaviour, not a DefenseClaw update. | The feed and the blocked counts leave out the connections such a reload closes and the denials of DefenseClaw's own ports, and a hook's mapping denial counts as a refusal only when no authenticated request follows it within 15 seconds. On a gateway shared by several daemons, expect these reloads whenever one of them creates or deletes a sandbox with its own credential or ingress profile. |
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
| Docker driver: `process.run_as_user` sets the uid, and files written to a bind mount are owned by it on the host. | Mount mode runs as the host uid. |
| Docker driver: content under `/sandbox` in the base image belongs to uid 998, the image's `sandbox` user. | The overlay chowns `/sandbox` to the run-as uid; without it writes to `~/.claude` fail and `SessionStart` silently does not run. |
| vm driver: `run_as_user` is ignored. The driver rewrites the image's `sandbox` account to the gateway's `[openshell.drivers.vm] sandbox_uid`/`sandbox_gid` (default 1000:1000) and runs every workload as it, for every sandbox on the gateway. | Setup writes the host uid and gid there, so the per-uid overlay images (`/sandbox` chowned to that uid) work unchanged; the workload check refuses any other identity, and the doctor's vm-identity check catches a gateway without the keys before a boot is spent. |
| vm driver: no shared folders and no `driver_config` but `gpu_device_ids`. | Per-run managed files are baked into a run image, root:root 0644, whose tag carries a digest of the files; a posture change on start is compared by digest and a stricter one refuses the start. |
| Landlock hides `/dev` entries that are not listed. | `/dev/ptmx`, `/dev/pts` and `/dev/tty` are read-write for PTY tools. |
| Claude Code drops a whole managed-settings drop-in with one invalid field, silently. | The hook-fire probe gates every image. |
| Claude's bare mode disables hooks. | Managed `env` pins `CLAUDE_CODE_SIMPLE=0`, which restores every hook except `SessionStart` in bare mode, and the probe plants bare mode in hostile settings. |
| Codex's own sandbox cannot run inside OpenShell; `codex exec` authenticates with `CODEX_API_KEY`. | Launch flags turn it off; the launcher exports `CODEX_API_KEY`. |
| Claude Code and OpenCode handle Ctrl-Z by restoring the terminal, signalling their process group to stop, and redrawing only on `SIGCONT`. In a sandbox that signal fails: the seccomp filter refuses any `kill()` aimed at a process group (EPERM), and `sandbox exec --tty` starts the command as the leader of a new session under the sandbox supervisor, so its process group is orphaned and the kernel would discard `SIGTSTP` anyway. Nothing stops, and the TUI waited for a `SIGCONT` that never came, with the terminal in cooked mode. Codex carries on once the signal returns. | In a terminal session with no job-control shell above it, the launcher execs `dc_supervisor.py` (Python 3, root-owned), which forks the harness into its own process group, makes it the terminal's foreground group and resumes it with `SIGCONT` whenever it stops, sending the signal to each process in the group individually (`kill(pid, SIGCONT)` per `/proc/*/stat`, never `killpg`, because the sandbox's seccomp filter blocks `kill()` aimed at a process group). Because the harness's own suspend fails in the sandbox, the supervisor also watches the terminal (`tcgetattr` on fd 0, every 0.2 s): when the harness, as the terminal's foreground group, switched it from raw to canonical mode and leaves it there for half a second, it is treated as suspended and sent `SIGCONT`; it arms again only once the terminal is raw again. The supervisor forwards `SIGHUP` and `SIGTERM` and exits with the harness's status; `SIGINT` and `SIGWINCH` reach the harness as usual. Ctrl-Z returns straight to the TUI. Headless and detached runs, a harness started from a `sandbox connect --shell` prompt (where Ctrl-Z suspends it to that shell), and an image whose base lacks `/usr/bin/python3` (the supervisor's interpreter) keep the plain `exec`. The image build refuses a `/usr/bin/python3` whose realpath the workload could replace. |

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

### macOS and Docker Desktop

Measured on an Apple silicon Mac (macOS 27.0) with Docker Desktop (engine
29.1.5) and OpenShell 0.1.1 in September 2026.

| Behaviour | Design consequence |
| --- | --- |
| Docker Desktop's LinuxKit VM kernel (6.12.65-linuxkit) runs only the capability and bpf security modules: `/sys/kernel/security/lsm` reads `capability,bpf`, and the kernel command line sets no `lsm=`. OpenShell's supervisor fails its Landlock allow/deny probe (the probe child exits 1), and the sandbox goes to its error state. | The supervisor refuses to start without Landlock whatever the policy says: OpenShell's default policy and a `landlock.compatibility: best_effort` policy fail the same probe. So no Docker-driver sandbox can start on Docker Desktop, and DefenseClaw's `hard_requirement` changes nothing there. A Mac runs the vm driver instead; the doctor still checks the Docker VM kernel for a gateway on the Docker driver, and a run that fails the probe there names the switch. |
| OpenShell's MicroVM driver (`OPENSHELL_COMPUTE_DRIVER=vm` or `compute_driver = "vm"`; Apple Hypervisor, so Apple silicon and a driver binary signed with `com.apple.security.hypervisor`; `e2fsprogs` from Homebrew's keg paths for the VM disks) boots each sandbox with its own kernel (6.12.76), passes the Landlock probe and runs the sandbox. It reads its image from the local Docker image store (`docker export`) and falls back to a registry pull of the same name when the lookup fails. | DefenseClaw drives it on a Mac (see [compute drivers](#compute-drivers)). Harness images are still built into local Docker; every name sent to the driver is under `defenseclaw.invalid/`, so the registry fallback cannot fetch anything. The doctor checks `e2fsprogs`, the signature and the images' architecture (a mismatch also falls back to a registry). |
| The vm driver prepares one rootfs per image ID (about 56 s and about 5 GB the first time, 6-8 s after that) and keeps it under `~/.local/state/openshell/vm-driver/images`; nothing evicts it. A tag pointing at an image ID the driver has prepared starts from the cache. | Run images are content-addressed, one per posture, and aliases share their base's image ID. The pre-create explain reports `vm_first_boot` for the CLI's note; the doctor and teardown name the cache and its size, and DefenseClaw never deletes it. |
| With `sandbox_uid`/`sandbox_gid` set to the host's 501:20, a new sandbox of a cached image runs as `uid=501(sandbox) gid=20(dialout)` with `/sandbox` 501:20 and writable; `/etc/passwd`, `/usr/bin/env`, the hook entrypoints and the managed settings stay root-owned (0644, or 0755 for programs and hooks). `upload` lands files owned by the workload, and `exec` runs as it (only while the sandbox is `Ready`). | The host uid and gid are the workload identity, so the images, the hook-fire probe and the policy stay the Docker driver's, and the copy is uploaded as the user the agent runs as. |
| In a MicroVM `/etc/hosts` is an empty root-owned 0755 file (the init layer of the `docker export` the driver makes the rootfs from), `nsswitch.conf` is the image's (`hosts: files dns` in the base), and `/etc/resolv.conf` is `nameserver 127.0.0.53` with `options timeout:2 attempts:2`, a loopback DNS relay that answers `localhost` with SERVFAIL; only the loopback interface is configured. `getent hosts localhost` fails, and Antigravity CLI 1.2.12 exits at start: `Failed to start: listen tcp: lookup localhost on 127.0.0.53:53: server misbehaving`. The workload cannot write `/etc`. Reproduced without OpenShell by `docker run` of the base image with an empty file mounted over `/etc/hosts` and a SERVFAIL resolver at `127.0.0.53`: getent, Node, Python, a cgo and a pure Go program and agy all fail (curl answers localhost itself). | Every image for the vm driver installs the pinned `nss-myhostname` after `files` (see [Build](#build)); in the same container getent, Node, Python, the cgo Go program and agy then resolve localhost, and with only a loopback interface `_gateway` and `_outbound` find nothing. A pure Go program still fails. The hook-fire probe's MicroVM run catches such a harness, and the vm driver boots only images that pass it. Reported upstream as a guest-init fix (write `127.0.0.1 localhost`, `::1 localhost` and the hostname to `/etc/hosts`). |
| The `nvidia/openshell/openshell` Homebrew formula runs the gateway as a `brew services` service. An OpenShell installed another way, such as from NVIDIA's release binaries, runs its gateway outside that service. | On macOS DefenseClaw manages only the Homebrew service. It finds an `openshell` installed another way on `PATH`, but the doctor's gateway-service check fails and setup offers to install the formula. |

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
- Linux amd64 and arm64 on the docker driver, and macOS on Apple silicon on
  the vm driver (see [compute drivers](#compute-drivers)). Windows, WSL2 and
  Intel Macs are unsupported: `openshell.CheckHost` refuses them before any
  sandbox command runs, except `teardown`. The vm driver on Linux and a
  Docker VM with Landlock on a Mac (Colima, OrbStack) may work, untested.
- The daemon and the gateway run as the same non-root user.
- `internal/openshell` doctor checks cover the platform, user, Landlock (ABI 3
  or newer), Docker (Engine 28 or newer, host networking, file sharing, disk),
  systemd linger, the gateway service, CLI, registration, mTLS files, gateway
  version and driver, global policy, bind mounts, OpenShell telemetry and the
  sandbox ports; on a vm gateway also `vm-driver` (e2fsprogs, the
  Hypervisor signature, image architecture), `vm-identity` and
  `vm-resources`, and the disk of the prepared-rootfs cache.

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

Live tests need a real OpenShell 0.1.x gateway (with bind mounts enabled for
the workspace tests) and Docker, so CI cannot run them. They are kept for dev
hosts on branch `test/openshell-live`, one commit on top of this branch: the
`openshell_integration` Go tests in `internal/openshell/`,
`internal/openshell/image/`, `internal/openshell/workspace/`,
`internal/openshell/sandboxcli/` and `internal/gateway/`, the end-to-end
suite in `test/e2e/openshell/` (mock model servers, harness scenarios),
`scripts/test-e2e-openshell.sh` and the manual OpenShell Integration E2E
workflow. To run them against newer work, rebase that commit onto it. This
section on that branch lists the commands and the environment variables the
tests read. The live tests create short-lived, prefixed sandboxes and delete
them.

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
