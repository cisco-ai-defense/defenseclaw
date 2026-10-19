# AXIS contributor feasibility probes

This contributor-only prototype starts the approved integration plan's Stage 2.
It adds no production AXIS adapter, command, configuration, installation path,
or support claim. Explicit contributor payloads are separate from the ordinary
Go package tests, which need no
AXIS, network, Claude account, Docker, or WSL installation.

The source reference is AXIS
[`fb5fd5f0f9377c2ccb30d7e027a36373de0d037c`](https://github.com/ROCm/axis/tree/fb5fd5f0f9377c2ccb30d7e027a36373de0d037c),
which reports `axis 0.3.5`. Review the local executable's provenance and SHA256
independently before running it. The flags bind this probe to those local bytes;
the version string alone does not establish the source commit. Never substitute
an arbitrary artifact's freshly calculated hash for that review.

## Requested platform targets

The integration targets AXIS through MXC on each native host:

| Native host | Required MXC executor | Evidence from this prototype |
| --- | --- | --- |
| Windows | `ProcessContainerWindows` | Not qualified; this Linux harness does not test native Windows. No WSL dependency or fallback. |
| Linux | `BubblewrapLinux` | Not qualified; the pinned strict-filesystem live probe is blocked below. |
| macOS | `Seatbelt` | Not qualified; verify the AXIS-to-MXC route and native behavior separately. AXIS's existing macOS dispatch is not evidence of an MXC route. |

These are requested support targets, not current product availability. Each
requires independent live qualification under the same DefenseClaw security
contract. No AXIS platform is enabled by this prototype.

The `mxc-runner` experiment uses a separately pinned MXC V1 API with AXIS child
guards. Its first CI stage only builds code and generates a combined dependency
lock. Review and commit that lock, then rebuild with `--locked` before any live
execution. It is not a replacement for the product adapter or acceptance gates.

## Ordinary offline tests

From the repository root:

```sh
go test -race ./test/e2e/axis -count=1
```

These cover missing/malformed pins, changed executable bytes, unsupported
platform admission, private path preparation, an unavailable daemon path,
environment allowlisting, literal argument handling, and bounded diagnostics.
On Linux they also test the prototype supervisor with benign system commands,
including exit status and timeout. Those helper tests do not run AXIS.

## Explicit Linux live probes

The optional live tests require a disposable, unprivileged Linux test account,
the repository Go toolchain, and reviewed AXIS 0.3.5 artifacts. Its MXC process
backend also requires the appropriate reviewed `lxc-exec` and seccomp launcher,
host Bubblewrap, unprivileged user namespaces, and seccomp support. `/bin/sh`
and `/bin/sleep` must exist. The probe requests block networking and no CPU,
memory, or process-count limits, so it neither installs nor requests a privileged
network helper or cgroup configuration. No dependency is downloaded or installed.

**Current blocking result from source review:** the probe explicitly requests
`filesystem.compatibility: hard_requirement`. The pinned MXC Bubblewrap path
cannot preserve default-deny filesystem reads because its substrate mounts the
host root read-only. AXIS's default `best_effort` setting acknowledges that
weaker substrate, so omitting this field would not prove host confidentiality.
The probe keeps `provider: mxc` fixed and is expected to refuse the hard policy
before running its payload. That refusal is a **failed live feasibility gate**,
not a passing negative test or permission to downgrade. See the pinned
[filesystem translation](https://github.com/ROCm/axis/blob/fb5fd5f0f9377c2ccb30d7e027a36373de0d037c/crates/axis-sandbox/src/linux/mxc.rs#L2993-L3022),
[substrate refusal](https://github.com/ROCm/axis/blob/fb5fd5f0f9377c2ccb30d7e027a36373de0d037c/crates/axis-sandbox/src/linux/mxc.rs#L2911-L2921),
and [compatibility default](https://github.com/ROCm/axis/blob/fb5fd5f0f9377c2ccb30d7e027a36373de0d037c/crates/axis-core/src/policy.rs#L493-L507).
The lifecycle/timeout probes remain acceptance targets until an independently
reviewed change resolves this blocker in the required MXC Bubblewrap route.
This integration does not offer AXIS-native execution as an alternate backend.

With the sample AXIS location below, reviewed `lxc-exec` and
`axis-seccomp-launcher` may be installed beside it in `/usr/local/bin`. At the
pinned source AXIS checks its own executable directory first, independently of
the fixed PATH, then trusted package locations. It validates candidate ownership,
permissions and path components. Alternatively, use the packaged `/usr/bin`
executor and `/usr/libexec/axis` launcher layout. Bubblewrap must be available
through the fixed `/usr/bin:/bin` PATH. See the
[pinned resolver](https://github.com/ROCm/axis/blob/fb5fd5f0f9377c2ccb30d7e027a36373de0d037c/crates/axis-sandbox/src/linux/mxc.rs#L3527-L3609).

Place artifacts in trusted locations that are not concurrently modified. Give
the canonical absolute AXIS path (no symbolic-link components) and the reviewed
executable SHA256 explicitly:

```sh
go test -tags axis_integration ./test/e2e/axis \
  -run '^TestLiveAXISOffline' -count=1 -v -timeout=90s \
  -args -axis-path /usr/local/bin/axis \
  -axis-sha256 '<reviewed-64-hex-digest>'
```

The tag with missing flags fails rather than returning a successful skip.
Non-Linux systems fail admission before executing the chosen binary. The probe
checks the digest before every AXIS invocation, including `--version`. This
verifies the entrypoint only: it does not attest every runtime dependency,
eliminate filesystem replacement races, or replace a reviewed immutable runtime
bundle. Do not run it elevated or in an untrusted installation directory.

Each invocation gets a private temporary root, HOME, CWD, caches and temporary
directory. Environment values are built from scratch with a fixed system PATH;
host credentials, proxies, loader options, and AXIS overrides are not inherited.
The generated policy requests writes only to these private paths. It does not
invoke AXIS's stock Claude state migration. Private HOME is environment/state
setup, not evidence that real host HOME or credentials are inaccessible; that
requires the filesystem gate above to pass.

**Research workaround:** this pinned CLI chooses standalone execution when its
daemon connection fails. The harness supplies a deliberately nonexistent socket
inside its private directory via `--socket`. It does not connect to an existing
user daemon. This is not a stable upstream standalone-mode contract and must not
be copied into a production adapter without a separate design decision. See the
[pinned CLI launch paths](https://github.com/ROCm/axis/blob/fb5fd5f0f9377c2ccb30d7e027a36373de0d037c/crates/axis-cli/src/main.rs#L728-L892).

The two live probes check headless child exit 23, literal command arguments,
guest HOME/CWD and selected absent credential variables, writes inside owned
directories, a bounded timeout, and removal of owned temporary files. Output is
memory-bounded and runtime diagnostics are withheld on failure rather than
dumping potentially sensitive content. A failure is not retried or downgraded.
Linux supervision signals TERM through the tracked wrapper process and bounds
its wait; Go kills that wrapper if the wait expires. It never signals a numeric
PID or process group that could have been reused. This is prototype custody, not proof
that runtime descendants cannot escape or that every AXIS resource is cleaned.
Check for leftovers on the disposable host.
The pinned noninteractive AXIS path does not install the interactive path's
TERM handler; this supervisor therefore does not claim that TERM triggers AXIS
teardown. That lifecycle limitation is another unresolved gate.

## Evidence and remaining gates

The [manual test record](manual-test-results.md) includes historical Linux AXIS
experiments in an isolated WSL2 distribution on Windows. Explicit AXIS-native
offline file/socket boundary probes passed; MXC strict-policy acceptance and
AXIS-native interactive keyboard input failed. Those experiments do not qualify
native Windows, the required MXC route, or an alternate product backend. WSL is
not a target or fallback for this integration. Passing ordinary tests or
cross-compiling live tests is not live feasibility evidence. The separate
[direct native runner](runner/README.md) uses the pinned Rust API for additional
fixed offline research probes, without the CLI's missing-socket workaround; it
does not establish the requested MXC platform support.

Even a successful live run proves only these benign offline probes. Before
Stage 2 can pass, record the exact host/kernel, AXIS and dependency provenance,
artifact digests, commands, and observed results, then independently qualify:

- Real interactive and headless Claude, PTY geometry/resize, raw input,
  signals, terminal restoration, parent death and descendant cleanup.
- Authenticated DefenseClaw hooks, immutable settings, hook-fire allow/block
  outcomes, and hostile project/user settings.
- Scoped host model transport, Anthropic streaming, API-key authentication,
  expiry/revocation, and separately Claude subscription/OAuth.
- Strict egress and bypass resistance, approvals and policy refresh, runtime
  dependency admission, resources and denial-event export.
- Cross-session ownership, copied project review/pull/undo, crash recovery,
  all runtime-object cleanup and an immutable verified harness bundle.

Native Windows MXC ProcessContainerWindows, Linux MXC BubblewrapLinux, native
macOS MXC Seatbelt, and managed deployment modes are not qualified here. Native
Windows and macOS need their own live harnesses; this Linux prototype is only a
subset of the required evidence.
The [integration plan](../../../docs/design/axis-sandbox-integration-plan.md)
remains the acceptance authority; this prototype does not complete its gates.
