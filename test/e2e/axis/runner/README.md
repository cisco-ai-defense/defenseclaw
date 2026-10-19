# Direct native AXIS offline runner

This contributor-only runner calls the public `axis-sandbox` Rust API from
upstream commit `fb5fd5f0f9377c2ccb30d7e027a36373de0d037c`. It selects
`axis_native`, requires Landlock ABI 3 or later and `hard_requirement`
filesystem compatibility, and requests block networking. It neither uses the
CLI's missing-socket workaround nor starts `axisd`, a proxy, or a model server.
It is not a production adapter or an arbitrary-command runner.

Build it as an example overlay in a fresh checkout of that exact source:

```sh
mkdir -p /path/to/pinned-axis/crates/axis-sandbox/examples
cp test/e2e/axis/runner/main.rs \
  /path/to/pinned-axis/crates/axis-sandbox/examples/defenseclaw_axis_offline.rs
cd /path/to/pinned-axis
cargo +1.95.0 build --locked --release -p axis-sandbox \
  --example defenseclaw_axis_offline
git diff --exit-code -- Cargo.lock Cargo.toml rust-toolchain.toml
timeout 30s target/release/examples/defenseclaw_axis_offline
```

Use a disposable **unprivileged** Linux account. The example uses the pinned
workspace's existing, committed `Cargo.lock` and dependencies without a second
dependency graph or a hand-written lockfile. Source-build artifacts must record
both the upstream commit and this overlay's digest. Building and running need
separate evidence; copying the source alone does not verify its compatibility.

The runner creates its own private HOME, workspace and synthetic sentinel files.
Before starting threads it replaces its own environment and CWD with the private
settings, and builds the child's environment from the same fixed allowlist. Its fixed payload
checks denied sentinel reads and writes and denied writes to a read-only file
return **EACCES**. IPv4/IPv6 TCP/UDP socket creation must return **EPERM**; no
DNS, bind, connect, send, or outbound packet is attempted. Allowed writes and
child exit 23 are checked. A second payload tests AXIS's configured timeout,
tracks the direct child with a pidfd, checks that child has stopped, invokes
destroy twice, and removes the owned temporary files.

This qualifies only these fixed benign cases on the host where it actually
runs. It does not prove descendant escape resistance, parent-death behavior,
every AXIS resource's cleanup, adversarial path handling, PTY/job control,
Claude, hooks, model authentication, streaming, or managed deployments. Runtime
output is bounded when read and withheld from failure reports. The payload
itself emits only fixed markers; this is not a general untrusted-output executor.

The pinned upstream lifecycle implementation still needs independent process
identity and process-tree custody review before production use. Observing the
direct child through a pidfd does not establish those guarantees. Run this
probe only in a disposable environment without unrelated user workloads; do not
interpret a passing result as a safe process-tree lifecycle certification.

Block mode needs Landlock and seccomp, without a network helper. A future proxy
qualification separately needs the supported namespace/firewall setup and
appropriate privileges or helper. Missing host controls are failures. The
runner admits no automatic MXC or weaker-filesystem fallback.
