# Linux MXC + AXIS child-guard contributor experiment

This standalone crate investigates a Linux MXC Bubblewrap route with AXIS
filesystem and syscall policy applied to the final child. It is contributor
code, invoked manually. DefenseClaw does not load this crate or enable an AXIS
provider. No Claude, model, credentials, listener, proxy or managed deployment
is involved.

The source inputs are AXIS
[`fb5fd5f0f9377c2ccb30d7e027a36373de0d037c`](https://github.com/ROCm/axis/tree/fb5fd5f0f9377c2ccb30d7e027a36373de0d037c)
and MXC
[`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`](https://github.com/microsoft/mxc/tree/fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2).
The runner uses the new typed MXC v1 SDK directly. It does not feed AXIS's old
`0.6.0-alpha` MXC JSON to the new SDK, replace a helper behind the old contract,
or choose `axis_native` when MXC refuses.

`patches/axis-offline-mxc-child.patch` exports one narrow AXIS function, reusing
its existing seccomp options. It blocks every socket domain except AF_UNIX and
adds the existing terminal process-group/thread-signal options only for the
interactive case. The caller explicitly sets `PR_SET_NO_NEW_PRIVS` before
applying AXIS Landlock and seccomp. Existing AXIS backend behavior is unchanged.
This export is a reviewed build overlay; it is not an upstream release API.
The separately pinned `mxc-literal-argv.patch` adds an explicit MXC v1
`argv::spawn`/`argv::spawn_with_pty` seam for Bubblewrap and Seatbelt. This
probe supplies a fixed absolute executable and OS argument vector; the
legacy shell-command field is empty. Unsupported backends refuse this seam.

## Requirements

The build requires Linux x86_64, already-provisioned Rust **1.95.0**, Python 3,
Git, and the native build prerequisites of the two upstream crates. Cargo
downloads dependency sources during the build. Neither the helper nor runner
installs prerequisites, changes host policy or starts services. The direct
dependency versions in Cargo.toml are exact. All transitive versions must be
captured in the generated combined lock before live execution.

The eventual offline live experiment requires an unprivileged Linux user,
Bubblewrap **0.5.0 or newer**, usable unprivileged user/PID/IPC/UTS/network
namespaces, seccomp-BPF, Landlock **ABI 3 or newer**, and pidfd support. These are
actual host capabilities, including LSM/AppArmor and namespace restrictions;
a kernel version string alone is insufficient. AXIS fb5's seccomp program uses
x86_64 architecture and syscall constants, so this runner refuses other CPUs.
There is no best-effort filesystem mode or alternate backend.

## Build-only lock discovery, then reviewed locked rebuild

Use a fresh disposable build directory containing this directory's tracked
files. Provision the two source checkouts as its children, at the exact commits
above, with no local modifications:

```text
mxc-runner/
  Cargo.toml
  prepare_build.py
  src/
  patches/
  mxc-literal-argv.patch  # exact reviewed copy from ../patches/
  axis-source/       # exact AXIS commit, full checkout
  mxc-source/        # exact MXC commit, full checkout
```

Run `python3 prepare_build.py generate-lock` in the first build. The helper
checks both Git identities and clean status, applies the bundled AXIS export
and pinned MXC literal-argv patches, generates a combined Cargo.lock with Cargo, builds with
`--locked`, compiles helper tests with `--no-run`, and assembles `build-artifact/`.
It never executes the resulting probe. The artifact includes the binary,
combined and original upstream locks, source, patch, licenses, exact toolchain
output and SHA-256 provenance.

The build-helper guards can be tested without Rust or a live sandbox using
`python3 -m unittest discover -s . -p test_prepare_build.py` in this directory.

**The generated combined Cargo.lock must be reviewed and committed alongside
this crate before any live probe execution.** Copy the reviewed lock into a
new staging directory with fresh clean upstream checkouts, then run
`python3 prepare_build.py build-locked`. This requires an existing combined
lock and refuses to update it. Record the final artifact's provenance and hash
in the manual-test evidence. A build result does not establish live isolation.

No combined lock has been hand-written or substituted from either upstream
workspace. Until the generated lock is imported and its locked rebuild passes,
this experiment is not ready for live execution. Build and live jobs must stay
separate, with the lock review between them.

## Fixed live contract, after the lock gate

The binary accepts no user command, policy, path or environment flags. Its
internal child selector accepts only `boundaries`, `argv`, `pty` and `timeout`; paths
come from an owned private fixture, validated by the child. The supervisor
clears inherited environment before calling the SDK or creating threads, and
the SDK request supplies only a fixed allowlist. HOME, XDG state and temporary
files are under that private fixture. No caller credential or proxy is passed.
The `argv` child compares the exact OS arguments, including empty, spaced,
quoted, metacharacter, Unicode and trailing-backslash values, then emits a
marker and exits 23 after AXIS guards apply. A shell interpretation would not
preserve those arguments. Pipe and PTY cases also use the literal-argv seam.

MXC explicitly selects `Containment::Bubblewrap`, denies egress, ingress and
host loopback, and owns the process handle, PTY and timeout. The request adds
only the synthetic fixture plus the runner to MXC's standard system mounts.
Those mounts are further restricted by AXIS Landlock in the final child.
The fixed ungranted canary is deliberately available read-write at the MXC
layer and excluded from the AXIS allowlist: both operations must return
`EACCES`, proving a real AXIS restriction instead of a missing mount. This
canary contains only a fixed public string. The read-only canary's write may
return `EACCES` or `EROFS`; its content must remain unchanged.

The guarded child must also create files in its allowed workspace/HOME/tmp,
reject creation of all four IPv4/IPv6 TCP/UDP socket cases with `EPERM` before
any connect or DNS operation, and exit with code 23. The interactive case uses
the **MXC-owned PTY**: initial geometry 30x100, child `isatty`, positive matching
foreground/process groups, a readiness handshake and parent resize to 40x120.
The fresh contained child installs a fixed SIGINT handler before AXIS guards;
the handler only stores an atomic flag. The child verifies `ISIG` and
`VINTR=0x03`, and the supervisor sends that control byte through the owned PTY.
Normal child flow must observe the flag within three seconds and check the
resized groups/geometry before acknowledging the interrupt. Only then does
the supervisor send the fixed input line. The child checks positive groups
again, acknowledges continued input and exits 23. No raw PID or process-group
signal is sent. A separate guarded child must reach its readiness marker and
produce the SDK's typed timeout outcome. This stronger signal test requires a
fresh reviewed build and live run; earlier probe results do not qualify it.

Output is bounded to 64 KiB per stream. A failing fixed synthetic child retains
at most 8 KiB of JSON-escaped stderr for contributor diagnosis, without an
environment dump. Each
case has a configured MXC timeout and a 15-second supervisor polling deadline;
stream interruption has a further bounded wait. Run the eventual manual
experiment under an outer 60-second process deadline as a final safeguard
against bugs in SDK spawn/wait calls themselves. No blanket process-name kill,
raw PID signal, firewall mutation or host namespace reconfiguration is used.

Before waiting, a pidfd records the SDK's direct child. After wait it must be
readable, and repeated SDK handle kills must succeed. This proves the direct
child stopped; it does not certify all descendant cleanup or proxy helpers.
The owned fixture is explicitly removed after all handles return. Success
emits a fixed JSON result; any unavailable capability or failed assertion is
a failed experiment with no fallback. SDK policy or execution warnings also
refuse the experiment.

## One native Linux live job

The reviewed combined lock is now committed with SHA-256
`d6556677c6decd2d5d786ca082ac2bcdb37fc92130d45b7002a7e8bffe2154db`.
The Linux locked build in [run 39107869070](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39107869070)
passed, including compilation of the test binary and rustfmt. It did not run
the probe. A separate, explicitly wired live job is still required.

Keep that single live job on a fresh native `ubuntu-24.04` GitHub-hosted VM,
under its ordinary unprivileged runner account. Do not use WSL as evidence for
native Windows. Use the reviewed locked-build artifact, a clean source
checkout at its exact build commit, and a separately reviewed SHA-256 of
its PROVENANCE.json. Before executing anything from the artifact, run:

```text
python3 verify_live_artifact.py --artifact <download>/build-artifact \
  --source-checkout <clean-checkout-at-build-commit> \
  --provenance-sha256 <independently-reviewed-digest> \
  --build-commit <exact-build-commit> --build-run <exact-build-run> \
  --receipt <owned-evidence-directory>/artifact-verified.json
```

The verifier must check all 15 manifest file hashes, including the MXC patch, the exact inventory, both
upstream source/lock identities, the committed combined lock, packaged source
against the clean build checkout, locked-build status and workflow attribution.
It rejects symlink inputs, extra files and lock-generation artifacts. It never
executes the probe. Its receipt is verification evidence, not authorization to
run unreviewed code. Helper tests, including tampered binaries and unreviewed
artifacts, run with `python3 -m unittest discover -s . -p 'test_*.py'`.

The job must install `bubblewrap` explicitly, check its version, record
`uname -r`, the actual Landlock ABI and the original AppArmor userns knob, then
probe the required namespaces as the unprivileged account. A suitable fixed
readiness command is Bubblewrap with user/PID/IPC/UTS/network namespaces,
`--die-with-parent`, read-only mounts of existing `/usr`, `/bin`, `/lib` and
`/lib64`, fresh `/proc` and `/dev`, an empty environment and `/usr/bin/true`.
It must have its own short outer deadline. Readiness failure is a failed live
gate, with its bounded stderr retained.

Use this exact readiness command with fixed system paths on the Ubuntu image:

```bash
env -i PATH=/usr/bin:/bin LANG=C \
  /usr/bin/timeout --signal=TERM --kill-after=2s 10s \
  /usr/bin/bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts \
    --unshare-net --die-with-parent --ro-bind /usr /usr \
    --ro-bind-try /bin /bin --ro-bind-try /lib /lib --ro-bind-try /lib64 /lib64 \
    --proc /proc --dev /dev --chdir / --clearenv \
    --setenv PATH /usr/bin:/bin --setenv LANG C -- /usr/bin/true
```

Ubuntu hosted runners can have
`kernel.apparmor_restrict_unprivileged_userns=1`. If the job explicitly opts
into the upstream CI-only host preparation recipe, it may temporarily set
**only that knob** to zero after recording its original value, retry the fixed
readiness command, and restore the original value in an `EXIT` trap. Register
restoration before attempting the write, check that restoration succeeded,
and fail the job if it did not. Restrict this preparation to an explicitly
authorized GitHub-hosted disposable CI VM. Record that the live result needed
this host preparation; it does not establish support on an unmodified host.
Do not change other namespace, firewall, LSM or kernel settings.

The workflow's explicit CI preparation block should follow this shape, with
the `evidence` directory created before registering the trap. No caller
environment value can select a different sysctl or replacement command:

```bash
set -euo pipefail
knob=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
original=absent
if test -r "$knob"; then original="$(cat "$knob")"; fi
changed=0
restore_userns() {
  result=$?
  trap - EXIT
  if test "$changed" = 1; then
    if ! sudo -n /usr/sbin/sysctl -w "kernel.apparmor_restrict_unprivileged_userns=$original" \
      >evidence/userns-restore.log 2>&1; then result=1; fi
    if test "$(cat "$knob")" != "$original"; then result=1; fi
  fi
  printf 'original=%s changed=%s current=%s\n' "$original" "$changed" \
    "$(cat "$knob" 2>/dev/null || printf absent)" >evidence/userns-preparation.txt
  exit "$result"
}
trap restore_userns EXIT
# Run the fixed readiness command above and record its first outcome.
# Only after a failed readiness check and explicit approval in this job:
test "$GITHUB_ACTIONS" = true
test "$RUNNER_ENVIRONMENT" = github-hosted
test "$original" = 1
changed=1  # register restoration before the first write attempt
sudo -n /usr/sbin/sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 \
  >evidence/userns-prepare.log 2>&1
# Retry the same fixed readiness command; failure still ends the job.
```

After verification and readiness, give the fixed binary execute permission,
create a private outer HOME/tmp/evidence directory, then run it once with
`env -i` and only fixed PATH, LANG, TERM, HOME and TMPDIR values. Use GNU
`timeout --signal=TERM --kill-after=5s 60s` as the outer process owner. Capture
bounded output, its exit code, the fixed JSON result, artifact receipt and
host-preparation/restoration evidence. A timeout is a failed experiment.
Require the result's explicit MXC Bubblewrap containment, hard filesystem
requirement and every fixed check; do not accept a successful CLI exit alone.

Snapshot only this probe's private `/tmp/dc-axis-mxc-*` fixtures before/after
the run, and inspect remaining processes by the verified executable's exact
device/inode and its fixed unique launch arguments. Report only matching probe
processes, not a global command-line dump. Require no new owned fixture and
no remaining exact artifact executable or command naming that artifact; preserve a failed result
instead of claiming cleanup. Do not issue process-name kills or post-reap raw
PID/group signals. The VM is disposable; unexpected leftovers fail the gate
and remain diagnostic evidence. This scan cannot certify arbitrary descendants
or helpers that exec another binary without retaining that path. Upload the
transcript even on failure. `run_live.py` implements the bounded single-run
driver; the separate `axis-mxc-v1-live.yml` workflow binds it to an independently
reviewed locked artifact and restores the one CI preparation knob on exit.

## Remaining production gates

Successful fixed probes would establish only this composition experiment.
Production still needs a maintained AXIS/MXC API integration, broker and
credential isolation, provider-neutral policy translation/admission,
filesystem overlap and denial semantics for real policies, resource-limit
enforcement, authenticated hook delivery, controlled network proxy allowlists,
multi-user boundaries, descendant/helper lifecycle evidence, terminal signal
behavior, packaging and platform qualification. The offline socket test makes
no proxy authorization claim. Existing AXIS `Sandbox` lifecycle APIs are not
used here, so this experiment does not certify their state model either.

Upstream reference points: [MXC Bubblewrap backend](https://github.com/microsoft/mxc/blob/fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2/docs/backends/bwrap/bubblewrap-backend.md),
[MXC public SDK](https://github.com/microsoft/mxc/blob/fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2/src/mxc-sdk/src/lib.rs),
[AXIS Landlock](https://github.com/ROCm/axis/blob/fb5fd5f0f9377c2ccb30d7e027a36373de0d037c/crates/axis-sandbox/src/linux/landlock.rs),
[AXIS seccomp](https://github.com/ROCm/axis/blob/fb5fd5f0f9377c2ccb30d7e027a36373de0d037c/crates/axis-sandbox/src/linux/seccomp.rs).
