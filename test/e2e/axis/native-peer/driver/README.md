# Fixed Linux outer driver

This contributor driver owns one closed baseline or lifecycle suite from the
reviewed native peer wrapper in a separate user/mount/PID/network/IPC/UTS
namespace. It does not activate
the AXIS customer provider or qualify the common launch gate.

The fixed input wrapper was built at `c76a05c3df66f43e76c6566b53aa2b3c1c7bca0b`
in Actions run `39172460882`, artifact `12153515281`. Two independent inert
reviews checked its source, dependency, archive, provenance and static image.
The image SHA-256 is
`485aa37bf8fda4aa35f41247c802931fd73decfac28eda60ed8ea44577f63e87`
(3,473,534 bytes); archive SHA-256 is
`ce84ed94fce099b59bea6b0593f23d7e845c3734ab1e62ea9f794fb38faa6e68`;
provenance SHA-256 is
`d84f37d59f7830eda86de0bd562acbb85a0ddb2d7c8e42132f019c0f4a434b60`.
Its fixed combined peer/payload receipt is
`6db10d2a73ee7860bb0d7ad8a6155166d2b59e7d504513e1222a634aac55c668`.
These are compiled source pins. There is no caller-supplied image, digest,
command, environment, backend or policy option.

The outer driver itself still requires independent source/build/image review
and explicit authorization for a bounded run. The previous b38 driver's failed
lifecycle attempt is [recorded separately](../README.md#lifecycle-probe-revision-and-first-failed-attempt);
this corrected pairing has not executed. The build workflow compiles two static
copies, runs only
fake/inert unit tests, and retains exact Git sources and dependency evidence.

The driver reads `REVIEWED-ARTIFACTS.json` and fixed member
`images/reviewed-wrapper` from a held, mode-0700, caller-owned artifact directory.
Every path component is opened without following links. Bounded bytes must
match the compiled digest before being copied into a sealed executable memfd.
The running driver image is likewise copied and sealed for its bootstrap.
The original artifact file path is never used to execute the wrapper.

An atomic pidfd owns a new outer PID namespace. A retained creating OS thread
waits for its init; the init installs `PR_SET_PDEATHSIG(SIGKILL)` before file
inspection. READY precedes one exact GRANT; EOF before GRANT refuses execution
and covers parent death before prctl. After GRANT the bootstrap execs the held
sealed wrapper with an empty environment. Only the fixed held fixture parent
and root survive that trusted-wrapper exec as FD8/FD9; other explicit non-stdio
descriptors close. No fixture parent/outside handle reaches a guest payload. The creator-thread death caveat is availability: an early
unexpected thread death terminates the owned init. No raw PID/group/name lookup
authorizes cleanup. An inability to obtain atomic custody never grants exec.

The outer deadline is 120 seconds. Cleanup gets a separate ten-second wait and
one ten-second retry. A failed first cleanup remains a failed result even when
retry succeeds; a pending exact owner stays reachable through reporting.
Stdout/stderr each retain at most 64 KiB, including failure paths. Success
requires the wrapper's exact selected suite, ordered cases, markers, canary
controls, exit values and both levels of cleanup. The outer cleanup result describes
whole-wrapper namespace custody; it does not replace SDK cleanup assertions.

After independent driver artifact admission, the fixed lifecycle invocation is:

```text
fixed-outer-driver --run-fixed --suite lifecycle --receipt /private/admitted/REVIEWED-ARTIFACTS.json --evidence /private/fresh-evidence
```

The paths carry metadata, not executable/policy authority. The evidence path
must be fresh; failed fixtures/results remain available. A future disposable
GitHub-runner recipe may save, change and restore the specific AppArmor userns
knob only when its explicit reviewed host-preparation contract permits it.
This driver never changes host sysctls, services, ACLs, credentials or firewall.

Unit tests always supply an unreviewed registry or fake runner. Linux-specific
tests parse inert ELF headers, use memory-only READY/GRANT streams and fake
custody; they never clone, call prctl, seal/execute an image or create a sandbox.

## Private proc bootstrap source revision

This source revision includes a fresh mount namespace and a fixed sealed FD3
parent-identity proof to each owned child. Before READY/control/backend work,
the child proves kernel ownership and single nonzero UID/GID mappings, makes
mount propagation private, mounts matching procfs and clears startup capabilities.
Only SYS_ADMIN inside the new user namespace crosses the trusted initialization
interval; all Go threads use the CGO0 all-thread barrier, and the Rust peer proves
it is single threaded with signals blocked until cap-zero. No host capability,
UID0 mapping, grant, alternate backend or customer activation is added.

This changes the private FD handoff. Existing e054 peer and d056 wrapper/c8d4
driver artifacts remain historical evidence and cannot qualify this source.
Fresh source-bound artifacts, registry pins and one separately reviewed runtime
attempt are required. The two earlier native failures remain failures.

## Host fixture capability revision

Before the first clone, the trusted driver opens held `/tmp` without links and
requires its original host UID0 and sticky directory mode. It creates one fresh
random `dc-axis-native-peer-<32hex>` directory with mode0700, verifies current-user
ownership, and retains both directory handles. No unmapped/overflow UID is proof
of host ownership. These two capabilities cross the trusted bootstrap/wrapper,
then the wrapper gives worker-owned duplicates at fixed FD7/FD8. Label/inode
correlation is checked without selecting a source through the display path.
Fixtures, including partial creation, are retained on every outcome.

The revised host preflight also requires `STATX_MNT_ID_UNIQUE` and
current-namespace `statmount(STATMOUNT_MNT_BASIC)` before the first clone. The
held parent and fresh empty root must belong to that same reachable mount,
with required status fields present and `MOUNT_ATTR_IDMAP` unset. Unsupported
or ambiguous queries refuse; there is no less strict fallback. This adds a
Linux 6.8 capability floor to this fixed contributor recipe. Unit tests use
synthetic response bytes only and never perform a mount or statmount call.
The kernel's clone-only private namespace chain then preserves that source
mapping; only reserved `/proc` is replaced before native source admission.
This is not provenance admission for arbitrary foreign production inputs.
Fresh source/artifact reviews and a new driver pin remain required before use.

Historically, the c914 static Bubblewrap, d074 payload and combined receipt
`6af34ded1837e54d4909f782235613acd56232eafe0c60e2ebc61af5e7fd6ec6` passed
one four-case attempt with the ae9 wrapper and 5125 driver. The first lifecycle
attempt replaced only that payload with 3f295; this corrected source now uses
6a1 with an errno-checked raw group query. Rust peer and c914 Bubblewrap bytes
stay unchanged. Historical runs remain evidence for their exact earlier
source only. A fresh driver artifact review and separately reviewed native
attempt are required.

## Lifecycle suite handoff

The closed `--suite lifecycle` selector is passed unchanged through the existing
owned bootstrap into the reviewed wrapper; omitted `--suite` remains baseline.
The driver requires the returned suite to match and admits exactly three
ordered results: wait-timeout, wait-cancel, tree-cancel. Every result must bind
its marker, terminal flags, separate Destroyed and native cleanup; the tree
result also requires verified ready files, live heartbeat progress and bounded
stability before Destroy. The bounded public count snapshots must independently
show progress in every fixed role and six stable post-terminal samples.
Baseline and lifecycle evidence cannot replace one another. No new controller, arbitrary command, file selector or caller hash
is introduced. This source pins the reviewed c76 wrapper, including its ten
inert lifecycle/canonical-registry unit-test passes. The reviewed b38 driver recorded twenty inert
passes before the first lifecycle attempt. That attempt failed overall: the
two wait cases passed, but the tree precondition refused before cancellation
or heartbeat observations. No descendant-cleanup result follows from it. The
new fixed payload requires EPERM from Setsid in every role and uses normal
descendants; it does not change the offline filter or admit session creation.
Only the positive-group, nonleader child/grandchild checks substantiate filter
denial; the parent check is consistency only.
The earlier four-case result remains evidence for its exact original pairing.


## Separate Claude version source

`claude-version` is a fixed distinct suite and receipt; its wrapper admission
pins the independently reviewed f9 image
`1493e1678ed0533a7a6fa81aa8bd04a0bad667aac43cbb10f3caec8f82d8c208`
(3,510,398 bytes). Its build 39199601189/artifact 12162799813, archive
`acfe0492ecf2c2670aab32af1411d722fc1ffa4758eedf2e44809fb33c1dd0d3`
and provenance
`3b63059284ac539d0c903adc613759e4cc428ef501640a2b595a156fc176b191`
passed three inert reviews. This new driver still needs its own build/artifact
review before any actual version canary.
The old baseline/lifecycle admission remains separate. The driver uses no new
launcher: it copies only reviewed loader SHA256
`76b812138a1d4be51ae095e94920e1fd1c5d25f793651baf834d05a2c455c040`
(853,616 bytes) from the held artifact input into one O_EXCL, O_NOFOLLOW,
CLOEXEC fixed leaf under the already-held fresh private fixture. It fsyncs and
closes the writer before any clone/grant; a readonly reopen must match that
created inode and exact bytes. The original input remains held and is checked
again after copying. The creator verifies local same-mount identity, no IDMAP,
single link, mode 0500 and no NOEXEC; unsupported floors refuse without repair.

The first table is proof3/grant4/ready5/self6/wrapper7/fixture-parent8/root9/
loader10. The wrapper-to-worker table is proof3/grant4/ready5/self6/
fixture-parent7/root8/loader9. Each transition duplicates only the fixed held
inputs; the first bootstrap keeps loader10 across its one fixed exec and later
copies use CLOEXEC. Loader and fixture custody stay retained on uncertain native
cleanup or source close. After confirmed whole-wrapper cleanup, the driver
revalidates and records the exact retained loader FileID, size and digest for a
collector to exclude that registered object only; a same-name replacement must
never be excluded. The vendor binary is not copied into public evidence.

The future finite assertion is exact `2.1.292 (Claude Code)\n` (22 bytes), stderr
empty, exit0, Destroyed and all owned cleanup complete. This is not full-agent,
dlopen, hook, broker or common-launch qualification. The historical b910 version
attempt using wrapper49c/driver017 failed at fixture admission before peer
Prepare or Launch; cleanup completed with zero pending custody. The f9 wrapper
corrects that bounded directory-enumeration check and recorded 32 inert passes
across 14 roots. This newly pinned pairing has not run.
