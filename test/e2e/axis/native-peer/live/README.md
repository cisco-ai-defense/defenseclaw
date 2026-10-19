# Fixed Linux native peer CI canary

The historical baseline pairing below completed one contributor-only four-case attempt using the
separately reviewed
c914 peer/revised static-musl Bubblewrap, d074 fixed payload, ae9 diagnostic
wrapper, and 5125 outer driver. The cases check literal argv, binary stdin/EOF and stderr, exit
23, and fixed offline filesystem and socket-creation boundaries. This is not
customer activation, PTY/Claude/model/hook qualification, or completion of the
AXIS integration.

The workflow is manual, same-repository and canonical-branch only. It has no
caller-selected artifact, command, image digest, policy, environment or retry.
The exact Actions source/run/attempt/workflow/branch/event and archive digest
must match constants in `prepare.py`. Each ZIP/provenance manifest is checked
in full with bounded readers, and every selected image/proof must match its
fixed hash and size. That baseline combined receipt is `6af34ded...`; the current
lifecycle pairing and its separate result are recorded below.
The four archives already received two independent inert reviews of source,
build, dependency and image evidence. CI preparation rechecks their exact
byte identity; it does not repeat upstream source/toolchain reconstruction.
The new peer, wrapper and driver include the reviewed FD3 namespace proof,
private mount propagation, matching procfs and capability drop before control
or workload launch. One [native attempt](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39152319549)
at `dabf4fa5` completed that bootstrap and started the owned worker with a matching
procfs PID view. It then refused before artifact admission or payload cases.
Both namespace cleanup owners completed with zero pending custody, and the
runner setting was restored. Source review found that this workflow supplied
an evidence-directory basename `wrapper`, while the harness requires
`native-peer-fixed-*` before creating evidence. The recipe now supplies
`native-peer-fixed-wrapper`; the reviewed images and policy are unchanged.
This explains a deterministic recipe refusal, without qualifying the unexecuted
payload cases or attributing every observed failure to that check.
The [corrected recipe attempt](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39152617635)
at `ff1c9e55` admitted the fixed artifacts and created evidence, then stopped
before fixture or peer creation. Source review found a host-UID0 check on `/tmp`
inside a namespace that maps only the nonzero runner UID; its actual Fstat value
was not recorded. The revised 90cd driver verifies the held root-owned sticky
parent and creates its private fresh fixture before cloning, then passes exact
held parent/root capabilities through the 6eec wrapper to the worker. It retains
the original root-ownership requirement without accepting an overflow UID as
proof. Artifact and policy admission otherwise retain their scope;
the peer, Bubblewrap, payload and combined receipt are unchanged. This new pair
has passed source/build/artifact review and inert tests, but has not yet passed
the native four-case attempt.
One [held-fixture attempt](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39155130062)
at `b656cf66` passed fixture admission and reached the actual peer's `Prepared`
and `Started` replies. The first argv case then reported exit code 1, before any fixed
payload marker or `Destroyed` reply; the remaining cases did not run. All three
native/worker/driver cleanup owners completed with zero pending custody. The
runner setting was restored, and ten synthetic fixture members totaling 192 bytes
were collected. Evidence artifact `12146776297` has ZIP SHA256
`bcb2c471fc7ca9a6759437b5c156f57f010db53825f89fa2a64a4c0a760300d1`.
The recorded zero stdout/stderr counts are inconclusive: the harness returns on
an unexpected exit before assigning captured buffer lengths. No payload, runner
or Bubblewrap cause is established, and no unchanged retry was performed.
The new 9ea wrapper retains validated bounded stream lengths even on failed
exits, and reports only a closed first-line stderr reason/OS-text category.
The 08c driver pins that exact reviewed wrapper. This is a diagnostic source
change; policy, fixture capabilities, native peer and payload remain unchanged.
One [diagnostic attempt](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39157247895)
at `05d7aa0c` again reached `Prepared` and `Started`, then argv exited 1 before
the payload marker. This time the validated counts were stdout 0 and stderr 68,
with closed category `bwrap_owned_source` and OS-text category `none`. That
category covers the original source's cached reopen, held-object identity,
mount-ID and mount-topology admission; it does not identify the failed condition.
No `Destroyed` reply or later case passed. All three cleanup owners completed
with zero pending custody and the runner setting was restored. Ten retained
synthetic fixture members totaled 192 bytes. Evidence artifact `12147416204`
has ZIP SHA256
`131301b4623c7462ddf6cae32a6a803a0c414e3b464276d784d0d90fce785ccc`.
No unchanged retry occurred. Source review is investigating inherited mount
descriptors across namespace clones; this result alone does not establish that
as the cause or qualify any boundary behavior.
The new pairing uses the reviewed c914 static Bubblewrap source-view revision,
ae9 wrapper and 5125 driver. The incoming held object and restrictive flags
remain authority; a cached identity-checked reopen supplies the current
namespace mount ID, and both current namespace inventories still refuse nested
mounts. This is scoped to the trusted clone-only creator chain. Before the
first clone, the driver requires current-namespace unique mount identity and
`statmount` basic attributes for its held parent and fresh root, refusing
ID-mapped or unsupported sources. The driver build passed 18 selected inert
tests. The Rust peer and d074 payload bytes are unchanged; static Bubblewrap,
its closure, wrapper/driver pins and combined receipt are revised. This pairing
passed the fixed attempt recorded below; no earlier failure is converted into
a pass.

## Passing fixed attempt

[Actions run 39161504223](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39161504223)
at `2e494e16e75410903577f62fa07cb9a009711f70` passed once with the exact
c914/ae9/5125/d074 pairing. All `argv`, `stdio`, `exit23` and `boundaries` records
agree across the driver, wrapper result and owned worker stdout: Prepared,
Started, fixed marker, Exited23, Destroyed and native cleanup. The private cwd
and exact environment, binary input plus EOF and separate stderr, read-only
guest root, explicit private writes, synthetic outside/read-only denials and
IPv4/IPv6/Unix socket/socketpair `EPERM` checks passed. Host-positive synthetic
access controls and original canary identities/bytes were preserved.

All three cleanup owners completed with zero pending custody and no output
truncation. The driver reported its current-mount/no-IDMAP preclone check.
The disposable runner's setting recorded original1, preparation0 and restored1.
Collection retained 13 synthetic members (nine public files, 288 bytes).
Evidence artifact `12148742045` has 26,987 ZIP bytes and SHA256
`b6c94089128c45c936217776663dcd8d175d58fdf07cefa7f232496c2334e0c8`.
The exact input source/build/artifact table is in the
[parent result](../README.md#first-passing-native-attempt-four-fixed-offline-cases).

This did not execute `wait`, `tree-*`, guest FD enumeration or guest namespace-ID
assertions. Parent/worker bootstrap observations are narrower. Timeout, cancel,
parent-death/descendant stress, terminal, Claude, hooks, credentials and model
traffic remain separate gates. Both production and common launch-gate
qualification fields remain false. Earlier failures remain unchanged above.

## Lifecycle pairing: first attempt failed

The first lifecycle recipe selected `--suite lifecycle`, retaining the wrapper's
baseline default and the historical four-case evidence above. That historical
pairing used the same reviewed c914 peer/Bubblewrap, 3f295 payload, and 52e4
wrapper under combined receipt
`8b50970b9636ff84ff6ed0aa3ae7d68d2bc063809e5d8af9073d8e4c804a3e9b`.
The paired driver is built at `b38a49dda8da9aca450994b709b44e9cea7d5c19`,
run `39169432727`, artifact `12151303749`, image
`a93df15dba750e5e2363ec4276b7c0e75f593101fa58ee9ef0e5b901bb2b3f39`
(3,211,390 bytes). Wrapper run `39168692019`, artifact `12151861098`, binds
image `70159109952811847fa4e16cc02fca1046d696ebcbb0ff3aa820e1562899dccb`
(3,473,534 bytes). Payload run `39167683927`, artifact `12151291706`, binds
image `ff14f6e2bbce3c35566326ba98cec890b500b6032df3c3ee2b408c9a494128f2`
(1,929,342 bytes). The wrapper recorded nine approved inert test passes and the
driver recorded twenty. The sole actual run `39170295582` at source
`c9e657b9c87ed3464cc1b3a7f339ea56ec805395` failed overall: wait-timeout and
wait-cancel passed their ready/terminal/Destroyed/native-cleanup assertions;
tree-cancel refused with `payload_tree_setsid_precondition` after only its
parent marker. Cancel, heartbeat progress/stability and descendant cleanup were
not observed for that tree. No terminal tree exit code was observed.

Evidence artifact `12152376279` has ZIP SHA256
`b2fa7afcf79a02bb6a5574deba17210616335a5fe7bc68cd571f21c46929ba6c`
(27,726 bytes). All three cleanup owners completed with zero pending custody;
eight public fixture files totaled 224 bytes (12 members including directories),
and the runner setting was restored to 1. There was no automatic retry. See the
[parent record](../README.md#lifecycle-probe-revision-and-first-failed-attempt)
for the source-level syscall mismatch and remaining gates.

The three cases are `wait-timeout`, `wait-cancel`, and `tree-cancel`. Timeout
requires the live ready marker before the five-second deadline; cancel requires
readiness and an explicit Cancel before the fifteen-second deadline. The tree
case additionally requires all three exact markers, held ready files and live
heartbeat progress before Cancel. It then samples six stable heartbeat states
after native Exited and before Destroy/Destroyed or host outer cleanup. The
finite observation corroborates only these three synthetic writers; independent
native owner cleanup and zero pending custody remain mandatory. The unchanged
offline filter must deny Setsid; only positive-group nonleader descendants
substantiate that denial, and the parent result is consistency only.

## Corrected group-query pairing: passing lifecycle attempt

The current fixed recipe retains `--suite lifecycle` and the same three cases,
limits, cleanup and evidence collection. Its reviewed 6a1 payload queries raw
allowed amd64 `SYS_GETPGRP` and checks errno before the same positive nonleader
predicate. Peer, static Bubblewrap and offline policy remain unchanged. The new
combined receipt is
`6db10d2a73ee7860bb0d7ad8a6155166d2b59e7d504513e1222a634aac55c668`.

The source-bound inputs are payload run `39171740021`, artifact `12152816365`
(image `3990927d43320f78586fc669c1a700ecf4c7c8359ba6ada3e41ccd56d4e78e9d`,
1,929,342 bytes); wrapper run `39172460882`, artifact `12153515281`
(image `485aa37bf8fda4aa35f41247c802931fd73decfac28eda60ed8ea44577f63e87`,
3,473,534 bytes); and driver run `39173104546`, artifact `12153496454`
(image `0f7ef1d91cd6a95d09b93341ca0cd59628d1c1346538002f554e0477cef23d60`,
3,211,390 bytes). Payload, wrapper and driver recorded one, ten and twenty
approved inert test passes respectively. Those tests do not execute a payload,
query a real group, create a namespace or install a filter.

One [lifecycle attempt](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39174025396)
at source `96c22c1fac0343aa5db1cfb06875bdd651b6c65c` passed all three cases.
Each observed Prepared, Started, its exact ready marker set, Exited(-1),
Destroyed and independent native cleanup. The timeout case reported
`timed_out=true` without Cancel; wait-cancel and tree-cancel sent Cancel before
the deadline and reported `timed_out=false`. Validated stdout lengths were
24, 24 and 111 bytes respectively, with no stderr or truncation.

The tree case verified all three held ready files and heartbeat counts
`[1,1,1]` progressing to `[2,2,2]` before Cancel. After native terminal and
before Destroy or outer cleanup, six bounded samples retained `[2,2,2]`.
The copied heartbeat bytes were each `2`. This corroborates termination of the
three known ordinary synthetic writers; it is not universal descendant-absence
proof or a separate-session escape test. Setsid remained denied by the unchanged
policy, with meaningful positive nonleader checks in the child and grandchild.

Evidence artifact `12153881045` contains 33 bounded ZIP members, SHA256
`47c4d62d0530c1cd6710d5ea46d49a36f122f22324719ed4f59f48d4c0ed4cef`
(29,088 bytes). Driver, wrapper stdout, owned worker stdout and persisted case
records agree. Native session, worker and whole-wrapper cleanup all completed
with zero pending custody. The retained fixture has 12 public files totaling
291 bytes (16 members including directories); original canary identities and
bytes were preserved. The disposable runner setting was saved at 1, changed to
0 and restored to 1. Production certification and common launch qualification
remain false. The earlier c9e tree refusal stays failed; the historical baseline
four-case pass remains a separate result. No automatic retry occurred.

The trust assumptions documented in
[`artifact-review.md`](../../../../../internal/axis/native/artifact-review.md)
still apply.

Only the trusted host metadata process receives the read-only Actions token.
The driver runs with an empty environment. Its reviewed code copies and seals
the exact wrapper, establishes atomic pidfd ownership of a new PID namespace,
and requires READY then one GRANT before exec. The wrapper separately owns its
worker and native sessions. The outer driver has a 120-second deadline plus
bounded cleanup/retry, and a trusted 160-second timeout encloses the driver.
The workflow requires the exact three lifecycle case assertions and cleanup
results for success. It never restarts a failed experiment automatically.

The disposable Ubuntu GitHub VM is the only permitted host for this recipe.
If its AppArmor unprivileged-userns knob is 1, the explicit preparation step
saves it, changes that one knob to 0, and restores/verifies it on ordinary exit.
An abrupt runner/VM termination cannot promise trap execution; that VM is
discarded. Production readiness must report this host requirement, and must
not change the user's host. No installer, service, firewall, DACL, capability
grant or user-PC sysctl change is part of this workflow.

The evidence artifact retains exact input API/provenance records, preparation
hashes, driver raw result/stderr, wrapper result, host-floor/restore records,
and a bounded copy of the exact owned synthetic fixture when native custody
has completed. Copying requires the wrapper receipt, fixed random path shape,
current UID ownership, no-follow descriptor opens, regular single-link files,
and total depth/member/byte bounds. The only dot-containing names admitted are
the six exact public `tree-{parent,child,grandchild}.{ready,heartbeat}` files,
only as regular files immediately under `work`. It never deletes the source fixture. A
missing or unsafe copy is recorded as incomplete evidence.

Source tests use inert archives, fake metadata, missing admission, and private
temporary data only. No test executes a peer, driver, Bubblewrap or payload.
The two Linux descriptor-copy tests are skipped on Windows and run in the CI
source test step. A local preparation rehearsal may read the four already-downloaded
reviewed archives as data without executing them.

Before dispatch, the root and independent reviewer must review this exact
workflow/helper source and the driver artifact. After one attempt, preserve
the actual result before diagnosing or changing source/policy. A successful
canary still leaves terminal, arbitrary prepared workloads, credential relay,
agent hooks and actual Claude/model traffic as separate qualification gates.


## Fixed real Claude version recipe

The existing manual workflow now has a closed choice between the historical
`lifecycle` suite (default) and the separate `claude-version` suite. The latter
uses `prepare_version.py` and `REVIEWED-CLAUDE-VERSION.json`. Its exact wrapper
and driver artifacts have passed author, root and independent inert reviews:
wrapper run `39199601189`, artifact `12162799813`, image
`1493e1678ed0533a7a6fa81aa8bd04a0bad667aac43cbb10f3caec8f82d8c208`
(3,510,398 bytes); driver run `39200076588`, artifact `12163566207`, image
`31345e92f7e5ce7468cf78a81f04d8b4c3c400d86e6612c3388e877735955fa3`
(3,244,158 bytes). The distinct receipt is
`e24ee1736320e9df281e0ab7049b2df8cbacbf27d81d31fc46e21cef09b165b7`.
These checks do not execute the images. The first real version attempt below
failed before native peer admission; the corrected pairing later passed its
separately authorized finite version attempt.

Preparation authenticates the four fixed Actions artifact identities and full
ZIP/provenance inventories. The fixed musl
Claude 2.1.292 binary is reacquired only from its literal official release URL,
with the exact reviewed manifest/signature/key hashes, pinned signing fingerprint,
verified signature and binary SHA256/size. Fixed installed GPG is a host data
reader with no options, no helper autostart, no auto-key import/retrieval and
no dirmngr; missing readers refuse without installing anything. The image is
never invoked during preparation. Vendor bytes, private keyring and staged
images are excluded from the evidence upload paths; the fixed public license is
retained. The existing empty-env driver, namespace custody, bounded deadline,
disposable-runner-only AppArmor save/restore and no-retry recipe are reused.

The version collector requires confirmed native, worker and whole-wrapper cleanup
and zero pending source-resource custody before reading the retained private
fixture. It holds the registered loader object while copying public canaries and
excludes only the fixed root leaf whose full FileID, mode, owner, single-link
status, size and digest revalidate against the trusted driver's record and the
reviewed loader. A same-name replacement is refused. Other fixture files retain
the existing nofollow, name/depth/count/size and aggregate byte bounds. The
853,616 loader bytes and the vendor image are never copied into the result ZIP.
The collection `members` count includes every visited source entry, including
the one excluded loader; `bytes` counts only copied public file bytes, and
`excluded_loader` records the separately revalidated object.

The recipe requires exactly `2.1.292 (Claude Code)\n` (22 stdout bytes), empty
stderr, exit0, Destroyed and independently completed cleanup. Missing exact
version output is not evidence that no execution occurred: a started child may
have failed before producing it. This finite canary does not qualify an agent
session, arbitrary dlopen, hooks, broker transport or the production launch gate.

The first [version attempt](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39198761851)
at source `b910df5e13246fc3a4eb0c2450b52cba46d54fb7`, using wrapper49c and
driver017, failed at
`native_stage=fixture_capability`. Signed official release reacquisition and
artifact preparation succeeded. Worker namespace bootstrap, READY/GRANT and
receipt admission completed, but no Prepared, Started, version output or native
case result was observed. The worker's `execution_performed=false` belongs to
that pre-peer stage; it does not assert that the trusted wrapper never ran.

Evidence artifact `12162847926` has 25 bounded members (131,518 bytes), SHA256
`31b8316d6b9bfa9a6427a43d5be7af92bc4ecfc917fe3bb1f6f636c7cd24a33f`.
Native, worker and whole-wrapper cleanup completed, with every reported pending
custody count zero. The retained fixture contained only its registered loader:
the collector revalidated and excluded that one visited entry, copying zero
public bytes. The disposable AppArmor setting was restored from 0 to its saved
value 1. Vendor and loader image bytes were absent from uploaded evidence.

Source review found a deterministic fixture check error consistent with this
failure: positive-limit `Readdirnames` can return the last nonempty batch with
a nil error, while the initializer demanded `io.EOF` alongside its one allowed
loader name. The corrected bounded check accepts only the exact initial entry
set and separately requires an empty `io.EOF` read when needed. It preserves
loader identity, held-root and cleanup checks. The portable ordinary filesystem regression passed
eight race-test results on Windows with zero failures/skips. The corrected
wrapper build passed 32 inert tests across 14 roots, including the Linux
directory regression; the new driver recorded 28 inert passes across 25 roots.
Both artifacts passed three inert reviews. The failed b910 attempt remains
preserved.

One changed [version attempt](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39200679279)
at source `1689fe5fcbd8a79533965598246ddf49bc91a18c`, with the f9 wrapper and
e01 driver pinned above, passed. Its one `claude-version` case observed
Prepared, Started, the reviewed wrapper's exact 22-byte stdout assertion,
zero stderr, Exited(0) without timeout or truncation, and Destroyed. The case
recorded native terminal and completed native cleanup before outer cleanup.
Owned worker and whole-wrapper namespace cleanup also completed, with all
reported pending native and loader-resource custody counts zero.

Evidence artifact `12163736916` contains 31 bounded ZIP members (134,055 bytes),
SHA256 `caa84c0f6e5076ca3d4c441f8595a6b9879f7208689310875be2767d9ba8d628`.
Driver, wrapper stdout, owned worker stdout and persisted case records agree.
The collector visited 11 fixture entries including the excluded registered
loader and retained six unchanged 32-byte public sentinels, totaling 192 bytes.
It revalidated the loader's full FileID and exact digest after cleanup, then
excluded its bytes. Vendor image bytes were also absent from uploaded evidence.
The disposable runner's AppArmor setting was saved at 1, changed to 0 and
restored to 1. No unchanged retry occurred. This proves this fixed offline
`--version` path on the reviewed Linux host floor. Agent sessions, arbitrary
dlopen, all-connector hook enforcement and the production launch gate remain
separate qualification requirements; certification fields remain false.
