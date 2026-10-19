<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Native Windows current-MXC observations

These contributor observations do not activate AXIS or certify a customer
runtime. The host is native Windows 11 x64 build 26200.9457, non-administrator.
No WSL, host ACL modification, AppContainer/DACL fallback, privileged host-prep,
WFP service installation, agent login, real credential, hook or model call was
used.

## First fixed native PSEC attempt: failed

[Locked build 39112591970](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39112591970)
at DefenseClaw source `215f3e98936b34279e31670a4fed14d5f47542c2` compiled the
reviewed AXIS policy parser and current MXC native-only contributor seam. The
exact source inputs were AXIS `fb5fd5f0f9377c2ccb30d7e027a36373de0d037c` and MXC
`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`. Source blobs, inventories,
upstream locks/licenses, reviewed combined lock, overlay, compiler and both
archive/API digests were independently verified before the fixed attempt.

| Input | SHA256 |
| --- | --- |
| GitHub ZIP, artifact `12130379341` | `088a0e1edf12145e4a3133c85841a3c332010aa4d32a2d577a3c293421f76753` |
| Build provenance | `267d7b93c44b26b95048eadbbe2ad41f29b61af9d4de8aa56e3c247464843893` |
| Combined lock | `3b29ecb06dd2a81266c84712f8d6e088605290f386e87498bb7a7472a005af69` |
| Native probe PE | `bfb895fd2ea760aa7cc20f92368b2981927e20e0080282324d0985eb7f540198` |
| First-run custody executable | `a515ed12c4c919f73817628f41827293972afbc00e0013f44d80e59a21de1f1f` |
| First-run custody Go source | `f56db393a2d0c7934151c72b2d6fafec6b4c589e00234cf5f23bd514265a3792` |
| First-run Python outer driver | `e366b493186bf4a6ddf483ef5f70edd8c8c4b94f389069ae21f9ea3f66e2fda8` |
| First-run artifact verifier | `57edf7e9d647e3b6787adec3fc0e96f585cf2bc21d17bcaea2a79d2aefb87178` |
| Non-executing verification receipt | `50de519ab72c5cd90e4946486fce258218d1375cc1f057cee26afc2d79dc2170` |

The exact wrapper command was `custody-root.exe -receipt <verified-receipt>
-receipt-sha256 50de519ab72c5cd90e4946486fce258218d1375cc1f057cee26afc2d79dc2170
-case-root <fresh-private-evidence>/psec-headless-01`. It started the fixed
probe with no caller workload arguments. Native ProcessContainer was selected
directly with DACL fallback disabled, hard filesystem policy, blocked network,
explicit private environment and the unchanged default UI restriction.

| Observation | Result |
| --- | --- |
| Outer wrapper | Exit 1 in 3.484 seconds; no outer deadline, truncation or read error. |
| Native child | `Exited(-1073741502)`, NTSTATUS `0xC0000142` (`DLL_INIT_FAILED`); empty child stdout/stderr and no boundary marker. |
| Outer custody | Assignment to the owned Job before resume observed; active process count zero afterward; Job empty. |
| Fixture | One exact synthetic owned fixture retained for inspection. |
| Qualification | Failed; no filesystem/environment/network boundary success, terminal or Claude claim. |

Raw evidence remains privately under
`C:\Users\vnarajal\.codex\axis-manual-test\windows-current-psec-max-01`.
The verified artifact, source/import inspection records and exact first-run
helper source snapshots remain under
`C:\Users\vnarajal\.codex\axis-manual-test\mxc-v1-windows-215-root-review`.

Read-only inspection found Shell32/COM/TDH/Userenv/VCRuntime imports in the
SDK-bearing self-payload; this host's Shell32 imports User32 and GDI32. MXC
maps the default disabled UI policy to PSEC's Win32k system-call restriction.
Their interaction is a hypothesis, not an established failure cause. The next
distinct diagnostic uses a separate std-only payload with the same policy,
requires actual import inspection, and can report only its loader marker,
exit23 and bounded ownership/cleanup observations. It cannot turn this failed
boundary attempt into a passing qualification.

## Separate std-only loader diagnostic: passed

[Locked build 39115553188](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39115553188)
at `a96ef846d7c75987c9266aa96f928c8915dbcc3d` passed compilation and the pure
SDK admission tests. Those tests ran in the SDK's own workspace with its
unchanged upstream lock; Cargo had refused external-dependency package testing
in the earlier attempts. The contributor combined lock stayed unchanged.
Independent reviews verified all 16 inventory files, nine source Git blobs,
upstream locks/licenses, toolchain, overlays and exact successful workflow/API
identities before execution. PE import inspection confirmed that the distinct
122880-byte child imports kernel/NT/CRT support without the supervisor's
Shell32/COM/TDH/Userenv dependency surface.

| Input | SHA256 |
| --- | --- |
| GitHub ZIP, artifact `12132482302` | `9836ea32e96ca324bd19e0a96ff20213744f235a6ac416887d7f18770e1c1503` |
| Provenance | `1107fbbd9fe328c8e3d9197b233de0a8ff856d6e4b296cfdc402909f0061f9f5` |
| SDK supervisor | `c8e0f6bb418517e68d3b185cbac65320aa3ce165dfcb812ae4a597a7699d2c50` |
| Std-only loader child | `9bad1152a7391eb3fb02cbec6cf3ba35845327f71c1cd705e63aded9528a1446` |
| Reviewed custody Go source | `d08f4bad5d261708118017fb9f07efdb23f2842f009acae6a3a127166cb8e07e` |
| Custody executable, Go 1.26.5 | `58329247f68ff9ebe962c663a7fa27e3bbf566560be7dd4c1dbf4b370e7a8981` |
| Root verification receipt | `301792d55aaf0271393e63dc477c85ac32e94651d07a8367b06130493709faf6` |
| Actual live result | `43be5131c408eff3d2285d4aaa65f9809d0100bb5c297c66e03be10327f49fc8` |

The adversarial tester performed exactly one `run_live.py --loader-only`
execution, with the pinned custody executable and receipt, in a fresh private
fixture. It returned exit 0 in 5.047 seconds, with the exact
`FIXED_PSEC_LOADER_STARTED` marker, typed `Exited(23)`, a signaled retained direct
handle and all four loader diagnostic checks. Outer Job assignment happened
before resume; its final active process count was zero. The receipt reported
no deadline, overflow, reader error or retained exact owned fixture, and custody
stderr was empty. Helper/image/receipt pins matched before and after the run.
No filesystem, network or UI policy was relaxed.

Evidence remains privately under
`C:\Users\vnarajal\.codex\axis-manual-test\windows-current-psec-loader-max-02`.
This proves this distinct minimal payload can start under the same native
policy. It does not identify the exact cause of the SDK-bearing self-payload's
DLL failure or qualify its failed nine boundary checks. A separate std-only
filesystem/network/argv child remains the next gate; terminals, Claude, hooks,
credential brokering and complete lifecycle still require their own tests.

## Separate std-only boundary and literal argv: failed

[Locked build 39120734916](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39120734916)
at `3a8b1e8cec430209254f62bbe5afe52f60ce7b77` passed all ten exact SDK
admission tests, including one native file-custody fixture without payload
execution. Two independent reviews verified 24 ZIP entries, 20 inventory
files, 12 exact Git source blobs, all three overlays, all 15 reconstructed
SDK source fingerprints, unchanged locks/licenses and three PE import tables.
The std-only boundary child adds Winsock imports to the minimal loader's
kernel/NT/CRT footprint; the SDK-bearing supervisor stays outside PSEC.

| Input | SHA256 |
| --- | --- |
| GitHub ZIP, artifact `12135005005` | `6ce964e2ea6c37321780b32e061b1b73515a821f42cb9966b2aceded339e5ff5` |
| Provenance | `9b8d87f8185f5336b2b4e2ffa386877f8279a6e8a7c8c682740efdcfed9ed5ad` |
| Supervisor | `1ccbb1f1d7afb6f8be38cbc96cf89274f069ae655a1207564a1aa9daf7e4c338` |
| Boundary child | `077028f01c154de5a1fc521f0a68d036711b27541dd29bc4790f42139b250064` |
| Custody executable | `ab635640c1a6925854bd99f68b6a1d9d966dbb9e071b69cab704b544b4154b7d` |
| Root verification receipt | `00d85eadc878066fd2eff35f99497e1706dc1fc07cf9e1e3d07b241b3f42534d` |
| Actual live result | `7622beede7b34ff7694c5e4e904a708b34c80503ef9ecc50ca6b939a2e552aec` |

The adversarial tester performed exactly one fixed `--standalone-boundary`
run. The literal Windows argv case passed with `FIXED_ARGV_PASS`, typed exit 0
and a signaled retained process handle. The next boundary case exited 1 with
`Access is denied` before either permitted-write canary appeared. This does
not identify the precise failing call or qualify any filesystem/network
boundary checks. The wrapper took 9.265 seconds; its owned Job was assigned
before resume and ended with zero active processes. No deadline, output
overflow or reader error occurred. No policy, grant, ACL or UI restriction
was relaxed, and the failed artifact was not retried.

Private evidence remains under
`C:\Users\vnarajal\.codex\axis-manual-test\windows-current-psec-boundary-max-01`.
Its exact owned fixture `psec-headless-01\tmp\dc-axis-windows-psec-X8IPVg` is
retained. The next source adds fixed operation labels around early cwd,
seal-read and permitted-write calls, without changing those operations or
their grants. A fresh locked build and independent review are required before
another native attempt. Customer Windows AXIS remains unavailable.

## Fixed early-operation diagnostic: canonicalization refused

[Locked build 39122262255](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39122262255)
at `b405223cf9c26cc5ed76ac52025f5ca94e386dc1` retained the same policy,
grants and child operations, adding only fixed early-operation labels. Two
independent reviews verified the new artifact and exact source before one
fresh `--standalone-boundary` run. The literal Windows argv case again passed.
The boundary child completed its private cwd lookup, then exited 1 at
`private cwd canonicalize: Access is denied. (os error 5)`. Seal read and the
permitted-write checks were not reached. This label does not distinguish the
directory open from the subsequent final-path query inside Rust's
`canonicalize`.

| Input | SHA256 |
| --- | --- |
| Root verification receipt | `df3f4256fddaad2f5e88754d25a47933ce7fd32e57f103a2993bbef902fe732f` |
| Custody executable | `ab635640c1a6925854bd99f68b6a1d9d966dbb9e071b69cab704b544b4154b7d` |
| Actual live result | `f66a8ebd7355c393079b40674ff08cb5979cd2dc2097c1947033a5ea6ab89626` |

The owned outer Job was assigned before resume and ended empty with zero
active processes. No deadline, output overflow or reader error occurred. One
exact synthetic fixture was retained under the private evidence directory
`C:\Users\vnarajal\.codex\axis-manual-test\windows-current-psec-boundary-max-02`.
No policy, grant, ACL or UI restriction was changed, and this failed artifact
was not retried. Boundary qualification remains failed.

## Call-specific diagnostic: DOS path query refused, direct read passed

[Locked build 39123961008](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39123961008)
at `a13bc3e8369c12b74eb616b1db4f5d537769780c` adds only read-only diagnostics
after the same mandatory canonicalization error. Two independent reviews
verified its 24 ZIP entries, 20 manifest files, exact source/lock/license bytes,
three overlays and all 15 reconstructed SDK source fingerprints. One fresh
native `--standalone-boundary` attempt passed literal argv, then failed the
original mandatory canonicalization check. It was not retried.

| Fixed diagnostic | Actual result |
| --- | --- |
| `CreateFileW` directory open, access 0 | success |
| Normalized DOS final path on that handle | Win32 5, Access denied |
| Opened DOS final path on that handle | Win32 5, Access denied |
| Normalized NT final path on that handle | success, length 158 |
| Closing the diagnostic handle | success |
| Bounded direct fixture-seal read | success, exact public sentinel |

No path contents or credentials were logged. These observations distinguish
the DOS-query failure from the granted direct read; they do not establish why
the kernel denied those queries or qualify the remaining boundary checks.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12134839210` | `0e4d8f495a99b1a40ccfa6b8c0d00c9376d321147451fff1e3be1785fa77025b` |
| Provenance | `475bc2e3b83038a39f3f85369e79d994b445584ae1e58e44a6298484d241e58d` |
| Root verification receipt | `67e926aa5e373e085729326a2d47dec1c258c7f98a3976ae0c59918137690c4f` |
| Actual live result | `97ab772b1c6fa198f4dc2f823e9f6c053f48962264f450609fb6aca5562eee5b` |

The wrapper exited 1 in 3.58 seconds without deadline, overflow or reader error.
The owned outer Job was assigned before resume and ended empty. The exact
synthetic fixture `dc-axis-windows-psec-vgwIwA` remains retained under private
evidence `windows-current-psec-boundary-max-03`. No policy, grants, host ACL,
firewall, UI restrictions or SDK code changed.

The next fixed test records canonicalization as a compatibility result and
uses its explicit current directory for the boundary operations. Fixture
shape, private environment and seal assertions remain mandatory. This is a
test correction, not broader filesystem permission or application support;
applications requiring the denied DOS query remain unqualified. A new locked
build, independent artifact review and native run are still required.

## Direct canary iteration: private environment spelling refused

[Locked build 39125660254](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39125660254)
at `830eb041671ebc2f6e685ab4d13847101643961f` passed its ten SDK admission
tests and two independent source/artifact reviews. One fresh fixed native
attempt passed literal argv and the same directory-open, NT-query and seal-read
controls. Both DOS queries again returned Win32 5. The child then refused its
private environment equality check before either permitted write. It was not
retried and no remaining boundary check is qualified.

The parent derives its environment from a canonicalized verbatim-disk path;
the revised child derives its expectation from `GetCurrentDirectoryW`. A
prefix spelling mismatch is the source-based explanation to test next, not a
measured environment leak. The next assertion accepts only an optional `\\?\`
prefix with every remaining UTF-16 unit identical. A pure build test preserves
refusals for different homes/drives/case, dot/slash rewrites and UNC/device
paths. Sandbox grants and native policy remain unchanged.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12136312656` | `6b2e97352fa0b1f49d41b06c78ec2194238d924b336abfd648d19a4e52c17cce` |
| Provenance | `b8f99453c9cdfa958c2f90a2bfd1cbc2f130361c92c2c1b30023041b526c513c` |
| Root verification receipt | `44382c550f1e44d2e89862f8d244108091449a6084d142e1a3c818f5ce4f2026` |
| Actual live result | `1949b49c8e530f17d29cd2f0bc3c5ba85643ddc915285a18ee674865fd85de8d` |

The wrapper exited 1 in 12.781 seconds, without deadline, overflow or reader
error. The owned outer Job ended empty with zero active processes. The exact
failed fixture `dc-axis-windows-psec-NUZsHW` remains under private evidence
`windows-current-psec-boundary-max-04`. No host ACL, firewall, UI restriction,
policy or SDK change was made. Customer Windows AXIS remains unavailable.

## Narrow prefix comparison: mismatch remains

[Locked build 39127497805](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39127497805)
at `53281811a4fc41c099a756cf575de26e99d995cc` passed the ten selected SDK
admission tests and one exact pure private-path comparison test. Two
independent reviews checked its 24 archive entries, 20 manifest hashes, source
and locks, all 15 reconstructed SDK files and unchanged PE import DLL lists.
One fresh fixed native attempt passed literal argv and direct seal read, then
refused the private environment comparison again. The optional verbatim-disk
prefix correction did not resolve the mismatch. The generic six-key assertion
does not identify the differing key or value; no environment leak or precise
cause is established by this result.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12137236542` | `c0d511dcbd215aac30b703f9f7b12b0e5e127e3dcb25f15cd851ab9330c45b77` |
| Provenance | `686e475c338927b67d1bdc44ae02bc60f527624bd6bbd8f5261d8208e3dbd64d` |
| Root verification receipt | `00e55fcc6dca641f737596ad605ddb72ca664819eac7b3b5ab0459d41847ac7d` |
| Actual live result | `239adb07ff169ab30944cab743017c0b123b16d4be5297e90d54fc042173ae05` |

The wrapper exited 1 in 5.016 seconds with no deadline, overflow or reader
error. The owned outer Job was assigned before resume and ended empty. The
exact failed fixture `dc-axis-windows-psec-m6U12J` remains under private
evidence `windows-current-psec-boundary-max-05`. The artifact was not retried.
No policy, grant, ACL, firewall, UI restriction or SDK overlay changed.

The next source retains the same exact assertion and adds only a fixed failing
key, bounded UTF-16 lengths, prefix flags, ASCII-case comparison flag and
first-difference index. It never logs path or environment contents. A fresh
locked build and independent review precede further native testing.

## Bounded diagnostic: TEMP differs before permitted writes

[Locked build 39129614000](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39129614000)
at `246210c3b484ea1de0785756dd4410beda25adfb` preserves the exact private
environment assertion and adds only bounded comparison metadata. Ten selected
SDK tests and the exact pure comparison test passed. Two independent reviews
verified the artifact, source, lock, all 15 reconstructed SDK files and the
unchanged import DLL lists before one fresh native attempt.

Literal argv and direct seal read passed. Both DOS path queries again returned
Win32 5. The child then reported:

```text
FIXED_PRIVATE_ENV_MISMATCH key=TEMP actual_units=214 expected_units=135 actual_verbatim=true expected_verbatim=true ascii_case_only=false first_difference=128
```

The preceding HOME and USERPROFILE assertions passed by the pinned source's
execution order. TMP, APPDATA and LOCALAPPDATA were not reached. The diagnostic
contains no environment values or path contents and does not establish the
cause of the differing TEMP value. No permitted write, negative write or
network check is qualified by this failed attempt.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12137991365` | `715c01dac75dd24300f3154622eb3837afa0de36de37462873fc477b271c6b49` |
| Provenance | `099bcb4a93fb74974afa727911570f604300c7f44d56d5519bb8457723e53581` |
| Root verification receipt | `b257b27b49f1cf7ee4fa510e17e198760f77a31a409d9188d8458f054a720612` |
| Actual live result | `9dd809393930bf404fb020c8d708a6aedad217f98cf3014b1339a7982228b261` |

The wrapper exited 1 in 3.343 seconds without deadline, overflow or reader
error. The owned outer Job was assigned before resume and ended empty with
zero active processes. The exact failed fixture `dc-axis-windows-psec-BS9U2l`
remains under private evidence `windows-current-psec-boundary-max-06`. This
artifact was not retried, and no policy, grant, host ACL, firewall, UI setting
or SDK overlay changed. Windows customer execution remains unavailable.

A separate outside-PSEC control uses the same reviewed fixed child and eight
explicit environment entries. Its expected exit occurs at the successful
outside read, after the environment assertions and two private permitted
writes, before negative writes or sockets. This control cannot qualify PSEC
containment. Its first wrapper attempt refused the existing evidence parent's
DACL before creating a fixture or child; the raw stdout and nonzero exit are
retained in `environment-control-01-outer-result.json`. A fresh private parent
and separately reviewed invocation are required for a further attempt.

## Outside-PSEC environment control: passed

The same reviewed build-246 boundary child ran once outside PSEC with eight
explicit environment entries, no inherited credentials and a fresh synthetic
fixture. Its separately reviewed Go wrapper used `processutil.RunTree` and an
owned non-breakaway kill-on-close Job assigned before child resume. A pinned
outer wrapper image/process and bounded readers enforced a 55-second deadline.

The fresh evidence parent was created atomically with a protected DACL for
the current token SID and SYSTEM. No existing ACL was changed, and no failed
fixture was reused or removed. The wrapper revalidated the new parent's owner,
DACL and non-reparse identity before creating the fixture. The original
control-01 refusal remains a pre-execution result, not a containment test.

Control-02 passed in 0.156 seconds: zero wrapper exit, no deadline, overflow or
reader error, and matching stdout/persisted reports. The child exited 1 with
the exact expected `outside read was not denied` failure. By the pinned source
order, all six private environment comparisons and credential/parent-canary
absence checks had passed; both private allowed writes were present, and the
outside/read-only/seal sentinels remained unchanged. It stopped before
negative writes and sockets. The complete fresh fixture remains retained.

| Input | SHA256 |
| --- | --- |
| Exact Go wrapper source | `d91f089bc1f91e7184b248e9c6b67f3624e0d1456751632f430fd9b48b823ac3` |
| Go 1.26.5 wrapper image | `fd5132faff988a3a7ac7f96ff4bc878e15528c9993e30ea94754692d81b9c349` |
| Fixed private-parent creator | `4275cda2c0e5a45f897773a2b81061d9cd710676d0e14a30f1a512214e668fb2` |
| Bounded outer driver | `1df16fa4a749de7fd991be19b317784e1a4ac7b173dea9220ace6fce1244ed80` |
| Actual outer result | `e075cb59147d03e72695946c2a97a0148a79c4b314a6ed943d7091ab33317fbd` |

This narrows the TEMP discrepancy to the SDK/PSEC launch path compared with
the direct Go control. Source review found no SDK-side TEMP rewrite between
the explicit request and its UTF-16 `CreateProcessW` environment block.
Microsoft documents TEMP/TMP profile redirection for
[AppContainer launches](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).
That is a hypothesis for this PSEC observation, not an established cause.
The existing metadata shows the differing value shares the entire exact
synthetic fixture root before diverging at its first child component. A new
child-only lexical diagnostic retains every exact assertion and continues
through the remaining present variables after a mismatch, then fails before
any credential check, write or socket. A missing variable still fails
immediately. It classifies root/home/local-AppData/private-tmp/Packages prefixes,
component count, dot/slash components and final Temp component without logging
values or accessing any filesystem path. A fresh locked build and independent
artifact review are required before that diagnostic can execute.

## Lexical diagnostic: three private Packages paths differ

[Locked build 39133952217](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39133952217)
at `42f8b10731b70b93bf754d493869f3e54a93ee68` passed the ten selected SDK
units and the expanded exact pure path-comparison test. Two independent reviews
verified all 24 archive files, 20 manifest entries, 15 reconstructed SDK paths,
source/lock identity and unchanged PE import inventories. One fresh native
attempt used the reviewed custody image and a fresh evidence directory under
the atomically private parent created for control-02. No previous fixture was
reused, and the artifact was not retried.

Literal argv and direct seal read passed; both DOS path queries still returned
Win32 5. The exact environment assertions failed with these bounded lexical
observations:

| Key | Actual/expected UTF-16 units | Relative components | Final component is exact `Temp` |
| --- | --- | --- | --- |
| TEMP | 245 / 166 | 7 | true |
| TMP | 245 / 166 | 7 | true |
| LOCALAPPDATA | 240 / 181 | 6 | false |

All three reported exact lexical prefixes for this fixture root, its home,
local AppData and Packages branch; none matched the originally supplied private
tmp branch. No dot component or forward slash was reported. HOME, USERPROFILE
and APPDATA matched exactly by the pinned loop's execution order. These are
lexical comparisons, not held-file identity or a proof of the redirection
mechanism. No values or profile names were logged, and no credential, write or
socket operation was reached after the failing environment loop.

The observed shape agrees with the documented AppContainer profile redirection
cited above. The next investigation must bind expected native paths to the
actual contained process's native identity; accepting an arbitrary matching
prefix would not establish that binding. No assertion, grant, policy, host ACL,
UI setting or firewall was broadened for this attempt.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12139512326` | `f2bca34f9cb442be4beecbc02c1364c318eacc530c4ff2c6f0962dbdf83616c1` |
| Provenance | `b1703cf28cb7f2c0bdf858b10a0ab3d8739e0161f378200552b1f1f543706303` |
| Root verification receipt | `3f39edc6cf949502839d34cbf0a461b6d13c6f15a4cfcfde9f92901c1d074f65` |
| Actual live result | `7afa1f763bea5066373851117e47db2ba9c17e1af4aaaf352040cf8eae354901` |

The wrapper exited 1 in 2.953 seconds without deadline, overflow or reader
error. The owned outer Job was assigned before resume and ended empty with zero
active processes. The exact synthetic fixture `dc-axis-windows-psec-Yhxaa8`
remains under
`environment-control-private-02/windows-current-psec-boundary-max-07`.
Windows boundary, terminal, hooks, credentials and Claude qualification remain
incomplete; customer AXIS execution is unavailable.

## Native process identity: private environment mapping refuses

[Locked build 39138642152](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39138642152)
at `4a5aa3d964d19fe35fd27e933bacfc956088b0df` passed six exact pure Rust tests
and eleven exact SDK tests. Two independent artifact reviews checked all 27
archive members, source/lock identity and sixteen reconstructed SDK paths.
The child's ten imported DLLs match the prior standalone child; native token
and profile queries remain in the trusted parent.

The Go custody wrapper's native-identity receipt constants were synchronized
separately in `1ab78c8d`. Its new cross-language inert test accepts the actual
Python verifier's three-image identity and rejects the earlier variant/scope.
Native race/vet passed before a fresh Go1.26.5, CGO-disabled build. The attempt
loaded frozen hash-checked Git helper bytes, independently of later source work.

One fresh case08 ran. Literal argv passed with an observed signaled direct
process handle. The next case refused with the fixed error `native private
environment binding refused`. Source ordering places this failure in the pure
native-folder/private-root binding after successful token/SID/profile API
queries; it does not establish the returned folder's shape or a valid mapping.
No native-identity environment marker or subsequent credential/write/socket
boundary checks passed. The expected-path check was not weakened or retried.

The wrapper exited 1 in 6.083 seconds; the probe observation took 3.666 seconds.
The outer Job was assigned before resume, ended empty with zero active
processes, and reported no deadline, overflow or stream-read error. The exact
synthetic fixture `dc-axis-windows-psec-MnHFQy` remains under
`environment-control-private-02/windows-current-psec-boundary-max-08`.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12141560414` | `df1864bdc92408e41a77736fbc4f3f6fce5502ab251129a3ced2bd6600693dfb` |
| Provenance | `296183a3e95c03fe1c6489ddc52776891b2512f72b12f2dda8af402232e9cdae` |
| Root verification receipt | `c595a5a503b4305117d2f4393a4514a21c77b12ba18b7874acf3916a0c633987` |
| Go custody image | `27c5d09fc98e8d46e0fb790a019ff12b18969bb60ba528c0a8a2da3f7a917be8` |
| Actual live result | `22b04d978b291028986fcd2c3a1687c2d50ba6a9dcd52b3c448e5564e1f3e522` |

The next investigation must establish the relationship between the native
profile API's result and the child's explicitly supplied private USERPROFILE.
No native path values were logged. Full Windows and real Claude acceptance
remain incomplete.

## Caller-context mapping: known-folder base differs

[Locked build 39144717621](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39144717621)
at `fcd356d70f19016aa84da6bc96b0efea005319d9` passed six exact pure Rust
tests, the separate native directory filesystem regression and eleven exact
SDK tests. Two independent artifact reviews checked all 27 archive members,
source/lock identity, sixteen reconstructed SDK LF fingerprints and child PE
imports. The superseded a7 artifact was not executed; planned case09 was held.

Exactly one fresh case10 used frozen reviewed helpers and the corrected build.
Literal argv passed. The next case refused with `native profile caller
known-folder base differs`, before the child received its expected environment
frame or reached credential, write or socket checks. This establishes that the
queried native path did not match the mapper's exact caller-base prefix; it does
not establish either actual path, its spelling, or a valid alternate mapping.
No raw native path values were logged and no expected-path assertion was relaxed.

The driver finished in 3.363 seconds, with a 3.255-second probe observation.
The owned Job was assigned before resume and ended empty with zero active
processes. No deadline, overflow or stream-read error was reported. The owned
synthetic fixture remains under the private case10 evidence directory.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12143247367` | `9d07a3789b6218601eb56a382a15809a95bc266bc661918ee53ade982e4a66bf` |
| Provenance | `bc06c949c666871f4a38b9b3abda7d85f136f62bac70a4047fb43171c1737ae7` |
| Root verification receipt | `f5627a068f45a5d25903c750d484556b1094b2c8e5173e2dc2bae401d9c4b3d2` |
| Actual live result | `6f59697bb5bad56c6afa78a3975c1431c4f8e25dacdb4267e8114d0dc5044b9a` |

Windows boundary and full Claude qualification remained incomplete at this
gate. The separate fixed Claude version slice had not yet executed.

## Fixed signed Claude version: native process creation refuses

[Locked build 39146773781](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39146773781)
at `347735e54cffbe54f507e522f4cb11e28a1620fd` built the distinct fixed Claude
version slice. Its 22 exact test passes comprised six pure environment tests,
four pure DLL protocol tests, one native directory filesystem regression and
eleven SDK tests. Independent reviews checked the 30 archive members, 26 manifest
hashes, exact source/locks and all sixteen reconstructed SDK fingerprints. These
were build and inert reviews; they did not execute PSEC or Claude.

One fresh version-only attempt used that artifact and the independently reviewed,
signed Claude Code 2.1.292 image. The existing wrapper reported Win32 87
(`ERROR_INVALID_PARAMETER`) after `CreateProcessW` failed while attaching the PSEC
environment. That wrapper did not sample the raw native status immediately. The
payload produced no stdout. No Claude start, version output, child-side marker,
environment, hook, credential or model behavior was observed. This is a process
creation failure; it does not establish a DLL-initialization or runtime cause.
No policy, Win32k restriction, filesystem grant or expected value was relaxed.

The outer driver returned in 11.672 seconds; the probe observation took 4.911
seconds. The owned Job was assigned before resume and ended empty with zero
active processes. No deadline, overflow or stream-read error was reported. The
fresh inner synthetic fixture was retained after refusal. No retry occurred.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12143867428` | `892053f72c45231645d2e8ed6186fea659c740b562ccba9b8b558016780367ed` |
| Provenance | `5006ce09e43e8bb235210b4753fed796de18891e2ee4371bb4075b7ef050800a` |
| Root verification receipt | `96374104298f058b9f739a066cef2ed357e968977bf3d7ba9a28c943436ba996` |
| Fixed local image | `eb95bb65955f8b1702e800815f9a2c0388a5de0f196c354c7ee1dd5cb9a2ba23` |
| Local-image review receipt | `a9c38cec7b47197f04e6016eada1e9743e218f3b0ee8d77c1c913a5d2351fa3a` |
| Go custody image | `32f21133e5037b4408fe6df89128e5b4e98014f4b4e5a7bb66ae130a9f13de77` |
| Actual live result | `a62bad914905fcdb45c6aa1f281cf8dfbd7b514a73fd5b66eb24fea58f24676d` |

The eight private environment values were requested configuration; the realized
Claude environment remains unverified. A changed-source diagnostic was prepared
to capture immediate status samples and bounded structural counts under the same
policy, rather than retrying the unchanged artifact.

## Changed-source Claude creation diagnostic: immediate status samples

[Locked build 39150253860](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39150253860)
at `ad643e9b5a85fc446316da8917a1d83ec8fc6bcf` passed 23 exact tests: six
pure environment tests, four pure DLL protocol tests, one native directory
filesystem regression and twelve SDK tests. The new pure SDK test checks status
capture order and numeric count bounds without launching a process. Independent
inert reviews checked 30 archive members, 26 manifest hashes, exact source/locks,
all sixteen reconstructed SDK fingerprints and the linked native status import.

One fresh version02 attempt used that changed diagnostic, the same fixed signed
Claude Code 2.1.292 image and literal `--version`. It retained the same filesystem,
offline and Win32k/UI policy. `CreateProcessW` failed before any Claude start was
observed. Immediately after its raw BOOL refusal, the diagnostic copied
`GetLastError` as 87 and sampled `RtlGetLastNtStatus` as `0xc0000034`.
The last NT status can be stale; this sample does not establish a missing path,
identify a parameter, or prove a filesystem or PSEC cause. Payload stdout was
empty. No version, realized environment, hook, credential or model behavior passed.

| Structural observation | Value |
| --- | --- |
| Application UTF-16 units | 199 |
| Command UTF-16 units | 171 |
| Environment-block UTF-16 units | 1144 |
| CWD UTF-16 units | 175 |
| Argv entries, including program | 2 |
| Environment entries | 8 |
| Any diagnostic count capped | false |

UTF-16 lengths include terminating NULs. No argument, environment value, volume
identifier or host path was emitted by this numeric diagnostic. The downstream
literal adapter derives the explicit application path from its held executable
handle using a volume-GUID name; argv[0] retains its separately quoted original
path spelling. Their unequal lengths do not by themselves identify an error.

The driver returned in 5.187 seconds; the probe observation took 4.8908274 seconds.
The owned Job was assigned before resume and ended empty with zero active
processes. No deadline, overflow or stream-read error was reported. The fresh
inner synthetic fixture was retained after refusal. No policy was relaxed and
no unchanged retry occurred.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12145046979` | `253f47827c78d6fbb51323e76ce56d45b8cd9cf38daa36d17a504dd471a1195f` |
| Provenance | `83c1b606b6ba4ac1f7a03afb7d03ba095e4750aae4eec719967181546af2ee4d` |
| Root verification receipt | `be08283bd701bd2e924ccad8b9c76db1a8c9eda3c9012bda0121a9de313229f1` |
| Native probe image | `ad989718fcd8431f68d6fb9f8f4859e80f872c50b5cf4f816cfbca704a41b162` |
| Actual live result | `83ed3da797c222a0a666256a2efbf0bb4ac10955cfd8f02522018a7e4580543f` |

The evidence does not establish an upstream defect: this path uses reviewed
downstream SDK overlays for literal argv, held executable custody and native
process observation. A fixed comparison of the exact native launch parameters
outside PSEC may help separate parameter/path compatibility from containment,
but no such control was implemented or executed by this result. The later
separate control is recorded below.

## Read-only synthetic profile query: missing registered profile

One separately reviewed query02 control ran outside PSEC with eight exact private
environment values and an absent thread token. `SHGetKnownFolderPath` returned
`S_OK`; `GetAppContainerFolderPath` for the fixed unregistered synthetic SID
returned `0x80070002`. Path classes remained null. The attempt returned in 2.926
seconds without deadline, overflow, stream-read or pin-close errors.

The helper made no explicit profile-creation or filesystem-write calls. Its
supervisor used the existing owned-Job runner and reported no full-tree or
Job-empty qualification. This refusal neither classifies the Case10 path mismatch
nor binds any expected path to its actual contained child. See the separate
[control results](../profile-query-control/manual-results.md). The retained outer
query result SHA256 is
`e470d41ac2cf782c09131bdfd3258ec76f63cc2e2508ff58b4017e838e81f5fe`.

## Uncontained native-create control: attachment is not necessary for refusal

[Locked build 39154166072](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39154166072)
at `ea90b28a36fed512afa8b3adb8fff73c619c5ee1` built the distinct
`claude-create-control-only` slice. Independent inert reviews checked 31 unique
archive members, 27 manifest hashes, eighteen exact Git source paths, unchanged
combined/upstream locks, and all seventeen SDK fingerprints reconstructed from
five reviewed overlays. The actual CI log contains 24 distinct one-time passes:
thirteen SDK tests, six pure environment tests, four pure DLL protocol tests and
one native directory regression. CI did not run the control or Claude.

One fresh native attempt used that separately admitted control, the fixed signed
Claude Code 2.1.292 image and literal `--version`. The control constructed a normal
PSEC startup plan and a HANDLE_LIST-only plan, using the same bounded application,
command, environment and cwd buffers, creation flags, eighteen `STARTUPINFOW`
fields and three actual inherited handles. It reported this exact proof before
its single selected raw call:

```json
{"fixed_create_control_inputs_equal":true,"psec_attribute_attached":false,"constructed_psec_attribute_count":2,"selected_attribute_count":1}
```

The normal reference plan was not executed. The PSEC object was still constructed
and held, but no security-environment attribute was attached to the attempted
Claude process. This was an **uncontained diagnostic**, with no claimed PSEC
filesystem, network or Win32k enforcement. Its separate receipt, Cargo feature
and fixed selector cannot be used as a production fallback or ordinary PSEC case.

The selected `CreateProcessW` call failed before any Claude start or version
output was observed. Immediate `GetLastError` was 87; the sampled last NT status
was `0xc000000d`. The NT sample may be stale and does not identify a failing
parameter or cause. No Claude environment, authentication, hook or model behavior
was observed.

| Structural observation | Value |
| --- | --- |
| Application UTF-16 units | 205 |
| Command UTF-16 units | 177 |
| Environment-block UTF-16 units | 1180 |
| CWD UTF-16 units | 181 |
| Argv entries, including program | 2 |
| Environment entries | 8 |
| Any diagnostic count capped | false |

Lengths include terminating NULs. Equality describes the two constructed plans
within this one attempt, not the differently named fixtures from earlier runs.
The numeric and equality records do not expose host paths or environment values.
The downstream adapter still supplied its held-image volume-GUID application
name and separately quoted original argv[0].

The driver returned in 5.422 seconds; the probe observation took 3.2272703 seconds.
The outer Job was assigned before resume and ended empty with zero active
processes. No outer deadline, overflow, stream-read error or driver error was
reported. The fresh inner fixture was retained after refusal. No unchanged retry
occurred and no existing host namespace, ACL or deployed runtime policy changed.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12146194784` | `89128269cbcf7a5fafc35463e367a741a31bf16c256c6e5e3dcdf717d92d765c` |
| Provenance | `d82a4bcb5578ad6679b711d1d0d747bc2a5487b8fbdf29f37ce0bdb3b26a6f2a` |
| Root verification receipt | `c3db147ce2bdb4eec457fb959b64f607fd652e2a9a50e8a2ea80ea24da8101aa` |
| Native control probe image | `101ba1cbad3f503512d8cb9a30b9471362b1fcdbdc87d648b92c9b0d8891ff25` |
| Fixed local image | `eb95bb65955f8b1702e800815f9a2c0388a5de0f196c354c7ee1dd5cb9a2ba23` |
| Go custody image | `8a4eb11a09e1a0cfdb88a8cbc4273cfe0bb21190367c46c5f8df776b9020a82b` |
| Actual live result | `e1084a0a0f9a0ca94e6788734ec414d375b30e1438f04955002fb6570c35f04d` |

This narrows the observation: attaching PSEC was not necessary for the refusal in
this downstream adapter. It does not establish the cause, exclude every effect
of PSEC object construction, or reproduce a defect on unmodified MXC. No customer
runtime or Claude qualification follows. The compatibility investigation is
tracked in [MXC issue 1523](https://github.com/microsoft/mxc/issues/1523).

## Uncontained application-path control: DOS starts the fixed image

One separately reviewed native run used the fixed Go
[application-path control](../claude-path-control/README.md), with no SDK, PSEC
object, AXIS process or sandbox policy. The image was the same independently
reviewed signed Claude Code 2.1.292, SHA256
`eb95bb65955f8b1702e800815f9a2c0388a5de0f196c354c7ee1dd5cb9a2ba23`,
254,858,400 bytes. Helper source `17ebe67f727b66900d9b922d5a8e53ad5c428c1c`
and supervisor source `b00149e1d728a3da73c18dcdf08f84738cdc1e27` were independently
reviewed before their local Go 1.26.5 Windows/amd64, CGO-disabled builds. The
compiled source closure contained nineteen exact local Git source files and
twenty-two selected files from the reviewed `golang.org/x/sys` v0.47.0 module.
The source/build checks did not execute the binaries.

The one-shot native driver admitted the two exact helper images and local-image
receipt into a fresh private fixture. It enforced a 30-second outer cutoff.
The supervisor created the helper in its owned kill-on-close Job using JOB_LIST,
sampled membership through the retained process handle, and verified that
handle's image identity before resuming its retained primary thread. The helper
held the copied Claude image and its ancestors, then required each application
spelling to resolve to the same volume and full 128-bit file ID before creating
any child. No PID reopening or changes to existing host namespaces, policies or
ACLs were used.

| Application spelling | Creation | Immediate Win32 error | Sampled NTSTATUS | Version observation |
| --- | --- | --- | --- | --- |
| Volume GUID | refused | 87 | `0xc000000d` | child was not created |
| GLOBALROOT plus native device path | refused | 87 | `0xc000000d` | child was not created |
| Ordinary DOS | succeeded | 0 | no failure sample | exit 0, exact fixed version stdout, empty stderr |

The NTSTATUS samples may be stale and do not establish a failing parameter or
cause. For the successful DOS case, the child remained suspended until assigned
to its owned Job and the image queried through that same retained process handle
matched the pinned image's full file ID. It then resumed, exited 0 and produced
the exact 22-byte `2.1.292 (Claude Code)` line including LF. Stdout SHA256 was
`46ef67828dfb9d34aef4d5df24d529825edb3cfa334f333e445fe5d0f1b14cc2`;
stderr was empty. Its output readers joined and their handles closed.

The literal command buffer, eight supplied environment values, cwd, creation
flags and startup/stdio shape were held constant across the three calls.
Command/environment/cwd lengths were respectively 166/922/138 UTF-16 units;
application lengths were 194/183/148 in table order. Lengths include terminating
NULs. Flags were `134743044` (SUSPENDED, UNICODE_ENVIRONMENT,
EXTENDED_STARTUPINFO_PRESENT and NO_WINDOW). One HANDLE_LIST attribute carried
three anonymous-pipe handles, with stdin at EOF. Fresh pipe handle values and
mutable command buffers were necessarily per-case allocations; this is
structural consistency, not equality of their numeric handle values or of
earlier runs' differently named fixtures. No raw path, environment value,
handle or file ID was printed by the measurement.

All three child Jobs reported empty with zero active processes. The supervisor
also reported empty Job/zero active processes and joined/closed output readers.
The driver returned in 6.031 seconds, the supervisor in 4.2482648 seconds and the
helper in 2.8581524 seconds. Case durations were 0.9126255, 0.5417824 and 0.5944191
seconds in table order. There was no deadline, overflow, stream-read or driver
error. The fresh fixture was retained; no retry or old-fixture removal occurred.

| Input or observation | SHA256 |
| --- | --- |
| Fixed local image review receipt | `a9c38cec7b47197f04e6016eada1e9743e218f3b0ee8d77c1c913a5d2351fa3a` |
| Measurement helper | `a78aef62fd7f1b98293cf570a87e672fc3cb7b20d922748d7f34931b34adf823` |
| Outer supervisor | `dfec8f3c7f93181df30c9748031dc664bf89b4079f6733cec6dbf09e2891e119` |
| One-shot driver | `821dc630262e386a1ed673fa9c0f488faef4c30e7e7614f102c76de5862067f2` |
| Actual retained outer result | `f38e14ee23f64a46d5e1a6950efac46b6311b0beea7479e8293cbb69881cce53` |

The measurement completed, while `all_version_paths_passed` was false because
only one spelling started successfully. It supports a narrowly scoped change to
the downstream application-path selection, followed by a new reviewed SDK build
and contained attempt. It does not establish an unmodified MXC defect, general
CreateProcess compatibility, PSEC enforcement, realized Claude environment or
working authentication, hooks, model access or customer provider integration.
This successful version observation was **uncontained** and cannot be used as a
runtime fallback or sandbox qualification.

## Native PSEC Claude version smoke passes after DOS image binding

[Locked build 39161822089](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39161822089)
at `be32bd247b840bf7ab810c6d0d3581e0c4b334e4` built the normal contained
`claude-version-only` slice. Independent inert reviews verified thirty unique
archive members, twenty-six manifest hashes, seventeen exact Git source files,
unchanged combined/upstream locks, and all sixteen SDK fingerprints freshly
reconstructed from four reviewed overlays. The actual CI log reports all
twenty-five selected Rust tests passing exactly once: fourteen SDK tests, six
pure environment tests, four pure DLL protocol tests and one native directory
regression. This includes the exact-zero resume gate and read-only current-image
query with a byte-identical, different-file-identity negative. CI did not execute
PSEC or Claude.

The changed downstream literal adapter selects an ordinary DOS application
spelling from the held image. After suspended creation and Job assignment it
requires a direct kernel `ProcessImageFileMapping` comparison with that held
file HANDLE before resume. A nonzero status refuses with bounded owned-child
cleanup attempts. This introduces no NULL-application, name-reopen or alternate
runtime fallback, and does not relax the configured PSEC filesystem, network or
UI settings.

One fresh, separately reviewed native attempt then passed with the same fixed
signed Claude Code 2.1.292 image and literal `--version`. The child exited zero,
its retained direct process handle was signaled, and it emitted exactly
`2.1.292 (Claude Code)` plus LF: twenty-two stdout bytes, SHA256
`46ef67828dfb9d34aef4d5df24d529825edb3cfa334f333e445fe5d0f1b14cc2`.
Child stderr was empty. The final record reported `psec_attribute_attached=true`
and the three expected checks: fixed version output, signaled retained direct
handle and removed owned fixture.

The driver returned in 4.547 seconds; the probe observation took 4.3556386
seconds. The outer Job was assigned before resume and ended empty with zero
active processes. No deadline, overflow, output-read error or driver error was
reported. The fresh owned fixture was removed, and no retained fixture was
reported for this attempt. Earlier failed fixtures and evidence were preserved;
this was one changed-source attempt, with no retry.

| Input or observation | SHA256 |
| --- | --- |
| ZIP, artifact `12149401741` | `f31896fa66f99ca42b7c0873344f1aea06314129d8d0695e61203e6e4c2032e5` |
| Provenance | `ad442c865e97bf08f5c1764496ad2686d8e364f9a868893372920084637a5090` |
| Root verification receipt | `751d039adce0948b5c89333f121abc44ff16195ade7ffad8e4310a4b571aad31` |
| Native PSEC probe image | `e651b97bf2979e83b70134ff8f0618b6bfe6d81051fae39c2eee228c789cc454` |
| Fixed local image | `eb95bb65955f8b1702e800815f9a2c0388a5de0f196c354c7ee1dd5cb9a2ba23` |
| Fixed local image review receipt | `a9c38cec7b47197f04e6016eada1e9743e218f3b0ee8d77c1c913a5d2351fa3a` |
| Go custody image | `32f21133e5037b4408fe6df89128e5b4e98014f4b4e5a7bb66ae130a9f13de77` |
| One-shot driver | `2c1e5f1b824938f78b7e690cd93d87af12464f9fa181422d3b5189206ea39db7` |
| Actual live result | `4240a692ad9baa3dc6a1f561d086478a69651e298be610256603c9bd5d0bbe60` |

This establishes only the fixed version-start smoke through the downstream
native PSEC adapter. Eight private environment values were supplied, but
Claude's realized environment was not observed. This case does not exercise the
boundary child's native-profile handshake, filesystem/network assertions,
authentication, model access, hooks or terminal. It activates no customer
provider and does not reproduce or establish a fix to unmodified MXC. The
earlier environment-binding refusal remains a separate qualification gate.
The compatibility chronology is tracked in
[MXC issue 1523](https://github.com/microsoft/mxc/issues/1523).

## Boundary startup context kept stable: comparison still refuses

[Locked build 39165501746](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39165501746)
at `d83888d0340aecf7c312a513def41f9e97d00ce1` built the closed three-image
`standalone-boundary` slice. Independent inert reviews verified twenty-nine
unique ZIP members, twenty-five manifest hashes, seventeen exact Git sources,
unchanged combined/upstream locks and all sixteen SDK overlay fingerprints.
The actual CI log reports all twenty-seven selected Rust tests passing exactly
once, including both new startup snapshot tests. CI did not execute PSEC or the
contributor workload.

One separately reviewed Case11 then failed. Its literal argv case emitted
`FIXED_ARGV_PASS`, exited zero and signaled its retained direct handle. The next
case refused with `native profile caller known-folder base differs`. By the
frozen source's error ordering, the original eight startup values passed their
shape and unchanged checks, the caller known-folder query succeeded, and the
same held child's SID/folder query succeeded. The following exact normalized
UTF-16 prefix comparison failed. Profile-component admission, private profile
directory binding, the stdin expectation frame and the boundary child's first
environment/write/socket assertions were not reached.

The driver returned in 3.469 seconds; the probe observation took 3.3969189
seconds. The outer Job was assigned before resume and ended empty with zero
active processes. No outer deadline, output overflow, stream-read error or
driver error was reported. The fresh failed fixture was retained. Case10 and
earlier failures remain preserved; Case09 was never executed, and Case11 was
not retried.

| Input or observation | SHA256 |
| --- | --- |
| ZIP, artifact `12151285606` | `67016cd1dbfa1fbd66120735e69a8ab62f9720deb987e627fb39311e69089d60` |
| Provenance | `3e42961dbd1f8de73ae0c7a3a970af4e3630146fd9d18d0b65a300876dfc1324` |
| Root verification receipt | `b762183a422f9badf92728f85790fa5d02dfebfff73867d6f5e101ec9e40e9cb` |
| Native probe image | `69b0f1b6bd35985c3cd9d7d62b385b0cae5203eb6ea6e0fcdc16667add26e8bb` |
| Go custody image | `32f21133e5037b4408fe6df89128e5b4e98014f4b4e5a7bb66ae130a9f13de77` |
| One-shot driver | `0e4a8bb220af922f9f822ca4feb61ac7d8f15a816a5202f223da57c02aa71424` |
| Actual live result | `b0b6cc3a2b3c386bccec1736ec56446a0e7cf04c47febbfdb1ac2317512a4898` |

The parent kept its original eight path values across these native queries,
but that change did not resolve the refusal. The comparison already removes a
recognized optional verbatim-disk prefix; its remaining exact comparison is
case-sensitive. The evidence contains neither returned path, so it cannot
distinguish casing, a different native base or another suffix/shape mismatch.
No cache cause, alternate admitted prefix, filesystem/network enforcement,
resource-cleanup completion or customer-provider qualification follows from
this result. No comparison, grant or policy was relaxed after this attempt.

## Refusal classification: caller context matches, native suffix unrecognized

[Locked build 39168385401](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39168385401)
at `3bebfd10ee9537241e222e27708ec6aba34ac063` added only refusal-side string
classification and its mandatory pure callback test. Independent inert reviews
verified twenty-nine ZIP members, twenty-five manifest hashes, seventeen exact
Git sources, the unchanged locks and all sixteen reconstructed SDK fingerprints.
All twenty-eight selected Rust tests passed exactly once in the actual CI log.
The three x64 console images passed static import review. The supervisor's
fifteen added API-set import names contain functions already named in the prior
image's IAT; this static observation does not itself prove runtime compatibility.
The boundary child's GUI/Userenv exclusion remained unchanged.

One separately reviewed Case12 ran once and failed. The literal argv case
again passed and signaled its retained direct handle. The refusal-side record
reported these bounded relationships before preserving the original
`native profile caller known-folder base differs` error:

| Relationship | Observed value |
| --- | --- |
| Classification | `unrecognized_suffix` |
| Recognized verbatim-disk prefix, caller/native | false / false |
| Native exact/ordinal case-insensitive caller prefix | false / false |
| Expected native suffix shape | false |
| Native base comparisons | unknown; no base derived |
| Caller known-folder base vs startup LOCALAPPDATA, exact/ordinal | true / true |

The caller query therefore matched the frozen private startup value in this
attempt. A different caller/startup base and a case-only caller-prefix difference
do not explain this observation. The native result did not satisfy this probe's
assumed `Packages/<one allowed profile>/AC` suffix, and its actual shape remains
unknown. Microsoft's [GetAppContainerFolderPath reference](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getappcontainerfolderpath)
promises a local-app-data path with thread/process identity context; it does not
guarantee that textual grammar. The classifier is diagnostic only and did not
broaden admission or supply an expected child environment.

The driver returned in 4.078 seconds; the probe observation took 3.7780166
seconds. The outer Job was assigned before resume and ended empty with zero
active processes. No deadline, overflow, stream-read error or driver error was
reported. The failed owned fixture was retained. A bounded read-only metadata
inspection found the outer and inner private AppData Local/Roaming directories,
and the inner tmp directory, ordinary and empty. It recovered no native profile
path. No host profile contents, environment change or ACL mutation was needed.
The expectation frame and boundary assertions were not reached. Prior failures
were preserved, with no retry or cleanup of the failed fixtures.

| Input or observation | SHA256 |
| --- | --- |
| ZIP, artifact `12151877206` | `03c8d000a7444c06297b488e0c3512b0a7d840a000d09661ec28e97cce16d875` |
| Provenance | `8d9e8574c762fbf6768314f3ff6a84e7c5c32df5fad04ec5cbdcc2d3141ba74d` |
| Root verification receipt | `5dbab5961647d558c6494c401a0fad7e4009ce6549cc5fc88bb0d6465deb9fba` |
| Native probe image | `3923f1d16d17b9d88da251b7b24928909f18170a83e6ff8ccdb05ccd64e8b5b6` |
| Go custody image | `32f21133e5037b4408fe6df89128e5b4e98014f4b4e5a7bb66ae130a9f13de77` |
| One-shot driver | `905c5556f52aea8d306736ac8f82137a3bf79fe18b7d1cf571ad1899e5999724` |
| Actual live result | `d2ef6cf8819145b5aa92a4c5772d58ca1be70c0f2d871a81164a8757df9c9e2b` |

## Private refusal record: first build stops at compilation

The changed private-record diagnostic source at
`6a1f7080a39fbdfa39b98f3ea7db02516910dc3d` reached its native Windows
[build gate](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39171818814),
then failed Rust type checking at the security-descriptor pointer assignment.
No selected Rust test or native probe ran, and no returned API paths were
captured. The correction explicitly casts the same still-owned descriptor to
the const pointer type required by `OBJECT_ATTRIBUTES`; it changes no policy,
admission, record format, dependency, SDK overlay or required test count.
The changed-source replacement
[build `39172760986`](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39172760986)
at `783e7898baa0c839c2bb9d96eabb1220f921050e` passed compilation and all thirty
selected Rust tests exactly once, including the binary format and synthetic
NT-relative private-file/DACL/link/collision tests. Independent source, ZIP,
lock, SDK and test-log reviews passed before the next native attempt. CI did
not run PSEC or capture returned folder paths.

## Private record reported available; boundary still refuses

One fresh Case13 used the reviewed changed artifact once. The argv child
completed `FIXED_ARGV_PASS`; the boundary parent then reported
`native private path record available=true`, followed by the same
`unrecognized_suffix` classifier and strict known-folder prefix refusal.
Caller/startup equality remained true; no native base was derived. The driver
finished in 7.510 seconds and the probe in 7.1893379 seconds, with exit one.
The outer Job was assigned before resume and ended empty with active count
zero. No outer deadline, output overflow or stream-read/driver error occurred.
The failed owned fixture was retained.

The record-availability boolean is a parent observation. The later read-only
inspections below validated the private file separately; neither recorded folder
string appears in the result or this document. The strict mapper still refused
before the native environment frame, directory binding or boundary-child
environment, write and socket assertions. No native retry, admitted prefix,
existing host policy/ACL repair or production runtime activation was introduced.

| Evidence | SHA-256 |
| --- | --- |
| ZIP, artifact `12153163904` | `cb0deb6f042d8d1073f64ff87d9584380ff8ade0860f4e26df6a222114078f7f` |
| Provenance | `47b6ccdb35308ccc57ac1651f3b2234bc037986b9e0de9fbb0efef43c491d141` |
| Root verification receipt | `40ff02a83763c27f00875b09bbd9c2e18e1615ec3208d6744d94e98303029e8c` |
| Native probe | `dcb1a0d69f340f6fb60626b4c04b659f01d5c16494503fbfec8c45e6d80c6cf9` |
| Actual live result | `c330464f6ec10dc2c63d25a8a268239df43de053b35b1bfeba0ff03676a54119` |


## Private read isolates two independent mapper assumptions

The first two separately reviewed inspector invocations refused before reading
the record: attempt01 reported `fixed_ancestry`; attempt02 reported
`ancestor_5_security_acl_header`. Both closed all owned handles. These stages do
not identify an unexpected ACE or establish a privacy failure. Neither attempt
changed an ACL, the record or the failed native fixture.

The changed reader retained the fixed held nonfollowing ancestry, owner and
full-file-identity checks, exact private-root security check, and protected
current-user/SYSTEM record security. It required a regular single-link file,
exclusive sharing, bounded complete format with exact EOF, identity/size
rechecks, and successful handle closes. Attempts03 and04 completed in 0.160 and
0.177 seconds, respectively, with all handles closed. They emitted only closed
structure/grammar metadata; no raw API-returned values were logged or copied
into this document, CI artifacts or the native result.

The native returned path is an ordinary disk string with the fixed
`AppData/Local/Packages/<one component>/AC` labels under a different base string
from the frozen private caller query. These are lexical observations, not a
proof that two paths identify different filesystem objects. Attempt04 confirmed
exact `Packages` and `AC` spelling, four-way suffix split, base minimum, exactly
two remainder components, a nonempty profile and the existing 128-unit bound.
The ASCII-only profile predicate failed; canonical plain and braced GUID
predicates also failed. The diagnostics reveal no particular rejected
character. The base mismatch and component-grammar failure are independent;
either still prevents the current mapper from admitting the environment.

This is read-only diagnosis of the preserved Case13 refusal. It supplies no
child-environment expectation, new accepted prefix, changed native policy or
boundary qualification. No further native workload was run by these readers.

A separately reviewed predicate-only inspection05 then completed in 0.175
seconds with the same custody, complete-record, handle-close and process-wait
checks. All nine proposed ordinary-component booleans passed: nonempty,
existing bound, well-formed UTF16, no controls, no reserved characters, no
traversal meta name, no trailing dot/space, no reserved device basename, and
the combined predicate. The ASCII-only predicate and independent base-string
mismatch remained unchanged. This reveals no particular name or rejected
character and grants no mapping authority.

At this point the next mapper correction was source-only: it binds the native OS profile root
to the actual held child token, requires caller/child TokenUser equality, and
admits only the exact default AppData Local branch and one safe literal
component. It independently keeps caller-knownfolder equality with the frozen
private startup value. It neither opens the OS profile nor creates a missing
private descendant. New pure gates and existing frame/custody tests were still required
in CI; no new artifact or native result qualified this change then. The separate
source-only native-handle [upstream proposal](https://github.com/microsoft/mxc/pull/1524)
is not a released SDK or a production runtime qualification.

| Closed metadata result | SHA-256 |
| --- | --- |
| Inspection03 | `2e2eb8ffda45967082dc3fe73cbc40b8cc2f6da3e2921dd7056235d06d458673` |
| Inspection04 | `92582dcbece5ca751b4ae2c3f5bda06675368896a3427b6d9221fbb466c0c052` |
| Inspection05 | `f827cbf092dcf65add35646ba21b81d771062d51cf51fa9abbbdd6bc3f915b1c` |

## Separate Linux lifecycle contributor result

Separately, Linux contributor run
[39174025396](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39174025396)
at `96c22c1fac0343aa5db1cfb06875bdd651b6c65c` passed the fixed wait-timeout,
wait-cancel and tree-cancel cases. Each observed Prepared/Started, exact ready
markers, expected `Exited(-1)`/timeout flag, Destroyed and independent native
cleanup. Three known ordinary tree writers progressed from heartbeat counts
`[1,1,1]` to `[2,2,2]` before Cancel and remained stable through six samples
before Destroy. This is finite corroboration, without a universal descendant
absence or separate-session proof. All three cleanup owners completed with
pending zero; twelve public fixture files/291 bytes were retained, and the
runner setting `1→0→1` was restored. Artifact `12153881045` is 29,088 bytes,
with ZIP SHA-256
`47c4d62d0530c1cd6710d5ea46d49a36f122f22324719ed4f59f48d4c0ed4cef`.
The earlier Linux baseline-four pass and c9e tree failure remain separate.
This grants no Windows, Claude/model, broker/hooks or common production
qualification.

This records a failed boundary qualification and narrower diagnostic facts.
It establishes no qualified mapper, supported suffix, enforcement, full resource
cleanup or customer-provider qualification. No native rerun or changed build is
authorized by this record.

## Held-child token mapper build and Case14 directory-open refusal

The initial mapper build
[39178182150](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39178182150)
at `2bd3ba2d613a672053a2d6b7b24ab8eb42c6f6dc` failed Rust compilation with
E0061: the new SID-range helper signature missed two existing private-record
callers. No selected Rust tests or native case ran from that failed build. The
correction retained the original two-argument helper for those callers and a
separate explicit-header validator for the new child TokenUser binding.

The corrected build
[39179229027](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39179229027)
at `2d679e73ef4fb8767bced5d78c7e01e83316f972` passed all thirty-three selected
tests exactly once. Independent inert reviews verified thirty ZIP members,
twenty-six manifest hashes, eighteen exact Git source files, all sixteen
reconstructed SDK fingerprints, unchanged locks and three x64 console images.
Artifact `12156041712` is 1,414,060 bytes; ZIP SHA-256 is
`ec66f75f071e8706334922213e252c884c237d4b0b5654bab585d1bda866156b`
and provenance SHA-256 is
`b725c8b8abe38a3e706de2d2801bc204c4c8947841dbba26fb93e857dff940aa`.
These reviews executed no packaged image.

After source, artifact and fixed-recipe review, ROOT ran Case14 once. Literal
argv passed with `FIXED_ARGV_PASS`, empty child stderr, `Exited(0)` and a
signaled retained direct handle. The parent then refused with
`private native directory open refused`, exiting one. Elapsed time was
7.848 seconds outside / 7.7105487 seconds in the probe. The outer Job was
assigned before resume and observed with zero active processes and empty;
there was no outer deadline, output overflow or reader error. The failed
fixture remains retained. Result SHA-256 is
`a2cc1ee3263aa5d622425ac05ad885cf7dc365fffe524917e7474048f0147ba1`.

The error helper is shared by fixture ancestry pinning before boundary child
creation and mapped private-directory opens after the mapper. This result
does not distinguish them, establish successful token/profile mapping, or
identify a missing directory, access denial or sharing conflict. No new private
path inspection, host-profile open, missing-directory creation, ACL repair or
native retry followed this attempt. The next source-only diagnostic adds only
a closed gate, component index and the exact NtOpenFile return status; its new
pure formatter gate raises the boundary inventory to thirty-four. All existing
open-only, no-reparse, access, sharing and admission checks remain unchanged.
No full boundary, realized child environment or customer-provider qualification
is established.


## Case15 identifies missing private Packages fixture directory

The diagnostic build
[39189445357](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39189445357)
at `1cd45a63741b6296880deffe7cc4a8ff5ace6672` passed all thirty-four selected
tests exactly once. Independent inert reviews verified thirty ZIP members,
twenty-six manifest hashes, eighteen exact Git sources, all sixteen reconstructed
SDK fingerprints, unchanged locks and three x64 console images. Artifact
`12160046169` is 1,415,074 bytes, with ZIP SHA-256
`ce43f94b8820b96106bbc0e2d2e52ffa94c73ac7e6b299e4ac39c4a6698d095d`
and provenance SHA-256
`697984cd00659a9d18a4c407ef41d2f12d448e9be7564d830fa0cad3019c4c1f`.
These reviews executed no packaged image.

ROOT ran the reviewed Case15 recipe once. Literal argv passed with
`FIXED_ARGV_PASS`, empty child stderr, `Exited(0)` and its signaled retained
handle. The boundary supervisor then refused with exactly
`private native directory open refused: gate=private_environment component_index=3 ntstatus=0xc0000034`.
Elapsed time was 4.269 seconds outside / 4.1986862 seconds in the probe; the
outer Job was assigned before resume and observed empty with zero active
processes. No outer deadline, output overflow, reader error or custody error
occurred. The failed fixture remains retained. Result SHA-256 is
`2a7ace9ef7fdded6eaaf7bd71c43653f19da46be3f42f453fbc22ab0564c5f92`.

Source inspection identifies index three as literal `Packages` immediately
below the held private `home/AppData/Local`. `Paths::create` creates only through
Local; the exact status is `STATUS_OBJECT_NAME_NOT_FOUND`. The gate is reached
after the same-child token/profile mapper, distinguishing this fixture omission
from Case14's ambiguous refusal. The result still precedes the child environment
and boundary assertions, so it grants no realized-environment, full containment
or customer qualification.

The changed source retains the exact native authority/mapping checks and
revalidates the full branch against the held root before any creation. It uses
NT-relative exclusive creation only for the four new private directories
`Packages/<validated component>/AC/Temp`, with an atomic protected owner+SYSTEM
DACL verified before use. A collision or link refuses without adoption; no
native OS profile is opened, no existing host ACL is changed, and no runtime
fallback is enabled. One added synthetic filesystem gate raises the boundary
inventory to thirty-five. A reviewed new build and one native attempt are still
required. Case14 and Case15 failures are preserved; no retry used their images.


## Case16 native boundary canaries pass; saved parser contract corrected

The fixture-correction build
[39191897344](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39191897344)
at `b95bf7274311ea7760244f70d9ee5176aeb8ad86` passed all thirty-five exact
selected tests, including the new exclusive/private/pinned directory-tree
filesystem regression. Independent inert reviews verified thirty ZIP members,
twenty-six manifest hashes, eighteen Git sources, sixteen reconstructed SDK
fingerprints, unchanged locks and three x64 console images. Artifact
`12160164619` is 1,417,752 bytes, with ZIP SHA-256
`a07e06a3365f6011eb352c168a44362411aa2ea7882c4140d4c3aed77388bb22`
and provenance SHA-256
`67ad20b09337e2bae0e5ea5a602774873d6fa32064f1f3cc403777143fb9b5ef`.

ROOT executed Case16 once after source, artifact and fixed-recipe review.
The native supervisor and owned Go custody exited zero. Literal argv passed;
the boundary child emitted both `FIXED_NATIVE_ENV_BINDING_PASS` and
`FIXED_BOUNDARIES_PASS` and exited zero. The fixed exit23 and timeout cases
reported `Exited(23)` and `TimedOut`, and every retained direct handle was
signaled. The final supervisor record reported all ten expected checks,
native PSEC attachment and owned fixture removal. The outer Job was assigned
before resume and observed empty with zero active processes. No fixture was
retained; there was no outer deadline, output overflow, reader or custody
error. Elapsed time was 8.754 seconds outside / 8.4591805 seconds in the probe.

The unchanged original outer receipt nevertheless has `passed=false`: its
exact-output parser expected only the old boundary stdout marker and empty
child stderr. The already reviewed child also emits the native-environment
marker and closed canonicalization diagnostic. Original receipt SHA-256 is
`e66cb9720b44206e1c2d61a729eb499b2ac78afc90ce4b90068452c08f8400d2`.
A separate data-only evaluation of that same saved receipt passed the corrected
exact fixed-canary contract and refused five negative mutations, without
altering the original receipt or running any native program again. Assessment
SHA-256 is
`10e4e7f51ea99a2dd141d1b04cdd7cdb600cd34e66e69aa39a61cfffbb3cecbd`;
its corrected parser SHA-256 is
`f7037d174c28b132b5dedb561c0ea7ff60a3340f5967924485639702cf9a466d`.

The fixed canonicalization diagnostic observed Win32 access denial (5) for
canonicalization and both DOS final-path query spellings; its directory open,
NT final-path query, handle close and read of the public seal succeeded. No
returned path was logged by that diagnostic. This records compatibility facts
and does not make those path strings authority or resolve general CLI path
compatibility. No image, filesystem/network policy, private environment
expectation, native profile rule, UI restriction or SDK fallback was relaxed
by the parser correction.

This passes the recorded fixed native-environment, filesystem/loopback,
exit/timeout and owned cleanup canaries on this host. Earlier failed cases and
the separate successful Claude `--version` smoke remain preserved. It does not
qualify a Windows native peer/bridge, interactive terminal, full Claude session,
credentials, model, broker, hook or customer-provider runtime. No additional
native execution is authorized by this result record.
