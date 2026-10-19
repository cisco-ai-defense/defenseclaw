<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Native Windows current-MXC PSEC contributor probe

## Boundary startup context and refusal-only diagnostics

The closed `standalone-boundary` build slice preserves the existing three-image
native-identity boundary contract. Its new source validates and freezes the
supervisor's eight original private startup values before the caller known-folder
query, fixture setup, SDK work or Rust worker threads. It verifies their exact
names, fixed private path relationships, system directory and startup cwd. The
boundary supervisor keeps those values unchanged; only the existing fixed public
inheritance canary is added. Loader, DLL and Claude selectors retain their prior
supervisor environment behavior.

The child still receives the existing inner fixture's exact eight explicit
values. That recorded startup correction retained same-child SID/folder lookup,
exact frozen caller-prefix/one-profile mapping, held NT-relative private
directories and frame-plus-EOF assertions. Original startup values are rechecked around the native queries and
directory binding. No extra native prefix, observed-child environment value,
host profile grant, namespace change or fallback is accepted. This removes a
parent context change after DLL imports. The separately reviewed d838 build
passed its twenty-seven selected Rust tests, but one fresh Case11 still refused
with `native profile caller known-folder base differs` after its argv case.
The outer Job ended empty; the failed fixture was retained. The startup checks
did not resolve this comparison or establish its cause. See
[the actual result](manual-results.md#boundary-startup-context-kept-stable-comparison-still-refuses).

The two snapshot/validation tests are mandatory only for this boundary
slice. Its recorded build ran twenty-seven exact Rust tests and packaged three PEs plus
the existing DLL protocol/child source used by compile and pure-test gates.
That recorded source used twenty-five tests for ordinary DLL/Claude builds and
twenty-six for the separate uncontained control. The new mapping gates described
below add three tests; dependency locks and SDK fingerprints remain unchanged.

The changed source adds refusal-only classification of the already returned caller
and same-child native folder strings. It emits only fixed categories and
booleans: optional verbatim-disk prefix, exact/Windows ordinal case-insensitive
prefix relationships, exact native suffix shape, and derived-base equality to
the frozen caller base and startup LOCALAPPDATA, including caller-to-startup
equality. Invalid shape and failed
ordinal comparison remain unknown. No raw strings, path hashes, lengths or
identity values are printed. These are string relationships, without alias or
object-identity equivalence. Diagnostics never feed admission: the exact
diagnostic additions left prefix, same-child authority and held-directory
requirements unchanged at that stage.
A new pure callback test brings the boundary build requirement to twenty-eight
Rust tests. The separately reviewed 3beb build passed all twenty-eight. One fresh
Case12 then reported `unrecognized_suffix`, with exact and ordinal prefix
relationships both false. The caller known-folder base matched startup
LOCALAPPDATA exactly; no native base could be derived under the assumed suffix
grammar. Admission still refused before the boundary assertions. The API
[reference](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getappcontainerfolderpath)
does not guarantee that textual suffix. At that point the actual returned shape remained
unknown; no extra prefix or suffix was admitted. See
[the recorded diagnostic](manual-results.md#refusal-classification-caller-context-matches-native-suffix-unrecognized).

The refusal-only diagnostic records both returned API strings only after
that same strict mapping refusal. It creates the fixed
`native-folder-refusal.private.bin` once, relative to the already held private
fixture root, with a protected current-user and SYSTEM DACL at creation. The
writer verifies that DACL before any data, refuses links and collisions, and
checks writes and close. The bounded binary format stores two lossless UTF16
fields, each at most 2,048 units, with a versioned header, explicit counts and
final completion marker; a complete record is at most 8,216 bytes. Embedded NUL,
incomplete records and trailing bytes are invalid. It grants no authority and
never changes the original mapping refusal.

Only a fixed availability boolean can enter stderr. Raw record contents are
excluded from logs, result JSON, receipts and every admitted artifact inventory;
the outer runner retains only the fixture pathname. The record remains in that
owned private fixture for separate private inspection, with no automated upload.
The recorded private-record build required thirty exact Rust tests, including a pure binary
format test and a separate synthetic NT-relative creation/DACL/link/collision
test. The link test is mandatory: an unsupported host refuses the gate rather
than skipping it. Those diagnostic-only additions left other slice counts unchanged.
The corrected 783e build passed all thirty gates, including the synthetic
private-file test. One fresh Case13 reported private-record availability and
then preserved the same strict mapping refusal. Its outer Job ended empty and
the failed fixture was retained. Separately reviewed read-only inspections later
validated the complete protected record and emitted only closed metadata. The
returned native base string differs from the frozen private caller base.
Exact `Packages` and `AC`, nonempty profile and the existing 128-unit bound
passed; the profile failed the probe's ASCII-only component predicate. These
are independent comparison and grammar failures. No offending character or
returned string was disclosed, and no new base or component was admitted.
A further predicate-only inspection passed every proposed ordinary-component
check while preserving those earlier failures. The changed mapper below built,
but its first native boundary attempt refused at a private directory open.
It does not qualify the boundary child.
See [the actual result](manual-results.md#private-record-reported-available-boundary-still-refuses).

## Literal DOS application and held-image gate

The Windows literal overlay now selects an ordinary DOS `lpApplicationName`
from the held executable for compatibility. The separately recorded direct
control accepted that spelling and refused the GUID/GLOBALROOT spellings;
that uncontained observation does not qualify this SDK/PSEC launch path.
Literal argv remains unchanged. A pathname selects the image to create, but
cannot authorize it: after suspended creation and Job assignment, the overlay
requires `NtQueryInformationProcess(ProcessImageFileMapping, 44)` to match the
retained process image against the already held executable file HANDLE before
`ResumeThread`. The held leaf additionally requests execute access, with no
write/delete sharing. A nonzero status refuses and attempts termination and
bounded waits for the owned child, reporting any cleanup failure. There is no
name-reopen, NULL-application or runtime fallback.
Legacy script launch behavior, PSEC attachment and UI/network/filesystem
restrictions remain unchanged.

This native query is documented by
[NtDoc's original research](https://github.com/m417z/ntdoc/blob/main/descriptions/processinfoclass.md#processimagefilemapping-44)
and [the phnt declarations](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h).
It is not a Microsoft-supported compatibility promise. Only exact status zero
permits resume; an unavailable or unsupported query refuses. The pure ordering
test covers zero, informational, warning and failing statuses. A separate
read-only Rust test compares the current process with its held image, a
byte-identical fresh copy with a different full file identity, and an unrelated
regular file. It creates no child and never executes the copy. Exact admission
requires both new tests: fourteen SDK tests normally, fifteen for the distinct
uncontained control, with two synthetic file-fixture tests and one read-only
image-mapping query recorded. The fifth control overlay still changes only its
explicitly selected PSEC attribute plan and cannot be admitted as a contained
artifact.

The equivalent Go current-process query passed once on the local Windows host
with the identical-copy negative included. The reviewed replacement build also
passed the Rust read-only query and exact-zero ordering tests. One fresh native
PSEC run then passed the fixed signed Claude Code 2.1.292 `--version` case: exit
zero, exact version stdout, empty child stderr, signaled retained direct handle,
removed owned fixture and empty outer Job. This is a version smoke only; the
eight private values were requested, while Claude's realized environment,
filesystem/network boundaries, authentication, models, hooks, terminal and
customer provider remain unqualified. See the exact build and result pins in
[manual results](manual-results.md#native-psec-claude-version-smoke-passes-after-dos-image-binding).

## Current native environment binding

The `standalone_std_boundary_native_identity_environment` variant follows the
separately recorded Case07 lexical observations. Earlier native attempts
refused before the boundary assertions and remain recorded. Case16 later passed
the native environment and fixed boundary canaries after the private fixture
setup correction; its saved-output parser correction is recorded below. The
separate Claude result remains a version smoke only. This variant changes no
filesystem grant, network/UI restriction, SDK fallback,
host ACL, profile registration or production provider. Existing argv, exit23,
timeout and loader payload behavior remains unchanged.

A fourth overlay, `patches/mxc-windows-process-identity.patch`, adds an owned
read/query+synchronize duplicate from the SDK's actual retained native
CreateProcess handle. BaseContainer supplies that duplicate; other backends
default to Unsupported, and a warning wrapper only delegates the same native
object. The parent never reopens an integer PID. It queries TokenAppContainerSid
from that same duplicate, bounds and validates the returned SID buffer, then
uses GetAppContainerFolderPath. The capability's source-only upstream
[proposal](https://github.com/microsoft/mxc/pull/1524) is separate from this
contributor overlay and its qualification. No child environment observation
supplies an expectation.

The changed mapper also obtains TokenUser from that same held child token and
requires exact validated SID equality with the caller's process token. Both
opens request only TOKEN_QUERY; thread impersonation refuses. It calls
[GetUserProfileDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getuserprofiledirectoryw)
with that same child token, using a fixed bounded result buffer. The native
folder must match that independently queried OS root plus the explicit default
`AppData\Local\Packages\<one safe component>\AC` branch exactly. Redirected or
other bases refuse. The caller's known-folder query must independently equal
its frozen controlled startup LOCALAPPDATA; it is not required to equal the OS
profile base and does not authorize that base. Neither source path is opened.

Only the same-SID component transfers into the held fresh fixture. It remains
at most 128 UTF16 units and must be one well-formed ordinary Windows component.
Traversal, separators, ADS, controls, reserved punctuation, trailing dot/space
and DOS device/meta names refuse. Other literal Unicode, internal spaces and
ordinary punctuation are preserved without normalization or expansion. The
same predicate validates both the native suffix and the rebased private frame.
The new pure component test runs in parent and child, and a separate pure test
checks native profile-buffer count/NUL bounds. The corrected mapper artifact
passed thirty-three selected gates. The refusal-diagnostic build then passed
thirty-four. The new exclusive private-subtree filesystem gate requires
thirty-five for the boundary; ordinary DLL/Claude remain twenty-eight and the
separate control twenty-nine. Old test inventories cannot admit these changed
sources.

A missing native identity, different User SID, API failure, unexpected caller
thread identity, mismatched default prefix, missing private directory or unsafe
component refuses before the fixed child can perform a mutation. The parent
opens the existing `home/AppData/Local` through held-relative custody. After
all token/profile mapping checks and a full root-bound branch revalidation, it
exclusively creates only `Packages/<validated component>/AC/Temp` under that held
private Local directory. Every new directory receives the protected owner and
SYSTEM DACL atomically; the same exact DACL verifier used by the private-record
writer validates it before use. Existing directories, files and links at those
four new names refuse rather than being adopted. All seven directory handles
remain pinned against rename until the case ends. The normal owned-fixture
cleanup removes the new subtree only after those handles close. No native OS
profile directory is opened or created; no existing ACL is changed.

Case14's generic directory refusal did not distinguish fixture ancestry from
the mapped branch. The reviewed thirty-four-test diagnostic artifact then ran
Case15 once: its exact refusal was `gate=private_environment component_index=3
ntstatus=0xc0000034`, identifying absent `Packages` under the held private Local
directory. The initial fixture setup creates only through Local. Its literal
argv case passed and its outer Job ended empty. This is a private fixture setup
omission; the source fix above preserves the native mapping checks, filesystem
grants and no-reparse rules. A fresh build and native boundary attempt remain
required before it is qualified. The new synthetic filesystem test covers
exclusive creation, private DACLs, rename custody/release, collisions, links and
rejection of a forged branch before creation. See
[Case15 evidence](manual-results.md#case15-identifies-missing-private-packages-fixture-directory).

The reviewed b95 build passed all thirty-five selected gates. ROOT then ran
Case16 once: native environment binding, filesystem and loopback canaries,
exit23, timeout, retained handle waits and owned fixture removal all passed;
the outer Job was empty. The original outer result remained false because its
parser still expected only the former boundary stdout marker and no child
stderr. The fixed child also emitted its native-environment marker and existing
closed canonicalization diagnostic. A separately reviewed data-only assessment
of that unchanged saved receipt accepted the corrected exact contract and
refused five negative mutations, adding zero native executions. The diagnostic
still observed DOS canonicalization access denial while NT final-path and seal
reads succeeded; this is a compatibility observation, not authorization. See
[Case16 evidence](manual-results.md#case16-native-boundary-canaries-pass-saved-parser-contract-corrected).
This qualifies these fixed synthetic checks on the recorded host and policy;
it supplies no Windows peer/bridge activation, terminal, broker, agent hook,
authentication/model session, general resource limit or customer qualification.

The resulting private expectation must match the fresh fixture's exact
`home\AppData\Local\Packages\<one bounded native-profile component>\AC`
shape. Only `Temp` is appended to obtain TEMP/TMP. Before native child creation,
the parent pins the original fixture directory through a direct NT device
volume and held-relative directory opens. After the native folder query, it
extends that same root capability to each profile directory and Temp; it never
rebinds authority to a DOS, GLOBALROOT or observed child path. Directory handles
request list/attributes/synchronize access (plus read-control for new-directory
DACL verification), refuse reparse points and deny delete
sharing while the case runs. List access makes directory-name rename custody
effective; attribute-only opens do not establish that property. Directory read
and write sharing remain enabled so normal content operations can proceed.
These pins do not make directory contents or metadata immutable. Executable
image handles separately retain read-only access without write/delete sharing.
The effective drive must equal its queried global
mount, the target must be a local HarddiskVolume with NTFS, and mapping samples
must remain unchanged. These checks do not claim qualification against arbitrary
same-user concurrent namespace changes. No existing path or namespace is repaired.

The parent sends three bounded UTF16 paths on the owned stdin pipe and closes
it. The distinct fixed `boundary-native-env` selector requires the exact frame
and EOF before its first environment assertion or write. It compares
LOCALAPPDATA/TEMP/TMP against those native-derived values, using only the
previously admitted exact optional verbatim-disk-prefix difference. HOME,
USERPROFILE and APPDATA must still equal their original fixture locations.
The old `boundary` selector retains its original strict expectations for the
separate direct control; the parent never falls back to it. The std-only child
imports no AXIS/SDK/native identity module or additional native API.

The locked build records the fourth patch, every exact changed SDK source,
the two original source modules and exact pure parser/spelling/buffer tests plus one
new SDK Unsupported-default test. These tests perform no native token/profile
query, process creation or PSEC execution. A separate native filesystem-only
regression proves attribute-only rename remains possible, actual held directory
custody rejects rename, sibling content writes remain possible, and rename works
after close. Its exact non-ignored result is required in build provenance. The
existing SDK synthetic image-custody test now also requires an actual ancestor
rename refusal and release. Neither native fixture test launches a process or
changes an ACL. New source, compiler/imports, artifact
identity and one fresh native run require independent review. Old Case07 and
direct-control results do not qualify this new variant.

The relevant primary API contracts are Microsoft's
[GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
and [GetAppContainerFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getappcontainerfolderpath).
The latter may resolve a path for the parent's user identity, so a successful
API result alone cannot authorize a host profile outside the fixed fixture.

This separate, headless experiment investigates AXIS policy validation with
the current typed MXC SDK. It does not activate a DefenseClaw provider, replace
the old paired executor, or certify a customer runtime. No WSL, host fallback,
credentials, Claude, model, hook, proxy, privileged helper or service is used.

Exact source inputs are AXIS
`fb5fd5f0f9377c2ccb30d7e027a36373de0d037c` and Microsoft MXC
`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`, SDK 1.0.1. AXIS contributes its
public policy parser and validation. The runner constructs only a fixed
hard-filesystem/block-network policy, then explicitly translates its accepted
filesystem and timeout fields into typed MXC 1.0.0 authoring types. This is
not a general AXIS policy translator, and it does not forward the old AXIS
0.6.0-alpha wire contract or claim LPAC token equivalence. The fixed AXIS policy
uses `process.identity: backend_default` and allows child processes; no isolated
identity intent or resource limit is silently dropped.

The first locked native run (build `215f3e98936b34279e31670a4fed14d5f47542c2`)
failed before its payload marker with `0xC0000142` (`DLL_INIT_FAILED`). Its outer
Job was empty afterward and the failed fixture was retained. The SDK-bearing
self-payload imports Shell32/COM and other libraries; a Win32k/import interaction
is a hypothesis, not an established cause. No UI restriction or filesystem
grant is relaxed to make the experiment pass.

The distinct `separate_std_loader_diagnostic` artifact includes a second binary,
`defenseclaw-axis-windows-psec-loader-child.exe`, whose source uses only Rust std
and has no AXIS/SDK references. The parent requires the fixed `--loader-only`
selector and computes that exact sibling path. It uses the same hard/block
policy and native admission, then requires the unique marker and typed exit23.
Its four checks cover that marker, exit, retained direct handle and owned fixture
removal only; it never reports the nine boundary checks. Both image hashes and
the diagnostic variant must be verified, and the child's imports inspected,
before any separately reviewed native execution.

That separate diagnostic passed once on the native host from build
`a96ef846d7c75987c9266aa96f928c8915dbcc3d`: the std-only child printed its marker,
returned typed exit 23, and its retained direct handle was signaled. The outer
custody Job was empty and no owned fixture remained. This demonstrates startup
under the unchanged policy; it does not establish the precise DLL failure cause
or qualify the original boundary checks.

The next source-only variant, `standalone_std_boundary_literal_argv`, moves
the boundary, exit and timeout payload into a third, std-only binary. It also
tests empty arguments, spaces, quotes, trailing backslashes, Unicode and shell
metacharacters as literal arguments. These new sources have not been compiled
or executed. The previously reviewed loader live helpers intentionally reject
this different variant until separately updated and reviewed.

## Reviewed SDK overlay

`patches/mxc-strict-windows-psec.patch` introduces a Windows-only public
`v1::spawn_windows_psec` entry point. It requires explicit ProcessContainer,
forces DACL mutation off, and calls the native `BaseContainerRunner::new`
through the SDK's existing logger/telemetry wrapper. Native policy and host
serviceability validation still run before creation. The fallback dispatcher
is never called. Missing native support or a policy requiring unavailable
PSEC capabilities is an error. No host DACL/BFS fallback is permitted.
This contributor entry point also refuses ingress/host-loopback allowances,
egress allowances, proxy configuration, added capabilities and denial capture
before constructing the backend. Only the explicit fixed offline posture is
admitted; later proxy work requires its own capability and PSEC-version checks.

The next build composes that strict overlay, the shared reviewed
`test/e2e/axis/patches/mxc-literal-argv.patch` (SHA256
`7117afc3c7ae28345757c364518b7b9120a7dd8e6b844403b06fe05403e4a76d`),
then `patches/mxc-windows-literal-argv.patch`. The last overlay adds only a
strict `v1::spawn_windows_psec_argv` route. It retains the native admission and
fallback refusal, requires an empty legacy command, passes an explicit absolute
application name to `CreateProcessW`, and encodes bounded UTF-16 arguments using
Windows C/Rust quoting rules. It starts no shell. The generic Unix literal-argv
dispatcher continues to reject ProcessContainer. Native pipes, Job setup,
filesystem policy, UI restrictions and network policy remain unchanged.
The new route admits only unambiguous local drive paths on fixed volumes.
It refuses UNC/device/ADS paths, redirected or SUBST drives, and reparse points.
It opens each path component without following reparse points, holds directory
names against rename and the image against writes/deletion through process
creation, and uses the image handle's volume
GUID path as the explicit application. The host still needs its own reviewed
digest/identity admission before this contributor seam can become a general
customer launcher.

The patch also makes a failure to confirm an empty owned Job an error, instead
of a warning followed by successful teardown. Native PSEC owns a security
environment handle, closes it after process termination, and does not create
the legacy profile/tracking resources observed in the old paired experiment.
This source behavior still requires actual host verification. An error is a
failed qualification, never evidence of completed containment or cleanup.

The first prototype uses piped stdio only. An inherited-console SDK option
and process-local Ctrl-C callback require a later separately reviewed change
with all three console handles validated. Windows ProcessContainer's advertised
typed PTY function currently refuses caller-controlled PTY creation; this
headless experiment makes no terminal-support claim.

## Build and lock gate

Use an already-provisioned Windows x86_64 build host, Rust 1.95.0, Python 3,
Git and the native MSVC/Windows SDK prerequisites required by MXC. Cargo
downloads dependency sources during this explicit contributor build. The
helper never installs prerequisites or runs its resulting probe. Windows
Server 2022 CI is a compilation host only; no PSEC live run is permitted there.

Prepare a fresh staging directory containing this subtree's tracked files
and exact clean child checkouts. Stage the shared literal-argv patch from its
exact repository Git bytes into `patches/mxc-literal-argv.patch`; it is an
explicit additional build input rather than a duplicate tracked patch:

```text
mxc-v1/
  Cargo.toml
  prepare_build.py
  src/
  patches/
  axis-source/       # exact AXIS commit
  mxc-source/        # exact current MXC commit
```

Run `python prepare_build.py generate-lock`. It verifies source identities,
applies the four reviewed MXC overlays in order, generates a combined lock, builds with
`--locked`, compiles probe tests, runs the exact selected pure environment and DLL-protocol tests, and packages the
four binaries, source, patches, licenses, locks, compiler identity and SHA256
provenance. It fingerprints the 13 modified and three added SDK files before
and after the build; an unstaged Git diff alone cannot detect changes to added
files. No dependency has been added for the separate std-only child.
The pure Python build-helper gates run with:

```powershell
python -m unittest discover -s test/e2e/axis/windows/mxc-v1 -p test_prepare_build.py
```

Review and commit the generated combined `Cargo.lock`, then prepare fresh
source checkouts and run `python prepare_build.py build-locked`. A missing or
changed lock is a refusal. Neither upstream lock is a substitute for this
combined lock. No live execution is allowed before the reviewed locked rebuild
and independent source/artifact verification.

The committed combined lock is SHA256
`3b29ecb06dd2a81266c84712f8d6e088605290f386e87498bb7a7472a005af69`
(223 packages). Review matched 150 registry checksums to the two upstream
locks and checked the other 70 versions against the official crates.io index
for checksum, non-yanked status and Rust 1.95 compatibility. The only path
packages are this fixed probe, AXIS core 0.3.5 and MXC SDK 1.0.1. This lock
review is independent of the still-pending native build and live gates.
The disposable Windows build initializes its installed Visual Studio x64
developer environment and verifies that `link.exe` belongs to that exact
installation; Git for Windows' Unix linker is not a compatible MSVC linker.

## Fixed live scope, after review

The probe accepts no caller command, path, policy or environment flags. Its only
optional operator selectors are the fixed `--loader-only` and `--dll-startup-only` diagnostics. Its
standalone child accepts only fixed argv, boundary, exit-23 and timeout cases. It
clears the supervisor environment before invoking SDK code or creating threads;
the child receives only explicit system/private state entries with environment
inheritance off. A harmless parent-only `DC_AXIS_INHERIT_CANARY=fixed-public`
must be absent in the child, so inherited safe environment cannot pass silently.
CWD, HOME and temporary paths are private synthetic fixtures.
A 20-second outer watchdog bounds the contributor process, while MXC owns the
configured per-child timeout. It is not a production supervisor contract.

The boundary case tests an allowed write, a read-only canary and a synthetic
outside canary beneath a granted writable parent and an explicit deny on the
nested file. The reviewed SDK seam verifies all explicit grants and denies
survive typed normalization before construction; same-string overlap pruning
cannot make this a default-deny-only observation. Access-denied errors
are required; an unrelated failure is not accepted. Four task-owned IPv4/IPv6
TCP/UDP listeners receive positive host controls before the child attempts its
connections. UDP sends may succeed locally, so the host receivers must observe
no contained delivery. This covers those loopback endpoints only, through the
bounded receiver window; Internet/DNS and proxy enforcement remain unqualified.

The SDK's actual native entry point supplies the PSEC evidence; the child does
not assert `TokenIsAppContainer`, because a current PSEC token is a different
contract from the old BaseContainer experiment. The supervisor retains a
read/query handle duplicated from the SDK's retained direct-child process handle before wait,
checks it becomes signaled, and never signals an inferred PID. General process
tree and parent-death qualification require additional controlled live cases.
The verified owned fixture path is removed only after handles have stopped.
Errors retain the fixture for inspection, including an SDK Job-empty failure;
the retained direct-child handle closes through RAII even on an early pipe error.

This host's read-only query on 2026-10-18 reported PSEC major 1/minor 0 and
support flags `0x3`: native filesystem deny is present, enumeration and ingress
capabilities are absent. Runtime validation remains authoritative. Denial
capture, ingress allowances, enumeration-only grants and proxy identity modes
are outside this prototype; it must refuse requests it cannot represent.

The fixed boundary child records its DOS-based Rust `canonicalize` result but
uses its explicit current directory for the canary operations. A native run on
this host opened that directory with access 0, obtained its NT final path and
read its fixed seal, while both normalized and opened DOS final-path queries
returned Access denied. The fixture shape, exact private environment and seal
checks remain mandatory. This preserves the DOS-query compatibility limitation
without confusing it with denial of a granted file operation; no grant or SDK
policy is broadened. A passing canary run would not qualify applications that
require the denied query.

The fixed private-environment assertion accepts only the optional `\\?\`
prefix on an otherwise byte-for-byte identical local drive path. The parent
canonicalizes the fixture, while Windows can return its current directory
without that prefix. Case folding, slash changes, dot components, other drives,
UNC/device paths and a different home remain refused. A selected pure Rust
test exercises these cases during the build; it performs no sandbox operation.

## Separate fixed DLL initialization diagnostic: source only

The new four-PE artifact has variant
`standalone_std_fixed_dll_startup_diagnostic` and scope
`fixed_windows_native_psec_dll_startup_diagnostic`. It requires a new independently
verified receipt. The three-PE native-environment receipt retains its own exact
variant and cannot authorize this diagnostic. No new artifact or native run has
qualified this source addition.

`run_live.py --dll-startup-only` selects exactly three fresh native PSEC children,
one each for `user32.dll`, `gdi32.dll` and `shell32.dll`. The fourth PE is a separate
std-only program using direct Kernel32 FFI. It accepts only three literal
selectors, flushes a fixed START marker, then calls `LoadLibraryExW` with
`LOAD_LIBRARY_SEARCH_SYSTEM32`. It reports either a loaded marker or the immediate
numeric `GetLastError` value. It does not call an exported UI function or any SDK,
profile, token, network or filesystem mutation API. It disables error dialogs in
its own process. Its initial PE import inventory must be independently checked
before execution to ensure the diagnostic itself does not import a target DLL.

All existing strict PSEC, filesystem, network and UI settings remain unchanged.
Each child has a five-second MXC timeout; the parent retains its twenty-second
watchdog, the owned-Job wrapper its thirty-second deadline, and the outer Python
driver its existing bounded wait. Every case's raw start/return/exit/timeout
observation is retained. Abnormal exit, timeout, missing return, malformed output,
unsignaled retained handle or cleanup failure fails the diagnostic. A normal
returned DLL error may complete a measurement, but the final
`dll_initialization_all_succeeded` value is false; a zero wrapper exit alone is
not a DLL compatibility claim. The pure Rust protocol tests never load a DLL.

The original SDK-bearing self-payload has 37 distinct case-insensitive imported
DLL names; the separate std-only boundary child has ten. Both import VCRuntime,
so its presence alone does not explain the original startup failure. The retained
SDK image imports `SHGetKnownFolderPath` from Shell32; this host's inspected
Shell32 image imports User32 and GDI32. This is a dependency hypothesis until
the new fixed diagnostic actually observes each load. Microsoft documents
[the Win32k policy](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_system_call_disable_policy)
as denying GUI system calls, and
[LoadLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw)
as calling DLL process-attach initialization. The
[System32-only load flag](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
excludes normal CWD/PATH searches for the module and its dependencies.

Enabling Win32k is not implemented by this diagnostic. An explicit future
compatibility experiment would have to preserve all PSEC UI restrictions and
apply/verify matching Job UI restrictions before resuming a child. Those
[restrictions](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions)
do not themselves establish a private window station or desktop. The pinned
runner currently leaves `STARTUPINFO.lpDesktop` null. A private noninteractive
station/desktop would need separate reviewed object ownership and access tests;
[CreateWindowStation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowstationw)
also restricts named creation to administrators. No UI policy, window station,
desktop, existing ACL or host namespace is changed here.


## Fixed signed Claude version slice

The separate `claude-version-only` slice has two retained native creation refusals
described in [manual results](manual-results.md). It tests
only the fixed, independently reviewed Anthropic Claude Code 2.1.292 Windows
image with literal `--version`, closed stdin, a ten-second native deadline,
eight explicitly supplied private environment values, offline policy and the
unchanged Win32k/UI restrictions. It provides no authentication, model, hook,
terminal, workspace or customer-provider qualification. A prior boundary or DLL
receipt cannot authorize this slice.
The eight values are requested configuration; this version-only command does
not observe Claude's realized environment or pass the boundary child's native
environment frame handshake.

`prepare_build.py build-locked --probe-slice claude-version-only` selects its
separate `standalone_std_fixed_signed_claude_version` artifact contract. Omitting
`--probe-slice` retains `dll-startup-only`. Both choices build the same four
bounded CI executables and run the existing pure and filesystem-only admission
gates; neither executes the probe, PSEC or Claude. The signed local Claude image
is never uploaded as a CI-built executable, and the 64 MiB CI-image bound remains
unchanged.

The separately reviewed local-image receipt has schema
`fixed-reviewed-anthropic-claude-version-v1`, a pinned receipt SHA256, exact
254858400-byte image identity
`eb95bb65955f8b1702e800815f9a2c0388a5de0f196c354c7ee1dd5cb9a2ba23`,
product version `2.1.292.0`, independently checked Valid Anthropic signature facts,
and false execution/production-qualification flags. Receipt fields cannot admit
another program. Signature facts describe an independent review; the source-
pinned image SHA256 and size supply executable authority. There is no payload
hash override, download, arbitrary executable selector or arbitrary argv.

The host wrapper is built from the two reviewed source files together:
`go build -o <fresh-private-output> custody_windows.go claude_image_windows.go`.
It validates the separate CI receipt and local-image receipt, retains the image
and ordinary mounted NTFS ancestors, then copies only that verified supervisor
and the fixed Claude bytes into a new owner-private held bin. Images deny
write/delete sharing; list-access directory pins deny rename while allowing
ordinary contents/metadata to remain mutable. Held-root creation, SHA256 copy
checks, retained image handles and the existing pre-resume owned Job stay in
force through termination. No whole host HOME or credentials are granted.

After separate source, artifact, signature and host-wrapper review, the closed
`run_live.py --claude-version-only` case additionally requires
`--local-image-receipt` and `--local-image-receipt-sha256`. Acceptance requires
exact version output, exit zero, empty stderr, the held direct process signal,
empty outer Job and owned-fixture cleanup. Timeouts, extra output, wrong images,
receipt/mode mismatches and cleanup failures remain failures. No native run is
authorized by this documentation or by a build-only artifact.

The SDK overlay diagnostic keeps the same launch policy and literal argv. One
changed-source build and attempt are recorded in [manual results](manual-results.md).
On native creation refusal it copies `GetLastError` and
`RtlGetLastNtStatus` immediately after the raw BOOL return, before error wrappers
or formatting can disturb thread-local status. It emits only those numbers and
capped application/command/environment/cwd UTF-16 lengths plus argv/environment
entry counts. UTF-16 lengths include terminating NULs. Counts do not contain
paths, arguments or environment values and cannot grant authority. Legacy
command-string launch behavior is unchanged. The last NT status is a sampled
thread value, not proof of which parameter or native operation caused failure.
A separate exact pure SDK test
checks capture order, numeric formatting and count bounds without launching a
process. The observed status samples do not establish a cause or authorize an
unchanged retry, weaker policy, or production runtime activation.


## Fixed uncontained native-create discriminator

`claude-create-control-only` is a separate contributor build/receipt and closed
runtime selector. Its separately reviewed build and one native attempt are
recorded in [manual results](manual-results.md). It asks whether the same fixed
Claude 2.1.292 `--version` creation inputs work when the process security-
environment attribute is omitted. It is **uncontained**, supplies no PSEC
filesystem/network/Win32k enforcement, and cannot qualify a sandbox or act as a
runtime fallback. No existing Claude, DLL or boundary receipt admits this mode.

The dependency-free `fixed-claude-create-control` Cargo feature binds the binary
to this one selector before any fixture or API call. Ordinary binaries refuse
the control selector; the control binary refuses every ordinary selector.
Only this build slice applies `patches/mxc-fixed-claude-create-control.patch`
after the four existing overlays. The original recorded control build used
sixteen normal SDK fingerprints and twelve SDK tests, with seventeen control
fingerprints and a thirteenth pure comparison/admission test. The replacement
DOS/image-binding source adds the two gates described above; no dependency,
upstream lock, CI executable-size limit or local-image authority is changed.

The SDK still constructs and owns the requested strict PSEC object and the
normal startup attribute list, without executing that reference plan. A second
list carries only the exact same three inherited pipe handles. Before its one
raw `CreateProcessW` call, the control compares complete bounded UTF-16
application, mutable command-line, environment and cwd buffers byte for byte,
creation flags, handle inheritance, all `STARTUPINFOW` fields individually
(excluding padding), and the actual three handle values. It publishes only a
fixed equality boolean and attribute counts, never the private values. The
reference is constructed in this attempt; it is not an equality assertion about
the differently named fixtures retained from earlier attempts.

In the recorded control attempt, the selected call retained the held-image
volume-GUID application spelling,
separately quoted original program/`--version`, eight explicit private values,
NULL process/thread security attributes, `CREATE_SUSPENDED`, `CREATE_NO_WINDOW`,
`CREATE_UNICODE_ENVIRONMENT`, `EXTENDED_STARTUPINFO_PRESENT`, cwd and pipe setup.
Only the PSEC attachment and its attribute-list storage/count differ between the
two constructed plans. The fixed patch refuses legacy command strings, other
program basenames, other arguments, inherited/default environments, non-capture
stdio, non-eight-name environments and capture-denial requests before creation.
The existing independently pinned local Claude image and all retained native
image/ancestor handles remain required. There is no arbitrary command/path/hash
selector in this control.

The SDK Job must receive the suspended process before resume; the independent
outer Go kill-on-close Job and retained direct handles remain in force. Stdin
is closed, native wait is ten seconds, the Rust supervisor is twenty seconds,
the Go wrapper waits thirty seconds, and the Python owner waits fifty-five
seconds. Outer deadlines are also required around prelaunch host I/O; these
waits do not independently bound filesystem syscalls. A result needs the exact
equality record, exact version stdout, empty Claude stderr, exit zero, direct
handle signal, empty outer Job and owned fixture cleanup. Success would isolate
a difference in this downstream call path; it would not identify the failing
PSEC parameter, prove an upstream defect, observe Claude's realized environment,
or qualify authentication, models, hooks, terminal or production use.

Source, fresh CI artifact, host wrapper and one-shot recipe received independent
review before that one native attempt. The control emitted exact constructed-
input equality, then failed native creation with Win32 87 before any Claude
start was observed. PSEC attachment was not necessary for this refusal; the PSEC
object was still constructed, and the cause remains unresolved. This text
authorizes no execution or retry of an existing artifact.
