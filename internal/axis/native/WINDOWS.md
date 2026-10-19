<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private Windows native peer source contract

This source connects the existing shared wire, Conversation and Owner to Windows
raw-overlapped transport, inherited-capability bootstrap and native PSEC. It is
source only: no Rust typecheck, unit test, PSEC workload or peer launch has run.
There is no customer activation or default selection.

The platform modules in `src/` supply the Windows entry point, engine, raw IO
and capability bootstrap. Cargo.toml moves
only the existing axis-sandbox and libc dependencies behind the Linux target;
all versions and Cargo.lock remain unchanged. Linux custody/namespace/engine and
transport remain selected unchanged; Linux main is nested under cfg without a
behavior change. Owner changes only its Pipe alias, wait-interest projection
and Linux-only tests. Conversation, frames, admission and lifecycle stay shared.

The Windows main accepts exactly the fixed argv0, rejects a nonempty parent
environment, adopts the exact three inherited overlapped standard handles,
consumes the bounded Go 56+40 capability prefix before any JSON, and gives the
capabilities to WindowsEngine. All inherited asset/pipe flags are cleared after
adoption. No path/argv/environment option, PID lookup or fallback is added.

The prefix still matches the reviewed Go encoder: 56-byte header; up to 514
40-byte records ordered payload/CWD/read/write; exact full FileID and local NTFS
metadata; unique explicit HANDLEs; digest correlation to the validated Prepare.
Actual object access masks are additionally checked by the SDK adapter.

Each raw IO operation owns stable `Box<UnsafeCell<OVERLAPPED>>` storage, a
bounded read-cell or immutable write buffer and a manual-reset event until
terminal observation. OVERLAPPED.hEvent is event|1
so inherited Go IOCP association cannot receive a foreign completion packet.
Wait/close use the separate untagged event. CancelIoEx is only a request; pending
storage is retained until GetOverlappedResult(wait=false) observes completion.
Unknown completion/cleanup or exhausted cancellation reserve fails this peer
with fixed ExitProcess(70), retaining live storage until OS teardown. The Go
Session's independent owned Job remains required on every error. No wait=true,
reader thread, std::io wrapper on an overlapped handle or unbounded join exists.

Workload pairs use an owner+SYSTEM protected descriptor, first-instance local
named pipes, exact current server/client process identities and a fresh opaque
UUID name. Parent endpoints are overlapped; child endpoints are synchronous.
Only child endpoints are made inheritable. The SDK validates three distinct
PIPE handles, inheritance, synchronous mode and directional rights before PSEC
launch. Ordinary workload stdio never receives an overlapped endpoint.

## SDK source overlay

[`patches/mxc-owned-windows-psec.patch`](patches/mxc-owned-windows-psec.patch)
applies after the existing four reviewed Windows overlays at fda29ac6; the
uncontained Claude-control patch is excluded. The exact final SDK fingerprint
set has eighteen files. The overlay modifies BaseContainerRunner and v1 exports, and adds
two owned-input/security source files. Existing API/capture paths pass no owned
stdio override and retain their semantics.

PreparedOwnedWindowsPsec consumes payload/CWD/read/write Files rather than
reopening caller paths. The host must retain its admitted immutable private
image COPY and section/view through native completion. A held original alone
is not that contract. The host must also retain no-delete-share ancestor
leases above CWD and around the sealed payload until native completion; Files
alone do not establish DOS name stability. Actual GrantedAccess must provide
the role's required
rights, while DELETE/WRITE_DAC/WRITE_OWNER, readonly data/EA/attribute writes
and every unrecognized right are refused. The exact held payload is the expected class44 comparison object;
its held-derived ordinary DOS spelling selects CreateProcess, with strict image
mapping after Job assignment and before Resume unchanged.

The initial filesystem floor is deliberately narrow: CWD is one protected
current-user+SYSTEM private root; every plan read/write grant is exactly that
root or a descendant whose actual held DOS spelling equals the plan. Traversal
is root-relative with no-follow, read-only opens, no delete sharing and full
FileID checks, retaining each opened ancestor. The only additional policy read
object is the exact sealed payload itself. CWD receives its own same-object NT
empty-name, no-delete-share self pin even when no descendant is granted. This
pins the supplied root, not its parents or the sealed image's ancestors. Other
host grant layouts refuse.
PSEC still receives serialized path spellings. These pins and private scope do
not establish a universal kernel object-binding guarantee for policy paths
under concurrent host namespace mutation; no such qualification is claimed.

The typed owned-PSEC process adapter uses the existing BaseChild/UiJobObject,
not another launcher or controller. Stop signals the exact Job/root without a
blocking wait. Poll uses zero-time root observation and Job accounting; after
root exit it stops remaining descendants and reports terminal only after
active0, then releases the PSEC handle. Capture/proxy/preserved-policy modes are
refused. Shared Owner alone handles input/output/deadline/cancel/destroy.

## Build and validation boundary

This source revision has received static source review and Rustfmt1.95
edition2024 parse/check. Compilation and native peer behavior remain unverified.
The dedicated Windows build helper stages exact Git bytes and pinned upstream
commits, applies only the four Windows overlays plus the owned-input overlay,
and records locks, source fingerprints, PE data and the exact inert test logs.
The Linux builder retains these Windows sources, helper, document and overlay
as data; its Linux overlay set and nineteen native test roots remain unchanged.

Before any peer execution: hosted MSVC build with exact Git/lock/overlay/test
provenance; independent artifact review; and one separately reviewed fixed
contributor invocation under Go Job custody.
Hosted tests below create no child process or PSEC and execute no copied image.

Peer exact roots (12 total including the four shared protocol roots):
- conversation::tests::prepared_handle_cannot_admit_duplicate_launch
- conversation::tests::late_controls_do_not_reopen_exited_session_and_destroy_is_separate
- wire::tests::independent_go_hash_vector_and_no_read_ahead
- wire::tests::ambiguous_json_and_null_poison_the_decoder
- windows_io::tests::read_buffer_storage_stays_stable_and_observation_follows_completion
- windows_io::tests::completion_never_treats_cancel_request_as_terminal_proof
- windows_io::tests::overlapped_event_suppresses_foreign_iocp_without_changing_owned_handle
- windows_io::tests::wait_set_is_bounded_unique_and_contains_no_pseudo_handle
- windows_bootstrap::tests::prefix_only_pure_roundtrip_and_all_boundaries
- windows_io::workload_tests::native_owned_workload_pair_transfers_and_cancels_without_a_child
- windows_io::workload_tests::native_sync_workload_end_is_never_adopted_as_overlapped
- windows::tests::native_sdk_owned_stdio_accepts_only_the_fixed_sync_child_endpoints

SDK exact roots:
- owned_windows_psec::tests::owned_access_requires_exact_role_rights_without_host_mutation_rights
- owned_windows_psec::stdio_tests::stdio_requires_synchronous_mode_and_direction_before_native_launch
- owned_windows_psec::native_access_tests::native_current_image_read_handle_cannot_be_promoted_to_execute_or_write
- owned_windows_psec::native_access_tests::native_relative_grant_pin_requires_the_exact_held_file_object

Primary contracts: Microsoft ReadFile, GetOverlappedResult, CancelIoEx,
GetQueuedCompletionStatus (event low-bit suppression), ConnectNamedPipe
(ERROR_PIPE_CONNECTED and non-null OVERLAPPED), UuidCreate, NtQueryObject public
basic GrantedAccess layout, UpdateProcThreadAttribute HANDLE_LIST; exact Go1.26
nonblocking mode and external-IOCP handling; pinned fda BaseContainer/UiJobObject.
