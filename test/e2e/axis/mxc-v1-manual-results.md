# Linux AXIS/MXC V1 contributor experiment results

The fixed native Linux offline experiment passed with MXC V1 Bubblewrap and
AXIS child guards. This contributor result does not qualify or enable AXIS
in DefenseClaw, and does not certify `defenseclaw sandbox run claude` with AXIS.
The earlier
[Windows-hosted Linux experiments](manual-test-results.md) used a different
runtime route and are separate evidence.

## Platform and source identity

Recorded 2026-10-18 on native GitHub-hosted `ubuntu-24.04`, x86-64, as the
ordinary unprivileged runner account. All three live transcripts record kernel
`6.17.0-1022-azure` and Bubblewrap `0.9.0`. The contributor runner explicitly
selects the MXC V1 Bubblewrap backend and applies AXIS guards in its fixed
child; there is no backend fallback. This composes MXC's public SDK with AXIS
policy primitives, rather than certifying the existing AXIS sandbox lifecycle.

All builds below use Rust 1.95.0 and these reviewed source identities:

| Input | Exact identity |
| --- | --- |
| AXIS | [`fb5fd5f0f9377c2ccb30d7e027a36373de0d037c`](https://github.com/ROCm/axis/tree/fb5fd5f0f9377c2ccb30d7e027a36373de0d037c) |
| MXC | [`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`](https://github.com/microsoft/mxc/tree/fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2) |
| AXIS contributor export patch, SHA256 | `d5d01f621bddc52885f92fd4e017303cf08077c8bb86e4934b3589e4a4383af0` |
| Reviewed combined `Cargo.lock`, SHA256 | `d6556677c6decd2d5d786ca082ac2bcdb37fc92130d45b7002a7e8bffe2154db` |

The narrow AXIS export patch reuses its existing seccomp implementation for
the fixed offline child. No normal AXIS execution path is changed. The source,
patch, build helper and qualification limits are in the
[contributor runner](mxc-runner/README.md).

## Verified builds

Each build compiled with the reviewed combined lock and did not execute the
sandbox probe. Before each live run, independent review checked the exact
artifact inventory, all 14 file hashes, eight packaged source files against
the build commit, both upstream lockfiles and licenses, locked-build status,
toolchain and workflow attribution. The live workflow repeated strict artifact
verification against a clean checkout at the build commit before making the
probe executable.

| Build | DefenseClaw build commit | Binary SHA256 | `PROVENANCE.json` SHA256 |
| --- | --- | --- | --- |
| [39107869070](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39107869070) | `1d05670d42c8b28411b4c46d36d7575e73cde868` | `9287ebd975aaf551aee2fb6dda52f3b24bc262e7a8c695ee196af27a3b87ea70` | `0c219629b160cf53b8f0e0531edd2327361b1995d4e8d40927abf54659f679aa` |
| [39109408092, Linux job](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39109408092/job/117622089219) | `2362bcab78001bba29a5b06cb9d69b7a01769a01` | `82100a20d707692222b0db19536fa7007d1a0989973fbf60588d3d4cbdbbddf8` | `96c77ede6025b65db17fa3bb4a18aa587ca9c60ab85bbda6a5114070c3205804` |
| [39110212879, Linux job](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39110212879/job/117624528901) | `f8a9055cfe599fb4905f547ffb83f496143b6dfb` | `15403b3151d651b7c33d4de02f5060b22995cfbd49398ac49d58164536ba0a13` | `941d83834e8bd410c017670718f107c1904557e2d9de434e487c435e8f329789` |

The second build also passed a pure unit test for bounded, JSON-escaped fixed
child diagnostics. Its overall workflow failed in the separate macOS job;
the Linux build, formatting, diagnostic test and artifact upload passed.
The corrected fixture build passed formatting and all four pure helper tests,
including owner-only fixture creation and removal. Static artifact verification
passed before its separately pinned live execution.

## Live observations

| Attempt | Live workflow commit | Actual result | Interpretation |
| --- | --- | --- | --- |
| [39108735152](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39108735152) | `369dc52bd3b55d9500e7bf2a1e9631b1af56488a` | Exit **1** in the first fixed boundaries case; only the generic `fixed child wrote stderr` refusal was retained | Failed experiment. The original child error was discarded, so this run does not identify its cause or prove any boundary assertion. |
| [39109820667](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39109820667) | `7642f139643d66397a0b06933b85378930866d27` | Exit **1**; bounded child diagnostic reports `fixture ownership or mode differs`, outcome `Exited(1)` | Refused during fixture validation, before AXIS guard application and boundary assertions. |
| [39110683727](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39110683727), corrected owner-only fixture | `e1e5022322b2d906d7974099664a4375f6efd49e` | Exit **0** in 1.077 seconds; empty stderr; all 12 fixed checks present; Landlock ABI **7** | Passed this fixed offline composition experiment. No source change or guard downgrade followed the live result. |

Code inspection identified the fixture setup error: pinned `tempfile` 3.27.0
defaults directory permissions to `0777` masked by the process umask, normally
yielding `0755`, while the child correctly requires `0700`. The second
diagnostic did not print the actual numeric mode or owner, so `0755` is the
default-mode explanation rather than a separately measured metadata value.
The corrected contributor code requests `0700` atomically at directory creation
and checks ownership and exact mode before creating any payload files. The
strict child check, AXIS guards and all fixed cases remain intact. The
[pinned tempfile implementation](https://github.com/Stebalien/tempfile/blob/v3.27.0/src/lib.rs#L395-L397)
documents the default.

The first two live runs completed in about 0.021 seconds with no result JSON.
Neither
produced completion evidence for the allowed-write, ungranted read/write,
read-only write, socket, exit-23, PTY input/resize or typed-timeout assertions.
The first run does not identify which point its child reached; the second
stopped at fixture validation. They supply no positive filesystem, network,
terminal or lifecycle qualification.

The third run produced explicit `mxc_sdk_v1_bubblewrap`,
`landlock_and_offline_seccomp`, `filesystem: hard_requirement` and
`network: block` evidence. Its retained result artifact is
`axis-mxc-v1-linux-live-e1e5022322b2d906d7974099664a4375f6efd49e`, ID
`12130621271`, with GitHub artifact SHA256
`4b2e5105da508423088a0e40de2f3905feb3a0308d7b53c3b5bbbd1bad776911`.

## Passed fixed cases

| Case | Observed assertion in the successful run |
| --- | --- |
| Private state | Expected HOME, working directory and allowlisted environment; allowed writes in private workspace, HOME and temporary directories |
| Strict filesystem | Synthetic ungranted read and write returned **EACCES**; read-only write returned **EACCES** or **EROFS**; host verified unchanged canaries and no ungranted write file |
| Offline network | IPv4/IPv6 TCP/UDP `socket()` creation returned **EPERM**, without a DNS lookup, connection or outbound packet attempt |
| Exit status | Fixed boundary and PTY children returned **23** through the SDK |
| MXC-owned PTY | Child passed `isatty()` and foreground-group equality; initial 30 rows by 100 columns; acknowledged fixed input after resize to 40 rows by 120 columns |
| Timeout | Guarded child announced readiness; MXC reported its typed **TimedOut** result for the configured one-second timeout |
| Direct-child lifecycle | Before-wait pidfds reported exited after SDK wait; repeated SDK handle cleanup calls succeeded |
| Owned fixture | Explicit removal succeeded after SDK handles returned; final fixture path was absent |

The ungranted canary directory was deliberately writable in the MXC filesystem
policy but omitted from the AXIS Landlock grants. The required **EACCES**
therefore tests the inner AXIS restriction on a visible synthetic path, rather
than accepting a missing mount or unrelated error as confidentiality proof.
No SDK policy or execution warnings were accepted. The result explicitly sets
`production_or_claude_qualification: false` and
`proxy_or_descendant_cleanup_qualification: false`.

The PTY test checked nonnegative foreground/process-group equality, but did
not record the numeric IDs or require them to be positive. PID namespaces can
make a group outside the namespace appear as zero, so that equality alone is
incomplete foreground-ID evidence. Actual input acknowledgement and resize
passed; positive group-ID and foreground-signal checks remain to be qualified.

## Host preparation, environment and cleanup scope

The first fixed rootless namespace readiness check failed on each disposable
VM with `kernel.apparmor_restrict_unprivileged_userns=1`. The explicitly wired
CI preparation temporarily changed only that knob to zero and retried the
same fixed readiness command. The `EXIT` trap restored the original value;
all three retained receipts report `original=1 changed=1 current=1`. These
attempts
therefore do not establish readiness on an unchanged host. No other host
namespace, firewall or LSM setting was changed by the experiment.

The driver constructs a private outer HOME and temporary directory, starts
the fixed binary with an empty inherited environment and a fixed allowlist,
and applies an outer 60-second deadline with a five-second forced-termination
grace. The contributor child receives only synthetic fixtures and a private
allowlisted environment. No developer workspace, Claude account, provider
credential, OAuth token or model request was used.

After each attempt, the evidence records no remaining exact artifact
executable or command naming that artifact, and no newly owned
`/tmp/dc-axis-mxc-*` fixture. This is a bounded inspection of this probe's
identity and fixture prefix. It does not establish arbitrary descendant,
helper, listener or general process-tree cleanup. The disposable VM's later
destruction is not counted as a successful SDK cleanup assertion.

## Pending production qualification

The successful fixed experiment leaves production gates open:
maintained AXIS/MXC integration, complete common-policy translation and
admission, real Claude, hook allow/block, credential isolation, broker-only
egress, streaming, resource limits, terminal signals, descendant/helper
custody, copied-workspace workflows, cross-user and managed behavior,
packaging, installation and upgrade. No customer runtime is enabled by these
contributor results.

## Stronger foreground gate

The independently verified locked artifact from build `39111547034` at `b2e1461dc9f35ed0cad9a2cae718ff28f99335c5` was run in [native Linux experiment 39112173778](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39112173778). The stronger check refused: `isatty=1`, but both the foreground and process group IDs were `0` inside the PID namespace. The earlier equality check therefore did not establish a valid foreground group. The receipt recorded exit 1, no remaining matching artifact processes and no new owned fixtures; the disposable runner restored its namespace sysctl.

The next bootstrap establishes a positive process group and assigns the existing controlling PTY to it inside the PID namespace before AXIS guards. It preserves PID isolation, blocks SIGTTOU only for setup, restores the prior mask, and still requires positive matching IDs. This source also adds a parent-only public environment canary and verifies the outer MXC canary read/write grant before Landlock removes access. A new reviewed locked artifact and live run are required; no success is claimed for this iteration yet.

## Positive namespace group result

[Native Linux experiment 39113129947](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39113129947) passed the independently reviewed locked artifact from build `39112683483` at `d05ed40afa43a1c1812259554646b887ae9a9c58`. Its 13 fixed checks include the parent-only environment canary and positive outer-MXC pre-Landlock read/write control. Both initial and resized observations were `isatty=1`, foreground group `2`, process group `2`; input/resize and exit 23 passed. Landlock ABI was 7. The receipt recorded exit 0 in 1.073 seconds, empty stderr, no remaining matching processes and no new owned fixtures. The disposable runner restored its namespace sysctl.

The fixed-artifact live harness was committed separately at `9a79e22213bc209e7fe19e3e775ea8c10121a7ba` on `codex/axis-platform-live` to keep the implementation PR head stable during review. Binary SHA256 was `6e3630a7b7a050e68d3584948e9fa47f9f60680c101a8bbdf9121eb416e78728`; reviewed provenance was `bb7d7943d0a3c62d115017ff1f6f366faa40985be997733eae760a3156284f65`. The live result artifact is `12130214822`, digest `f28e10c42886f761bb9a398eee1cc144ad44756d4d75748c123bb28e8aa6f27d`. This result still does not qualify foreground SIGINT or a real agent/broker flow; the new signal protocol needs its own reviewed build and live result.

## Foreground SIGINT and continued input

[Native Linux experiment 39115616638](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39115616638)
passed all 14 fixed checks, including the real PTY control-byte SIGINT
acknowledgement followed by continued input and exit 23. Initial, resized and
continued observations each reported `isatty=1`, foreground group `2` and
process group `2`. The owned terminal retained `ISIG` and `VINTR=3`; the
supervisor wrote byte `0x03` to that PTY rather than signalling a numeric PID.
The child signal handler only set an atomic flag, and normal child execution
checked and acknowledged it. The result reported Landlock ABI 7, hard filesystem
enforcement, blocked networking, exit 0 in 1.075 seconds and empty stderr.

The exact locked build was [39115090877](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39115090877)
at `8cea62c312e6563a9db2c898dc350485223368e0`. Root review independently
verified the 14-file inventory, eight Git source blobs, upstream locks/licenses,
unchanged combined lock, workflow/toolchain and exact external artifact digest
before the live workflow executed it. The separate live harness was
`08ac157da16ffac25bdc140f82f830054d970b30`.

| Evidence | SHA256 |
| --- | --- |
| Build ZIP, artifact `12132405552` | `4227c8f06dc5d60b4874791420ddf7ba38754a88a324d8c39f077216ccc4f305` |
| Build provenance | `53a94c44c15c775a01123c7259e72e01fb9b3053cab5d990714d7a33b1cc8c5b` |
| Probe | `327e123d9343448e294d21e162db2548b855a3c2a040894ba36aa9fa95ef4228` |
| Live result ZIP, artifact `12131663388` | `07bb7a6492ae9f9706bdc89a4e5468395aad601ca3691bab08ac69b40a957d3b` |

The earlier [SIGINT attempt 39114952890](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39114952890)
observed the same three positive groups, SIGINT acknowledgement and continued
input but failed its strict record parser: the terminal echoed `^C` without
a newline before the resized group record. The corrected child emits one
newline before that record. A regression preserves rejection of the joined
record and acceptance of the delimited record; terminal settings and the strict
parser were not relaxed. That earlier attempt remains a failed qualification.

Both attempts recorded no remaining matching probe processes and no new owned
fixtures, and restored the disposable runner's AppArmor namespace knob with
`original=1 changed=1 current=1`. This qualifies the fixed synthetic offline
terminal protocol only. It does not establish arbitrary descendant custody,
broker credentials, real Claude, general policy translation or product support.

## Native literal arguments

[Native Linux experiment 39118661388](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39118661388)
passed all 15 fixed checks using the additive typed MXC literal-argv API. The
child checked empty, spaced, quoted, Unicode, trailing-backslash and shell
metacharacter arguments as literal data, then returned its fixed marker and
exit 23. The boundary, offline socket, timeout, input/resize and real SIGINT
checks also passed. All three PTY observations again had `isatty=1` and
foreground/process groups `2 == 2`. The receipt reports Landlock ABI 7,
exit 0 in 1.128 seconds, empty stderr, no matching probe process and no new
owned fixture. Disposable runner AppArmor preparation was restored.

The first literal run [39117371416](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39117371416)
failed before boundary assertions because the strict environment verifier did
not account for Bubblewrap's own `PWD`. That failure remains recorded. The
fix permits only `PWD` equal to the verified private working directory; shell
keys `SHLVL` and `_`, inherited keys and a different `PWD` remain refused.
The pinned Bubblewrap [source](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c)
sets `PWD` from its explicit `--chdir`, including after `--clearenv`.

The passing locked build was [39118099423](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39118099423)
at `7c62a3cf6310c5f54f3635d13cec9ac376742bc3`. Root review checked all
15 manifest files, nine Git source blobs, unchanged locks, licenses, workflow
and toolchain before manually dispatching the separate live harness
`dc6efffef7a8795da5a052ca5e13bd720c1970d1`.

| Evidence | SHA256 |
| --- | --- |
| Build ZIP, artifact `12133580892` | `7d7cf06eda40bad4b5b9d4dd4a17b23e6f1ffd9af2164cd41bf3bfa3cce3a81c` |
| Build provenance | `095d08d042af01210b2fe796746599586ca374fc60b974fc7d33b9e6def12a1a` |
| Probe | `20794a3222b3b7096b65afa564ec801aaff622faee86304fe29aeeda180f13bf` |
| Live ZIP, artifact `12133795206` | `c2eaa2621d93b1d51cef8cf67479dbde3eb3bcbde8014a88a73cd9c510a20d12` |

This result does not qualify a production provider, general policy translation,
host broker/credentials, real Claude or arbitrary descendant custody.
