# Atomic Red Team and Shell Attack Evolution mining note

Read-only source preparation and normalization were run against the enabled
lock entries:

| dataset | locked revision | license | prepared source |
| --- | --- | --- | --- |
| `atomic-red-team` | `cb486d9a888e921fac5902a06c7b46e420bb14a7` | MIT | `/Users/vnarajal/Desktop/defenseclaw-benchmark-data/detection-tuning-v2/sources/atomic-red-team` |
| `shell-attack-evolution` | `d201aafbbcbb5347078ca64f06c5428fa6814bc9` | CC-BY-4.0 | `/Users/vnarajal/Desktop/defenseclaw-benchmark-data/detection-tuning-v2/sources/shell-attack-evolution` |

The source preparation command was:

```text
python3 benchmarks/scripts/benchmark_prepare.py --lock benchmarks/datasets.lock.json --data-dir /Users/vnarajal/Desktop/defenseclaw-benchmark-data/detection-tuning-v2 --datasets atomic-red-team,shell-attack-evolution
```

The normalized evidence artifact is outside the repository at
`/Users/vnarajal/Desktop/defenseclaw-benchmark-data/detection-tuning-v2/normalized/atomic-shell-v3.jsonl` with manifest
`atomic-shell-v3.manifest.json` and SHA-256
`9fbe0afedf8709ae92294ef2e0cbee047c3c1ac4ca9a271558de1778641ee9e6`.

## Counts and truth contract

| dataset | source evidence | normalized rows | label policy |
| --- | ---: | ---: | --- |
| Atomic Red Team | 340 technique YAML files; 1,801 command definitions | 1,750 | `source_truth=malicious`, `deterministic_truth=contextual_or_dual_use`, `expected_disposition=detect_only`; source attack-emulation provenance is not runtime success |
| Shell Attack Evolution | 17,159 command-catalog rows; 1,489 curated response rows | 17,099 | `source_truth=malicious`, `deterministic_truth=contextual_or_dual_use`, `expected_disposition=detect_only`; honeypot/Vi harm does not prove DefenseClaw success or authorize blocking |

Normalization removed 1,600 exact payload duplicates and 0 label conflicts.
Atomic rows retain the exact command, ATT&CK technique (`335` unique technique
IDs), stable source YAML/test identity (`1,715` rows have an atomic-test GUID;
35 do not), and stable source revision. Shell rows retain exact commands and
stable catalog line or `session_id:turn_index` identities. The lock's Shell
include paths do not contain the source TTP/session label files, so no ATT&CK
metadata is invented.

Shell curated evidence is English-only: `1,489/1,489` rows have
`response_source=curated_ubuntu`, non-empty command, response, and
`system_change`; they cover `160` sessions and all are period `2021_2022`.
`severity_vi` counts are `0:591`, `1:35`, `2:669`, `3:71`, `4:123`. The
normalizer records this result availability as provenance but does not turn a
severity score into a block label or copy response text into the value-free
detector payload.

Atomic definitions have command arguments and optional cleanup definitions but
no execution result. Shell command-catalog rows have arguments/frequency but
no result; only the curated file has response/system-change evidence. Thus no
row from either public corpus is a deterministic successful runtime proof.

## Candidate audit

The following are candidate families, not labels. Counts are exact normalized
row counts from `atomic-shell-v3.jsonl`; families overlap. The lexical
selectors are intentionally exposed here so a future CEL/ActionFacts rule can
be reviewed against the source evidence rather than inferred truth.

| candidate selector | total | Atomic | Shell | representative normalized ID |
| --- | ---: | ---: | ---: | --- |
| fetch/download command (`curl`, `wget`, `fetch`, `Invoke-WebRequest`, `certutil`, `bitsadmin`) | 1,837 | 107 | 1,730 | `atomic-red-team/0492ba6c758f8e17a9edeaaa` |
| upload/egress syntax (`--data`, `--upload-file`, `-T`, `--post-data`, shell pipe) | 189 | 10 | 179 | `atomic-red-team/1467441ee8ded5218c1583da` |
| sensitive path or credential-reader token | 19 | 16 | 3 | `atomic-red-team/06f40b4c4d7996f49feb8c4f` |
| persistence install (`schtasks /Create`, `crontab`, `systemctl enable`, `launchctl`, `authorized_keys`, Run keys) | 30 | 23 | 7 | `atomic-red-team/0901cb040619548062d4c79f` |
| security-control tamper (`wevtutil cl`, `iptables -F`, `auditpol /clear`, etc.) | 5 | 5 | 0 | `atomic-red-team/23b1b19a22e7b55f7d11d7b8` |
| literal root wipe (`rm -rf /` or `--no-preserve-root`) | 1 | 1 | 0 | `atomic-red-team/b99afa769b1526320de8b50e` |
| download URL piped directly to shell | 8 | 2 | 6 | `shell-attack-evolution/09e52db6c2d31e81c722cfcc` |
| raw `/dev/tcp` or socket-connect candidate | 179 | 2 | 177 | `shell-attack-evolution/008fb21f0eb714094584fa41` |

The last family is deliberately only a network/socket candidate: the corpus
contains raw-socket and download/execute forms, not a complete reverse-shell
proof. Similarly, `curl`/`wget` alone is not exfiltration; the upload count is
only syntax-level candidate coverage.

The repository ActionFacts projection was run with:

```text
go run ./benchmarks/cmd/actionfacts-features < /Users/vnarajal/Desktop/defenseclaw-benchmark-data/detection-tuning-v2/normalized/atomic-shell-v3.jsonl > /tmp/atomic-shell-actionfacts.jsonl
```

Value-free parser feature counts (rows containing the feature, not event
counts) are:

| ActionFacts feature | Atomic | Shell |
| --- | ---: | ---: |
| `operation=execute` | 1,608 | 17,071 |
| `operation=read` | 71 | 2,891 |
| `operation=write` | 170 | 236 |
| `operation=delete` | 29 | 125 |
| `operation=schedule` | 21 | 1 |
| `operation=policy_bypass` | 49 | 0 |
| `operation=credential_read` | 3 | 0 |
| `network.action=download` | 5 | 168 |
| `network.action=upload` | 1 | 0 |
| `dataflow=stdout->stdin` | 198 | 10,223 |
| `dataflow=network->process` | 4 | 168 |
| `dataflow=process->network` | 1 | 0 |
| `path.access=read` | 74 | 2,793 |
| `path.access=write` | 309 | 1,647 |
| `path.access=execute` | 96 | 5,702 |

Candidate ActionFacts/CEL primitives are therefore:

- `command.program` plus `operation=fetch`/`network.action=download` for a
  network fetch; require a literal artifact identity and a successful result
  before any download/execute chain can become block-eligible.
- `operation=upload`/`network.action=upload` and
  `dataflow=process->network` for egress; join with a proven sensitive
  `path.access=read` and exact artifact/identity continuity. Do not treat a
  URL, `curl`, or a placeholder as proof.
- `path.access=read|write|execute|delete`, `operation=credential_read`,
  `operation=schedule`, and `operation=policy_bypass` for bounded local
  effects. These are candidate selectors, not standalone blocking truth.
- Existing exact-proof semantic IDs relevant to these families include
  `exec.remote_ip_download_execute_same_artifact`,
  `tamper.posix_system_log_destruction`,
  `tamper.windows_audit_policy_wipe`,
  `credential.windows_registry_hive_dump`, and the bounded
  `chain.reverse_shell_payload_write_then_persistence_install_same_artifact`.
  The public rows do not supply the successful-result, same-artifact, or
  identity joins required by those proofs.

## Hard negatives and blockers

Neither source supplies a ground-truth benign split in the pinned files. The
following are useful contextual hard negatives only, not benign labels:

- `shell-attack-evolution/02acc3ac34eea34f330e132c` — curated `ls`; command
  and response exist, but no malicious effect is proven by the command alone.
- `shell-attack-evolution/04a4c0b37079410061cc3fca` — curated `pwd`; same
  limitation.
- `shell-attack-evolution/b842cc75eeb79d9596b4cbf2` — catalog
  `curl https://ipinfo.io/org`; network fetch syntax is not exfiltration.
- `atomic-red-team/0017685e2b46b9fc7d3a7eb1` — an Atomic monitoring test
  (`trap`, `echo`, `cat`) with no runtime result; source provenance does not
  make the literal call a deterministic malicious proof.

Blockers are: no benign labels; no Atomic runtime outcomes; Shell catalog rows
have no outcomes; Shell curated responses/system changes are source evidence
but do not establish DefenseClaw success semantics; and the locked Shell paths
omit ATT&CK/TTP annotations. No production detection code was changed and no
source was uploaded.
