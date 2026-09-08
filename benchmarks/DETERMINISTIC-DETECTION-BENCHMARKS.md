# Improving DefenseClaw deterministic detection with public benchmarks

Status: public evaluation report, September 2026.

## Abstract

DefenseClaw's deterministic guardrails were tuned and evaluated across the
`default`, `permissive`, and `strict` policy profiles using revision-pinned
public datasets. **Balanced is the public name for `default`; it is an alias,
not a fourth experimental arm.** The evaluated scope is English-only.

The final default/balanced and permissive command detector scored 9 TP, 7,908
TN, 0 FP, and 0 FN on validation: 100% F1, 0% observed FPR, and no benign
blocks. The positive denominator is only nine, so this is evidence of precise
closed-rule behavior—not a claim of universal malicious-command recall.
Strict recovered the same nine positives with eight additional findings:
69.23% F1, 0.1012% FPR, and no benign blocks.

The opt-in English privacy pack scored 5,929 TP, 13,018 TN, 0 FP, and 1,454 FN
on validation in every profile: 89.08% F1 and 0% observed FPR. An independent
10,000-row Ylemis holdout scored 4,190 TP, 1,756 TN, 0 FP, and 270 FN: 96.88%
F1 and 0% observed FPR.

Benign trajectory results were deliberately measured separately from attack
recall. ISETrace and TerminalBench produced no findings or blocks. LinuxArena
produced 0.89–2.78% default/permissive alert FPR and 0.97–2.95% strict alert
FPR, but zero benign blocks. That alert noise is a documented limitation.

The work added exact ActionFacts projections, bounded CEL and regex selectors,
code-owned semantic validators, five MCP-description YARA signatures, opt-in
production-protection packs, and 11 new bounded chains. Runtime enforcement
remains fully deterministic; GPT-OSS was used only for optional offline label
proposals and error analysis.

## Claims and non-claims

This evaluation supports these claims:

- exact-proof command rules can achieve low observed FPR and low benign block
  rates on the evaluated public samples;
- structured English identifiers can be detected at materially higher recall
  without adding validation false positives;
- identity-preserving bounded chains reject mismatched, failed, mutated,
  unresolved, or incomplete sequences;
- strict intentionally trades additional visibility for more alert noise; and
- user-configured protection packs can make otherwise dual-use administration
  deterministically forbidden within a declared trust boundary.

It does not claim:

- that nine command positives estimate broad real-world recall;
- that zero observed false positives means population FPR is zero;
- that every call in a successful attack trajectory is malicious;
- that contextual misses are benign;
- that authored conformance fixtures estimate field prevalence;
- that inspected retrospective test sets are untouched holdouts; or
- that an LLM participates in runtime decisions.

## Evaluation contract

### Profiles

| Published profile | Runtime profile | Intended posture |
| --- | --- | --- |
| Balanced/default | `default` | Low-noise general-purpose enforcement |
| Permissive | `permissive` | Fewer user-facing restrictions |
| Strict | `strict` | Broader alert visibility and more exact blocks |

### Outcomes

- **Detection**: any deterministic finding, including audit-only findings.
- **Alert**: a user-visible advisory or enforceable finding.
- **Block**: synchronous denial before the tool call executes.
- **Abstain/out of scope**: the available facts cannot prove the benchmark
  truth contract; these rows are not silently counted as benign.

Confusion matrices are written `TP/TN/FP/FN`. FPR is `FP / (TN + FP)` over
accepted benign negatives. Benign block rate is reported independently because
an allow-only finding can be noisy without interrupting an agent task.

## Public datasets

All external records are downloaded from the original source and pinned by
revision in [`datasets.lock.json`](datasets.lock.json). Download-only sources
are not redistributed.

| Source | Role in this evaluation | Truth use |
| --- | --- | --- |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Literal attack-emulation commands | Command-positive candidates; exact effects finalized locally |
| [Shell Attack Evolution](https://huggingface.co/datasets/zyw-286/shell-attack-evolution-dataset) | Diverse malicious-shell candidates | Command-positive candidates; exact effects finalized locally |
| [NL2Bash](https://github.com/TellinaTool/nl2bash) | Ordinary shell commands | Command and privacy hard negatives |
| [tldr-pages](https://github.com/tldr-pages/tldr) | Documented command examples | Command hard negatives |
| [Gretel PII](https://huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1) | English structured PII text | Privacy positives and negatives |
| [Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII) | Large synthetic PII corpus | Privacy positives and negatives |
| [Ylemis India PII](https://huggingface.co/datasets/Pranshurs/ylemis-india-pii-benchmark) | Independent English identifier holdout | Privacy binary and span truth |
| [LinuxArena](https://huggingface.co/datasets/anonymouslinuxarena/linuxarena-public) | Honest agent trajectories with real arguments | Benign finding FPR and block rate |
| [TerminalBench trajectories](https://huggingface.co/datasets/yoonholee/terminalbench-trajectories) | Honest terminal-agent trajectories | Benign finding FPR and block rate |
| [ISETrace](https://huggingface.co/datasets/valiere/ISETrace) | Benign action/state sequences | Benign finding FPR and block rate |
| [MonitoringBench](https://huggingface.co/datasets/neur26anonsub/ctrldataset2026) | Environment-successful attacks with exact tool arguments | Proof yield and coverage; only closed exact effects become positives |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | Tool-description injection and data-stealing tasks | YARA binary truth and contextual chain stress |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | Benign and prompt-injection tool sequences | Contextual stress; no block truth inferred |
| [Agentic RedTeam](https://github.com/Alkur123/agentic-redteam-benchmark) | Paired structured attack/benign sequences | Detect-only contextual truth |
| [HF Agentic Red Team](https://huggingface.co/datasets/sh111111111111111/agentic_red_team) | Argument-bearing synthetic trajectories | Detector coverage and rule discovery |
| [ATBench](https://huggingface.co/datasets/AI45Research/ATBench), [ATBench-Codex](https://huggingface.co/datasets/AI45Research/ATBench-Codex), [ATBench-Claw](https://huggingface.co/datasets/AI45Research/ATBench-Claw) | Agent-trajectory safety stress | Benign atomic FPR and contextual chain abstention |
| [Labeled BashBench](https://huggingface.co/datasets/AISafety-Student/labeled-bashBench) | Executed shell tasks with silver labels | Coverage only |
| [Anode Agent-Trace-Cyber](https://huggingface.co/datasets/AnodeAI/Agent-Trace-Cyber-v1) | Cyber-agent traces | Schema and coverage evaluation |
| [LinuxArena trajectories](https://huggingface.co/datasets/eval-aware/linuxarena-trajectories) | Real argument-bearing trajectories | Counterfactual identity hard negatives |
| [Zenodo cyber-training shell data](https://zenodo.org/records/8136017) | Independent mixed shell commands | Binary stress and abstention |

The benchmark also contains small Apache-2.0 fixtures under
[`fixtures/`](fixtures/) for exact grammar and chain-boundary conformance.
Their results are always labeled as authored conformance, not population
accuracy.

## Methodology

### 1. Source admission

A source entered the public suite only when its URL, immutable revision,
license status, schema, and truth semantics could be recorded. Sources without
usable per-call truth were assigned to coverage-only lanes. Non-English rows,
unsupported schemas, malformed payloads, and records requiring assumptions
about hidden state were excluded or marked out of scope.

### 2. Safe preparation

[`benchmark_prepare.py`](scripts/benchmark_prepare.py) materializes only the
locked paths. Git sources are read from object storage without running hooks,
filters, source code, or dataset commands. Hugging Face LFS objects are fetched
directly and verified against their declared digest and size. Absolute paths,
links, traversal, submodules, executable bits, and oversized objects are
rejected.

### 3. Normalization

Each adapter projects source-specific data into
[`case-v1.schema.json`](schema/case-v1.schema.json). It retains only facts the
runtime can actually observe: tool identity, command or structured arguments,
dialect, working directory when supplied, event order, and authoritative
success/failure when the source provides it. Prompts, chain-of-thought,
unrelated tool output, and source scorer prose are excluded.

Exact payload duplicates and conflicting labels are removed before splitting.
Related rows are assigned together with fixed seed `741983` so a template or
trajectory does not cross development, validation, and test by accident.

### 4. Offline labeling

Public source labels are only the starting point. Attack-dataset provenance is
not copied onto every call. Optional GPT-OSS batch processing proposes one of:
deterministic malicious, benign, contextual/dual-use, or unresolved. It also
proposes typed operations and possible bounded-proof roles.

The final label is produced by deterministic code. A malicious positive is
accepted only when the literal standalone call proves a dangerous effect, or a
complete bounded sequence proves every required role. Dynamic operands,
unknown targets, missing result status, conditional execution, uncertain
identity, mutation between source and sink, and incomplete lineage force an
abstention or contextual label.

No human adjudication was used. Model-correlated and source-label errors remain
a threat to validity. The model is never present in the runtime path.

### 5. Tuning loop

For each false negative or promising real-argument cluster:

1. Build exact positives plus lexical, structural, dynamic-identity,
   documentation, preview, conditional, failed-result, wrong-target, and
   mutation hard negatives.
2. Add the smallest bounded CEL and/or regex candidate selector.
3. Add a code-owned parser or semantic finalizer when argv, SQL, Windows,
   Kubernetes, artifact identity, or control flow needs exact interpretation.
4. Project only the ActionFacts needed by the proof.
5. Run focused tests, public command development, and the large benign lanes.
6. Narrow or reject any default/permissive rule that creates noisy findings or
   blocks unresolved dual use.
7. Place broader non-blocking visibility in strict when useful.
8. Freeze the rule meaning and run fixed validation and retrospective test
   partitions.

High recall never overrode the low-noise requirement. Useful but incomplete
signals stayed alert-only or strict-only.

### 6. Bounded sequence proofs

Contextual attacks are not classified from nearby suspicious words. The
runtime stores value-minimized ActionFacts and evaluates a fixed catalog of 18
chains over at most the current event plus eight successful predecessors, in
one authenticated session and within 30 minutes.

A chain declares role bits, result requirements, exact identity joins,
mutation barriers, and separate detection/enforcement masks. Failed, denied,
cancelled, replayed, cross-session, unresolved, or identity-mismatched events
cannot complete a proof. Persisted identities are domain-separated digests,
not raw secrets or file contents.

### 7. Scoring and verification

Binary rows are scored for detection, alerting, and enforcement separately.
Benign-only datasets report FPR and block rate, not meaningless zero F1.
Coverage datasets report counts, not TP. Every run emits case predictions,
manifests, policy inventory, environment, classification digest, and checksums;
the `verify` command recomputes and checks those artifacts.

## Initial state

The initial command labels treated attack-source provenance too broadly. They
are retained to show why that contract produced a misleadingly low F1, but are
not numerically comparable with final exact-proof truth.

| Benchmark | Profile | TP/TN/FP/FN | F1 | FPR | Benign blocks |
| --- | --- | ---: | ---: | ---: | ---: |
| Command validation, initial | Default/balanced | 44/7,669/69/3,714 | 2.27% | 0.8917% | 2/7,738 |
| Command validation, initial | Permissive | 44/7,669/69/3,714 | 2.27% | 0.8917% | 2/7,738 |
| Command validation, initial | Strict | 46/7,667/71/3,712 | 2.37% | 0.9175% | 6/7,738 |
| Privacy validation, initial | Default/balanced | 1,772/13,018/0/12,494 | 22.10% | 0% | 0/13,018 |
| Privacy validation, initial | Permissive | 1,770/13,018/0/12,496 | 22.08% | 0% | 0/13,018 |
| Privacy validation, initial | Strict | 11,705/13,007/11/2,561 | 90.10% | 0.0845% | 1/13,018 |

The final command truth asks a narrower question—whether the literal call or
complete chain proves a prohibited effect—so an “F1 improvement ratio” between
these tables would be invalid.

## Final binary results

### Public command corpus

| Split | Profile | TP/TN/FP/FN | Precision | Recall | F1 | FPR | Benign blocks |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Development | Default/balanced | 5/23,649/3/0 | 62.50% | 100% | 76.92% | 0.01268% | 0/23,652 |
| Development | Permissive | 5/23,649/3/0 | 62.50% | 100% | 76.92% | 0.01268% | 0/23,652 |
| Development | Strict | 5/23,608/44/0 | 10.20% | 100% | 18.52% | 0.1860% | 3/23,652 |
| Validation | Default/balanced | 9/7,908/0/0 | 100% | 100% | 100% | 0% | 0/7,908 |
| Validation | Permissive | 9/7,908/0/0 | 100% | 100% | 100% | 0% | 0/7,908 |
| Validation | Strict | 9/7,900/8/0 | 52.94% | 100% | 69.23% | 0.1012% | 0/7,908 |
| Retrospective test | Default/balanced | 6/7,738/0/0 | 100% | 100% | 100% | 0% | 0/7,738 |
| Retrospective test | Permissive | 6/7,738/0/0 | 100% | 100% | 100% | 0% | 0/7,738 |
| Retrospective test | Strict | 6/7,732/6/0 | 50.00% | 100% | 66.67% | 0.07754% | 0/7,738 |

For default/permissive validation, the 0/7,908 FPR point estimate has a 95%
Wilson upper bound of 0.04855%. The 9/9 recall estimate has a 95% Wilson lower
bound of 70.09%, illustrating the much larger recall uncertainty.

Three strict development blocks are reported as false positives under the
current exact-proof truth. This visible disagreement is not hidden or relabeled.

### English privacy pack

| Split | Profile | TP/TN/FP/FN | Precision | Recall | F1 | FPR | Span F1 | Benign blocks |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Development | All profiles | 17,367/39,057/0/4,363 | 100% | 79.92% | 88.84% | 0% | 73.11% | 0/39,057 |
| Validation | All profiles | 5,929/13,018/0/1,454 | 100% | 80.31% | 89.08% | 0% | 73.38% | 0/13,018 |
| Retrospective test | Default/balanced, permissive | 4,052/13,019/0/3,405 | 100% | 54.34% | 70.41% | 0% | 18.43–18.45% | 0/13,019 |
| Retrospective test | Strict | 4,371/13,018/1/3,086 | 99.98% | 58.62% | 73.90% | 0.007681% | 20.70% | 0/13,019 |

The weaker retrospective span result is a real generalization limitation. The
pack is opt-in because organizations differ on which identifier classes should
alert or block.

### Independent Ylemis PII holdout

| Profiles | TP/TN/FP/FN | Precision | Recall | F1 | FPR | Benign blocks |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| All profiles | 4,190/1,756/0/270 | 100% | 93.95% | 96.88% | 0% | 0/1,756 |

This holdout has 10,000 rows, of which 6,216 are inside the supported English
structured-identifier scope. The truth lens is detection-only; enforcement F1
would conflate detector quality with policy posture.

### MCP-description YARA

| Split | TP/TN/FP/FN | Precision | Recall | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: |
| Development | 29/230/0/14 | 100% | 67.44% | 80.56% | 0% |
| Validation | 7/53/0/2 | 100% | 77.78% | 87.50% | 0% |
| Inspected test | 8/47/0/2 | 100% | 80.00% | 88.89% | 0% |
| Combined | 44/330/0/18 | 100% | 70.97% | 83.02% | 0% |

The retained upstream-only comparison was 1/328/2/61: 3.08% F1 and 0.6061%
FPR. The five supplemental signatures remain alert-only because description
text cannot prove authorization.

### Zenodo mixed shell data

| Split | Profile | TP/TN/FP/FN | F1 | FPR | Benign blocks |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Development | Default/balanced, permissive | 0/969/0/555 | 0% | 0% | 0/969 |
| Development | Strict | 8/969/0/547 | 2.84% | 0% | 0/969 |
| Validation | Default/balanced, permissive | 0/373/0/167 | 0% | 0% | 0/373 |
| Validation | Strict | 1/372/1/166 | 1.18% | 0.2681% | 0/373 |
| Test | All profiles | 0/361/0/0 | Undefined | 0% | 0/361 |

This negative result is important: most source positives do not meet the exact
deterministic proof contract, and default/permissive correctly abstain rather
than broadening blocks.

## Benign trajectory noise

| Corpus/split | Profile | TN/FP | FPR | Benign blocks |
| --- | --- | ---: | ---: | ---: |
| ISETrace development | All profiles | 1,936/0 | 0% | 0/1,936 |
| ISETrace validation | All profiles | 645/0 | 0% | 0/645 |
| ISETrace test | All profiles | 646/0 | 0% | 0/646 |
| TerminalBench development | All profiles | 1,416/0 | 0% | 0/1,416 |
| TerminalBench validation | All profiles | 473/0 | 0% | 0/473 |
| TerminalBench test | All profiles | 473/0 | 0% | 0/473 |
| LinuxArena development | Default/balanced, permissive | 16,570/271 | 1.6092% | 0/16,841 |
| LinuxArena development | Strict | 16,439/402 | 2.3870% | 0/16,841 |
| LinuxArena validation | Default/balanced, permissive | 5,596/50 | 0.8856% | 0/5,646 |
| LinuxArena validation | Strict | 5,591/55 | 0.9741% | 0/5,646 |
| LinuxArena test | Default/balanced, permissive | 5,430/155 | 2.7753% | 0/5,585 |
| LinuxArena test | Strict | 5,420/165 | 2.9543% | 0/5,585 |

LinuxArena findings are largely legitimate secret-like values used against
local services. They remain allow-only and never blocked, but the alert rate is
still a UX cost. Destination- and policy-aware suppression is future work.

## Contextual and coverage results

| Public corpus | Result | Interpretation |
| --- | --- | --- |
| MonitoringBench | 2,442 successful attacks with exact calls; 41 closed sudoers proofs across fixed splits | Real proof yield; not all calls are positives |
| AgentDojo | 0/67/0/11, F1 0%, FPR 0% | Eleven contextual positives lack complete deterministic proof |
| Agentic RedTeam | 0/438/0/438, F1 0%, FPR 0% | Detect-only contextual positives missed |
| InjecAgent chains | 0/0/0/544, F1 0% | No stable source/sink lineage for deterministic block truth |
| ATBench action | Development FPR 0.6548%; validation 1.2302%; test 1.9469%; zero blocks | Atomic benign noise; no accepted deterministic positives |
| Labeled BashBench | 375 actions; 36 default/permissive and 63 strict detections | Silver-label coverage only |
| HF Agentic Red Team | 25,982 calls; 1,246 default and 1,397 strict detections | Outcome-unknown coverage only |
| Anode cyber traces | 300 normalized cases | Schema/coverage only; no accepted binary truth |

These rows expose a central limitation: broad “contextual malicious” recall is
low when the dataset does not preserve exact identity, result, authorization,
and control-flow evidence. The solution is bounded proof—not turning suspicious
vocabulary into a default block.

## Authored conformance

### Opt-in protection packs

| Pack | TP/TN/FP/FN | F1 | FPR | Benign blocks |
| --- | ---: | ---: | ---: | ---: |
| Cloud production | 20/9/0/0 | 100% | 0% | 0/9 |
| Database destruction | 14/10/0/0 | 100% | 0% | 0/10 |
| Infrastructure destruction | 4/7/0/0 | 100% | 0% | 0/7 |
| Kubernetes production | 6/7/0/0 | 100% | 0% | 0/7 |

These results prove conformance to authored closed grammars. They do not
estimate population prevalence or FPR.

### New exact chain fixtures

| Proof | Exact hits | Hard negatives unmatched | Blocks |
| --- | ---: | ---: | ---: |
| Cloud principal creation → administrator attachment | 3 | 10 | 0 |
| Firewall trust expansion → destination use | 1 | 7 | 0 |
| Privileged Kubernetes CronJob patch → job creation | 2 | 13 | 0 |
| PostgreSQL `COPY PROGRAM` atomic | 2 | 8 | 0 |
| Privileged host-root Kubernetes apply → execution | 2 | 9 | 0 |
| Credential dump → remote execution, same target/principal | 2 | 15 | 0 |
| Command-capable SQL UDF atomic | 3 | 8 | 0 |
| Command-capable SQL UDF create → invoke | 3 | 10 | 0 |
| SQL Server command execution enable → invoke | 2 | 8 | 0 |
| Wireless capture → deauthentication, same BSSID | 2 | 10 | 0 |
| Reverse-shell artifact write → persistence install | 4 | 10 | 4 |

Only the last row carries block-eligible fixture truth. Every profile scored
4 TP, 10 TN, 0 FP, and 0 FN and blocked the four complete proofs.

## Detection changes

### Atomic semantic rules

Thirty-four exact semantic IDs were added or materially completed:

- Execution: `exec.remote_ip_download_execute_same_artifact`,
  `exec.postgresql_copy_program`, `exec.sql_command_udf_create`.
- Persistence: `persistence.global_ld_preload_install`,
  `persistence.windows_accessibility_feature_hijack`.
- Privilege: `privilege.cloud_iam_administrator_attachment`,
  `privilege.kubernetes_cronjob_privileged_patch`,
  `privilege.sudoers_unrestricted_nopasswd`,
  `privilege.windows_uac_autoelevation_hijack`.
- Credential access: `credential.macos_fake_update_prompt`,
  `credential.macos_login_keychain_dump`, `credential.pam_password_capture`,
  `credential.windows_lsass_memory_dump`,
  `credential.windows_registry_hive_dump`.
- Impact: `impact.linux_magic_sysrq_destruction`,
  `impact.posix_host_halt`, `impact.windows_delete_all_shadow_copies`,
  `impact.windows_recovery_disable_pair`,
  `impact.windows_recovery_store_destruction`.
- Security-control tampering: `tamper.cloud_audit_control_destruction`,
  `tamper.complete_firewall_relaxation`,
  `tamper.endpoint_security_product_disable`,
  `tamper.linux_security_control_disable`, `tamper.macos_unified_log_erase`,
  `tamper.posix_logging_hardening_disable`,
  `tamper.posix_system_log_destruction`, `tamper.windows_amsi_disable`,
  `tamper.windows_audit_policy_wipe`,
  `tamper.windows_credential_protection_weaken`,
  `tamper.windows_defender_component_disable`,
  `tamper.windows_defender_multi_control_disable`,
  `tamper.windows_registry_security_control_disable`,
  `tamper.windows_telemetry_disable`, `tamper.windows_usn_journal_delete`.

Twenty-eight use both bounded CEL and regex candidate selection. Four use CEL
with regex disabled where a broad lexical fallback would be unsafe. Two use a
code-owned exact proof selected by regex. Candidate selectors do not by
themselves authorize a block.

### ActionFacts

New value-minimized facts represent structured replacement deltas, sensitive
egress artifacts, SQL command-execution primitives, privileged Kubernetes
objects, wireless BSSIDs, cloud principals, remote-execution target/principal
identity, payload/persistence identity, result status, and bounded literal
stdin. This lets rules join typed identities instead of nearby words.

### Bounded chains

The catalog expanded from seven to 18 proofs. New chains cover download then
execution of the same artifact, sensitive egress then execution, firewall
trust expansion, SQL Server command execution, privileged Kubernetes host-root
operations, wireless capture/deauthentication, credential dump to remote
execution, cloud principal/admin attachment, privileged CronJob mutation,
command-capable SQL UDF creation/invocation, and reverse-shell persistence.

### YARA

Five alert-only MCP-description signatures were added for addressed sensitive
data transfer, concrete financial action, exact destructive user-data action,
security-control downgrade, and multi-attribute profile changes. The canonical
rules are in
[`policies/yara/mcp-tools/description_injection.yara`](../policies/yara/mcp-tools/description_injection.yara).

### Policy packs

Five selectable opt-in packs cover high-assurance PII, protected cloud
resources, destructive database operations, infrastructure destruction, and
protected Kubernetes resources. A sixth staged SSH authorized-key integrity
contract has deterministic ActionFacts support but is not yet activatable
through policy. Configuration supplies the
missing trust fact: for example, a globally dual-use destroy operation becomes
deterministically prohibited when it resolves to a customer-declared protected
environment.

## Reproduce the evaluation

### Build and test

```bash
go test ./benchmarks/...
go test ./internal/actionfacts ./internal/guardrail ./internal/audit ./internal/gateway
python -m unittest discover -s benchmarks/scripts -p 'test_benchmark_*.py'
```

### Download and normalize

```bash
export BENCHMARK_DATA_DIR="$PWD/.benchmark-data"

python benchmarks/scripts/benchmark_prepare.py \
  --lock benchmarks/datasets.lock.json \
  --data-dir "$BENCHMARK_DATA_DIR" \
  --datasets atomic-red-team,nl2bash,shell-attack-evolution,tldr

python benchmarks/scripts/benchmark_normalize.py \
  --lock benchmarks/datasets.lock.json \
  --data-dir "$BENCHMARK_DATA_DIR" \
  --datasets atomic-red-team,nl2bash,shell-attack-evolution,tldr \
  --split validation \
  --output "$BENCHMARK_DATA_DIR/public-command-validation.jsonl"
```

### Run, score, and verify

```bash
go run ./benchmarks/cmd/defenseclaw-benchmark run \
  --corpus "$BENCHMARK_DATA_DIR/public-command-validation.jsonl" \
  --dataset-lock benchmarks/datasets.lock.json \
  --profiles default,permissive,strict \
  --output outputs/benchmarks/public-command-validation

go run ./benchmarks/cmd/defenseclaw-benchmark verify \
  --output outputs/benchmarks/public-command-validation
```

For the published command truth, apply the checked-in stable-ID adjudication
overlay after normalization. For trajectory datasets, use the dedicated
adapter named for that source. The adapter and split metadata are included in
the emitted corpus manifest.

### Reproduce optional GPT-OSS proposals

```bash
python benchmarks/scripts/benchmark_label_bedrock.py --help
python benchmarks/scripts/benchmark_apply_labels.py --help
python benchmarks/scripts/benchmark_finalize_proof_labels.py --help
```

Use an isolated object prefix and retain the returned model ID, prompt/schema
version, input/output digests, token counts, and completion status. Re-running
the deterministic finalizer—not accepting raw model output—is required.

## Machine-readable results

The exact public summary used by this report is in
[`results/public-scorecard-v1.json`](results/public-scorecard-v1.json). It
keeps binary, benign-only, coverage-only, and conformance results in separate
arrays so downstream consumers cannot accidentally aggregate incompatible
truth contracts.

## Conclusion

The strongest result is not a single F1 number. It is the separation of
evidence: exact effects can block; complete bounded chains can block; explicit
customer-policy violations can block; broader contextual signals alert or
abstain. On the evaluated public data this produces low default/permissive
false-positive and block rates while preserving strict visibility. The main
remaining gap is real-world contextual recall with enough source/sink identity
and result evidence to complete deterministic proofs.
