# Experiment ledger

Every measured experiment across both benchmark programmes, with provenance and the
caveats that govern how each number may be used. Append-only in spirit: correct an entry
in place, but never delete a row that was published or relied on.

Two programmes, two HuggingFace Spaces:

| programme | Space | scope |
|---|---|---|
| **System One** | existing, public, rev `c11a65bcc85c` | cascade guardrail models on the DefenseClaw parity grid |
| **SLM tool-call security** | existing, public, final at `55490b2f855a` | small/local models for destructive tool-call classification |

System One arms go in the System One Space. Cohort arms go in the new one. A model may
appear in both if it is measured under both protocols, but the numbers are not
interchangeable — different corpora and different label sets.

---

## Reading rules

These apply to every number below. They were learned the hard way in this programme.

**In-sample ceilings are not results.** A "best F1" found by sweeping thresholds on the
same rows it is scored on is an oracle upper bound. Where a held-out figure exists, quote
that instead.

**`P(block) − P(confirm)` does not transfer.** On the disjoint s3 corpus its AUC inverted
*below chance*: OpenJev 0.856982082821162 → 0.2994021851164708 (def B) and
0.6476939399613056 → 0.3123558047927796 (def A); Jev 0.838702313793487 → 0.3420025352798462
(def B). It is the argmax variable for 5 of 11 re-mineable arms under def A. **Never rank
on it.** `P(block)`, `risk` and `P(block) + P(confirm)` all transfer.

**Two AUC definitions exist and are not interchangeable.** Definition A: max block, max
confirm, then subtract. Definition B: max of the per-event difference. Every AUC below is
labelled. Never compare across definitions. All eight pre-existing `auc-variants-*.json`
artifacts are definition A.

**Zero-FP gates mostly do not survive.** Of 24 s2→s3 gate transfers, 4 survived and 3 of
those were degenerate. 12 of 24 violated the s2 Wilson bound. FPR caps were respected in
8 of 48 transfers.

**Cross-validation was materially optimistic.** Within-s2 CV called Jev's zero-FP gate
perfect at 5/5 folds; the disjoint corpus showed that same threshold leaking 66 false
positives. CV cannot see corpus shift, and corpus shift is where the damage is.

**A run is valid only if** its meta says `complete: true` **and** the on-disk sha256 of the
prediction body equals `prediction_sha256`. Runs cannot be spliced; multi-shard merges are
fine only when every row was produced under identical serving conditions.

---

## Corpora

| name | cases | scorable | positives | benign | sha256 (cases) |
|---|---|---|---|---|---|
| s2 (core, parity grid) | 4,277 | 3,817 | 436 (A 17 + B 419) | 3,381 (D) | `39f2c1df2369952a0525cc4c5575f4bdb590fb3ca8c1bc6805cf4f376c1adbf7` |
| s3 (held-out) | 24,476 | 24,476 | 221 (A 193 + B 28) | 24,255 | `0ccbc08fb408ffefc89e051c585cfe22433b1ed4c9714f60cc0f7e242969fa03` |

Grade C (460 rows) is diagnostic only and excluded from scoring. s3 has no grade C or E.

**Case_id overlap between s2 scorable and s3: zero.** s3 is a genuinely disjoint corpus,
not a resample.

**Prevalence differs 12.65×** — s3 0.009029253145938878 against s2 0.11422583180508253. F1 is
prevalence-sensitive, so raw s2→s3 F1 drops are mostly prevalence, not overfitting. Use the
penalty metric (s3 oracle best − s3 at transferred threshold, both on s3) where prevalence
cancels.

Production grid cell: **C7 / I3 / Q2**, `--instruction-format structured`.

---

## Two baselines every number must be read against

**The trivial floor.** Blocking every case scores block-only F1 **0.20503174229955326** at this
11.42% prevalence (tp 436 / fp 3,381 / fn 0 / tn 0; precision 0.11423, recall 1.0). Against
that floor, **five re-mined arms score BELOW trivial at their shipped operating point** —
`open-jev-qwen-9b` 0.17551020, `open-jev-qwen-2b` 0.17194570, `decider-2b` 0.10843373,
`jevify` 0.04921700, `kev-9b` 0.018140589569160998 — and two more clear it by under 0.012
(`SecJudge` 0.20724154, `bespoke-nimble-9b` 0.21568627). Argmax F1 in this lens is barely a
discrimination measure. Quote the floor alongside any shipped F1.

**Correction, 2026-09-24.** Four of those five, not five, are *board* arms. `decider-2b` has a
settled scorecard and a comparison row but no leaderboard row: it never reached the `ADDED`
registry, so the site has never carried it. The published page therefore states **4 of the 11
ranked rows** below the floor and 2 more clearing it by under 0.012, with both lists computed
over the ranked population at build time. Say "re-mined arms" for the list of five and "board
rows" only for the four.

(Blocking everything has FPR 1.0 and fails any deployment gate, so this is not an argument
that trivial blocking is competitive. It is an argument that shipped F1 below ~0.205 tells you
the operating point is broken, not that the model cannot discriminate — the re-mining results
below show exactly that.)

**The length cue.** The corpus contains a real length/event-count signal worth **AUC ~0.77 with
no model at all**: natural prompt tokens 0.7692264380822134, event count 0.7772553177633239,
`context_events` 0.7445374041120237, `context_bytes` 0.7266059794480217. This is a property of
the data-generating process — destructive multi-step trajectories genuinely are longer — not a
labelling artifact. But **every arm's headline AUC contains a length component, so arm
comparisons should be length-controlled** (mean AUC within prompt-length quintiles). The pure
length counter falls 0.7692 → 0.5398672584287441 under that control, which validates the
stratification.

## Programme 1 — System One board

Block-only F1 on s2 at the parity grid. "Shipped" is the argmax operating point as
published. "Ceiling" is the in-sample best over a full threshold sweep, definition A.

| arm | shipped | ceiling (in-sample) | variable | Δ | ratio |
|---|---|---|---|---|---|
| Gemma 4 judge (det→LLM) | 0.71248247 | **not re-mineable** | — | — | — |
| OpenJev | 0.70231214 | 0.8086560364464692 | P(block) | +0.1063 | 1.15× |
| Jev 1.13.0 | 0.54152824 | 0.8112994350282486 | P(block) | +0.2698 | 1.50× |
| gemma-4-26B-A4B-it | 0.47495961 | 0.6600741656365884 | P(b)−P(c) ⚠ | +0.1851 | 1.39× |
| open-jev-qwen-27b | 0.33206107 | **0.8216340621403913** | P(block) | +0.4896 | 2.47× |
| DiffusionGemma 26B-A4B | 0.26792453 | 0.562111801242236 | P(b)−P(c) ⚠ | +0.2942 | 2.10× |
| bespoke-nimble-9b | 0.21568627 | 0.5809716599190283 | P(block) | +0.3653 | 2.69× |
| secjudge | 0.20724154 | 0.3967280163599182 | P(b)+P(c) | +0.1895 | 1.91× |
| open-jev-qwen-9b | 0.17551020 | 0.5730071033938438 | P(b)−P(c) ⚠ | +0.3975 | 3.26× |
| open-jev-qwen-2b | 0.17194570 | 0.48895658796648894 | P(b)−P(c) ⚠ | +0.3170 | 2.84× |
| decider-2b | 0.10843373 | 0.44723247232472324 | P(b)−P(c) ⚠ | +0.3388 | 4.12× |
| jevify-gemma4-26b-a4b | 0.04921700 | 0.6031746031746031 | P(block) | **+0.5540** | 12.26× |
| **kev-9b** | **0.018140589569160998** | 0.4182648401826484 | P(block) | +0.4001 | **23.06×** |

⚠ = ceiling rests on `P(block) − P(confirm)`, which inverted below chance held-out. Not
publishable as a ranking.

**Correction, 2026-09-24 — the Δ range depends on which ceiling column you read.** The range
"+0.1063 (OpenJev) to +0.5540 (jevify)" is taken over the table above, whose ceiling column
includes the five ⚠ rows. Drop `P(block) − P(confirm)` as the column requires, and the ceiling
for those five falls to their best *durable* variable, which moves the minimum:

| arm | ceiling on the best durable variable | variable | Δ vs shipped | withheld P(b)−P(c) figure |
|---|---|---|---|---|
| gemma-4-26B-A4B-it | 0.6292629262926293 | P(block) | +0.1543 | 0.71759259 (def B) |
| DiffusionGemma 26B-A4B | 0.5048309178743962 | P(block) | +0.2369 | 0.62777778 (def B) |
| open-jev-qwen-9b | 0.4640198511166253 | P(block) | +0.2885 | 0.57300710 (def A) |
| open-jev-qwen-2b | 0.23096841015018124 | P(block) | **+0.0590** | 0.58262875 (def B) |
| decider-2b | 0.38693877551020406 | P(block) | +0.2785 | 0.44723247 (def A) |
| kev-9b | 0.4182648401826484 | P(block) | +0.4001 | 0.60920502 (def B) |

Over durable variables the Δ range is **+0.0590 (`open-jev-qwen-2b`) to +0.5540 (`jevify`)**, and
OpenJev is no longer the floor of it. The published page uses the durable column and names each
withheld figure beside the ceiling it exceeds. Every arm's best durable variable is `P(block)`
except `secjudge`, whose best is `P(block) + P(confirm)` at 0.3967280163599182.

Nested out-of-fold figures on the durable column, for the arms whose ceiling moved:
gemma-4-26B-A4B-it 0.6262403528114664, DiffusionGemma 0.47831474597273854, open-jev-qwen-9b
0.45828144458281445, open-jev-qwen-2b 0.22054794520547946, decider-2b 0.37251655629139074.

### Held-out numbers (the quotable ones)

s2→s3 threshold transfer, strong design. Only three arms have a settled s3 counterpart:

| arm | variable | s2 threshold | s3 F1 at it | s3 oracle | penalty |
|---|---|---|---|---|---|
| OpenJev | P(block) | 0.1006 | 0.17160060210737582 | 0.24319419237749546 | 0.0716 |
| Jev 1.13.0 | P(block) | 0.06 | 0.17801512859304086 | 0.2932917316692667 | 0.1153 |
| DiffusionGemma | P(block) | 0.04662400059588728 | 0.05594215144055182 | 0.21374045801526717 | 0.1578 |

**What replicates:** the ordering on `P(block)`. Jev > OpenJev > DiffusionGemma at both the
transferred threshold and the s3 oracle. And the direction of the headline — argmax
discards real signal.

**What does not:** every specific F1, every FPR-capped point, every zero-FP gate.

Nested within-s2 grouped 5-fold (weak design; group key = case_id truncated to
`family/document`, unique per case so no group spans folds; `sha256(case_id)` round-robin
stratified by label; folds 765/763/763/763/763 with 88/87/87/87/87 positives):

| arm | in-sample | nested OOF (def A) |
|---|---|---|
| Jev 1.13.0 @Q0 | 0.8260381593714927 | 0.819304152637486 |
| open-jev-qwen-27b | 0.8216340621403913 | 0.8167053364269141 |
| Jev 1.13.0 @Q4 | 0.8192771084337349 | 0.8159806295399515 |
| Jev 1.13.0 | 0.8112994350282486 | 0.8004640371229699 |
| OpenJev | 0.8086560364464692 | 0.7991071428571429 |
| gemma-4-26B-A4B-it | 0.6600741656365884 | 0.6533665835411472 |
| jevify-gemma4-26b-a4b | 0.6031746031746031 | 0.5970937912813739 |
| bespoke-nimble-9b | 0.5809716599190283 | 0.5795339412360689 |
| open-jev-qwen-9b | 0.5730071033938438 | 0.5718799368088467 |
| DiffusionGemma | 0.562111801242236 | 0.5607476635514018 |
| open-jev-qwen-2b | 0.48895658796648894 | 0.4870229007633588 |
| decider-2b | 0.44723247232472324 | 0.43577981651376146 |
| kev-9b | 0.4182648401826484 | 0.41530054644808745 |
| secjudge | 0.3967280163599182 | 0.39549180327868855 |

CV optimism is small (0.0 to 0.0265, median ~0.0067) and variable choice is stable (all 13
arms pick the same variable in 5/5 folds). **Do not read that as re-thresholding being
free** — the s2→s3 result says otherwise.

### Settled artifact provenance

| arm | run_id | prediction_sha256 | rows / cases |
|---|---|---|---|
| kev-9b (s2) | `s2-kev-9b-h200` | `c3f8a277bdbd3865eaa4a44f8d8667af1b8b7b9b85642669f32ab9e08a392ff5` | 30,310 / 4,277 |
| open-jev-qwen-27b (s2) | `s2-open-jev-qwen-27b-h200` | `0b672a6485567acff32940a507297ea7c5b59b73ada7a91887c2bd869f58766d` | 30,310 / 4,277 |
| bespoke-nimble-9b (s3) | `s3-bespoke-nimble-9b-h200`, 53 shards | `b34651649b668c069dc02253c0e79682305ab57c4277d233fb189a6ad57a3842` | 100,001 / 24,476 |
| open-jev-qwen-2b (s2) | 4 shards `s2-open-jev-qwen-2b-shard{0..3}` | per-shard, all verified | 7,808+7,370+7,597+7,535 = 30,310 / 4,277 |
| OpenJev (s3) | `s3-openjev-merged` | `cbe2db0fd78ae35e8c9fd7f0b14bdfa5248553bd2ea5702ad3c763e004dd40cd` | 100,001 / 24,476 |
| Jev (s3) | `s3-jev-C7` | verified | 100,001 |
| DiffusionGemma (s3) | `s3-diffgemma-q2` | verified | 100,001 |

Board outputs live on `defenseclaw-dev` under `/home/ubuntu/.system-one-data/outputs/`.
Re-mining outputs under `/home/ubuntu/rescoring-remine/`.

### Not re-mineable

- `s2/gemma4-c7.jsonl`, `s2/gemma4-q2.jsonl`, `s2/deterministic.jsonl`, `s3/gemma4-c7.jsonl`
  — genuinely zero probability keys, `route: "llm"`.
- `s2/jev-q1-C7.jsonl`, `s2/jev-q3-C7.jsonl`, `s2/diffgemma-final.jsonl` — carry a 16-key
  per-category distribution (`context_manipulation.*`, `data_exfiltration.*`, …) but no
  `disposition.*` keys. Un-re-mineable on the four disposition variables specifically, not
  distribution-free. Note `diffgemma-q2.jsonl` *does* carry disposition distributions while
  `diffgemma-final.jsonl` does not.

### Findings worth keeping

- **The 27B's argmax is nearly silent.** tp 87 / fp 1 / fn 349 / tn 3380 at shipped. It
  blocks 88 times in 3,817 cases and catches 87 of 436 positives with one false positive.
  Re-thresholded on `P(block)` it reaches 0.8216340621403913.
- **SecJudge's five readouts are threshold-equivalent.** `sev`, `isattack`, `t05-50`,
  `t10-90`, `t20-75` give byte-identical AUCs at full precision and identical best F1
  (0.3967280163599182 for all C7 arms, 0.33046627433227704 for C0). Only the shipped action
  mapping differs. Re-mining cannot separate them.
- **Two arms are below chance on the leaderboard's own variable.** `risk` AUC:
  open-jev-qwen-9b 0.33537523505612854, open-jev-qwen-2b 0.37630349307652855. kev-9b is
  0.6542215809339292, so kev's weakness is threshold placement rather than a broken channel.
- **Jev @Q0 has the highest best-F1 of any settled artifact** at 0.8260381593714927 against a
  shipped 0.3643122676579926. It cannot be a board row (Q0 is a question-format variant, not
  the C7/I3/Q2 parity cell) and has no settled s3 counterpart.
- **Jev's score grid is coarse** — ~2 decimals, 93 distinct thresholds on `P(block)` against
  the 27B's 2,671 and DiffusionGemma's 3,813. Hypothesis that coarse grids overfit less is
  **unsupported**: Pearson r = 0.34240056308522954, Spearman ρ = −0.09340659340659342,
  disagreeing in sign, effect inside fold noise.
- **kev-9b's any-intervention figure depends on the scorecard node.** 0.20550458715596331 on
  `candidates[0].system_one` (model-alone, tp 56 / fp 53 / fn 380 / tn 3328) and
  0.24100719 on `candidates[0].deterministic_then_system_one`, which is the node the
  leaderboard's any-intervention column reads. The deterministic tier contributes 11 advisory
  confirms that the model alone does not make. Both appear on the page, in the two columns the
  behaviour table already carries. The block-only lens is identical on both nodes.
- **Composition axis:** `realdet_escalate_on_confirm` 0.751734 against
  `realdet_short_circuit` 0.73772791. The latter is a three-component cascade with a paid
  judge on 16% of cases (tp 263 / fp 14 / fn 173 / tn 3367; decided_by deterministic 13,
  openjev 3195, gemma 609) — **not** a like-for-like comparator for a single self-hosted model.

---

## Programme 2 — SLM tool-call security cohort

Status: in flight as of 2026-09-23 23:30Z. 14 ungated arms launched, 6 gated arms unlocked
and queued. Target 30,310 rows each on the s2 corpus at C7/I3/Q2.

Scorer verified against the board: reproduces the 27B scorecard exactly (tp 87 / fp 1 /
fn 349 / tn 3380, F1 0.33206107, AUC on P(block) 0.9480285133598713 to 16 digits), and rows'
`context_sha256` / `context_bytes` / `truncated` are byte-identical to settled 27B rows,
because the harness imports the reference driver's own `build_state` / `build_questions`.

| model | params | licence | origin | class | status |
|---|---|---|---|---|---|
| `open-jev-qwen-2b` (anchor) | 2B | CC BY-NC 4.0 | Alibaba base | Jev | merged 30,310 |
| `open-jev-qwen-27b` (anchor) | 27B | CC BY-NC 4.0 | Alibaba base | Jev | from board |
| `protectai/deberta-v3-base-prompt-injection-v2` | 184,423,682 | apache-2.0 | US | encoder | **30,310** |
| `answerdotai/ModernBERT-base` | 149,655,232 | apache-2.0 | EU/US | **negative control** | **30,310** |
| `answerdotai/ModernBERT-large` | 395,881,664 | apache-2.0 | EU/US | **negative control** | running |
| `mistralai/Shieldstral-1.0-3B` | 3,849,090,048 | apache-2.0 | France | safety | running |
| `ibm-granite/granite-guardian-3.1-2b` | 2,533,531,648 | apache-2.0 | US | safety | running |
| `ibm-granite/granite-guardian-3.2-3b-a800m` | 3,298,793,472 | apache-2.0 | US | safety (MoE) | running |
| `microsoft/Phi-4-mini-instruct` | 3,836,021,760 | mit | US | general | running |
| `HuggingFaceTB/SmolLM2-1.7B-Instruct` | 1,711,376,384 | apache-2.0 | EU/US | general | running |
| `HuggingFaceTB/SmolLM3-3B` | 3,075,098,624 | apache-2.0 | EU/US | general | running |
| `allenai/OLMo-2-0425-1B-Instruct` | 1,484,916,736 | apache-2.0 | US | general | running |
| `ibm-granite/granite-4.0-1b` | 1,631,750,144 | apache-2.0 | US | general | running |
| `ibm-granite/granite-4.0-micro` | 3,402,836,480 | apache-2.0 | US | general | running |
| `tiiuae/Falcon3-1B-Instruct` | 1,669,408,768 | **other** (Falcon LLM) | UAE | general | running |
| `tiiuae/Falcon3-3B-Instruct` | 3,227,655,168 | **other** (Falcon LLM) | UAE | general | running |
| `meta-llama/Llama-Guard-3-1B` | 1,498,482,688 | **llama3.2** (gated) | US | safety | queued |
| `google/shieldgemma-2b` | 2,614,341,888 | **gemma** (gated) | US | safety | queued |
| `google/gemma-3-4b-it` | 4,300,079,472 | **gemma** (gated) | US | general | queued |
| `google/gemma-3-1b-it` | 999,885,952 | **gemma** (gated) | US | general | queued |
| `meta-llama/Llama-3.2-3B-Instruct` | 3,212,749,824 | **llama3.2** (gated) | US | general | queued |
| `meta-llama/Llama-3.2-1B-Instruct` | 1,235,814,400 | **llama3.2** (gated) | US | general | queued |
| `meta-llama/Llama-Prompt-Guard-2-86M` | 278,810,882 | **other** (gated, 3rd group) | US | encoder | queued |
| `meta-llama/Llama-Prompt-Guard-2-22M` | 70,830,722 | **other** (gated, 3rd group) | US | encoder | queued |

All eight gated repos cleared 2026-09-23 ~23:40Z across three separate gating groups: Gemma
family, Llama 3.2, and a third covering Prompt Guard 2 (`licence: other`). A 403 rather than
401 is the signal that the token is valid but that repo's group is unaccepted.

**Encoder arm, final shape — and a claim to retract.** Three trained encoder classifiers
(DeBERTa injection-v2, Prompt Guard 2 at 22M and 86M) against two untrained MLM controls
(ModernBERT base, large). But **both Prompt Guards are `DebertaV2ForSequenceClassification`**
with default LABEL_0/LABEL_1, so all three trained encoders share the DeBERTa-v2 backbone
family. That is three *checkpoints*, not three *architectures*. Earlier framing that Prompt
Guard 2 supplied an "independent trained-encoder backbone" was wrong. The genuinely
independent encoder backbone in the cohort is ModernBERT, and it is a control rather than a
candidate. So a trained-encoder result still cannot be separated from a DeBERTa-family
result; it can only be shown to be non-checkpoint-specific within that family.

Notes on the cohort:

- **Qwen3-0.6B/1.7B/4B were dropped** on a non-China provenance constraint. They were the
  strongest ungated general models at their sizes; 12.72 GiB of weights downloaded, no GPU
  time spent. Consequence: with Gemma 3 and Llama 3.2 gated, the ungated non-China general
  field contains nothing that is both best-in-class for its size and permissively licensed.
- **Prompt Guard 2's repo names understate size.** "22M" is 70,830,722 params and "86M" is
  278,810,882 — the headline figures exclude embeddings.
- **Shieldstral carries a Pixtral vision encoder** (`Mistral3ForConditionalGeneration`), dead
  weight for a text-only task. Report full and text-tower-only footprints separately.
- **Llama Guard 3 1B has a genuine taxonomy mismatch. ShieldGemma does not.** Llama Guard's
  shipped template hardcodes S1–S13 (Violent Crimes, Non-Violent Crimes, Sex Crimes, Child
  Exploitation, Defamation, Specialized Advice, Privacy, Intellectual Property,
  Indiscriminate Weapons, Hate, Self-Harm, Sexual Content, Elections). **Nothing covers
  destructive tool calls, code execution or system damage** — the 8B model has an S14 "Code
  Interpreter Abuse" and the 1B's default list does not. S2 Non-Violent Crimes is the nearest
  fit and using it would be a manufactured mapping, so it was not used. Instead the
  template's documented `categories` hook carries a single category built from our I3 policy
  plus the Q2 block criterion, recorded verbatim, with
  `llamaguard_default_taxonomy_covers_task: false` in the run metadata. Readout is P(unsafe)
  vs P(safe) over first-token ids [20451, 39257] against [6220, 19193].
  ShieldGemma's chat template takes a `guideline` argument, so it is **policy-adaptable
  rather than fixed-taxonomy** — closer to Shieldstral than expected. Our I3 policy and block
  criterion were passed as the guideline, recorded verbatim, reading P(Yes) vs P(No).
- **Six arms need a licence-accepted HF token to fetch.** That is a real reproducibility cost
  and belongs in the Space writeup.
- **Community re-uploads of gated models were refused** — a mirror launders the provenance the
  licence column exists to record.

### Stage 0 results — the leakage gate, and the first scored arms

Run 2026-09-24 on the dev host, zero GPU. Scorer parity proven against the house method
before anything new was reported: OpenJev recomputed to 0.7023121387283237 (Δ 1.27e-09 from the
published 8-dp figure), `open-jev-qwen-2b` to 0.17194570135746606 exactly, the 27B confusion
matrix exactly, and its AUC on `P(block)` to 0.9480285133598713 with Δ 0.0.

**GATE: PASSED.** Prediction stated before measurement — both ModernBERT controls are untrained
`ModernBertForMaskedLM` backbones with no safety training and should land at chance. Computed
null band for 436 positives / 3,381 negatives (Hanley-McNeil, SE 0.014691343359335349):
**[0.471205496131191, 0.528794503868809]**.

| control | AUC | naive verdict |
|---|---|---|
| `control-modernbert-large` | 0.46228994190416495 | at chance ✓ |
| `control-modernbert-base` | 0.6622467295653802 | above chance, investigated |

The base control's excess is **entirely the length cue**, and length is not a label leak:
- It scores *below* a pure counting variable with zero semantic content (0.662 against 0.769).
  Spearman(score, prompt length) = 0.597867523607295.
- Within length quintiles both collapse to chance: base 0.5178408464714641, large
  0.49254286838283756.
- The two controls **disagree** (Pearson r = 0.1435084459826658) and sit on opposite sides of
  chance. A genuine corpus-level leak would be visible to both in the same direction.
- Readouts are near-degenerate: 53 and 46 distinct values, median exactly 0.5.

**No surface-cue or label-leakage signal. The escalation ladder is clear to proceed.**

**Nine of 19 candidates fail to clear the trivial floor at their shipped operating point** —
`olmo-2-1b-instruct`, `smollm3-3b`, `prompt-guard-2-22m`, `prompt-guard-2-86m` and
`granite-guardian-3.1-2b` all score exactly **0.0**, plus `llama-guard-3-1b`,
`shieldstral-1.0-3b`, `shieldgemma-2b` and `falcon3-3b-instruct`. An earlier count of eight
here was wrong.

Ranked on length-controlled AUC, the only measure here that is neither an oracle, nor a
trivial-baseline artifact, nor the flagged variable:

| rank | arm | AUC | length-controlled |
|---|---|---|---|
| **1** | `deberta-v3-prompt-injection-v2` | 0.8390509973434926 | **0.82393827900586** |
| 2 | `open-jev-qwen-2b` (best non-flagged, `P(block)`) | 0.5535215681805231 | 0.6045972185774873 |
| 3 | `control-modernbert-base` | 0.6622467295653802 | 0.5178408464714641 |
| 4 | `control-modernbert-large` | 0.46228994190416495 | 0.49254286838283756 |

Both controls rank last and the one real candidate ranks first — the shape a clean corpus
should produce.

**2-class arms have genuinely inapplicable variables.** DeBERTa and both controls emit one
scalar, so definitions A and B coincide (their AUC is not labelled), `risk` is the same
ordering, and `P(block)+P(confirm)` / `P(block)−P(confirm)` **do not exist**. Not computed, not
zero-filled. Their any-intervention F1 is identical to block-only by construction — reported as
an identity, not a second number.

**🚩 The 2B anchor's best variable under both definitions is `P(block) − P(confirm)`** (0.869 def
B, 0.826 def A) — the known-inverting variable. Not usable. Its honest non-flagged best is
`P(block)` at 0.5535215681805231. Note also its leaderboard variable `risk` is **0.37630349307652855,
below chance**.

**DeBERTa against the two reference points.** It beats the 2B anchor genuinely: shipped
0.21057810578105782 against 0.17194570135746606, but that margin is nearly all trivial-baseline
(DeBERTa clears the floor by 0.005546363481504557; the anchor falls 0.0330860409420872 below
it). The real win is discrimination — 0.839 against 0.554, or 0.824 against 0.605
length-controlled.

Against OpenJev it is far short. Shipped-to-shipped gap **0.4917340329472658**, i.e. 29.98% of
OpenJev. The sharper statement: **DeBERTa's in-sample oracle ceiling of 0.48 still falls
0.22231213872832367 short of OpenJev's honest shipped 0.7023121387283237** — 68.3% of it. Even
with a threshold fitted directly on the test labels it cannot reach OpenJev's real operating
point, so the gap is not a tuning problem.

**DeBERTa's 512-token limit: severe in extent, not the binding constraint.** The real cap is
`min(token_budget, max_position_embeddings − 2) = 510`. **17,202 of 30,310 rows (56.75%)**
exceeded it and were re-rendered to fit, losing context the model never saw.

Do not conflate that with the row-level `truncated` boolean, which is true for only **2,086
rows (6.88%)** and records something else entirely — it is a corpus request-build flag, and it
is byte-identical across all arms including the cap-6144 controls. A reader checking the field
named `truncated` against a claim of 56.75% would conclude the claim was wrong. The 56.75%
figure is the runner's own `shrunk` count. within the scored set 16,975 of 28,018 rows (60.59%) and **1,996 of 3,817 cases
(52.29%)** have at least one truncated event, 58 cases have every event truncated. But
truncation does **not** correlate with its errors: AUC 0.8017085164830626 within the truncated
stratum against 0.7771006013326832 untruncated — the truncated stratum is marginally *better*,
and F1 at the oracle threshold is indistinguishable (0.4799 against 0.4806). Raw recall and FPR
do differ, but positive prevalence differs 5.4× between strata, which is the driver. Mechanism
consistent with `build_ids`: the shrink trims event history while preserving the
decision-relevant current tool call.

**What actually holds DeBERTa back is calibration.** It emits `block` on 27,460/30,310 rows and
3,629/3,817 cases (95.1%); argmax at 0.5 is unusable and its oracle threshold sits at
0.9987551566979116. Its *ranking* is informative, its *operating point* is not. At 186.7
rows/min CPU-only int8 the deployment-relevant next step is threshold calibration on held-out
data, not a longer-context replacement.

Artifacts: `/home/ubuntu/cohort-scoring/` — `cohort-scores.json`, `leakage-diagnostic.json`,
`final-comparisons.json`, plus `score_cohort.py`, `leakage.py`, `final.py`.

### Laptop feasibility — measured, not estimated

CPU-only, `CUDA_VISIBLE_DEVICES=""`, 8 pinned threads. Decoders via GGUF Q4_K_M under
llama.cpp; encoders via dynamic-int8 transformers. All 11 decoder conversions and all 3
encoder quantizations succeeded. Latency model stated explicitly:
`row_latency = 1200/pp1200 + 1/tg32`, from `llama-bench -t 8 -p 1200 -n 32 -r 3`. The single
generated token is under 1% of latency in every case.

**Memory is not the discriminator.** Nothing in the cohort needs 24 GB, and nothing needs
even 8. The hungriest is Phi-4-mini at **3.137 GiB irreducible peak RSS** (5.048 GiB
worst-observed under mmap), so every model fits in 8 GB with at least 2.95 GiB spare. Q4_K_M
sizes run 0.871 GiB (OLMo-2-1B) to 2.323 GiB (Phi-4-mini). So "does it run on a laptop" is
**yes for the entire cohort**, and the question becomes whether any of them is accurate
enough.

**Throughput is the discriminator, and it is unflattering.** Rows/min at 8 threads:

| model | rows/min | | model | rows/min |
|---|---|---|---|---|
| OLMo-2-1B | 30.38 | | granite-guardian-3.2-3b-a800m | 11.98 |
| Falcon3-1B | 27.67 | | SmolLM3-3B | 11.40 |
| SmolLM2-1.7B | 19.35 | | Phi-4-mini | 10.08 |
| granite-4.0-1b | 18.83 | | Shieldstral (text tower) | 9.91 |
| Falcon3-3B | 13.68 | | granite-4.0-micro | 9.61 |
| granite-guardian-3.1-2b | 12.45 | | | |

A 3,000-row pass is **1h39m on the fastest and 5h12m on the slowest**.

**Encoders are ~6× faster, with a real catch.** DeBERTa-v3-base does **186.7 rows/min** int8 —
but at 512 tokens, its architectural maximum, so longer prompts must be truncated. That is a
functional limitation, not a free win. ModernBERT-base does **44.6 rows/min at the full 1200
tokens**, still 1.5× the best decoder.

**Shieldstral's vision tower separates completely.** Vision 403,305,472 params plus projector
16,778,240 = **10.91% dead weight** for a text-only task. llama.cpp's converter emits only the
text tower for `mistral3`: 236 tensors, exactly 3,429,006,336 elements, matching
`language_model` to the parameter, zero vision tensors. Text-only Q4_K_M is
**2,146,497,312 bytes (1.9991 GiB)** as a real file on disk; the vision side exports separately
as an 840,284,704-byte mmproj you never build. So Pixtral costs nothing, and Shieldstral's
laptop problem is speed, not footprint.

**Two caveats on these figures.** Peak RSS came from the kernel's `VmHWM` high-water mark
polled every 5 ms and cross-checked against `getrusage`, because there is no `/usr/bin/time`
on the host — the peak-RSS column already includes the weights and is **not additive** with
the Q4 size. And the studio carried ~31 of 96 cores of other load throughout, so there is
bandwidth contention that could not be removed. `llama-bench` deviations were under 4%, but a
real laptop also thermally throttles, so **every throughput figure is an optimistic ceiling.**

### Serving results worth reusing

For scoring-only workloads that never generate a token:

- `logits_to_keep=1` — without it a batch materialises `[batch, seq, vocab]` logits and
  cannot fit.
- `use_cache=False` — a KV cache wastes ~31 GB on a 3B model here.
- **The token budget binds, not the batch count.** `max_batch` 32 against 128 gave 291.8 vs
  271.6 rows/min. Batches average 28 against a max of 32.
- Encoder classifiers run ~8× faster than generative arms (3,059 vs ~1,190 rows/min
  aggregate) because there is no generation step.

---

## Infrastructure incidents

**2026-09-23 22:47Z — token cap destroyed a run.** `benchmark_run_system_one.py` defaults to
`--max-input-tokens 200_000_000`; a full 100,001-request s3 pass needs ~282M. The
`open-jev-qwen-2b` s3 driver measured 200,018,264 and raised
`RuntimeError: measured provider usage exceeded the cap` **after** completing all requests,
so no meta was written. On disk: rows 1–70,833 clean, then `route: "error"` with
`error_code: provider_budget_exceeded` on rows 70,834–100,001 — exactly trailing and
contiguous. **Recoverable in place:** all error rows pass the prediction schema and carry a
valid recomputed `request_sha256`, so `--resume --resume-retry-errors` truncates to the clean
prefix and continues. Caveat: `dropping` latches at the *first* error row anywhere, so an
isolated earlier transient error would drop everything after it — check with
`sysone/reshard/check_recoverable.py <body> <model> <run_id>`. The budget is **per driver**,
so sharding avoids the cap for free.

**2026-09-23 23:07Z — a third party's queued job died from invisible contention.**
`cisco-jev-q-smoke-04` was handed card 0 while a directly-pinned sweep held 127,841 of
143,771 MiB. vLLM reserves ~90% of card memory by default, so its engine core failed to
initialise; `rc=4` after 60s with **no "out of memory" string in the log**. Root cause: the
queue reports worker liveness, not card availability, and `dispatch.sh` cannot see pinned
processes. Mitigations added: `queue/RESERVATIONS.json`, surfaced at the top of
`queue/status.sh`, plus a `gpu-queue` skill. **Card affinity for `qadd` is still missing**
(deferred — a schema change is unsafe while other agents are submitting).

**Nimble reshard, uncommitted-boundary design.** `shard0` walks forward from case 0 while
replicas claim chunks backward from case 24,476; `shard0`'s obligation is only to cover up to
the lowest claimed chunk, so every claim shrinks its target and both halves finish together
for any rate ratio. Rate went 140 → 409 rows/min, ETA 10.5 h → ~3.1 h. When a co-tenant
slowed `shard0` from 132 to 77.5 rows/min the pool silently absorbed 1,508 more requests.

**Max utilisation costs something.** Pushing aggregate SM from 46.1% to 99.1% by co-locating
the cohort slowed nimble's `shard0` by 41%. Sensitivity: evicting a co-tenant buys ~22 min,
total loss of `shard0` costs ~44 min. The trade is real, bounded, and worth stating rather
than treating the utilisation number as free.

---

## Publication record — System One Space

**2026-09-24 09:41Z, rev `c11a65bcc85ca7548e4d418249af2eb9c554bc87`** (parent
`ec65348100cdf321ef8759912e985c0bcaac9088`). Public before and after, visibility read at gate 3
and gate 5 and unchanged. 19 files, 2,223,068 payload bytes, 102 SVG elements.

Added: `open-jev-qwen-27b` (rank 4 of 11) and `kev-9b` (rank 11 of 11) as ranked rows, plus a
re-thresholding section and a held-out-corpus section for `bespoke-nimble-9b`. Gates: 971 figure
assertions / 0 mismatches; verifier 14 pages / 0 problems / 810 internal links / 93 retired
figures absent; payload guard PASS, and also PASS with the first-party protocol exemption off for
every page except `prompts.html`.

Artifact work this required, none of it a re-run:

- `open-jev-qwen-27b`'s H200 scorecard carried only `candidates[0].system_one`. The leaderboard
  column reads `deterministic_then_system_one`, so it was re-scored by `benchmark_score_system_one.py`
  against `deterministic-real/s2-run/predictions.jsonl` and `s2/gemma4-c7.jsonl`. Every rebuilt
  cell matches the independently assembled comparison row.
- `kev-9b`'s settled body lived only under `rescoring-remine/kev-s2/`. Staged to
  `outputs/kev/s2-settled/` by `05-settlement/stage_kev_9b.py` after ten checks, then scored,
  and its AUC file regenerated by `sysone-auc_variants.py`. **That script reproduces the
  independent re-mining pass exactly**: 0.8262192391914883 / 0.6554552016259236 /
  0.590903293906314 / 0.6542215809339292, identical at full precision from two code paths.
- Neither run meta carried `display_name`, `repo_id`, `repo_revision`, `base_model`,
  `base_revision`, `license` or `errors_by_code`, and `27b`'s serving record had no nested
  `served` / `serving` blocks. All composed additively from provenance already on disk, each key
  logged with its source under `meta_augmented`; `prediction_sha256` still covers each body.
  `27b`'s four replica startup records were checked to agree field by field first.

**Correction found while doing it — the provider-spend rollup double-counted six runs.** Six runs
have their manifest at two paths at the same `run_id` and body digest (a staged copy beside a
guard payload, a pre-settlement copy beside the settled one, a resume ledger beside the run it
resumed), so 151,608 requests were counted twice. Now deduped by `(run_id, prediction_sha256)`.
Which copy is kept has to be *chosen*: the SecJudge pair records `model` as `nghodki/SecJudge` at
one path and `secjudge` at the other, and only the stem is on the roster, so path order dropped
SecJudge out of the reported families. One of the 35 `fault-inject-mock` manifests was also a
duplicate pair, so the rollup's shrink guard fired and its floor moved to 34 / 1,972 with the
duplicate named in code. **No dollar total moved.** Requests 1,739,149 → 1,808,873, reported
manifests 171 → 168, error rate 0.00190% → 0.00182% on an unchanged 33 errors.

Other derived counts moved because six run manifests have landed under `outputs/` since the
previous upload, four of them from other work: manifests found 319 → 325, reported families 9 →
11, shard manifests set aside 24 → 29, added arms 6 → 8, ranked rows 8 → 11, assertions 787 →
971, artifacts read 193 → 211. `_wordcount.json` was stale — it omitted two pages and predated
three uploads — and was regenerated over all 14 pages (147,167 words).

**Licence discrepancy, unresolved.** The Programme 2 cohort table below records
`open-jev-qwen-2b` and `open-jev-qwen-27b` as **CC BY-NC 4.0**. `cardData.license` on
`ZefanCai/Open-Jev-2B` and `ZefanCai/Open-Jev-27B-v1.1` reads **apache-2.0**, and the Space
publishes the cardData value with the repo and revision it was read from, which is what the 2B
row already did before this change. One of the two records is wrong and the Space is currently
consistent with the cardData one. Resolve before any redistribution decision rests on it.

**Not published.** `kev-9b`'s 0.6092050209205021 and the four other `P(block) − P(confirm)`
ceilings, each named on the page beside the durable ceiling it exceeds. `decider-2b` remains off
the board: it has a settled scorecard and a comparison row but no registry entry, and adding it
was outside the scope of this change.

Per-case detail on the payload: `compare.html` carries a pre-existing coded matrix under
`id="bench-data"` — one row per case of `[grade, surface, n_events, dataset, openjev, diffgemma,
gemma4, deterministic, adjudicator]`, all integer indices, no case id and no corpus text. It was
already public at `ec65348100cd` and this change does not touch it. Flagging it because the
aggregate-only rule is stated in absolute terms and this is the closest thing on the payload to
row detail.

---

## Open items

- Publish further System One s3 rows as they settle. Only `bespoke-nimble-9b` has a settled s3
  counterpart on the board so far; the s3 section is built to take more.
- Resolve the `open-jev-qwen-*` licence discrepancy above: cohort table CC BY-NC 4.0 against
  `cardData.license` apache-2.0.
- Decide whether `decider-2b` becomes a board row. Its artifacts are complete except for a
  scorecard with the deterministic node, which is one re-score away.
- `Llama-Prompt-Guard-2-22M/86M` need a third gating group accepted (403, not 401).
- Card affinity for `qadd`.
- Four archive licence/secret-hygiene decisions (see task #54).
- Whether the non-China provenance constraint applies to the board as well as the cohort.
  OpenJev (rank 2) and `open-jev-qwen-27b` (best re-thresholded) are both Qwen derivatives
  under CC BY-NC 4.0, so if the constraint is real for deployment, the two strongest results
  in the programme are unshippable.
