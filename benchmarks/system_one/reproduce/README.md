# DefenseClaw System One - reproduction bundle

This bundle holds the scripts and provenance records that are **not** in the public
repository. Together with the public `benchmarks/` tree it is the full chain behind one
ranked leaderboard row.

## Where the other half lives

Repository: `cisco-ai-defense/defenseclaw` (public). The benchmark work is on a branch -
`main` does not carry it.

- Browsable branch tree: <https://github.com/cisco-ai-defense/defenseclaw/tree/feat/system-one-benchmarks/benchmarks>
- Commit-pinned tree (a branch moves; use this to reproduce): <https://github.com/cisco-ai-defense/defenseclaw/tree/d2ae73f32736db0aa9fd8e78d5656355c1a41012/benchmarks>

Branch head at bundle time: `d2ae73f32736db0aa9fd8e78d5656355c1a41012`.

### The code paths, and which ref serves them

| path | on branch | on `main` |
|---|---|---|
| `benchmarks/scripts/benchmark_run_system_one.py` | yes | **404** |
| `benchmarks/scripts/benchmark_score_system_one.py` | yes | **404** |
| `benchmarks/system_one/contexts-v1.json` | yes | **404** |
| `benchmarks/system_one/questions-v1.json` | yes | **404** |
| `benchmarks/system_one/questions-v2.json` | yes | **404** |
| `benchmarks/datasets.lock.json` | yes | yes (**and `main` is the copy that was used**) |
| `benchmarks/coverage-report.mapping.json` | yes | yes |

The protocol files are at `benchmarks/system_one/`. Any citation of `protocol/v1/` or
`protocol/v2/` is wrong - those directories exist on neither ref.

## The dataset lock: read this before citing it

**Three copies of `benchmarks/datasets.lock.json` differ, and the two deep links above do
not serve the one that was used.**

| copy | sha256 (first 16) | entries | `enabled: false` |
|---|---|---|---|
| `origin/main` | `6ae524117b304760` | 91 | **14** |
| branch `d2ae73f` | `a5d79911072ec6df` | 91 | 11 |
| local working tree (uncommitted) | `48a6639433402efc` | 92 | 12 |

`origin/main` is **byte-identical** to the copy the site build actually read
(`build.py` resolves it at line 8537), so the site's licence statements describe `main`.
Four licence-relevant entries diverge on the branch:

| entry | `main` (used) | branch (served by the deep links) |
|---|---|---|
| `mcptox` | enabled `false`, `review-required`, `review_required` | enabled `true`, `other`, **`approved`** |
| `msb` | enabled `false`, `review-required`, `review_required` | enabled `true`, `MIT`, **`approved`** |
| `agent-trace` | enabled `false`, Apache-2.0, `review_required` | enabled `true`, Apache-2.0, **`approved`** |
| `assay` | enabled `false`, `review-required`, `review_required` | enabled `false`, `MIT`, **`approved`** |

`mcptox` is the serious one. The corpus's own manifest - which the Space already cites -
records `"license": "unresolved"`, `"license_note": "Upstream repository ships no LICENSE
file. License is unresolved."` and `"local_evaluation_only": true`. The branch copy marks
that entry `enabled: true` / `approved`, contradicting the corpus's own manifest.

**Therefore: cite the lock by sha, or cite `main` for that one file.** Do not present the
branch lock as the lock that was used. Reconciling this needs `main`'s lock committed onto
the branch so one commit-pinned ref carries both code and lock; that is a commit to a
shared branch and is the repository owner's decision.

Note also that 91/14 becomes 92/15 the moment the uncommitted local entry lands.

### The uncommitted entry, and why committing it is not sufficient

The working-tree copy adds `robustintelligence/augur_unsafe_tool_input_eval`, which was
genuinely used: it is the `source.dataset` of `toolcall-labels` (9,999 cases) and
`intent-ablation` (18,322 pairs). But the entry is written `enabled: false` /
`license_status: review_required`, and `benchmarks/scripts/benchmark_normalize.py:982`
hard-fails on exactly that combination:

    if entry.get("enabled") is not True or entry.get("license_status") != "approved":
        raise ValueError(f"{dataset_id}: dataset is not enabled and license-approved")

So an outsider with the public scripts and the committed lock **still could not** rebuild
those two corpora: they were produced by a path that bypassed the lock's own gate.
Committing the entry is necessary and not sufficient - its `enabled` and `license_status`
have to be reconciled too.

**Scope limit:** `s2/cases.manifest.json` does not reference augur, so the **ranked row
does not depend on it**. This defect blocks the Q4 toolcall-labels and intent-ablation
findings only.

## Environment pins

`00-environment/requirements-frozen.client-venv.txt` is **34 packages of the harness client
venv only** - `boto3`, `botocore`, `huggingface_hub`, `httpx`, `pyarrow`, `pytest`,
`PyYAML`, `tqdm` and transitive deps. It contains **no `torch`, no `vllm`, no
`transformers`, no `tokenizers`, no `accelerate`, no `peft`**. It pins the client that
*called* the models, not the stack that *served* them, so it supports re-running scoring
against given predictions and nothing more.

**The serving environment is pinned in no lockfile anywhere.** What real versions exist were
recovered per arm from each run meta and settled serving contract, and are collected in
`00-environment/pinned-stack-by-arm.json`:

| arm | recovered pins | source |
|---|---|---|
| `open-jev-qwen-2b`, `open-jev-qwen-9b` | `transformers 5.10.2`, `peft 0.19.1` | run meta + serving contract |
| `bespoke-nimble-9b` | `transformers 5.17.0`, `peft 0.21.0` | run meta + serving contract |
| `gemma-4-26B-A4B-it`, `jevify-gemma4-26b-a4b` | `torch 2.13.0+cu130`, `cuda 13.0` - **no transformers/peft pin** | serving contract |
| `secjudge` | **none recorded**; fp32 on CPU | serving contract |

## Placeholders

Operational detail is replaced, not deleted, so the structure still reads:

| Placeholder | Meaning |
|---|---|
| `<GPU_HOST>` | address of the 4x NVIDIA L40S serving host |
| `<SSH_KEY>` | path to the private key used to reach `<GPU_HOST>` |
| `$WORK` | operator home root that held `.system-one-data/` and `.system-one-space-build/` |

`127.0.0.1` is retained deliberately: every model is served on loopback and reached over an
`ssh -L` tunnel, so the address is part of the contract, not a host detail. Environment
variable **names** (`SYSONE_NO_KEY`, `CHEAP_KEY`) are retained; no value is present anywhere.
`/opt/dlami/nvme/` is left verbatim because it is a mount point, not an identity: it is the
GPU host's instance-store scratch holding `HF_HOME` and the staged checkpoints. Repoint it
at any fast local disk.

## No dataset content

Scripts here reference datasets **by id and revision only**. No rows, prompts, case text,
tool-call arguments or provider rationales are included; this was verified mechanically
against the payload guard's own corpus index (see `MANIFEST.json :: scrub.verified_absent`).

## Reading order

| Stage | What it establishes |
|---|---|
| `00-environment/` | environment pins, and what they do not cover |
| `01-dataset-lock/` | pinned model revisions and checkpoint fetch |
| `02-case-construction/` | case construction, serialisation, truncation, length/template gates |
| `03-serving/` | serving per model family; `contracts/` holds the settled serving provenance |
| `04-run/` | the run, and its progress/row gates |
| `05-settlement/` | settlement and settled-file discipline |
| `06-scoring/` | scoring through the shared scorer |
| `07-analysis/` | recall@FPR, calibration, registry and report builders |
| `08-site-build/` | site build and payload verification |

`03-serving/contracts/*.serving.json` are the load-bearing provenance records: attention
implementation, prefix-cache state **and the reason for it**, dtype, device map, replica
topology, temperature, chat-template digest and pinned stack versions.

## Known gaps for an outside reproducer

1. **48 of the 77 enabled datasets are `fetch: manual`**, and 69 of 77 are
   `redistribution: download-only` (counts against `main`'s lock, the one that was used).
   Nothing here can redistribute them; a ranked row requires clearing those acquisitions
   first. This is the largest single barrier.
2. **`nghodki/SecJudge` is `gated: manual`.** Without publisher approval the SecJudge arm
   cannot be fetched at all.
3. **The SecJudge row can never be reproduced exactly.** Its contract records
   `"base_revision": "not declared by the publisher"` for `answerdotai/ModernBERT-large`:
   SecJudge ships full fine-tuned weights and its card pins no base revision. No bundle can
   fill that hole.
4. **The serving stack is pinned in no lockfile** (see Environment pins). Two arms have no
   `transformers`/`peft` pin and SecJudge has none at all.
5. **The lock refs are split** (see above): the code is only on the branch, the correct lock
   only on `main`.
6. **`toolcall-labels` and `intent-ablation` cannot be rebuilt** from the public scripts plus
   the lock as written (see above). The ranked row is unaffected.
7. **`08-site-build/guard.py` is reference only, not payload-safe.** Its own detector table
   contains a private-key regex (line 99) and a CJK character class, so it matches its own
   credential and CJK checks. Read it here; do not ship it.
8. **`08-site-build/build.py` is a point-in-time copy** of a file that was under active edit
   when this bundle was staged. Re-copy it, re-scrub it and regenerate `MANIFEST.json`
   before publishing - see `MANIFEST.json :: restage_required`.
9. **Hardware.** The serving topologies assume 4x L40S (46 GiB each); the 27B arm shards a
   base model that does not fit on one card.
10. **`open-jev-qwen-27b` has no settled artifacts yet.** Its serving contract must be added
    to `03-serving/contracts/` once that arm settles.

## What an outsider can actually do

- **Audit the whole chain** end to end: yes, from these scripts plus the branch code.
- **Re-score published predictions** with the shared scorer: yes - that is what the frozen
  client venv supports.
- **Reproduce a ranked row**: only after clearing 48 manual dataset acquisitions, and only
  approximately for the two arms whose serving stack carries no `transformers`/`peft` pin.
- **Reproduce the SecJudge row exactly**: never, because its base revision was never
  declared by the publisher.
