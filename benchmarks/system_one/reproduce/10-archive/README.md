# 10-archive — staging, payload guard, upload, and post-upload verification

The tooling that moved evidence off individually-losable hosts and into the private HuggingFace
dataset repositories, and the checks that ran on either side of it. Vendored from
`defenseclaw-dev:$WORK/`.

This directory is the answer to "is the data backed up, and how would we do it again".

## The split convention

Every stager here follows the same rule, and it is the rule the repos are already organised
under:

- raw predictions + run metas/plans → **`Vineethsain/defenseclaw-system-one-predictions-v1`**
  under `predictions/<stage>/`
- analyses, scorecards, gates, digests → **`Vineethsain/defenseclaw-system-one-evaluations-v1`**
- corpora and request bodies → **`Vineethsain/defenseclaw-system-one-corpora-v1`**
- the laptop-class cohort, all of it → **`Vineethsain/defenseclaw-slm-toolcall-v1`**

All four are **private**. Nothing here publishes to a public repo.

## Scripts

| script | what it does |
|---|---|
| `stage_and_upload.py` | Stages the hosted-Jev evidence and publishes it to the two existing private repos. |
| `stage_backfill.py` | Backfills everything produced after the repos were last written. Written because the repos held three arms while the rest lived only on hosts that can be lost. |
| `stage_qwen.py` | Stages the three adapter arms' evidence on the same convention. |
| `settle_context.py` | Settles one body whose meta predates the schema generation that added `complete` / `actual_input_tokens`, **without** rewriting provenance that is already published. |
| `jev_guard.py` | Payload guard over everything staged for the two private repos: row guard (reuses the programme's own `guard2.py` `guard_file()` on every new prediction body), plus CJK and credential layers. Writes to new result paths — it never overwrites an existing guard-results file. |
| `build_manifests.py` | Builds `MANIFEST-*.json` and `SHA256SUMS-*.txt` for a staged bundle, mapping each staged repo path to its studio-verified record. |
| `do_upload.py` | Performs the upload. |
| `push_card.py` | Pushes the dataset card. |
| `verify_after.py` | Re-reads the repo after upload and verifies what landed. |
| `claims_check.py`, `claims_check2.py`, `floor_check.py`, `final_state.py` | Verify specific published claims against the staged evidence before it is cited. |
| `mkmanifest.py` | Regenerates `../MANIFEST.json`. Its purpose table is hand-kept: add a row for every new file before running it. |
| `guard_probe.py` | The payload guard `mkmanifest.py` uses to set `payload_safe`. It indexes the corpora, so it only runs on `defenseclaw-dev`. Its own detector table matches its credential check, so, like `../08-site-build/guard.py`, it is reference only. |
| `corpora-maintenance/` | Two jobs run against the private corpora repo after upload: `ds_job.py` removes the augur-derived corpora, `redact_job.py` ships the credential-redacted TerminalBench corpora. Each has a `*_verify.py`. The redaction fixtures hold a fake `hf_` token, split into two halves on vendoring for the same reason as `stage_backfill.py` below. |

## One deliberate divergence from the host copy

`stage_backfill.py` holds a **synthetic** AWS access key id as a constant named
`SYNTHETIC_CRED`. It is SecJudge's own worked example, published verbatim in that publisher's
public model card, and the script's job is to **redact** it out of three staged files so the
private repos stay clean under the programme's own credential scan. It grants nothing.

On vendoring, the literal was split into two concatenated halves so that *this file* does not
carry a credential-shaped token into the repository — GitHub push protection and the programme's
scanner both match the whole form. **The value is identical and the behaviour is unchanged.** The
comment in the file says the same thing at the point of use. The host copy at
`$WORK/stage_backfill.py` therefore differs from this one by exactly that one line.

## What is and is not in the backup

**Backed up:** the settled prediction bodies and their metas, the corpora, the request bodies, the
scorecards and analyses, the manifests and `SHA256SUMS`. The digests in the HF `SHA256SUMS` files
match the `prediction_sha256` values the published Spaces were computed from — that has been
checked, not assumed.

**The last gap, closed 2026-09-24:** the merged OpenJev s3 body `outputs/s3/openjev-full.jsonl`
(run `s3-openjev-merged`, 100,001 rows, sha256
`cbe2db0fd78ae35e8c9fd7f0b14bdfa5248553bd2ea5702ad3c763e004dd40cd`). Only its meta and its five shards
had been staged, and the shards do not reproduce it byte for byte. It passed `guard2.guard_file()`
with 0 failures and is now at `defenseclaw-system-one-predictions-v1:predictions/s3/openjev-full.jsonl`.

**Withheld by policy, not missing:** `outputs/s2-adjudication/adjudication-{in,out}.jsonl` (raw
reviewer prompts and rationales; the parsed labels are in
`defenseclaw-toolcall-security-labels-v1`), and `outputs/s1-n1000/full1000-{openjev,diffgemma}.jsonl`
(abandoned incomplete at 2,952 and 9,691 of their planned requests, with no meta; incomplete
live outputs are never uploaded).

**Not backed up, by decision:** model weights. They are re-downloadable from the pinned repos and
revisions in `../../../slm_toolcall/harness/weights_manifest{,2,3,4}.json` and in the System One
arm registry, and they are large. A restore needs network access to HuggingFace for weights.

**Not reproducible at all:** the CPU/laptop RSS and throughput measurements. The scripts that
produced them were never saved; only their logs survive. This is stated on the Space's footprint
page as well.
