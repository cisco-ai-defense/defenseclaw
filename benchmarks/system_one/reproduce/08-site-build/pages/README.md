---
title: Tool-call guard benchmark
emoji: 🛡️
colorFrom: blue
colorTo: gray
sdk: static
app_file: index.html
pinned: false
license: other
short_description: Which small model guards an agent's tool calls
---

# Tool-call guard benchmark

Small models scored on one question: is this agent's next tool call safe to run?
**Gemma 4 26B-A4B** on Bedrock is the incumbent LLM judge the candidates are measured against and
carries no rank. `index.html` holds the leaderboard, and the roster below is generated from the
same records it ranks.

{{ui:roster_md}}

## Pages

| Page | What it covers |
| --- | --- |
| `index.html` | Every arm at one common operating point, with the all-allow baseline and the block-everything floor beside it; arms grouped by parameter count and ranked inside each band; AUC per arm with its aggregation definition and the chance band; each arm at its own best threshold, labelled an oracle upper bound; the leaderboard at each arm's shipped threshold with the lens control; the candidate roster; the arms added after the first publication; the shipped-against-re-thresholded figures with the trivial floor and the held-out designs; bespoke-nimble-9b on the second corpus; the SecJudge row and what it discloses; Von against the block-everything floor; and where a model sits in the cascade. |
| `examples.html` | Head-to-head cases where one model beats another, adjudicated by a third model blinded to the votes, plus the three code-level failures quoted from source. |
| `finding-intent.html` | The intent measurement: eight negative runs on AgentDojo, then a reversal on proof-backed data across all four models, with the control and the recall bound. |
| `finding-architecture.html` | Cascade and routing results: tier order, one-sided and two-sided routing, the four measured allow-thresholds, per-surface thresholds, escalate-on-confirm, per-call and per-session enforcement, question format, the disagreement queue, rule mining. |
| `finding-safety.html` | Injected failures and where they resolve, the two question formats that fail open, the promotion gate, resume validation, Lane B on benign traffic, repeatability. |
| `finding-performance.html` | Latency as queueing, the prefix-cache negative result, the cheap service tier, Von's rejection, and cost. |
| `finding-data.html` | The two scored corpora with their prevalences, digests, grade composition and the rule that assigned every label; why the measurement was not previously possible, what was normalised, the grade-A supply correction, and what was rejected. |
| `prompts.html` | The prompt contract: four instruction variants, five question variants and ten context variants as sent, with the measured effect of each, plus one synthetic filled request. |
| `recommendations.html` | Recommendations with evidence, measured gain, effort and risk, under three headings: immediate, other, not recommended. |
| `experiments.html` | Every experiment in one sortable table: question, method, scale, headline result, status. Negative results carry equal weight. |
| `glossary.html` | Contexts C0–CD, questions Q0–Q4, instructions I0–I3, truth grades A–E, the two scoring lenses, the separation statistics, family identity, routing terms, and the models. |
| `reproduce.html` | Which dataset repo holds what, where the code is, the seeds and model revisions, and every figure restated during this work. |

## Interactive controls

Two controls, both driven by already-measured data emitted as a JSON blob in `<head>`. No framework,
no external file, no `script src=`.

- **Lens control** (`index.html`) flips every switchable cell between the block-only and
  any-intervention lenses and re-ranks the leaderboard, because the ranking is different under each.
- **Threshold slider** (`finding-architecture.html`) snaps to the four allow-threshold settings that
  were actually run — 0.05, 0.10, 0.20, 0.30 — and moves block F1, block FPR, confirm rate and LLM
  call rate together. Nothing between those four points was measured and nothing is interpolated.

With scripting disabled both pages render a usable default state: the block-only lens and the 0.30
threshold column. The verifier checks that by stripping every `<script>` and re-reading the page.

## How the numbers get here

One Python script reads the analysis JSONs on disk, renders every chart as hand-written inline SVG,
and substitutes values into the page templates. It aborts rather than shipping a wrong or missing
figure:

- **Figure assertion checks** — (file, key path, expected value) triples, counted in
  `_build-figures.json` as `assertions_checked`. Any disagreement between an artifact and an
  asserted figure stops the build and nothing is written.
- **Unresolved-token check** — a placeholder with no value aborts the build.
- **Label-fit and layout check** — every label is width-estimated against its gutter and against the
  chart canvas, and every text run is checked for overlap with another text run and for straddling
  the edge of a `<rect>`. Any of those aborts the build.
- **Link and structure check** — every internal link must resolve to an existing page *and* anchor.
  Tag balance, external-resource, `script src=` and no-JS-fallback checks all run before upload.
- **Payload guard** — every file is scanned against an index built from the corpora themselves
  (117,848 rows, 201,106 case ids, 2.2M sensitive-text shingles) plus CJK and credential patterns.
  A hit aborts the upload.

`_build-figures.json` is the machine-readable audit trail: every substituted value, every artifact
read, and the assertion count.

Each chart names the exact artifact and key path it was drawn from, and carries a **Table view**
containing every plotted value, so the picture is never the only record of a number.

## Constraints this site respects

- **Evaluation-only.** Nothing here is approved for training, synthetic generation, teacher context,
  distillation, or redistribution.
- **Aggregate metrics only for the proof-backed corpus.** One corpus is licensed
  `redistribution: aggregate-only` with a publication restriction of local-evaluation-only. Rates,
  counts and intervals appear here; no case, user request, tool call, tool description or risk
  description does.
- **Templates published, instantiations withheld.** The 33 files of filled-in prompts each embed a
  corpus row, so `prompts.html` publishes the templates and one clearly labelled synthetic
  instantiation.
- **Disagreement-queue cases published as coded rows.** Every row is `redistribution:
  download-only`, so `compare.html` carries truth grade, surface, event count, source dataset name,
  the four votes and the adjudicator's verdict as small integers into printed code tables, and none
  of the payload. This is the one place per-case structure is published, and the redistribution rule
  carries an explicit carve-out for coded contingency data that carries no identifier and no text.
  The 2,133 rows collapse to 500 distinct tuples; `reproduce.html` states the rule and the carve-out
  together.
- **No external assets.** No CDN, no web fonts, no image files, no `script src=`. Inline SVG, one
  inlined stylesheet, and inline JavaScript that the pages work without. Dark and light are both
  selected palettes via `prefers-color-scheme`, not an automatic inversion.

## Sources and artifacts

The 13 source datasets are public, pinned by revision in `benchmarks/datasets.lock.json`, and
linked from `reproduce.html`. All are `download-only`, so this site links them and republishes none
of their rows. One, the coding-agent security benchmark, is **CC-BY-NC-4.0** and is flagged as the
only non-commercial source.

The derived analysis artifacts every number is drawn from are held privately and are available on
request. Each figure carries its file and key path as provenance, not as a download location.
