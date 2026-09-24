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

Small models scored as the middle tier of a tool-call guard cascade: deterministic rules, then a
small model, then the Gemma 4 judge on the cases the small model is unsure of. Every model is
ranked at one shared false-block budget on the Broad comparison corpus; `index.html` carries the
table and the recommended stack.

{{ui:roster_md}}

The recommended stack is `rules → OpenJev → Gemma 4 judge`, two-sided routing at 0.30, with a
rule-engine `confirm` escalated rather than ending the cascade: block-only F1
{{fig:lb.casc_esc.f1}} at block FPR {{fig:lb.casc_esc.fpr}}, with the judge called on {{fig:s2.twosided.llm}} of cases. OpenJev weights are CC BY-NC 4.0:
non-commercial, attribution required, contact the authors for commercial use.

## Pages

| Page | What it covers |
| --- | --- |
| `index.html` | Which model: the answer, every model at the shared budget, precision-recall curves, size, calibration, notes on individual models. |
| `decide.html` | Deploy: the cascade, routing, threshold, tier order, traffic mix, per-call enforcement, cost, latency, the calculator and the twelve recommendations. |
| `risks.html` | Failure handling, the fail-open question formats, the promotion gate, resume validation, benign over-flagging, repeatability and the disagreement queue. |
| `intent.html` | The intent check: eight negative AgentDojo runs, the reversal on proof-backed data, the control, and the recall limit. |
| `method.html` | The scored corpora and labels, how a figure is scored, why question format is held fixed, the prompt contract, the data inventory and a glossary. |
| `reproduce.html` | Sources and licences, code paths, seeds, settled-file rules, a worked reproduction, the experiment ledger and restated figures. |

## How the numbers get here

One Python script reads the analysis artifacts, renders every chart as inline SVG and substitutes
values into the page templates. It aborts rather than ship a wrong or missing figure: every
asserted figure is checked against its artifact, every placeholder must resolve, every internal
link must reach a page and an anchor, and a payload guard scans every file against the corpora for
case ids, verbatim text, CJK and credentials before upload. Figures are published at reading
precision with the exact artifact value kept in the page; `_build-figures.json` is the audit trail.

## Constraints

- **Evaluation-only.** Nothing here is approved for training, synthetic generation, teacher
  context, distillation or redistribution.
- **Aggregate metrics only for the proof-backed corpus.** Rates, counts and intervals appear here;
  no case, request, tool call or description does.
- **Templates published, instantiations withheld.** Filled-in prompts embed corpus rows, so
  `method.html` publishes the templates and one synthetic instantiation.
- **One coded per-case table.** The disagreement queue on `risks.html` is published as small
  integers into printed code tables, with no identifier and no corpus text, under an explicit
  carve-out stated on `reproduce.html`.
- **No external assets.** No CDN, fonts, images or `script src=`.

The 13 source datasets are public, pinned in `benchmarks/datasets.lock.json` and linked from
`reproduce.html`. One, the coding-agent security benchmark, is **CC-BY-NC-4.0**, the only
non-commercial source. The derived analysis artifacts are held privately and are available on
request.
