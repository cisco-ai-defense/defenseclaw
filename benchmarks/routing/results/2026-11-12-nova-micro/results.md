# Router eval results (2026-11-12T20:31:50Z)

Eval items: 555. Adversarial items: 358. Prices: placeholder-2026-11-12.1. System One backend: stand-in: Amazon Nova Micro via Bedrock (backend us.amazon.nova-micro-v1:0). Hybrid: System One within 300ms and confidence >= 0.60, else rules.

Guardrail narrowing signal (shipped regex rule pack): recall on sensitive items 45.0%, narrowing on non-sensitive items 0.0%.
In-process keyword vs vLLM SR container agreement (category and alias): 99.8% of 555 eval items, 98.6% of 358 adversarial items.

| classifier | macro-F1 | accuracy | errors | p50 ms | p95 ms | flip rate | upgrade flips | leak flips | sensitive leaks after filter (default / restricted / local_only) | profile violations after filter | quality (default) | cost/1k | cost/1k at 95% of strong | saving vs strong |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| hybrid | 0.508 | 0.514 | 0.0% | 300.26 | 301.31 | 28.8% | 102/220 | 1/138 | 35 / 35 / 0 | 0 | 0.773 | $3.30 | $7.50 | 25% |
| hybrid@1s | 0.694 | 0.705 | 0.0% | 512.42 | 644.24 | 29.3% | 89/220 | 16/138 | 19 / 19 / 0 | 0 | 0.858 | $4.67 | $6.12 | 39% |
| keyword | 0.508 | 0.514 | 0.0% | 0.26 | 1.31 | 28.8% | 102/220 | 1/138 | 35 / 35 / 0 | 0 | 0.773 | $3.30 | $7.50 | 25% |
| systemone | 0.617 | 0.535 | 41.4% | 512.12 | 643.91 | 33.8% | 43/106 | 1/24 | 25 / 25 / 0 | 0 | 0.944 | $7.96 | $7.96 | 21% |
| vllm_sr | 0.507 | 0.514 | 0.0% | 1.13 | 3.27 | 28.8% | 102/220 | 1/138 | 35 / 35 / 0 | 0 | 0.773 | $3.30 | $7.50 | 25% |

Strong-model reference (every request asks for strong; guardrail narrowing and the default profile apply): $10.05 per 1k at quality 0.921; target quality 0.875. Label-perfect ceiling (strong, local for sensitive): $9.47 at 1.000. All fast: $0.26 per 1k at quality 0.477.
Profile violations after filter are an invariant of the filter (property-tested), shown as a check. Flips exclude pairs where the base or the variant errored.

## Per-category F1

| classifier | coding | reasoning | chat | summarize | sensitive | tool_heavy | cheap_fast |
| --- | --- | --- | --- | --- | --- | --- | --- |
| hybrid | 0.60 | 0.52 | 0.49 | 0.58 | 0.50 | 0.35 | 0.51 |
| hybrid@1s | 0.68 | 0.87 | 0.63 | 0.69 | 0.72 | 0.38 | 0.90 |
| keyword | 0.60 | 0.52 | 0.49 | 0.58 | 0.50 | 0.35 | 0.51 |
| systemone | 0.48 | 0.89 | 0.90 | 0.41 | 0.51 | 0.21 | 0.91 |
| vllm_sr | 0.60 | 0.52 | 0.49 | 0.58 | 0.50 | 0.34 | 0.51 |

## Per-profile policy (after the profile filter)

| classifier | profile | violations before filter | violations after filter | sensitive leaks after | denied | quality |
| --- | --- | --- | --- | --- | --- | --- |
| hybrid | default | 52 | 0 | 35 | 0 | 0.773 |
| hybrid | local_only | 524 | 0 | 0 | 0 | 0.337 |
| hybrid | restricted | 97 | 0 | 35 | 0 | 0.766 |
| hybrid@1s | default | 32 | 0 | 19 | 0 | 0.858 |
| hybrid@1s | local_only | 501 | 0 | 0 | 0 | 0.337 |
| hybrid@1s | restricted | 103 | 0 | 19 | 0 | 0.847 |
| keyword | default | 52 | 0 | 35 | 0 | 0.773 |
| keyword | local_only | 524 | 0 | 0 | 0 | 0.337 |
| keyword | restricted | 97 | 0 | 35 | 0 | 0.766 |
| systemone | default | 51 | 0 | 25 | 0 | 0.944 |
| systemone | local_only | 521 | 0 | 0 | 0 | 0.337 |
| systemone | restricted | 301 | 0 | 25 | 0 | 0.928 |
| vllm_sr | default | 52 | 0 | 35 | 0 | 0.773 |
| vllm_sr | local_only | 524 | 0 | 0 | 0 | 0.337 |
| vllm_sr | restricted | 97 | 0 | 35 | 0 | 0.766 |

## Route flips by gadget family (default profile)

| family | hybrid | hybrid@1s | keyword | systemone | vllm_sr |
| --- | --- | --- | --- | --- | --- |
| category_claim | 0/40 | 3/40 | 0/40 | 9/13 | 0/40 |
| category_claim_chat | 0/30 | 3/30 | 0/30 | 0/4 | 0/30 |
| inject_cloud | 0/30 | 2/30 | 0/30 | 0/6 | 0/30 |
| inject_route | 0/40 | 24/40 | 0/40 | 20/24 | 0/40 |
| kw_prefix | 34/40 | 17/40 | 34/40 | 3/23 | 34/40 |
| kw_suffix | 34/40 | 28/40 | 34/40 | 6/14 | 34/40 |
| launder_claim | 0/30 | 4/30 | 0/30 | 1/5 | 0/30 |
| system_note | 0/20 | 1/20 | 0/20 | 1/9 | 0/20 |
| system_note_leak | 0/20 | 2/20 | 0/20 | 0/5 | 0/20 |
| token_gadget | 34/40 | 16/40 | 34/40 | 4/23 | 34/40 |
| zero_width | 1/28 | 5/28 | 1/28 | 0/4 | 1/28 |
