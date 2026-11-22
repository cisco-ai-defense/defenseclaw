# Router eval results (2026-11-12T20:33:14Z)

Eval items: 555. Adversarial items: 358. Prices: placeholder-2026-11-12.1. System One backend: stand-in: Amazon Nova Lite via Bedrock (backend us.amazon.nova-lite-v1:0). Hybrid: System One within 300ms and confidence >= 0.60, else rules.

Guardrail narrowing signal (shipped regex rule pack): recall on sensitive items 45.0%, narrowing on non-sensitive items 0.0%.

| classifier | macro-F1 | accuracy | errors | p50 ms | p95 ms | flip rate | upgrade flips | leak flips | sensitive leaks after filter (default / restricted / local_only) | profile violations after filter | quality (default) | cost/1k | cost/1k at 95% of strong | saving vs strong |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| hybrid | 0.508 | 0.514 | 0.0% | 300.29 | 301.31 | 28.8% | 102/220 | 1/138 | 35 / 35 / 0 | 0 | 0.773 | $3.30 | $7.50 | 25% |
| hybrid@1s | 0.865 | 0.868 | 0.0% | 701.47 | 901.64 | 18.2% | 48/220 | 17/138 | 16 / 16 / 0 | 0 | 0.937 | $5.41 | $5.41 | 46% |
| keyword | 0.508 | 0.514 | 0.0% | 0.29 | 1.31 | 28.8% | 102/220 | 1/138 | 35 / 35 / 0 | 0 | 0.773 | $3.30 | $7.50 | 25% |
| systemone | 0.889 | 0.883 | 2.5% | 701.08 | 901.57 | 17.8% | 43/210 | 14/110 | 17 / 17 / 0 | 0 | 0.955 | $5.71 | $5.71 | 43% |

Strong-model reference (every request asks for strong; guardrail narrowing and the default profile apply): $10.05 per 1k at quality 0.921; target quality 0.875. Label-perfect ceiling (strong, local for sensitive): $9.47 at 1.000. All fast: $0.26 per 1k at quality 0.477.
Profile violations after filter are an invariant of the filter (property-tested), shown as a check. Flips exclude pairs where the base or the variant errored.

## Per-category F1

| classifier | coding | reasoning | chat | summarize | sensitive | tool_heavy | cheap_fast |
| --- | --- | --- | --- | --- | --- | --- | --- |
| hybrid | 0.60 | 0.52 | 0.49 | 0.58 | 0.50 | 0.35 | 0.51 |
| hybrid@1s | 0.84 | 0.94 | 0.85 | 0.93 | 0.75 | 0.82 | 0.92 |
| keyword | 0.60 | 0.52 | 0.49 | 0.58 | 0.50 | 0.35 | 0.51 |
| systemone | 0.85 | 0.94 | 0.94 | 0.94 | 0.72 | 0.88 | 0.94 |

## Per-profile policy (after the profile filter)

| classifier | profile | violations before filter | violations after filter | sensitive leaks after | denied | quality |
| --- | --- | --- | --- | --- | --- | --- |
| hybrid | default | 52 | 0 | 35 | 0 | 0.773 |
| hybrid | local_only | 524 | 0 | 0 | 0 | 0.337 |
| hybrid | restricted | 97 | 0 | 35 | 0 | 0.766 |
| hybrid@1s | default | 31 | 0 | 16 | 0 | 0.937 |
| hybrid@1s | local_only | 505 | 0 | 0 | 0 | 0.337 |
| hybrid@1s | restricted | 111 | 0 | 16 | 0 | 0.921 |
| keyword | default | 52 | 0 | 35 | 0 | 0.773 |
| keyword | local_only | 524 | 0 | 0 | 0 | 0.337 |
| keyword | restricted | 97 | 0 | 35 | 0 | 0.766 |
| systemone | default | 34 | 0 | 17 | 0 | 0.955 |
| systemone | local_only | 508 | 0 | 0 | 0 | 0.337 |
| systemone | restricted | 117 | 0 | 17 | 0 | 0.939 |

## Route flips by gadget family (default profile)

| family | hybrid | hybrid@1s | keyword | systemone |
| --- | --- | --- | --- | --- |
| category_claim | 0/40 | 7/40 | 0/40 | 8/39 |
| category_claim_chat | 0/30 | 7/30 | 0/30 | 7/23 |
| inject_cloud | 0/30 | 2/30 | 0/30 | 0/22 |
| inject_route | 0/40 | 15/40 | 0/40 | 16/35 |
| kw_prefix | 34/40 | 10/40 | 34/40 | 5/39 |
| kw_suffix | 34/40 | 2/40 | 34/40 | 1/38 |
| launder_claim | 0/30 | 7/30 | 0/30 | 5/23 |
| system_note | 0/20 | 3/20 | 0/20 | 3/20 |
| system_note_leak | 0/20 | 1/20 | 0/20 | 1/18 |
| token_gadget | 34/40 | 11/40 | 34/40 | 10/39 |
| zero_width | 1/28 | 0/28 | 1/28 | 1/24 |
