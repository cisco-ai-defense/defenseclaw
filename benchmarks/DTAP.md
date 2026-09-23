# DTap trajectory projection

The reproducible DTap projection uses the Hugging Face dataset
`AI-Secure/DTap-Bench-Agent-Trajectories` at revision
`836caf2fdd78b888ddd14fb62dc038e932e17898`. The source is Apache-2.0 and is
download-only; raw trajectories are not committed.

Download the pinned tree with the HF CLI, then normalize it:

```bash
hf download AI-Secure/DTap-Bench-Agent-Trajectories \
  --repo-type dataset \
  --revision 836caf2fdd78b888ddd14fb62dc038e932e17898 \
  --local-dir /path/to/dtap

python3 benchmarks/scripts/benchmark_normalize_dtap.py \
  --root /path/to/dtap \
  --revision 836caf2fdd78b888ddd14fb62dc038e932e17898 \
  --output generated/dtap-v3-reproducible/cases.jsonl \
  --manifest generated/dtap-v3-reproducible/manifest.json
```

The pinned release produces 6,540 bounded cases: 423 atomic action cases and
6,117 stateful cases. The normalizer is English-only and keeps a tool call
only when its arguments are real and non-empty and a matching tool-result row
provides non-empty, non-error evidence. Calls are matched by tool name and
FIFO order, and source call windows anchor the bounded chunks so identity and
order remain continuous even when unsupported calls are omitted.

The only continuity keys are the exact source path, source domain/task ID, and
matching tool name; the normalizer does not infer authority from a trajectory
label or from agent/evaluator text.

Successful benign trajectories produce 4,692 in-scope benign cases for FPR
measurement. The source `attack_success` judge proves the complete malicious
trajectory, not any particular emitted chunk. Accordingly, all 1,848
malicious-source chunks retain `source_truth=malicious` but use
`deterministic_truth=contextual_or_dual_use`, `expected_disposition=detect_only`,
and `applicability=out_of_scope`. They are categorized as
`trajectory_success_candidate` and `proof_pending`, with an explicit exclusion
reason. This adapter has no independent exact proof verifier and therefore
emits no deterministic malicious positives.

Prompts, agent prose, evaluator prose, judge text, and tool-result content are
not authoritative action evidence. The malicious projection is suitable for
candidate coverage and later proof work, not scored deterministic policy truth.
