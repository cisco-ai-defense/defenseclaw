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
  --output generated/dtap-v2/cases.jsonl \
  --manifest generated/dtap-v2/cases.manifest.json
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

The benign/malicious path and the source deterministic-environment judge are
candidate trajectory truth, not deterministic proof of every constituent
action. Prompts, agent prose, evaluator prose, judge text, and tool-result
content are not authoritative action evidence. The projection therefore does
not claim that every call in a source-labeled malicious trajectory is
malicious; it is suitable for bounded trajectory candidates and hard-negative
coverage, not unconditional atomic policy truth.
