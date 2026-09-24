"""Export the exact prompt strings production sends, using the runner's own job builder
and the shim's own prompt assembly (no-image text-lane branch, PAD=0, PERMS=1,
READOUT_INSTR_STYLE unset, LAYOUT unset) -- so these are the real, unmodified prompts.

Usage: export_prompts.py <cases.jsonl> <n_cases> <out.json>
"""
import json, sys, importlib.util
from pathlib import Path

REPO = Path("$WORK/defenseclaw-system-one")
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "benchmarks/scripts"))
spec = importlib.util.spec_from_file_location(
    "runner", REPO / "benchmarks/scripts/benchmark_run_system_one.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

LETTERS = [chr(65 + i) for i in range(26)] + [chr(97 + i) for i in range(26)]

def desc(v):
    return "" if v is None else (v if isinstance(v, str) else json.dumps(v, ensure_ascii=False))

def instr_of(q):
    i = q["instructions"]
    return i if isinstance(i, str) else json.dumps(i, ensure_ascii=False)

def options_for(q):
    """Mirror shim.answer_choice / answer_score / answer_noul."""
    t = q["type"]
    if t == "choice":
        return [(k, desc(v)) for k, v in q["criteria"].items()], ""
    if t == "score":
        return (
            [(str(i), desc(l)) for i, l in enumerate(q["criteria"])],
            " Rate along the ordered levels below (lowest first).",
        )
    if t == "noul":
        c = q.get("criteria") or {}
        return [
            ("yes", desc(c.get("true")) or "The statement is true."),
            ("no", desc(c.get("false")) or "The statement is false."),
        ], ""
    raise ValueError(t)

cases_path, n_cases, out_path = Path(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3])
context_config = json.loads((REPO / "benchmarks/system_one/contexts-v1.json").read_text())
question_config = json.loads((REPO / "benchmarks/system_one/questions-v1.json").read_text())

groups = []
with cases_path.open() as fh:
    for line_no, line in enumerate(fh):
        if len(groups) >= n_cases:
            break
        line = line.strip()
        if not line:
            continue
        case = json.loads(line)
        for (event_index, ctx, ins, qid_v, state, state_meta, questions) in runner.case_jobs(
            case, ["C7"], ["I3"], ["Q2"], context_config, question_config, "structured"
        ):
            if len(groups) >= n_cases:
                break
            state_text = state if isinstance(state, str) else json.dumps(state, ensure_ascii=False)
            prefix = f"State:\n{state_text}"          # shim.prefix_text with PAD=0
            reqs = []
            for qid, q in questions.items():
                opts, suffix = options_for(q)
                instr = instr_of(q) + suffix
                lines = "\n".join(f"[{LETTERS[i]}] {k}: {d}" for i, (k, d) in enumerate(opts))
                prompt = (
                    prefix
                    + f"\n\nQuestion: {instr}\nOptions:\n{lines}\n\nAnswer with the letter of the best option only."
                )
                reqs.append({"qid": qid, "prompt": prompt, "n_options": len(opts)})
            groups.append({
                "case_id": case.get("id"),
                "event_index": event_index,
                "prefix_chars": len(prefix),
                "requests": reqs,
            })

out_path.write_text(json.dumps(groups))
print(f"groups={len(groups)} requests={sum(len(g['requests']) for g in groups)}")
print(f"prefix_chars: min={min(g['prefix_chars'] for g in groups)} "
      f"median={sorted(g['prefix_chars'] for g in groups)[len(groups)//2]} "
      f"max={max(g['prefix_chars'] for g in groups)}")
