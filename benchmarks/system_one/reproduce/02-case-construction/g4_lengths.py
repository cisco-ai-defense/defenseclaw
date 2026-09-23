"""G4: the real C7/I3/Q2 prompt-length distribution under Gemma 4 tokenizers.

Reads the genuine s2 request bodies (same state/questions the runner sends),
renders them with jevify's own prompt (the readout jevify was trained for) and
measures token counts. Nimble trained at 2,048 tokens; this reports how far
outside that the production C7 contexts actually sit.
"""

import hashlib
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, "$WORK/g4j/jevify/src")

from jevify.prompting import render  # noqa: E402
from jevify.questions import question_from_dict  # noqa: E402
from transformers import AutoTokenizer  # noqa: E402

HUB = Path("/opt/dlami/nvme/hf/hub")
PINS = json.loads(Path("$WORK/g4j/pins.json").read_text())
REQUESTS = Path("/opt/dlami/nvme/s2-requests-all.jsonl")


def snapshot(repo_id):
    return HUB / ("models--" + repo_id.replace("/", "--")) / "snapshots" / PINS[repo_id]


def serialize(value):
    """Same convention as jev.api._render / nimble_shim.serialize for structured instructions."""
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


def normalize_questions(questions):
    out = {}
    for name, definition in questions.items():
        definition = dict(definition)
        definition["instructions"] = serialize(definition.get("instructions"))
        criteria = definition.get("criteria")
        if isinstance(criteria, dict):
            definition["criteria"] = {k: (serialize(v) if v is not None else None) for k, v in criteria.items()}
        elif isinstance(criteria, list):
            definition["criteria"] = [serialize(v) for v in criteria]
        out[name] = question_from_dict(definition)
    return out


def percentiles(values, points=(0, 50, 90, 95, 99, 99.9, 100)):
    ordered = sorted(values)
    out = {}
    for p in points:
        index = min(len(ordered) - 1, max(0, int(round((p / 100) * (len(ordered) - 1)))))
        out[f"p{p}"] = ordered[index]
    return out


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    tokenizers = {}
    digests = {}
    for repo_id in ("google/gemma-4-26B-A4B-it", "google/gemma-4-E2B-it"):
        path = snapshot(repo_id)
        tokenizers[repo_id] = AutoTokenizer.from_pretrained(path, local_files_only=True)
        digests[repo_id] = hashlib.sha256((path / "tokenizer.json").read_bytes()).hexdigest()

    per_request = {k: [] for k in tokenizers}   # max over the 3 questions in a request
    per_question = {k: [] for k in tokenizers}  # every rendered prompt
    state_bytes, canonical_len = [], []
    rows = 0
    with REQUESTS.open() as stream:
        for line in stream:
            row = json.loads(line)
            questions = normalize_questions(row["questions"])
            state = row["state"]
            texts = []
            for key, question in questions.items():
                rendered = render(state, question)
                texts.append(rendered.messages)
            state_bytes.append(row["context_bytes"])
            canonical_len.append(row["canonical_len"])
            for repo_id, tokenizer in tokenizers.items():
                lengths = []
                for messages in texts:
                    text = tokenizer.apply_chat_template(
                        messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)
                    lengths.append(len(tokenizer(text, add_special_tokens=False)["input_ids"]))
                per_question[repo_id].extend(lengths)
                per_request[repo_id].append(max(lengths))
            rows += 1
            if rows % 2000 == 0:
                print(f"{rows} requests", flush=True)
            if limit and rows >= limit:
                break

    result = {
        "requests_file": str(REQUESTS),
        "requests_sha256_first_1mib": hashlib.sha256(REQUESTS.open("rb").read(1 << 20)).hexdigest(),
        "requests_scanned": rows,
        "grid": "C7/I3/Q2",
        "prompt": "jevify prompting.render, enable_thinking=False",
        "tokenizer_sha256": digests,
        "nimble_trained_prompt_tokens": 2048,
        "state_bytes": percentiles(state_bytes) | {"mean": statistics.mean(state_bytes)},
        "canonical_request_bytes": percentiles(canonical_len) | {"mean": statistics.mean(canonical_len)},
    }
    for repo_id in tokenizers:
        result[repo_id] = {
            "per_question_prompt_tokens": percentiles(per_question[repo_id])
            | {"mean": statistics.mean(per_question[repo_id]), "n": len(per_question[repo_id])},
            "per_request_max_prompt_tokens": percentiles(per_request[repo_id])
            | {"mean": statistics.mean(per_request[repo_id]), "n": len(per_request[repo_id])},
            "over_2048": sum(v > 2048 for v in per_question[repo_id]),
            "over_4096": sum(v > 4096 for v in per_question[repo_id]),
            "over_8192": sum(v > 8192 for v in per_question[repo_id]),
            "over_sliding_window_512": sum(v > 512 for v in per_question[repo_id]),
            "over_sliding_window_1024": sum(v > 1024 for v in per_question[repo_id]),
            "total_prompt_tokens": sum(per_question[repo_id]),
        }
    print(json.dumps(result, indent=2))
    Path("$WORK/g4j/out/g4-lengths.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
