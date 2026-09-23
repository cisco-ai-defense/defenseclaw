"""G1: pin the Gemma 4 chat templates and assert the rendered answer boundary.

Gemma 4 ships two chat-template families. The larger (12B-it / 26B-A4B-it / 31B-it)
prefills an empty thought channel; the smaller (E2B-it / E4B-it) does not. With
enable_thinking=True the prefill is dropped and a single-token answer assertion
still passes, so the scored distribution would be over reasoning text rather than
an answer label. This gate records the template digest and the exact rendered tail
token ids for enable_thinking False and True so that difference cannot pass silently.
"""

import hashlib
import json
import sys
from pathlib import Path

from transformers import AutoConfig, AutoTokenizer

HUB = Path("/opt/dlami/nvme/hf/hub")
PINS = json.loads(Path("$WORK/g4j/pins.json").read_text())

# jevify's own prompt: system + user, answer is the FIRST assistant token.
SYSTEM = "You are a precise classifier. Reply with a single token: only the label of your answer."
USER = "<state>\nexample state\n</state>\n\nChoose allow, confirm, or block.\n\nOptions:\nA. allow\nB. confirm\nC. block\n\nAnswer with the letter of the single best option."
LABELS = ["A", "B", "C", "Yes", "No"]


def snapshot(repo_id):
    return HUB / ("models--" + repo_id.replace("/", "--")) / "snapshots" / PINS[repo_id]


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 22), b""):
            digest.update(block)
    return digest.hexdigest()


def render(tokenizer, messages, **kw):
    return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True, **kw)


def main():
    out = {}
    for repo_id in PINS:
        path = snapshot(repo_id)
        entry = {"repo_id": repo_id, "revision": PINS[repo_id], "snapshot": str(path)}
        template = path / "chat_template.jinja"
        entry["chat_template_sha256"] = sha256_file(template) if template.exists() else None
        entry["chat_template_bytes"] = template.stat().st_size if template.exists() else None
        config = AutoConfig.from_pretrained(path, local_files_only=True)
        entry["model_type"] = config.model_type
        text = config.get_text_config() if hasattr(config, "get_text_config") else config
        for key in ("sliding_window", "max_position_embeddings", "num_hidden_layers", "hidden_size"):
            entry[key] = getattr(text, key, None)
        layer_types = getattr(text, "layer_types", None)
        entry["layer_types_distinct"] = sorted(set(layer_types)) if layer_types else None
        entry["layer_types_count"] = (
            {t: layer_types.count(t) for t in sorted(set(layer_types))} if layer_types else None
        )

        tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
        messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": USER}]
        variants = {}
        for name, kw in (("thinking_false", {"enable_thinking": False}), ("thinking_true", {"enable_thinking": True}), ("default", {})):
            try:
                rendered = render(tokenizer, messages, **kw)
            except Exception as exc:  # template may reject a system role
                variants[name] = {"error": f"{type(exc).__name__}: {exc}"}
                continue
            ids = tokenizer(rendered, add_special_tokens=False)["input_ids"]
            tail = ids[-4:]
            variant = {
                "rendered_tail_repr": repr(rendered[-120:]),
                "tail_token_ids": tail,
                "tail_token_texts": [tokenizer.convert_ids_to_tokens(i) for i in tail],
                "prompt_token_count": len(ids),
                "sha256_rendered": hashlib.sha256(rendered.encode()).hexdigest(),
            }
            # Single-token answer assertion at the boundary, the same check the
            # Nimble prompt compiler makes -- it passes under BOTH variants.
            single = {}
            for label in LABELS:
                combined = tokenizer(rendered + label, add_special_tokens=False)["input_ids"]
                suffix = combined[len(ids):]
                single[label] = {
                    "prefix_preserved": combined[: len(ids)] == ids,
                    "suffix_len": len(suffix),
                    "suffix_ids": suffix,
                    "is_special": bool(suffix) and suffix[0] in set(tokenizer.all_special_ids),
                }
            variant["single_token_answer"] = single
            variant["single_token_answer_passes"] = all(
                v["prefix_preserved"] and v["suffix_len"] == 1 and not v["is_special"] for v in single.values()
            )
            variants[name] = variant
        entry["variants"] = variants
        # system-role support: does the rendered output contain the system text?
        try:
            entry["system_role_text_present"] = SYSTEM in render(tokenizer, messages, enable_thinking=False)
        except Exception as exc:
            entry["system_role_text_present"] = f"{type(exc).__name__}: {exc}"
        out[repo_id] = entry
    print(json.dumps(out, indent=2))
    Path("$WORK/g4j/out/g1-template-pin.json").write_text(json.dumps(out, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
