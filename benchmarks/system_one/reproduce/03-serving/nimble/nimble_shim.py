"""Serve Bespoke-Nimble-9B on the /v1/systemone contract.

Deliberately reuses Open-Jev's published HTTP server, stable softmax, and typed
response formatter (`jev.server.make_server`, `jev.metrics.softmax`,
`jev.api.compile_request` / `format_response`) so that the ONLY difference
between how Nimble and Open-Jev are served is each model's own trained prompt
and logit readout. Everything downstream of the logits is byte-for-byte the
same code path for both families, which is what makes the comparison 1:1.

Scoring follows the adapter repo's published `inference.py` exactly: one
forward pass per schema field, candidate letter-code logits gathered from the
LM head at the answer boundary, softmax over just those candidates. The prompt
is built by the repo's own `parallel_schema.prepare_prompts`, whose sha256 is
verified against the checkpoint's `schema_config.json:prompt_code_sha256`.
"""

import argparse
import hashlib
import json
import time
from pathlib import Path

import torch

from jev.api import compile_request, format_response
from jev.metrics import softmax
from jev.server import make_server

MODEL_ID = "bespokelabs/Bespoke-Nimble-9B"
# Hub revision keyed by the sha256 of adapter_model.safetensors, and the temperature
# fitted for that exact checkpoint. Both are copied from the recipe repo's
# nimble/scoring/calibration.py; see --temperature to override.
ADAPTER_REVISIONS = {
    "ba7e28acb97f973e80fa51f3aa6fc6f75ea4081b89632ed45d8e5f3a1d7bfa6b":
        "93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c",
}
FITTED_TEMPERATURES = {
    (MODEL_ID, "93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c"): 2.179078721266035,
}


def serialize(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, allow_nan=False)


def build_schema(questions):
    """Map the /v1/systemone question types onto Nimble's trained schema fields.

    Mirrors nimble/serving/compiler.py NimbleCompiler.prepare.
    """
    schema = {}
    for name, question in questions.items():
        kind = question.get("type")
        criteria = question.get("criteria")
        field = {"description": serialize(question.get("instructions"))}
        if kind == "noul":
            true_text, false_text = "yes", "no"
            if isinstance(criteria, dict):
                true_text, false_text = serialize(criteria["true"]), serialize(criteria["false"])
            field.update(type="boolean", choices=[False, True],
                         choice_descriptions={"false": false_text, "true": true_text})
        elif kind == "choice":
            field.update(type="enum", choices=list(criteria),
                         choice_descriptions={key: (serialize(value) if value is not None else key)
                                              for key, value in criteria.items()})
        elif kind == "score":
            field.update(type="enum", choices=[str(index) for index in range(len(criteria))],
                         choice_descriptions={str(index): serialize(text)
                                              for index, text in enumerate(criteria)})
        else:
            raise ValueError("question type must be choice, score, or noul")
        schema[name] = field
    return schema


class NimblePredictor:
    def __init__(self, checkpoint, device="cuda:0", max_length=None, temperature=None,
                 name="bespoke-nimble-9b"):
        directory = Path(checkpoint)
        self.display_name = name
        self.contract = json.loads((directory / "schema_config.json").read_text())
        if self.contract["task"] != "schema_candidate_classification_v1":
            raise ValueError("unexpected checkpoint task")

        # The prompt compiler is part of the trained contract; refuse to serve if it drifted.
        self.prepare_prompts, self.choice_key, prompt_sha = _load_prompt_code(directory)
        if prompt_sha != self.contract["prompt_code_sha256"]:
            raise RuntimeError("prompt compiler differs from the published training contract")

        adapter_sha = _sha256(directory / "adapter_model.safetensors")
        self.revision = ADAPTER_REVISIONS.get(adapter_sha)
        if temperature is None:
            temperature = FITTED_TEMPERATURES.get((MODEL_ID, self.revision)) or 1.0
        self.temperature = float(temperature)
        self.trained_prompt_tokens = int(self.contract["max_length"])
        self.max_length = int(max_length or self.trained_prompt_tokens)

        from peft import PeftModel
        from transformers import AutoTokenizer, Qwen3_5ForConditionalGeneration
        self.tokenizer = AutoTokenizer.from_pretrained(directory)
        base = Qwen3_5ForConditionalGeneration.from_pretrained(
            self.contract["model"], revision=self.contract["revision"],
            dtype=torch.bfloat16, attn_implementation="sdpa",
        ).to(device)
        base.config.use_cache = False
        self.model = PeftModel.from_pretrained(base, directory).eval()
        self.device = device

        self.model_name = name
        self.method = "schema_candidate_letter_readout"
        self.provenance = {
            "repo_id": MODEL_ID, "display_name": name,
            "base_model": self.contract["model"], "base_revision": self.contract["revision"],
            "adapter_sha256": adapter_sha, "adapter_revision": self.revision,
            "prompt_code_sha256": prompt_sha, "temperature_fitted": self.revision is not None,
            "trained_prompt_tokens": self.trained_prompt_tokens, "max_length": self.max_length,
            "lora_rank": self.contract.get("lora_rank"),
        }

    @torch.inference_mode()
    def _field_logits(self, context, schema):
        """One forward pass per field; returns candidate logits per field, in schema order."""
        prepared = self.prepare_prompts(self.tokenizer, context, schema, self.max_length)
        rows, tokens = [], 0
        with torch.autocast("cuda", dtype=torch.bfloat16):
            for ids, candidates in zip(prepared.full_ids, prepared.candidate_ids):
                tokens += len(ids)
                input_ids = torch.tensor([ids], device=self.device)
                logits = self.model(
                    input_ids=input_ids,
                    attention_mask=torch.ones_like(input_ids),
                    use_cache=False, logits_to_keep=1,
                ).logits[:, -1, :].float()
                selected = logits[0, torch.tensor(candidates, device=self.device)].double()
                if not torch.isfinite(selected).all():
                    raise FloatingPointError("non-finite candidate logits")
                rows.append(selected.cpu().tolist())
        return prepared.names, rows, tokens

    def predict(self, request):
        if not isinstance(request, dict) or not {"state", "questions"} <= request.keys():
            raise ValueError("request requires state and questions")
        if request.get("model") not in (None, "nimble-latest", "nimble", MODEL_ID, self.display_name):
            raise ValueError("requested model is not loaded; see /v1/models")
        questions = request["questions"]
        if not isinstance(questions, dict) or not questions:
            raise ValueError("questions must be a nonempty object")

        # compile_request validates the request and yields the answer-key ordering and
        # legends that format_response needs. Nimble's own schema is built from the same
        # questions, and prepare_prompts preserves that ordering, so the logit rows line up.
        records = compile_request(request["state"], questions)
        schema = build_schema(questions)
        started = time.perf_counter()
        names, rows, tokens = self._field_logits(serialize(request["state"]), schema)
        if names != [record["id"] for record in records]:
            raise RuntimeError("field ordering diverged from the compiled records")
        for record, row in zip(records, rows):
            expected = 2 if record["kind"] == "noul" else len(record["options"])
            if len(row) != expected:
                raise RuntimeError("backend returned the wrong candidate count")

        result = format_response(records, [softmax(row, self.temperature) for row in rows])
        result.update(model=self.model_name,
                      usage={"input_tokens": tokens, "output_tokens": 0},
                      metadata={"method": self.method, "temperature": self.temperature,
                                "candidate_sequences": sum(len(row) for row in rows),
                                "forward_passes": len(rows),
                                "inference_seconds": time.perf_counter() - started,
                                **self.provenance})
        return result


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_prompt_code(directory):
    """Import the checkpoint's own parallel_schema.py and return it with its digest."""
    import importlib.util
    path = directory / "parallel_schema.py"
    spec = importlib.util.spec_from_file_location("nimble_parallel_schema", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.prepare_prompts, module.choice_key, _sha256(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--name", default="bespoke-nimble-9b")
    parser.add_argument("--device", default="cuda:0")
    parser.add_argument("--max-length", type=int)
    parser.add_argument("--temperature", type=float)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8801)
    args = parser.parse_args()
    predictor = NimblePredictor(args.checkpoint, device=args.device,
                                max_length=args.max_length, temperature=args.temperature,
                                name=args.name)
    server = make_server(predictor, args.host, args.port)
    print(json.dumps({"url": f"http://{args.host}:{server.server_port}",
                      "model": predictor.model_name, "method": predictor.method,
                      "temperature": predictor.temperature, **predictor.provenance}), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
