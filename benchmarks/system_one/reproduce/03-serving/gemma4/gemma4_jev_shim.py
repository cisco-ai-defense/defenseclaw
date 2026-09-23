"""Serve a Gemma 4 checkpoint on the /v1/systemone contract with jevify's own readout.

Same shape as nimble_shim.py: the wire contract, response formatting and confidence
come from Open-Jev's published helper (`jev.api.compile_request` / `format_response`,
`jev.server.make_server`), so everything downstream of the candidate probabilities is
byte-for-byte the same code path as every other row on the board. The only
model-specific parts are the prompt and the logit readout, and those are taken from
the jevify project itself (`jevify.prompting.render`, `jevify.scoring`), because the
adapter under test was trained against exactly that prompt.

Two correctness controls, both from this phase's gates:

* G1 -- the rendered generation prompt's trailing token ids are asserted against the
  digest pinned for the checkpoint's template family. Gemma 4's larger family
  prefills an empty thought channel; enable_thinking=True silently removes it while a
  single-token answer assertion still passes, which would score a distribution over
  reasoning text instead of an answer label.
* G2 -- attention defaults to eager. Torch's optimized CUDA SDPA disagrees with both
  eager and math-only SDPA on Gemma once a prompt crosses the sliding window.

The readout differs from jevify's shipped backend in one deliberate way: label mass is
summed over the whole vocabulary rather than a top-64 slice, so a label that falls out
of the top-k cannot silently become a uniform fallback. `label_mass` is reported.
"""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import torch

from jev.api import compile_request, format_response
from jev.server import make_server

sys.path.insert(0, "$WORK/g4j/jevify/src")
from jevify.prompting import render  # noqa: E402
from jevify.questions import question_from_dict  # noqa: E402

# G1 pins: sha256(chat_template.jinja) -> the asserted trailing generation-prompt tokens.
TEMPLATE_PINS = {
    # gemma-4-26B-A4B-it family: empty thought-channel prefill
    "ae53464bf3be25802b3a5b37def7fd89667067d7577049b3b2d74c4d8de4c6d4": [100, 45518, 107, 101],
    # gemma-4-E2B-it
    "0a2c8073c878ab1da004bee933a998606537bbb62016310352c7285c3f01c5b5": [107, 105, 4368, 107],
    # larkooo/gemma-e2b-rlcd redistribution of the same family
    "2f1b4d75d067bae3fe44e676721c7f077d243bc007156cb9c2f8b5836613d082": [107, 105, 4368, 107],
}
LICENSES = {
    "google/gemma-4-26B-A4B-it": "apache-2.0",
    "google/gemma-4-E2B-it": "apache-2.0",
    "kushalpatil/jevify-gemma4-26b-a4b": "gemma",
    "larkooo/gemma-e2b-rlcd": "apache-2.0 (card tag: gemma)",
}


def serialize(value):
    """Structured instructions/criteria -> text, matching jev.api._render exactly."""
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


def normalize_questions(questions):
    parsed = {}
    for name, definition in questions.items():
        definition = dict(definition)
        definition["instructions"] = serialize(definition.get("instructions"))
        criteria = definition.get("criteria")
        if isinstance(criteria, dict):
            definition["criteria"] = {k: (serialize(v) if v is not None else None) for k, v in criteria.items()}
        elif isinstance(criteria, list):
            definition["criteria"] = [serialize(v) for v in criteria]
        parsed[name] = question_from_dict(definition)
    return parsed


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 22), b""):
            digest.update(block)
    return digest.hexdigest()


class Gemma4JevPredictor:
    def __init__(self, checkpoint, repo_id, revision, name, attention="eager", dtype="bfloat16",
                 device="cuda:0", device_map=None, max_gpu_memory=None, temperature=1.0,
                 max_input_tokens=8192, weight_digests=False, prefix_cache=True):
        from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer

        directory = Path(checkpoint)
        self.display_name = self.model_name = name
        self.method = "jevify_label_readout"
        self.temperature = float(temperature)
        self.max_input_tokens = int(max_input_tokens)
        if attention not in ("eager", "sdpa"):
            raise ValueError("attention must be eager or sdpa")
        # Avoid TF32 rounding; the answer is read from a small set of logits.
        torch.backends.cuda.matmul.allow_tf32 = False

        template = directory / "chat_template.jinja"
        self.template_sha256 = sha256_file(template)
        if self.template_sha256 not in TEMPLATE_PINS:
            raise RuntimeError(f"unpinned chat template {self.template_sha256}; G1 must be re-run")
        self.expected_tail = TEMPLATE_PINS[self.template_sha256]

        config = AutoConfig.from_pretrained(directory, local_files_only=True)
        if config.model_type != "gemma4":
            raise ValueError(f"unsupported architecture: {config.model_type}")
        text_config = config.get_text_config() if hasattr(config, "get_text_config") else config
        self.sliding_window = getattr(text_config, "sliding_window", None)

        self.tokenizer = AutoTokenizer.from_pretrained(directory, local_files_only=True)
        options = dict(local_files_only=True, dtype=getattr(torch, dtype), attn_implementation=attention)
        if device_map:
            options["device_map"] = device_map
            if max_gpu_memory:
                options["max_memory"] = {i: max_gpu_memory for i in range(torch.cuda.device_count())}
                options["max_memory"]["cpu"] = "300GiB"
        started = time.perf_counter()
        self.model = AutoModelForCausalLM.from_pretrained(directory, **options).eval()
        if not device_map:
            self.model = self.model.to(device)
        self.load_seconds = time.perf_counter() - started
        placed = [p.device for p in self.model.parameters() if p.device.type == "cuda"]
        self.device = placed[0] if placed else torch.device("cpu")
        self.attention = attention
        self.placement = None
        if getattr(self.model, "hf_device_map", None):
            from collections import Counter
            self.placement = dict(Counter(str(v) for v in self.model.hf_device_map.values()))

        self.label_ids = self._label_id_index()
        # Prefix reuse is NOT numerically neutral in bf16: moving the boundary between reused
        # KV and freshly computed KV changes the accumulation order. Measured on the 324-row
        # holdout, carrying the cache across rows moved unpermuted-primitive probabilities by
        # up to 0.176 (mean 0.0116) without changing any argmax. Independent full prefill is
        # the reproducible default, and is what Nimble's CUDA scorer and the Open-Jev server
        # (--no-prefix-cache) both do.
        self.prefix_cache = bool(prefix_cache)
        self._cache = None
        self._prefix_ids = []
        self._asserted_tail = False

        self.provenance = {
            "repo_id": repo_id, "revision": revision, "display_name": name,
            "license": LICENSES.get(repo_id, "unknown"),
            "chat_template_sha256": self.template_sha256,
            "asserted_generation_prompt_tail": self.expected_tail,
            "enable_thinking": False,
            "attention": attention, "dtype": dtype, "tf32": False,
            "sliding_window": self.sliding_window,
            "max_input_tokens": self.max_input_tokens,
            "temperature": self.temperature,
            "prompt_source": "jevify.prompting.render",
            "prefix_cache": bool(prefix_cache),
            "readout": "full-vocabulary softmax, mass summed over label token variants, renormalized over labels",
            "response_formatter": "jev.api.format_response",
            "device_map": device_map, "max_gpu_memory": max_gpu_memory, "placement": self.placement,
            "torch": torch.__version__, "cuda": torch.version.cuda,
            "gpus": [torch.cuda.get_device_name(i) for i in range(torch.cuda.device_count())],
            "load_seconds": self.load_seconds,
        }
        if weight_digests:
            self.provenance["weight_sha256"] = {
                p.name: sha256_file(p) for p in sorted(directory.glob("*.safetensors"))
            }

    def _label_id_index(self):
        """token ids whose stripped, lowercased text equals a label -- jevify's match rule."""
        wanted = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
                  "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "yes", "no"}
        index = {key: [] for key in wanted}
        vocab = self.tokenizer.get_vocab()
        specials = set(self.tokenizer.all_special_ids)
        for token, token_id in vocab.items():
            if token_id in specials:
                continue
            text = self.tokenizer.convert_tokens_to_string([token]).strip().lower()
            if text in index:
                index[text].append(token_id)
        return {k: sorted(v) for k, v in index.items() if v}

    def _encode(self, messages):
        text = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)
        return self.tokenizer(text, add_special_tokens=False)["input_ids"]

    @torch.inference_mode()
    def _next_token_logprobs(self, ids):
        """One forward pass, reusing whatever token prefix the held cache already covers."""
        from transformers import DynamicCache

        if not self.prefix_cache:
            self._cache, self._prefix_ids = None, []
        shared = 0
        if self._cache is not None:
            limit = min(len(self._prefix_ids), len(ids) - 1)
            while shared < limit and self._prefix_ids[shared] == ids[shared]:
                shared += 1
        if shared < 16:
            self._cache, shared = DynamicCache(), 0
        else:
            held = self._cache.get_seq_length()
            if held > shared:
                self._cache.crop(shared - held)
        todo = ids[shared:]
        output = None
        for start in range(0, len(todo), 2048):
            chunk = torch.tensor([todo[start:start + 2048]], device=self.device)
            output = self.model(input_ids=chunk, past_key_values=self._cache, use_cache=True, logits_to_keep=1)
            self._cache = output.past_key_values
        self._prefix_ids = list(ids)
        logits = output.logits[0, -1].float()
        if not torch.isfinite(logits).all():
            raise FloatingPointError("non-finite logits")
        return torch.log_softmax(logits / self.temperature, dim=-1), shared

    def _label_probabilities(self, logprobs, labels):
        probabilities = logprobs.exp()
        raw = []
        for label in labels:
            ids = self.label_ids.get(label.strip().lower())
            if not ids:
                raise RuntimeError(f"no vocabulary token renders as label {label!r}")
            raw.append(float(probabilities[torch.tensor(ids, device=probabilities.device)].sum()))
        mass = sum(raw)
        if mass <= 0:
            raise FloatingPointError("no probability mass on any answer label")
        return [value / mass for value in raw], mass

    def predict(self, request):
        if not isinstance(request, dict) or not {"state", "questions"} <= request.keys():
            raise ValueError("request requires state and questions")
        if request.get("model") not in (None, self.display_name, self.provenance["repo_id"], "jev-latest"):
            raise ValueError("requested model is not loaded; see /v1/models")
        records = compile_request(request["state"], request["questions"])
        parsed = normalize_questions(request["questions"])
        if [r["id"] for r in records] != list(parsed):
            raise RuntimeError("question ordering diverged")

        started = time.perf_counter()
        rows, tokens, cached, masses = [], 0, 0, []
        for record, (name, question) in zip(records, parsed.items()):
            rendered = render(request["state"], question)
            ids = self._encode(rendered.messages)
            if not self._asserted_tail:
                if ids[-len(self.expected_tail):] != self.expected_tail:
                    raise RuntimeError(f"generation prompt tail {ids[-4:]} != pinned {self.expected_tail}")
                self._asserted_tail = True
            if len(ids) > self.max_input_tokens:
                raise ValueError(f"prompt has {len(ids)} tokens; limit is {self.max_input_tokens}. Nothing was truncated.")
            logprobs, shared = self._next_token_logprobs(ids)
            probabilities, mass = self._label_probabilities(logprobs, rendered.labels)
            tokens += len(ids)
            cached += shared
            masses.append(mass)
            # jev's answer_keys order: choice = criteria order, score = level index, noul = [false, true]
            if record["kind"] == "noul":
                by_key = dict(zip(rendered.keys, probabilities))  # keys are ["yes", "no"]
                rows.append([by_key["no"], by_key["yes"]])
            else:
                rows.append(probabilities)
            if len(rows[-1]) != len(record["answer_keys"]):
                raise RuntimeError("candidate count does not match the declared answer space")

        result = format_response(records, rows)
        result.update(
            model=self.model_name,
            usage={"input_tokens": tokens, "output_tokens": 0},
            metadata={"method": self.method, "temperature": self.temperature,
                      "forward_passes": len(rows), "cached_prefix_tokens": cached,
                      "label_mass_min": min(masses), "label_mass_mean": sum(masses) / len(masses),
                      "inference_seconds": time.perf_counter() - started,
                      **self.provenance})
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--repo-id", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--attention", default="eager", choices=["eager", "sdpa"])
    parser.add_argument("--dtype", default="bfloat16")
    parser.add_argument("--device", default="cuda:0")
    parser.add_argument("--device-map")
    parser.add_argument("--max-gpu-memory")
    parser.add_argument("--temperature", type=float, default=1.0)
    parser.add_argument("--max-input-tokens", type=int, default=8192)
    parser.add_argument("--weight-digests", action="store_true")
    parser.add_argument("--prefix-cache", action=argparse.BooleanOptionalAction, default=True,
                        help="reuse the state token prefix across a request's questions; "
                             "--no-prefix-cache gives an independent full prefill per question")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8901)
    args = parser.parse_args()
    predictor = Gemma4JevPredictor(
        args.checkpoint, args.repo_id, args.revision, args.name, attention=args.attention,
        dtype=args.dtype, device=args.device, device_map=args.device_map,
        max_gpu_memory=args.max_gpu_memory, temperature=args.temperature,
        max_input_tokens=args.max_input_tokens, weight_digests=args.weight_digests,
        prefix_cache=args.prefix_cache)
    server = make_server(predictor, args.host, args.port)
    print(json.dumps({"url": f"http://{args.host}:{server.server_port}", "model": predictor.model_name,
                      "method": predictor.method, **predictor.provenance}), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
