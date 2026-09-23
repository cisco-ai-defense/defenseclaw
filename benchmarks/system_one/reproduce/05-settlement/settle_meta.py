"""Enrich a completed System One prediction meta with full Gemma 4 provenance.

The runner already writes complete/prediction_sha256; this re-verifies the digest against
the bytes on disk and pins repo id, model + adapter revisions, the grid and the exact
serving controls, so the row is quotable. It also records, on the row's face, that arm 2
is the incumbent judge's own weights served through a different readout -- two rows drawn
from identical weights would otherwise mislead a reader of the leaderboard.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

PINS = json.load(open("$WORK/.system-one-data/outputs/gemma4jev/artifacts/pins.json"))
BASE = "google/gemma-4-26B-A4B-it"
INCUMBENT_JUDGE = "google.gemma-4-26b-a4b"
WEIGHTS = {
    "google/gemma-4-26B-A4B-it": {
        "model-00001-of-00002.safetensors": "1127684971bbca40465435a5cad69d67ad603bf5e61c6dfd5561fae4a3bcfdb3",
        "model-00002-of-00002.safetensors": "aab47033e1e8a492ef8e581efae1cf36478d0433567e7729b3c1728bc8970db7"},
    "kushalpatil/jevify-gemma4-26b-a4b": {
        "model-00001-of-00002.safetensors": "fddf798a9cc9f001a9c3da4bf053e8c36cbafd9d30c858fb4c1b20c44392539c",
        "model-00002-of-00002.safetensors": "da5b4c4f3ce5e88cc401dc9652c8775203765a36ee48bc484f768da653d2a786"},
}
LICENSE = {"google/gemma-4-26B-A4B-it": "apache-2.0",
           "kushalpatil/jevify-gemma4-26b-a4b": "gemma"}
DISPLAY = {"google/gemma-4-26B-A4B-it": "gemma-4-26B-A4B-it",
           "kushalpatil/jevify-gemma4-26b-a4b": "jevify-gemma4-26b-a4b"}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 22), b""):
            digest.update(block)
    return digest.hexdigest()


ap = argparse.ArgumentParser()
ap.add_argument("--predictions", required=True)
ap.add_argument("--repo-id", required=True)
ap.add_argument("--temperature", type=float, required=True)
ap.add_argument("--cuda-devices", required=True)
ap.add_argument("--serving-json")
args = ap.parse_args()

pred = Path(args.predictions)
meta_path = Path(str(pred) + ".meta.json")
meta = json.load(open(meta_path))

on_disk = sha256_file(pred)
if meta.get("prediction_sha256") != on_disk:
    sys.exit(f"REFUSING TO SETTLE: meta sha {meta.get('prediction_sha256')} != on-disk {on_disk}")
if meta.get("complete") is not True:
    sys.exit("REFUSING TO SETTLE: run is not complete")
rows = sum(1 for _ in open(pred))
if rows != meta["requests"]:
    sys.exit(f"REFUSING TO SETTLE: {rows} rows != {meta['requests']} planned requests")

errors_by_code = {}
forward_passes = None
with open(pred) as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        code = row.get("error_code")
        if code:
            errors_by_code[code] = errors_by_code.get(code, 0) + 1
        if forward_passes is None and isinstance(row.get("probabilities"), dict):
            forward_passes = len({k.split(".")[0] for k in row["probabilities"]})

is_adapter = args.repo_id != BASE
if is_adapter:
    relationship = (
        "LoRA fine-tune of %s (revision %s), merged into the served weights. Its pair on this "
        "board is the no-adapter arm gemma-4-26B-A4B-it served through the identical readout, so "
        "the difference between the two rows is the adapter and nothing else."
        % (BASE, PINS[BASE])
    )
else:
    relationship = (
        "SAME WEIGHTS as the incumbent Bedrock generative judge '%s' (revision %s) -- byte-identical "
        "safetensors, not a re-release. This row differs from the judge row only in how the decision is "
        "read out: a typed-decision label-logit readout (probabilities over the declared answer space) "
        "instead of a generative chat judge, plus the fitted temperature T=%.6f for score resolution. "
        "Any comparison between this row and the 'Gemma 4 (judge, reference)' row is therefore a "
        "serving-architecture comparison on one set of weights, not a model comparison."
        % (INCUMBENT_JUDGE, PINS[BASE], args.temperature)
    )

meta.update({
    "repo_id": args.repo_id,
    "canonical_repo_id": args.repo_id,
    "display_name": DISPLAY[args.repo_id],
    "license": LICENSE[args.repo_id],
    "base_model": BASE,
    "base_revision": PINS[BASE],
    "model_revision": PINS[args.repo_id],
    "adapter": ("LoRA on %s, merged into the served weights" % BASE) if is_adapter else None,
    "adapter_revision": PINS[args.repo_id] if is_adapter else None,
    "grid": "%s/%s/%s" % (meta["contexts"], meta["instructions"], meta["questions"]),
    "rows_on_disk": rows,
    "prediction_sha256_verified_against_disk": True,
    "weight_sha256": WEIGHTS[args.repo_id],
    "serving": {
        "engine": "transformers (gemma4_jev_shim.py); jev.api/jev.server wire contract",
        "readout": "typed-decision: full-vocabulary softmax, label-token mass, renormalized over candidates",
        "readout_kind": "typed_decision_guard",
        "not_a_generative_judge": True,
        "relationship_to_incumbent": relationship,
        "same_base_weights_as_incumbent_judge": not is_adapter,
        "emits": ["probabilities", "confidence"],
        "attention": "eager",
        "attention_note": ("G2: optimised CUDA SDPA diverges from eager past the sliding window on "
                           "Gemma 4 (0.0874 label probability, 11.72 candidate logits, full-vocab argmax "
                           "flip on a 961-token prompt); eager agreed with math-only SDPA to 2.9e-10"),
        "dtype": "bfloat16",
        "tf32": False,
        "prefix_cache": False,
        "prefix_cache_note": ("cached vs cache-free flips 5/324 holdout decisions (1.54%), max "
                              "probability delta 0.1626; cache-free is the defensible setting and "
                              "deliberately departs from OpenJev SERVE.md's --enable-prefix-caching"),
        "temperature": args.temperature,
        "temperature_note": (
            ("fitted global temperature from artifacts/out/temp-calibration.json; monotone in the "
             "logits, so holdout accuracy is unchanged at 0.845679 while score resolution is restored "
             "(uncalibrated: median top-probability 1.0000, 274/324 above 0.999)")
            if args.temperature != 1.0 else
            "served uncalibrated; the fitted temperature was 1.105 and the distribution is already resolved"),
        "chat_template_sha256": "ae53464bf3be25802b3a5b37def7fd89667067d7577049b3b2d74c4d8de4c6d4",
        "asserted_generation_prompt_tail": [100, 45518, 107, 101],
        "enable_thinking": False,
        "enable_thinking_note": ("enable_thinking=True still passes a single-token answer assertion but "
                                 "renders tail [107, 105, 4368, 107]; the template digest is the real guard"),
        "gpu": "NVIDIA L40S 46068 MiB, resident bf16, no CPU offload",
        "cuda_visible_devices": args.cuda_devices,
    },
    "settled": True,
    # top-level mirrors of the fields the Space provenance table reads (matches the 9B meta)
    "temperature": args.temperature,
    "readout": ("typed-decision label readout: one forward pass per question primitive, "
                "full-vocabulary softmax at the answer position, label-token mass summed and "
                "renormalized over the declared candidates, logits divided by T"),
    "errors_by_code": errors_by_code,
    "forward_passes_per_decision": forward_passes,
    "loader": ("transformers AutoModelForCausalLM via gemma4_jev_shim.py; served on the "
               "jev.api/jev.server wire contract. eager attention, prefix cache disabled."),
})
if args.serving_json and Path(args.serving_json).exists():
    try:
        meta["serving"]["shim_banner"] = json.loads(Path(args.serving_json).read_text())
    except Exception:
        pass

tmp = meta_path.with_suffix(".json.tmp")
tmp.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
tmp.replace(meta_path)
print("SETTLED", pred.name, "rows=%d" % rows, "sha256=%s" % on_disk)
