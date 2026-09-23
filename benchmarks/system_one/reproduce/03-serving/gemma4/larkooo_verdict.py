"""Record the MLX-to-CUDA verdict for larkooo/gemma-e2b-rlcd from its own shipped metadata."""

import json
from pathlib import Path

HUB = Path("/opt/dlami/nvme/hf/hub")
PINS = json.loads(Path("$WORK/g4j/pins.json").read_text())
lk = HUB / "models--larkooo--gemma-e2b-rlcd" / "snapshots" / PINS["larkooo/gemma-e2b-rlcd"]

config = json.loads((lk / "config.json").read_text())
source = json.loads((lk / "model-source.json").read_text())
provenance = json.loads((lk / "checkpoint-provenance.json").read_text())
weight_map = json.loads((lk / "model.safetensors.index.json").read_text())["weight_map"]

verdict = {
    "repo_id": "larkooo/gemma-e2b-rlcd",
    "revision": PINS["larkooo/gemma-e2b-rlcd"],
    "declared": {"library_name": "mlx", "base_model_relation": "quantized", "inference": False,
                 "card_license": "apache-2.0", "card_tags_include": ["mlx", "mlx-vlm", "gemma4", "rlcd"]},
    "model_source_json": source,
    "checkpoint_provenance": {k: provenance[k] for k in (
        "checkpoint_repository", "checkpoint_revision", "checkpoint_modified",
        "original_model", "original_model_revision", "model_license",
        "conversion_card_license_tag", "license_note")},
    "quantization": config.get("quantization"),
    "weights": {
        "total_parameters_counted": 1196198371,
        "dtype_breakdown": {"BF16": 617220579, "U32_packed_4bit": 578977792},
        "mlx_scale_tensors": sum(1 for k in weight_map if k.endswith(".scales")),
        "mlx_bias_tensors": sum(1 for k in weight_map if k.endswith(".biases")),
        "tensor_keys": len(weight_map),
        "google_e2b_reference": {"tensor_keys": 2011, "total_parameters": 5123178979, "dtype": "BF16"},
    },
    "own_negative_result_preserved": {
        "source": "docs/training.md in the same repo",
        "setup": "64 training scenes, 16 validation, 16 test; four questions per scene; 600 AdamW updates, lr 3e-4, seed 11, shuffled candidate order",
        "four_layer_state_plus_trained_head": {"test_correct": "21/64", "nll": 1.0769, "brier": 0.6510},
        "full_35_layer_state_plus_trained_head": {"test_correct": "23/64", "nll": 0.9659, "brier": 0.5818},
        "pretrained_gemma_answer_code_reference": {"test_correct": "64/64", "nll": 0.0063, "brier": 0.0010},
        "repo_conclusion": "the head configurations scored below the pretrained reference, so the default inference path uses Gemma's own candidate likelihoods",
    },
    "mlx_to_cuda_verdict": {
        "converts_to_cuda": False,
        "reason": ("the checkpoint is an unmodified redistribution of mlx-community/gemma-4-e2b-it-4bit "
                   "(checkpoint_modified: false), stored as MLX affine 4-bit: 280 .scales and 280 .biases "
                   "sidecar tensors and 578,977,792 U32-packed words across 2,511 keys, against google's "
                   "2,011 all-BF16 keys. transformers has no loader for that layout; converting means "
                   "dequantizing to bf16."),
        "why_it_does_not_matter": ("there are no trained weights to recover. Dequantizing would reconstruct a "
                                  "lossy copy of google/gemma-4-E2B-it at revision "
                                  "3e22461f65e89153144f8adb70e3b8c2cc9845a7, which we hold exactly. Its shipped "
                                  "default readout is pretrained Gemma's own candidate likelihoods, so "
                                  "evaluating google/gemma-4-E2B-it bf16 with an answer-code readout IS the "
                                  "faithful evaluation of this repo, at higher precision."),
        "gpu_time_budgeted": "zero",
    },
}
Path("$WORK/g4j/out/larkooo-verdict.json").write_text(json.dumps(verdict, indent=2) + "\n")
print(json.dumps(verdict["mlx_to_cuda_verdict"], indent=2))
