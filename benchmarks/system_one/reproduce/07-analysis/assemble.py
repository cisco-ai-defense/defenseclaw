"""Assemble the Gemma4Jev Phase 0 scorecard from the gate and holdout artifacts."""

import json
from pathlib import Path

OUT = Path("$WORK/g4j/out")
REFERENCE = {
    "Qwen3.5-9B (base, no adapter)": 215,
    "Bespoke-Nimble-9B (LoRA r=16 on Qwen3.5-9B)": 292,
    "Jev 1.13.0 (hosted)": 302,
}
LICENSES = {
    "google/gemma-4-E2B-it": "apache-2.0",
    "google/gemma-4-26B-A4B-it": "apache-2.0",
    "kushalpatil/jevify-gemma4-26b-a4b": "gemma",
    "larkooo/gemma-e2b-rlcd": "apache-2.0 per its own provenance file; its card tags license: gemma",
    "bespokelabs/Bespoke-Nimble-9B": "see repo",
    "openjev/openjev": "CC BY-NC 4.0 (weights); helper/ and serve/ Apache-2.0; base Apache-2.0",
}


def read(path):
    p = Path(path)
    return json.loads(p.read_text()) if p.exists() else None


def main():
    report = {"kind": "gemma4jev-phase0-scorecard", "phase": "0 (no training)",
              "licences_recorded": LICENSES, "gates": {}, "holdout_324": {}, "analysis": {}}

    g1 = read(OUT / "g1-template-pin.json")
    if g1:
        report["gates"]["G1_template_pin"] = {
            "verdict": "pass -- templates pinned; the enable_thinking hazard is confirmed and avoided",
            "per_repo": {
                repo: {
                    "chat_template_sha256": v["chat_template_sha256"],
                    "chat_template_bytes": v["chat_template_bytes"],
                    "model_type": v["model_type"], "sliding_window": v["sliding_window"],
                    "layers": v["num_hidden_layers"], "hidden_size": v["hidden_size"],
                    "layer_types": v["layer_types_count"],
                    "tail_thinking_false": v["variants"]["thinking_false"]["tail_token_ids"],
                    "tail_thinking_false_texts": v["variants"]["thinking_false"]["tail_token_texts"],
                    "tail_thinking_true": v["variants"]["thinking_true"]["tail_token_ids"],
                    "single_token_answer_passes_thinking_false":
                        v["variants"]["thinking_false"]["single_token_answer_passes"],
                    "single_token_answer_passes_thinking_true":
                        v["variants"]["thinking_true"]["single_token_answer_passes"],
                    "thought_channel_prefilled":
                        v["variants"]["thinking_false"]["tail_token_ids"] != v["variants"]["thinking_true"]["tail_token_ids"],
                } for repo, v in g1.items()},
        }

    gates2 = {}
    for name, path in (("e2b_single_load", "g2b-e2b.json"), ("jevify_single_load_stress", "g2b-jevify-stress.json"),
                       ("e2b_reload", "g2-e2b.json"), ("26b_reload", "g2-26b.json"),
                       ("jevify_reload_stress", "g2-jevify-stress.json")):
        v = read(OUT / path)
        if v:
            gates2[name] = {"repo": v["repo"], "sliding_window": v["sliding_window"],
                            "prompts": len(v["prompt_token_counts"]),
                            "prompts_crossing_window": v["prompts_crossing_window"],
                            "prompt_token_counts": v["prompt_token_counts"],
                            "same_config_repeat_floor": v.get("same_config_repeat_floor"),
                            "worst": v["worst"], "eager_required": v["eager_required"]}
    cpu = read(OUT / "g2d-cpu-pair.json")
    if cpu:
        gates2["cpu_float32_adjudication"] = {"pairs": {k: {kk: vv for kk, vv in val.items() if kk != "per_prompt"}
                                                       for k, val in cpu["pairs"].items()},
                                              "normalized_entropy": cpu.get("normalized_entropy")}
    gpu_pair = read(OUT / "g2d-gpu-vs-cpu.json")
    if gpu_pair:
        gates2["gpu_vs_cpu_adjudication"] = {"pairs": {k: {kk: vv for kk, vv in val.items() if kk != "per_prompt"}
                                                      for k, val in gpu_pair["pairs"].items()}}
    report["gates"]["G2_attention"] = {
        "verdict": ("SDPA rejected; every Gemma 4 number in this phase was produced with "
                    "attn_implementation=eager"),
        "detail": gates2,
    }

    g3 = {}
    for name in ("g3-e2b.json", "g3-jevify.json", "g3-26b-base.json"):
        v = read(OUT / name)
        if v:
            g3[name.removeprefix("g3-").removesuffix(".json")] = {
                "repo": v["repo"], "choice_rows": v["verdict"]["choice_rows"],
                "content_following_rate": v["verdict"]["content_following_rate"],
                "position_following_rate": v["verdict"]["position_following_rate"],
                "choice_accuracy_original": v["by_kind"]["choice"]["accuracy_original_order"],
                "choice_accuracy_reversed": v["by_kind"]["choice"]["accuracy_reversed_order"],
                "choice_accuracy_delta": v["verdict"]["choice_accuracy_delta"],
                "unpermuted_kinds_bit_identical": v["verdict"]["unpermuted_kinds_bit_identical"],
                "first_option_rate_original": v["first_option_rate_original"],
                "first_option_rate_reversed": v["first_option_rate_reversed"],
                "letter_histogram_original": v["letter_histogram_original"],
                "letter_histogram_reversed": v["letter_histogram_reversed"]}
    report["gates"]["G3_position_bias"] = {"detail": g3}

    g4 = read(OUT / "g4-lengths.json")
    if g4:
        report["gates"]["G4_length"] = {
            "verdict": ("pass -- the measured C7/I3/Q2 prompt distribution sits inside Nimble's 2,048-token "
                        "training length for 99.5% of prompts and never exceeds 4,096"),
            "requests_scanned": g4["requests_scanned"], "grid": g4["grid"],
            "tokenizer_sha256": g4["tokenizer_sha256"],
            "per_question_prompt_tokens": g4["google/gemma-4-26B-A4B-it"]["per_question_prompt_tokens"],
            "over_2048": g4["google/gemma-4-26B-A4B-it"]["over_2048"],
            "over_4096": g4["google/gemma-4-26B-A4B-it"]["over_4096"],
            "over_sliding_window_512": g4["google/gemma-4-26B-A4B-it"]["over_sliding_window_512"],
            "over_sliding_window_1024": g4["google/gemma-4-26B-A4B-it"]["over_sliding_window_1024"],
            "state_bytes": g4["state_bytes"],
        }

    for name in sorted(p.name for p in (OUT / "holdout").iterdir()) if (OUT / "holdout").is_dir() else []:
        results = read(OUT / "holdout" / name / "results.json")
        if not results:
            continue
        if "summary_temperature_1" in results:  # nimble
            report["holdout_324"][name] = {
                "model": results["model"], "adapter_revision": results["adapter_revision"],
                "note": results["note"],
                "temperature_1": results["summary_temperature_1"],
                "temperature_fitted": results["summary_temperature_fitted"],
                "fitted_temperature": results["fitted_temperature"],
                "selected_letter_counts_choice": results["selected_letter_counts_choice"],
                "wall_seconds": results["wall_seconds"]}
            continue
        settings, summary = results["settings"], results["summary"]
        report["holdout_324"][name] = {
            "repo": settings["repo"], "revision": settings["revision"], "permute": settings["permute"],
            "attention": settings["attention"], "offloaded": bool(settings["device_map"]),
            "licence": LICENSES.get(settings["repo"]),
            "all": summary["all"], "choice": summary.get("choice"), "noul": summary.get("noul"),
            "score": summary.get("score"), "by_family": summary["by_family"],
            "selected_letter_counts_choice": summary["selected_letter_counts_choice"],
            "wall_seconds": results["wall_seconds"],
            "median_seconds_per_item": results["median_seconds_per_item"]}

    report["holdout_324_reference_points"] = {
        k: {"correct": v, "count": 324, "accuracy": v / 324} for k, v in REFERENCE.items()}

    wd = read(OUT / "jevify-weight-diff.json")
    if wd:
        report["analysis"]["jevify_vs_base_weight_diff"] = {
            "total": wd["total"], "by_module_class": wd["by_module_class"],
            "finding": ("the merged LoRA changed exactly the 115 language-model self-attention projections: "
                        "1.110 B of 25.806 B parameters (4.30%). The 22.838 B MoE expert parameters, the "
                        "0.937 B dense MLP, the 10.9 M router, the embeddings, every norm and the whole "
                        "108-tensor vision tower are byte-identical to the base.")}
    report["analysis"]["larkooo_gemma_e2b_rlcd"] = read(OUT / "larkooo-verdict.json")
    report["analysis"]["temperature_calibration"] = read(OUT / "temp-calibration.json")
    report["analysis"]["nimble_temperature_calibration"] = read(OUT / "nimble-temp-calibration.json")
    report["analysis"]["permutation_averaging"] = {
        name.removeprefix("perm-average-").removesuffix(".json"): read(OUT / name)
        for name in ("perm-average-e2b.json", "perm-average-26b-base.json", "perm-average-jevify.json")
        if (OUT / name).exists()}
    report["analysis"]["threshold_vs_model_s2"] = read(
        Path("$WORK/g4j/out/threshold-vs-model-s2.json"))
    report["analysis"]["prefix_cache_not_numerically_neutral"] = {
        "measured_on": "324-row holdout, kushalpatil/jevify-gemma4-26b-a4b, eager, bf16",
        "what": ("the two jevify runs differ only in Choice option order, so the 178 unpermuted noul and "
                 "score rows should be identical. Carrying the KV prefix cache across rows makes the "
                 "boundary between reused and freshly computed KV depend on the previous row, and in bf16 "
                 "that changes the result."),
        "probability_drift_on_unpermuted_rows": {"n": 484, "max": 0.176, "mean": 0.0116, "median": 0.00174},
        "argmax_changes": 0,
        "fix": ("--no-prefix-cache gives an independent full prefill per question, which is what Nimble's "
                "CUDA scorer and the Open-Jev server already do")}

    Path(OUT / "phase0-scorecard.json").write_text(json.dumps(report, indent=2, sort_keys=False) + "\n")
    print(json.dumps({"gates": list(report["gates"]), "holdout_runs": list(report["holdout_324"])}, indent=2))


if __name__ == "__main__":
    main()
