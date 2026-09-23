"""Render the Gemma4Jev Phase 0 scorecard as text."""

import json
import sys
from pathlib import Path

d = json.loads(Path(sys.argv[1]).read_text())
L = []
A = L.append
A("=" * 118)
A("Gemma4Jev Phase 0 -- correctness gates and zero-training evaluation of two public Gemma 4 adapters")
A("=" * 118)
A("")
A("GATES")
A("-" * 118)
g1 = d["gates"]["G1_template_pin"]
A("G1 template pin: %s" % g1["verdict"])
A("  %-34s %-14s %-9s %-6s %-22s %-22s %s" % ("repo", "template sha8", "window", "layers", "tail thinking=False",
                                              "tail thinking=True", "single-token answer passes F/T"))
for repo, v in g1["per_repo"].items():
    A("  %-34s %-14s %-9s %-6s %-22s %-22s %s/%s" % (
        repo, v["chat_template_sha256"][:12], v["sliding_window"], v["layers"],
        v["tail_thinking_false"], v["tail_thinking_true"],
        v["single_token_answer_passes_thinking_false"], v["single_token_answer_passes_thinking_true"]))
A("")
g2 = d["gates"]["G2_attention"]
A("G2 attention (BLOCKING): %s" % g2["verdict"])
for name, v in g2["detail"].items():
    if "worst" in v:
        A("  %s  (%s, window %s, %d prompts, %d crossing, same-config repeat floor %s)" % (
            name, v["repo"], v["sliding_window"], v["prompts"], v["prompts_crossing_window"],
            v["same_config_repeat_floor"]))
        for pair, w in v["worst"].items():
            A("      %-26s labelprob=%-11.4g candlogit=%-9.4g fullvocab=%-9.4g candArgmaxX=%d fullArgmaxX=%d" % (
                pair, w["max_abs_label_probability_diff"], w["max_abs_logit_diff_candidates"],
                w["max_abs_logit_diff_full_vocab"], w["argmax_candidate_disagreements"],
                w["argmax_full_vocab_disagreements"]))
        A("      eager_required=%s" % v["eager_required"])
    else:
        A("  %s" % name)
        for pair, w in v.get("pairs", {}).items():
            A("      %-46s labelprob=%-11.4g logit=%-9.4g argmaxX=%d" % (
                pair, w["max_abs_label_probability_diff"], w["max_abs_candidate_logit_diff"],
                w["argmax_disagreements"]))
        if v.get("normalized_entropy"):
            for k, e in v["normalized_entropy"].items():
                A("      normalized entropy %-32s min=%.4f med=%.4f max=%.4f" % (k, e["min"], e["median"], e["max"]))
A("")
A("G3 position bias (324 rows, Choice options reversed; content-following keeps the KEY, position-following keeps the LETTER)")
A("  %-14s %-34s %6s %8s %8s %8s %8s %8s %8s" % ("run", "repo", "choice", "contentR", "positionR", "accOrig",
                                                 "accRev", "delta", "A-rate o/r"))
for name, v in d["gates"]["G3_position_bias"]["detail"].items():
    A("  %-14s %-34s %6d %8.4f %9.4f %8.4f %8.4f %+8.4f %.3f/%.3f" % (
        name, v["repo"], v["choice_rows"], v["content_following_rate"], v["position_following_rate"],
        v["choice_accuracy_original"], v["choice_accuracy_reversed"], v["choice_accuracy_delta"],
        v["first_option_rate_original"], v["first_option_rate_reversed"]))
    A("      letters original %s -> reversed %s ; unpermuted kinds bit-identical: %s" % (
        v["letter_histogram_original"], v["letter_histogram_reversed"], v["unpermuted_kinds_bit_identical"]))
A("")
g4 = d["gates"]["G4_length"]
A("G4 length: %s" % g4["verdict"])
p = g4["per_question_prompt_tokens"]
A("  %d C7/I3/Q2 requests, %d rendered prompts. tokens p0=%d p50=%d p90=%d p95=%d p99=%d p99.9=%d max=%d mean=%.1f" % (
    g4["requests_scanned"], p["n"], p["p0"], p["p50"], p["p90"], p["p95"], p["p99"], p["p99.9"], p["p100"], p["mean"]))
A("  over 2048 tokens: %d (%.2f%%)   over 4096: %d   over 512-window: %d   over 1024-window: %d" % (
    g4["over_2048"], 100 * g4["over_2048"] / p["n"], g4["over_4096"],
    g4["over_sliding_window_512"], g4["over_sliding_window_1024"]))
A("  state bytes p50=%d p95=%d max=%d" % (g4["state_bytes"]["p50"], g4["state_bytes"]["p95"], g4["state_bytes"]["p100"]))
A("")
A("324-ROW HOLDOUT (Nimble's own validation split, fingerprint 286a918b...; the shared accounting of the published artifact)")
A("-" * 118)
A("  %-22s %-9s %-8s %9s %7s %7s %7s %7s %8s %7s" % ("run", "correct", "acc", "nll", "brier", "ece15", "conf",
                                                     "P(ref)", "median s", "offload"))
for name, v in d["holdout_324"].items():
    if "all" in v:
        a = v["all"]
        A("  %-22s %4d/324 %8.4f %9.4f %7.4f %7.4f %7.4f %7.4f %8.3f %7s" % (
            name, a["correct"], a["accuracy"], a["mean_nll"], a["mean_brier"], a["ece_15bin"],
            a["mean_top_probability"], a["mean_reference_probability"],
            v["median_seconds_per_item"], v["offloaded"]))
    else:
        for tk in ("temperature_1", "temperature_fitted"):
            a = v[tk]["all"]
            A("  %-22s %4d/324 %8.4f %9.4f %7.4f %7.4f %7.4f %7.4f %8s %7s" % (
                name + " " + tk.replace("temperature_", "T="), a["correct"], a["accuracy"], a["mean_nll"],
                a["mean_brier"], a["ece_15bin"], a["mean_top_probability"], a["mean_reference_probability"], "-", "-"))
A("")
A("  published reference points on the same 324 rows:")
for k, v in d["holdout_324_reference_points"].items():
    A("    %-46s %3d/324  %.4f" % (k, v["correct"], v["accuracy"]))
A("")
A("  per-kind breakdown")
A("  %-22s %-16s %-16s %-16s" % ("run", "choice", "noul", "score"))
for name, v in d["holdout_324"].items():
    if "all" not in v:
        continue
    cells = []
    for kind in ("choice", "noul", "score"):
        g = v.get(kind)
        cells.append("%d/%d %.3f" % (g["correct"], g["count"], g["accuracy"]) if g else "-")
    A("  %-22s %-16s %-16s %-16s" % (name, *cells))
A("")
wd = d["analysis"].get("jevify_vs_base_weight_diff")
if wd:
    A("WHAT JEVIFY ACTUALLY TRAINED (tensor-by-tensor diff against google/gemma-4-26B-A4B-it)")
    A("-" * 118)
    A("  %-20s %8s %16s %8s %16s %12s %12s" % ("module class", "tensors", "params", "changed", "changed params",
                                               "maxAbsDelta", "maxRelFro"))
    for k, v in wd["by_module_class"].items():
        A("  %-20s %8d %16d %8d %16d %12.4g %12.4g" % (
            k, v["tensors"], v["params"], v["changed_tensors"], v["changed_params"],
            v["max_abs_delta"], v["max_rel_fro"]))
    t = wd["total"]
    A("  %-20s %8d %16d %8d %16d   changed fraction %.6f" % (
        "TOTAL", t["tensors"], t["params"], t["changed_tensors"], t["changed_params"], t["changed_params_fraction"]))
    A("  " + wd["finding"])
A("")
lk = d["analysis"].get("larkooo_gemma_e2b_rlcd")
if lk:
    A("larkooo/gemma-e2b-rlcd -- MLX to CUDA")
    A("-" * 118)
    v = lk["mlx_to_cuda_verdict"]
    A("  converts to CUDA: %s" % v["converts_to_cuda"])
    A("  %s" % v["reason"])
    A("  %s" % v["why_it_does_not_matter"])
    n = lk["own_negative_result_preserved"]
    A("  its own negative result, preserved: trained head %s and %s vs pretrained answer-code %s" % (
        n["four_layer_state_plus_trained_head"]["test_correct"],
        n["full_35_layer_state_plus_trained_head"]["test_correct"],
        n["pretrained_gemma_answer_code_reference"]["test_correct"]))
A("")
A("LICENCES RECORDED")
A("-" * 118)
for k, v in d["licences_recorded"].items():
    A("  %-40s %s" % (k, v))
print("\n".join(L))
Path(sys.argv[2]).write_text("\n".join(L) + "\n")
