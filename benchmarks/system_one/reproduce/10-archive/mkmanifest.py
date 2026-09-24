#!/usr/bin/env python3
import hashlib, json, os

B = "$WORK/.system-one-data/outputs/reproduce-bundle"
D = "$WORK/.system-one-data/outputs"
G = "<GPU_HOST>:$WORK"
S = "$WORK/.system-one-space-build/src"

# origin dir per source family
O = {
 "g4":   D + "/gemma4jev",
 "art":  D + "/gemma4jev/artifacts",
 "sj":   D + "/secjudge/code",
 "ojv":  D + "/openjev-qwen/validation/code",
 "j27":  G + "/sysone/j27",
 "sys":  G + "/sysone",
 "g4j":  G + "/g4j",
 "src":  S,
}

# rel -> (origin-key, purpose)
T = {
"01-dataset-lock/pins.json": ("art", "Pinned HuggingFace commit revisions for the four Gemma 4 family repos used by the Gemma4Jev arms."),
"01-dataset-lock/dl.py": ("art", "Snapshot-download the Gemma 4 family checkpoints strictly at the revisions in pins.json."),
"01-dataset-lock/download.sh": ("sys", "Fetch and stage the Open-Jev / Nimble / SecJudge checkpoints onto the GPU host NVMe."),

"02-case-construction/secjudge_serialize.py": ("sj", "SecJudge input serialisation, held fixed across every stage and context variant."),
"02-case-construction/secjudge_trunc.py": ("sj", "Measure the 512-token truncation rate on every corpus, split unsafe vs benign."),
"02-case-construction/run_trunc_all.sh": ("sj", "Driver: run the truncation measurement across all four corpora."),
"02-case-construction/sj_serialization_ablation.py": ("sj", "Justify the SecJudge serialisation choice from measured data rather than assertion."),
"02-case-construction/sj_serialization_ablation_alt.py": ("sj", "Alternate-form serialisation ablation, cross-checking the primary ablation."),
"02-case-construction/combine_ablation.py": ("sj", "Merge the production and alternate serialisation ablation results into one table."),
"02-case-construction/sj_plan.py": ("sj", "Exact compute budget: padded-token totals per stage/variant plus deduplication potential."),
"02-case-construction/g1_template.py": ("art", "Gate G1: pin the Gemma 4 chat templates and assert the rendered answer boundary."),
"02-case-construction/g4_lengths.py": ("art", "Gate G4: the real C7/I3/Q2 prompt-length distribution under the Gemma 4 tokenizers."),
"02-case-construction/audit_lengths.py": ("ojv", "Audit real s2 prompt lengths against each model's hard input ceiling."),
"02-case-construction/mk_selftest.py": ("j27", "Select worst-case selftest requests (longest real prompts) for memory headroom checks."),

"03-serving/common/provision.sh": ("sys", "Provision the GPU host for System One benchmarking of the LoRA adapters."),
"03-serving/common/provision_ojev.sh": ("sys", "Second venv pinned to Open-Jev's documented inference stack (transformers 5.10.2, peft 0.19.1)."),
"03-serving/common/ops.sh": ("sys", "Operations helper run on the GPU host; keeps backgrounding out of nested ssh quoting."),
"03-serving/common/launch.sh": ("sys", "Launch one replica per GPU for a given Open-Jev / Nimble adapter."),
"03-serving/common/phase.sh": ("ojv", "Phase launcher: bring up 4 single-GPU replicas of one model on the GPU host."),
"03-serving/common/check_placement.py": ("g4", "Gate: assert the 26B checkpoint is fully resident on GPU with no CPU/disk offload."),
"03-serving/common/probe_arch.py": ("j27", "Config-only probe: layer types, hidden size, and supported attn_implementation values."),
"03-serving/common/probe_bytes.py": ("j27", "Exact weight-byte accounting from safetensors headers only, reading no tensor data."),
"03-serving/common/verify_adapter.py": ("j27", "Verify a staged adapter matches its claimed architecture, from headers only."),
"03-serving/common/compare_attn.py": ("j27", "Quantify eager-vs-SDPA divergence on a checkpoint using identical request bodies."),

"03-serving/gemma4/gemma4_jev_shim.py": ("art", "Serve a Gemma 4 checkpoint on the /v1/systemone contract with jevify's own readout."),
"03-serving/gemma4/serve_gemma4.sh": ("art", "Serve a Gemma 4 checkpoint on /v1/systemone for the System One runner."),
"03-serving/gemma4/serve_g4_multi.sh": ("g4", "Serve Gemma 4 26B-A4B resident across N L40S, cache-free, eager attention."),
"03-serving/gemma4/serve_g4_2card.sh": ("g4j", "Two-card variant of the Gemma 4 26B-A4B serving topology."),
"03-serving/gemma4/g2_attention.py": ("art", "Gate G2 (blocking): eager vs SDPA vs math-only SDPA logit agreement across the sliding window."),
"03-serving/gemma4/g2b_attention.py": ("art", "Gate G2b: same weights and placement, only the attention kernel changes."),
"03-serving/gemma4/g2c_cpu.py": ("art", "Gate G2c: adjudicate eager vs SDPA on Gemma 4 26B-A4B against a CPU reference."),
"03-serving/gemma4/g2d_logits.py": ("art", "Dump answer-position candidate logits for a fixed prompt set, one device/kernel at a time."),
"03-serving/gemma4/g2d_compare.py": ("art", "Compare the g2d_logits.py candidate-logit dumps across devices and attention kernels."),
"03-serving/gemma4/g3_compare.py": ("art", "Gate G3: does the readout follow option content or option position?"),
"03-serving/gemma4/cpu_ref.sh": ("art", "Produce the float32 CPU reference logits that gate G2c adjudicates against."),
"03-serving/gemma4/chain2.sh": ("art", "Queue after run_holdouts.sh: G2 GPU-vs-CPU adjudication, then Nimble-9B on the same 324."),
"03-serving/gemma4/chain3.sh": ("art", "Third queued gate chain on a single dedicated card."),
"03-serving/gemma4/wdiff.py": ("art", "Which tensors did jevify's merged LoRA actually change relative to the base?"),
"03-serving/gemma4/larkooo_verdict.py": ("art", "Record the MLX-to-CUDA verdict for larkooo/gemma-e2b-rlcd from its shipped metadata."),

"03-serving/openjev-qwen/openjev_serve.py": ("ojv", "Serve a ZefanCai Open-Jev checkpoint under a display name carrying its base family."),
"03-serving/openjev-qwen/serve27.py": ("j27", "Serve an Open-Jev checkpoint whose base model does not fit on one card (27B sharded)."),
"03-serving/openjev-qwen/launch_2b_concurrent.sh": ("ojv", "Launch open-jev-qwen-2b replicas alongside the running bespoke-nimble-9b replicas."),
"03-serving/openjev-qwen/ab_prefix.py": ("ojv", "Gate Open-Jev's opt-in prefix cache against the unmodified full-prefill path."),
"03-serving/openjev-qwen/parity_openjev.py": ("ojv", "Parity gate: reproduce Open-Jev's published held-out accuracy with our serving stack."),
"03-serving/openjev-qwen/check_claims.py": ("j27", "Check the publisher's own JevBench figures against the numbers quoted to us."),
"03-serving/openjev-qwen/startup-shard0.json": ("j27", "Recorded startup provenance for 27B shard 0 (dtype, device map, attention, stack versions)."),
"03-serving/openjev-qwen/startup-shard1.json": ("j27", "Recorded startup provenance for 27B shard 1."),

"03-serving/nimble/nimble_shim.py": ("ojv", "Serve Bespoke-Nimble-9B on the /v1/systemone contract."),
"03-serving/secjudge/secjudge_infer.py": ("sj", "SecJudge CPU inference over a stage corpus."),
"03-serving/secjudge/sj_int8_probe.py": ("sj", "int8 dynamic-quantization equivalence check with a documented delta distribution."),

"04-run/drive_arm.sh": ("g4", "Drive one Gemma 4 s2 arm end to end: serve, tunnel, placement gate, smoke, full 30,310, settle."),
"04-run/drive_run.sh": ("g4", "Attach to an already-serving Gemma 4 shim and run one s2 arm to settlement."),
"04-run/progress.py": ("g4", "Report row counts, rate and ETA for the two Gemma 4 s2 arms."),
"04-run/resolution.py": ("g4", "Diagnostic: confidence/score resolution per arm while prediction files are still open."),
"04-run/check_rows.py": ("g4", "Assert a System One prediction file carries a graded, rankable readout."),
"04-run/run_holdouts.sh": ("art", "Phase 0 holdout sweep on the 324-item Nimble/Jev validation set."),
"04-run/holdout324.py": ("art", "Evaluate a Gemma 4 checkpoint on the 324-item Nimble/Jev holdout, with G3 built in."),
"04-run/run_secjudge_stages.sh": ("sj", "SecJudge stage runner: inference, merge, emit prediction arms, score with the shared scorer."),
"04-run/run_secjudge_stages2.sh": ("sj", "SecJudge stage runner, revision 2."),
"04-run/run_secjudge_stages3.sh": ("sj", "SecJudge stage runner, revision 3."),
"04-run/run_secjudge_stages4.sh": ("sj", "SecJudge stage runner, revision 4."),
"04-run/eta.py": ("sj", "Ground the stage ETAs in measured shard metas rather than guesses."),

"05-settlement/finish_arms.sh": ("g4", "Wait for both Gemma 4 arms to settle, then score them on the real deterministic tier."),
"05-settlement/settle_meta.py": ("g4", "Enrich a completed System One prediction meta with full Gemma 4 provenance."),
"05-settlement/after.sh": ("g4", "After finish_arms.sh scores both arms, build the three registry artifacts."),
"05-settlement/settle_s2_c7.sh": ("sj", "Settle only s2-C7: await shards, verify completeness, emit, score, recall@FPR."),
"05-settlement/check_settled.py": ("sj", "Settled-file discipline, applied independently of in-flight scorecards."),

"06-scoring/secjudge_emit.py": ("sj", "Turn cached SecJudge raw scores into prediction JSONL arms the existing scorer accepts."),
"06-scoring/score_incumbents.sh": ("sj", "Score incumbent models with the same shared scorer, cases and deterministic tier."),
"06-scoring/extract_incumbents.py": ("sj", "Collect the per-incumbent scorecards into one comparable rows table."),
"06-scoring/show_stage.py": ("sj", "Print one stage's case count, truth grades and cases_sha256 for spot checks."),

"07-analysis/recall_at_fpr.py": ("sj", "Recall at fixed FPR for SecJudge and every other measured model, on our corpora."),
"07-analysis/by_variable.py": ("g4", "Recall at fixed FPR for every ranking variable, with OpenJev's own FPR as a fifth point."),
"07-analysis/perm_average.py": ("art", "Permutation averaging, measured on runs already completed."),
"07-analysis/temp_fit.py": ("art", "Per-primitive vs single global temperature, fitted on our own 324-row measurements."),
"07-analysis/nimble324.py": ("art", "Re-run Bespoke-Nimble-9B on the same 324-row holdout for a calibration comparison."),
"07-analysis/nimble_temp.py": ("art", "Per-primitive vs single temperature on Bespoke-Nimble-9B's own 324-row logits."),
"07-analysis/assemble.py": ("art", "Assemble the Gemma4Jev Phase 0 scorecard from the gate and holdout artifacts."),
"07-analysis/render.py": ("art", "Render the Gemma4Jev Phase 0 scorecard as text."),
"07-analysis/build_extras.py": ("g4", "Build the leaderboard-registry artifacts for the two Gemma 4 s2 arms."),
"07-analysis/build_secjudge_report.py": ("sj", "Assemble secjudge-report.json and .md from settled artifacts only."),
"07-analysis/build_secjudge_md.py": ("sj", "Render secjudge-report.md from secjudge-report.json plus the incumbent scorecards."),
"07-analysis/narrative.py": ("sj", "Narrative sections for the SecJudge report, kept separate from the numeric builder."),

"08-site-build/build.py": ("src", "Site builder: reads the analysis JSONs, verifies every headline figure against its artifact, renders the pages."),
"08-site-build/verify.py": ("src", "Post-build verification gate suite over the generated static site."),
"08-site-build/guard.py": ("src", "Payload guard: case-id, sensitive-shingle, CJK, credential and size/type checks. REFERENCE ONLY - see README, not payload-safe."),
"08-site-build/publish.py": ("src", "Create the private static Space and upload the verified payload."),
"08-site-build/wc.py": ("src", "Card-span word counter used by the build's layout checks."),
"08-site-build/conform_to_space_contract.py": ("g4", "Conform the two settled Gemma 4 s2 arms to the Space build's added-arm contract without rewriting the runs."),
}

for n in ("gemma4jev_s2_gemma-4-26b-a4b-it", "gemma4jev_s2_jevify-gemma4-26b-a4b",
          "nimble_s2_bespoke-nimble-9b", "openjev-qwen_s2_open-jev-qwen-2b",
          "openjev-qwen_s2_open-jev-qwen-9b", "secjudge_s2_secjudge"):
    arm, _, model = n.partition("_s2_")
    T[f"03-serving/contracts/{n}.serving.json"] = (
        "CONTRACT:" + f"{D}/{arm}/s2/{model}.serving.json",
        f"Serving provenance contract for {model}: attention implementation, prefix-cache state and reason, "
        f"dtype, device map, replica topology, temperature, chat-template digest and pinned stack versions.")

T["00-environment/requirements-frozen.client-venv.txt"] = ("ENV", "Frozen pins for the evaluation-harness CLIENT venv only (34 packages). Contains no torch, vllm, transformers, tokenizers, accelerate or peft: it pins the client that called the models, not the stack that served them.")
T["00-environment/pinned-stack-by-arm.json"] = ("ENV", "Per-arm serving pins recovered from each run meta and settled serving contract, not from any lockfile; records which arms have no transformers pin at all.")

T["README.md"] = ("BUNDLE", "Bundle entry point: deep links, placeholder key, reading order, pinned stack and the known reproduction gaps.")

STAGES = {
 "00-environment": "Environment pins",
 "01-dataset-lock": "Dataset lock and model revision pins",
 "02-case-construction": "Case construction, serialisation and normalisation",
 "03-serving": "Serving, per model family, plus the settled serving contracts",
 "04-run": "The run",
 "05-settlement": "Settlement",
 "06-scoring": "Scoring",
 "07-analysis": "Analysis",
 "08-site-build": "Site build and payload verification",
}

files = []
for root, _d, names in os.walk(B):
    for n in sorted(names):
        if n == "MANIFEST.json":
            continue
        p = os.path.join(root, n)
        files.append(os.path.relpath(p, B))
files.sort()

recs = []
missing = []
for rel in files:
    p = os.path.join(B, rel)
    blob = open(p, "rb").read()
    ent = T.get(rel)
    if ent is None:
        missing.append(rel)
        origin, purpose = "UNKNOWN", "UNDOCUMENTED"
    else:
        key, purpose = ent
        if key.startswith("CONTRACT:"):
            origin = key.split("CONTRACT:", 1)[1]
        elif key == "ENV":
            origin = (D + "/requirements-frozen.txt" if rel.endswith(".txt")
                      else "derived from */s2/*.serving.json and */s2/*.jsonl.meta.json")
        elif key == "BUNDLE":
            origin = "authored for this bundle"
        else:
            origin = O[key] + "/" + os.path.basename(rel)
    recs.append({
        "path": rel,
        "stage": STAGES.get(rel.split("/")[0], "Bundle documentation"),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "bytes": len(blob),
        "origin": origin,
        "purpose": purpose,
        "payload_safe": rel != "08-site-build/guard.py",
    })

if missing:
    raise SystemExit("UNDOCUMENTED FILES: " + repr(missing))

man = {
 "kind": "defenseclaw-system-one-reproduce-bundle",
 "schema_version": 1,
 "generated_utc": __import__("datetime").datetime.now(
     __import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
 "repo": {
   "public": "cisco-ai-defense/defenseclaw",
   "branch": "feat/system-one-benchmarks",
   "commit": "d2ae73f32736db0aa9fd8e78d5656355c1a41012",
   "benchmarks_tree_branch": "https://github.com/cisco-ai-defense/defenseclaw/tree/feat/system-one-benchmarks/benchmarks",
   "benchmarks_tree_pinned": "https://github.com/cisco-ai-defense/defenseclaw/tree/d2ae73f32736db0aa9fd8e78d5656355c1a41012/benchmarks",
 },
 "scrub": {
   "placeholders": {
     "<GPU_HOST>": "address of the 4x L40S serving host",
     "<SSH_KEY>": "path to the private key used to reach <GPU_HOST>",
     "$WORK": "operator home root that held .system-one-data and .system-one-space-build",
   },
   "retained": ["127.0.0.1 (loopback tunnel endpoints; required to read the scripts)",
                "environment variable NAMES such as SYSONE_NO_KEY and CHEAP_KEY (names, never values)"],
   "verified_absent": ["host IPs other than loopback", "ssh key paths", "absolute operator-home paths (rewritten to the $WORK placeholder)",
                       "AWS account/instance/volume/security-group/AMI/ARN ids",
                       "credential values of any provider shape", "private key blocks",
                       "dataset rows, prompts, case text and provider rationales"],
 },
 "restage_required": {
   "path": "08-site-build/build.py",
   "reason": "point-in-time copy of a file that was under active edit when this bundle was staged",
   "action": "re-copy from src/build.py, re-apply the scrub, then regenerate this manifest with mkmanifest.py",
   "staged_sha256_may_be_stale": True,
 },
 "totals": {"files": len(recs), "bytes": sum(r["bytes"] for r in recs),
            "payload_safe_files": sum(1 for r in recs if r["payload_safe"]),
            "payload_safe_bytes": sum(r["bytes"] for r in recs if r["payload_safe"])},
 "files": recs,
}
open(os.path.join(B, "MANIFEST.json"), "w").write(json.dumps(man, indent=2) + "\n")
print("files:", man["totals"]["files"], "bytes:", f"{man['totals']['bytes']:,}")
print("payload-safe:", man["totals"]["payload_safe_files"],
      f"{man['totals']['payload_safe_bytes']:,} bytes")
