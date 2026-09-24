"""Arm registry for the laptop-class guardrail cohort.

readout families:
  letter3        decoder instruct LM; per-question single-letter choice, softmax over the
                 candidate letter token ids only (the Nimble shape, which needs no trained head)
  shieldstral    2-class yes/no policy classifier; softmax over the yes/no ids only
  seqcls         encoder with a trained 2-class sequence-classification head
  mlm_control    bare masked-LM backbone; yes/no readout at a [MASK]. NEGATIVE CONTROL, not a candidate.
"""
W = "/teamspace/studios/this_studio/laptopguard"
WEIGHTS = W + "/weights"

def _p(repo): return WEIGHTS + "/" + repo.replace("/", "__")

ARMS = {
 # ---- candidates: decoder instruct LMs -------------------------------------------------
 "granite-guardian-3.1-2b": dict(
    repo="ibm-granite/granite-guardian-3.1-2b", revision="81145486e85c6c82c01e759c0356d9d6da4d21a5",
    params=2533531648, licence="apache-2.0", origin="USA (IBM)", readout="letter3",
    note="purpose-built guardrail, fixed taxonomy"),
 "granite-guardian-3.2-3b-a800m": dict(
    repo="ibm-granite/granite-guardian-3.2-3b-a800m", revision="3de033d89b499a18d9a573b5192bf3b967ef48c5",
    params=3298793472, licence="apache-2.0", origin="USA (IBM)", readout="letter3",
    note="MoE, ~800M active; purpose-built guardrail"),
 "granite-4.0-1b": dict(
    repo="ibm-granite/granite-4.0-1b", revision="6a7381ba1f54d684ff508d991aeb7dc580157103",
    params=1631750144, licence="apache-2.0", origin="USA (IBM)", readout="letter3",
    note="GraniteMoeHybridForCausalLM (arch class hides dense/hybrid split)"),
 "granite-4.0-micro": dict(
    repo="ibm-granite/granite-4.0-micro", revision="56111ae135df9c53a78c99028e7bc24035a9e979",
    params=3402836480, licence="apache-2.0", origin="USA (IBM)", readout="letter3",
    note="GraniteMoeHybridForCausalLM"),
 "phi-4-mini-instruct": dict(
    repo="microsoft/Phi-4-mini-instruct", revision="cfbefacb99257ffa30c83adab238a50856ac3083",
    params=3836021760, licence="mit", origin="USA (Microsoft)", readout="letter3"),
 "smollm2-1.7b-instruct": dict(
    repo="HuggingFaceTB/SmolLM2-1.7B-Instruct", revision="31b70e2e869a7173562077fd711b654946d38674",
    params=1711376384, licence="apache-2.0", origin="France/USA (HuggingFace)", readout="letter3"),
 "smollm3-3b": dict(
    repo="HuggingFaceTB/SmolLM3-3B", revision="a07cc9a04f16550a088caea529712d1d335b0ac1",
    params=3075098624, licence="apache-2.0", origin="France/USA (HuggingFace)", readout="letter3"),
 "olmo-2-1b-instruct": dict(
    repo="allenai/OLMo-2-0425-1B-Instruct", revision="48d788eca847d4d7548f375ad03d3c9312f6139e",
    params=1484916736, licence="apache-2.0", origin="USA (Ai2)", readout="letter3"),
 "falcon3-1b-instruct": dict(
    repo="tiiuae/Falcon3-1B-Instruct", revision="28ba2251970a01dd1edc7ba7dad2eb71216ccfdf",
    params=1669408768, licence="other (Falcon LLM licence)", origin="UAE (TII)", readout="letter3"),
 "falcon3-3b-instruct": dict(
    repo="tiiuae/Falcon3-3B-Instruct", revision="411bb94318f94f7a5735b77109f456b1e74b42a1",
    params=3227655168, licence="other (Falcon LLM licence)", origin="UAE (TII)", readout="letter3"),
 # ---- candidate: 2-class policy classifier --------------------------------------------
 "shieldstral-1.0-3b": dict(
    repo="mistralai/Shieldstral-1.0-3B", revision="003ec7e2b0bab5f0e6307edbaf186fa5822b76f5",
    params=3849090048, licence="apache-2.0", origin="France (Mistral)", readout="shieldstral",
    note="Mistral3ForConditionalGeneration: ministral3 text tower + Pixtral vision encoder"),
 # ---- candidate: trained encoder classifier -------------------------------------------
 "deberta-v3-prompt-injection-v2": dict(
    repo="protectai/deberta-v3-base-prompt-injection-v2", revision="90c9989b1a342275dd0d1a95aad283c04e075671",
    params=184423682, licence="apache-2.0", origin="USA (ProtectAI)", readout="seqcls",
    note="trained 2-class injection head; 512-token limit"),
 # ---- CONTROLS: bare MLM backbones, no safety training. Expected near chance. ----------
 "control-modernbert-base": dict(
    repo="answerdotai/ModernBERT-base", revision="8949b909ec900327062f0ebf497f51aef5e6f0c8",
    params=149655232, licence="apache-2.0", origin="USA/France (Answer.AI/LightOn)",
    readout="mlm_control", control=True),
 "control-modernbert-large": dict(
    repo="answerdotai/ModernBERT-large", revision="45bb4654a4d5aaff24dd11d4781fa46d39bf8c13",
    params=395881664, licence="apache-2.0", origin="USA/France (Answer.AI/LightOn)",
    readout="mlm_control", control=True),
 # ---- gated arms, unlocked by a licence-accepted token ----
 "llama-guard-3-1b": dict(
    repo="meta-llama/Llama-Guard-3-1B", revision='acf7aafa60f0410f8f42b1fa35e077d705892029',
    params=1498482688, licence='llama3.2 (GATED, acceptance required)', origin='USA (Meta)', readout='llamaguard', loader='causal',
    gated=True, note='purpose-built safety classifier; default taxonomy S1-S13 has NO destructive-tool-call category'),
 "shieldgemma-2b": dict(
    repo="google/shieldgemma-2b", revision='d1dffc9c8c9237a90aab09c61383791e718ef9e8',
    params=2614341888, licence='gemma (GATED, acceptance required)', origin='USA (Google)', readout='shieldgemma', loader='causal',
    gated=True, note='purpose-built safety classifier; accepts a plain-language guideline'),
 "gemma-3-4b-it": dict(
    repo="google/gemma-3-4b-it", revision='093f9f388b31de276ce2de164bdc2081324b9767',
    params=4300079472, licence='gemma (GATED, acceptance required)', origin='USA (Google)', readout='letter3', loader='imagetext',
    gated=True, note='multimodal Gemma3ForConditionalGeneration'),
 "llama-3.2-3b-instruct": dict(
    repo="meta-llama/Llama-3.2-3B-Instruct", revision='0cb88a4f764b7a12671c53f0838cd831a0843b95',
    params=3212749824, licence='llama3.2 (GATED, acceptance required)', origin='USA (Meta)', readout='letter3', loader='causal',
    gated=True, note=''),
 "gemma-3-1b-it": dict(
    repo="google/gemma-3-1b-it", revision='dcc83ea841ab6100d6b47a070329e1ba4cf78752',
    params=999885952, licence='gemma (GATED, acceptance required)', origin='USA (Google)', readout='letter3', loader='causal',
    gated=True, note=''),
 "llama-3.2-1b-instruct": dict(
    repo="meta-llama/Llama-3.2-1B-Instruct", revision='9213176726f574b556790deb65791e0c5aa438b6',
    params=1235814400, licence='llama3.2 (GATED, acceptance required)', origin='USA (Meta)', readout='letter3', loader='causal',
    gated=True, note=''),
 # ---- trained encoder classifiers, independent backbone ----
 "prompt-guard-2-86m": dict(
    repo="meta-llama/Llama-Prompt-Guard-2-86M", revision='a8ded8e697ce7c355e395a0df51f94adb4a2fd27',
    params=278810882, licence='other (GATED, separate acceptance group)', origin='USA (Meta)', readout="seqcls", loader="seqcls",
    gated=True, note='trained injection/jailbreak encoder; 512-token limit; repo name understates params'),
 "prompt-guard-2-22m": dict(
    repo="meta-llama/Llama-Prompt-Guard-2-22M", revision='11614a155199674a0a95e6602d6ab0417b790ed0',
    params=70830722, licence='other (GATED, separate acceptance group)', origin='USA (Meta)', readout="seqcls", loader="seqcls",
    gated=True, note='trained injection/jailbreak encoder; 512-token limit; repo name understates params'),
}
for k, v in ARMS.items():
    v["path"] = _p(v["repo"]); v["key"] = k
    v.setdefault("loader", "causal"); v.setdefault("gated", False)
