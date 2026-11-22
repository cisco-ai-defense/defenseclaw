# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Registry of locked datasets for s7_datasets.py (DET111 DATA-A).

Per dataset id (the id in benchmarks/datasets.lock.json):
  slug     corpus name stem (the s7-gate corpus is <slug>-<VERSION>)
  fetch    prepare (git, via benchmark_prepare.py) | hf | zenodo
  dir      directory below data/sources when the adapter wants a fixed name (default: the id)
  norm     [adapter script, args...]; {src} {srcroot} {data} {rev} {out} {manifest} {lock} are substituted
  norm_slug / match   several ids share one adapter run (ATBench family): the run writes norm/<norm_slug>.jsonl,
           convert keeps only rows whose source.dataset equals `match`
  include_from   prepare only: fetch exactly the paths the adapter audits (splunk), never a whole repository
  overlay  {prefix, labels, truth, join_digest}: published per-command label files (benchmarks bucket, ~/s7c/hf/bench/data) applied to the
           normalized rows before convert (benchmark_apply_labels.py); ids with no annotation take the truth file, others are dropped
  include / extract   zenodo: files to fetch (default all); zip extracted safely (inert files) before the adapter reads it
  skip     why the set has no adapter (license, no tool-call content, already covered, unreachable)
"""
VERSION = "v1"

def _PUBLIC_CMD(prefix, **kw):
    """Published per-command labels of the public-command lane (benchmarks bucket bench/data): development + validation are
    per-command annotations; the retrospective test file is a truth file for the test split."""
    return dict(prefix=prefix, labels=["public-command-development-labels.jsonl.gz", "public-command-validation-labels.jsonl"],
                truth=["public-command-retrospective-test-labels.jsonl.gz"], **kw)


_ATB = ["benchmark_normalize_atbench.py", "--source-root", "{srcroot}", "--output", "{out}", "--manifest", "{manifest}"]

REGISTRY = {
    "DataDog/stratus-red-team": dict(slug="stratus-red-team", fetch="prepare",
        norm=["benchmark_normalize_stratus_red_team.py", "--input-dir", "{src}", "--output", "{out}", "--manifest", "{manifest}"]),
    "atomic-red-team": dict(slug="atomic-red-team", fetch="prepare", overlay=_PUBLIC_CMD("atomic-red-team/", join_digest=True),
        norm=["benchmark_normalize.py", "--lock", "{lock}", "--data-dir", "{data}", "--datasets", "atomic-red-team",
              "--split", "development", "--output", "{out}", "--manifest", "{manifest}"]),
    "nl2bash": dict(slug="nl2bash", fetch="prepare", overlay=_PUBLIC_CMD("nl2bash/"),
        norm=["benchmark_normalize.py", "--lock", "{lock}", "--data-dir", "{data}", "--datasets", "nl2bash",
              "--split", "development", "--output", "{out}", "--manifest", "{manifest}"]),
    "tldr": dict(slug="tldr", fetch="prepare", overlay=_PUBLIC_CMD("tldr/"),
        norm=["benchmark_normalize.py", "--lock", "{lock}", "--data-dir", "{data}", "--datasets", "tldr",
              "--split", "development", "--output", "{out}", "--manifest", "{manifest}"]),
    "AnodeAI/Agent-Trace-Cyber-v1": dict(slug="anode-cyber", fetch="hf",
        norm=["benchmark_normalize_anode_cyber.py", "--source", "{src}/agent_trajectories.jsonl", "--revision", "{rev}", "--output", "{out}", "--manifest", "{manifest}"]),
    "zenodo-cyber-training-shell-v4": dict(slug="zenodo-shell", fetch="zenodo", include=["data.zip"], extract="data.zip",
        overlay=dict(prefix="zenodo-cyber-training-shell-v4/", labels=[f"zenodo-shell-{s}-gpt-oss-120b-labels.jsonl" for s in ("development", "validation", "test")]),
        norm=["benchmark_normalize_cyber_training_shell.py", "--archive", "{archive}", "--input-dir", "{ext}", "--output", "{out}"]),
    "AI45Research/ATBench-Codex": dict(slug="atbench-codex", fetch="hf", dir="atbench-codex", norm=_ATB, norm_slug="atbench-family", match="AI45Research/ATBench-Codex"),
    "AI45Research/ATBench-Claw": dict(slug="atbench-claw", fetch="hf", dir="atbench-claw", norm=_ATB, norm_slug="atbench-family", match="AI45Research/ATBench-Claw"),
    "AI45Research/ATBench": dict(slug="atbench", fetch="hf", dir="atbench", norm=_ATB, norm_slug="atbench-family", match="AI45Research/ATBench"),
    "yoonholee/terminalbench-trajectories": dict(slug="terminalbench", fetch="hf",
        norm=["benchmark_normalize_terminalbench.py", "--source-root", "{src}", "--output", "{out}", "--manifest", "{manifest}"]),
    "CyCraftAI/TraceSafe": dict(slug="tracesafe", fetch="hf",
        norm=["benchmark_normalize_tracesafe.py", "--source-root", "{src}", "--revision", "{rev}", "--output", "{out}", "--manifest", "{manifest}"]),
    "Yunhao-Feng/AgentHazard": dict(slug="agenthazard", fetch="hf",
        srcmal_modulus=20, norm=["benchmark_normalize_agenthazard.py", "--input-dir", "{src}", "--revision", "{rev}", "--output", "{out}", "--manifest", "{manifest}"]),
    "OTRF/Security-Datasets": dict(slug="otrf-security", fetch="prepare",
        norm=["benchmark_normalize_otrf_security.py", "--input-dir", "{src}", "--revision", "{rev}", "--output", "{out}", "--manifest", "{manifest}"]),
    "splunk/attack_data": dict(slug="splunk-attack-data", fetch="prepare", include_from="benchmark_normalize_splunk_attack_data.py",
        norm=["benchmark_normalize_splunk_attack_data.py", "--input-dir", "{src}", "--revision", "{rev}", "--output", "{out}", "--manifest", "{manifest}"]),
}
