#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 CORPUS_JSONL OUTPUT_JSONL MODEL" >&2
  exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
caller_root=$(pwd)
case "$1" in /*) corpus=$1 ;; *) corpus=$caller_root/$1 ;; esac
case "$2" in /*) output=$2 ;; *) output=$caller_root/$2 ;; esac
export GUARDRAIL_BENCHMARK_LLM=1
export DEFENSECLAW_JUDGE_BENCHMARK_CORPUS=$corpus
export DEFENSECLAW_JUDGE_BENCHMARK_OUTPUT=$output
export DEFENSECLAW_JUDGE_BENCHMARK_MODEL=$3
export DEFENSECLAW_JUDGE_BENCHMARK_RULE_PACK=${DEFENSECLAW_JUDGE_BENCHMARK_RULE_PACK:-"$repo_root/policies/guardrail/default"}
export DEFENSECLAW_JUDGE_BENCHMARK_CONCURRENCY=${DEFENSECLAW_JUDGE_BENCHMARK_CONCURRENCY:-1}

case "$3" in
  bedrock/*|amazon-bedrock/*)
    export DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_REGION=${DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_REGION:-us-east-1}
    export DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_AUTH_MODE=${DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_AUTH_MODE:-profile}
    export DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_PROFILE=${DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_PROFILE:-devops}
    ;;
  *)
    export DEFENSECLAW_JUDGE_BENCHMARK_BASE_URL=${DEFENSECLAW_JUDGE_BENCHMARK_BASE_URL:-http://127.0.0.1:11434}
    ;;
esac

cd "$repo_root"
exec go test ./internal/gateway -run '^TestLLMJudgeDeterministicCorpus$' -count=1 -timeout 120m -v
