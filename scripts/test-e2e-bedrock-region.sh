#!/usr/bin/env bash
# Documentation-only stub for the Bedrock regional-provider path.
#
# Real Bedrock requires live AWS credentials and is therefore skipped
# in CI. This script:
#
#   1. Configures DefenseClaw to use Bedrock with an explicit region.
#   2. Captures the resolved YAML and prints it for human review.
#   3. Exits 0 immediately when AWS_ACCESS_KEY_ID / AWS_PROFILE are
#      unset (no creds = no live test).
#
# Run with a Bedrock-enabled account:
#   AWS_PROFILE=<profile> bash scripts/test-e2e-bedrock-region.sh
#
# All work happens under a throwaway DEFENSECLAW_HOME so a live AWS
# account never sees collateral damage from this script.

set -euo pipefail

REGION=${DEFENSECLAW_E2E_BEDROCK_REGION:-us-east-1}
MODEL=${DEFENSECLAW_E2E_BEDROCK_MODEL:-us.anthropic.claude-sonnet-4-6}

TMP_DIR=$(mktemp -d -t defenseclaw-e2e-bedrock-XXXXXX)
trap 'rm -rf "${TMP_DIR}"' EXIT

DEFENSECLAW_HOME="${TMP_DIR}/home"
mkdir -p "${DEFENSECLAW_HOME}"
export DEFENSECLAW_HOME

echo "==> Configuring DefenseClaw for Bedrock region=${REGION} model=${MODEL}"
defenseclaw setup llm \
  --non-interactive \
  --provider bedrock \
  --model "${MODEL}" \
  --region "${REGION}" \
  --bedrock-region "${REGION}" \
  --bedrock-auth-mode profile

echo
echo "==> Resolved YAML:"
cat "${DEFENSECLAW_HOME}/config.yaml" | sed 's/^/    /'

if [[ -z "${AWS_ACCESS_KEY_ID:-}" && -z "${AWS_PROFILE:-}" ]]; then
  echo
  echo "==> Skipping live ping: no AWS credentials in this environment."
  echo "    Set AWS_PROFILE (or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY) to exercise."
  exit 0
fi

echo
echo "==> Live reachability ping (defenseclaw doctor):"
defenseclaw doctor

echo "==> PASS"
