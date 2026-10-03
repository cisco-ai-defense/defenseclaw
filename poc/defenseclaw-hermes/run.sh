#!/usr/bin/env bash
# DefenseClaw POC — run script
# Refreshes AWS credentials and starts all containers.
set -euo pipefail
cd "$(dirname "$0")"

echo "Refreshing AWS credentials..."
eval $(AWS_PROFILE=dc-controlplane aws configure export-credentials --format env 2>/dev/null)

cat > .env <<EOF
DEFENSECLAW_MASTER_KEY=sk-defenseclaw-poc
AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN
AWS_REGION_NAME=us-west-2
EOF

echo "Starting DefenseClaw POC..."
docker compose up --build --abort-on-container-exit
