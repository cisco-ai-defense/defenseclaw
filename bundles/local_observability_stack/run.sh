#!/usr/bin/env bash
# Back-compat shim — forwards to bin/openclaw-observability-bridge.
#
# The stack is now driven by the unified bridge script so the CLI
# (`defenseclaw setup local-observability`) and manual users hit the
# same entry point. Kept for existing muscle memory / docs that still
# reference `./run.sh up`.

set -euo pipefail
exec "$(dirname "$0")/bin/openclaw-observability-bridge" "$@"
