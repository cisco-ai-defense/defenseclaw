#!/bin/bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
# startcheck.sh IMAGE... : run startcheck.py in each actor image (the pipeline step that keeps a pin bump from shipping a
# kit whose agent exits at launch; see startcheck.py). Runs wherever docker can pull the image (the lab: E1).
#   STARTCHECK_SECONDS=8  how long the agent must stay up
# Exit 0 when every image passes, 1 when any fails, 2 on a usage error.
set -uo pipefail
[ $# -ge 1 ] || { echo "usage: startcheck.sh IMAGE..." >&2; exit 2; }
here="$(cd "$(dirname "$0")" && pwd)"
rc=0
for img in "$@"; do
  echo "== $img"
  docker run --rm --user 1000:1000 -v "$here/startcheck.py:/startcheck.py:ro" --entrypoint python3 "$img" /startcheck.py "${STARTCHECK_SECONDS:-8}" || rc=1
done
exit $rc
