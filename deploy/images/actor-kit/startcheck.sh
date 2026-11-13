#!/bin/bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
# startcheck.sh IMAGE... : run startcheck.py in each actor image (the pipeline step that keeps a pin bump from shipping a
# kit whose agent exits at launch; see startcheck.py). Runs wherever docker can pull the image (the lab: E1).
#   STARTCHECK_SECONDS=8  how long the agent must stay up
#   STARTCHECK_CA_BUNDLE  CA bundle mounted as the actor trust bundle (default: the host store)
# Exit 0 when every image passes, 1 when any fails, 2 on a usage error.
set -uo pipefail
[ $# -ge 1 ] || { echo "usage: startcheck.sh IMAGE..." >&2; exit 2; }
here="$(cd "$(dirname "$0")" && pwd)"
rc=0
for img in "$@"; do
  echo "== $img"
  # The actor gets the egress trust bundle at /run/ate/trust-bundle.pem (the kit config lists it) and the platform TLS
  # stacks (Devin) refuse to start without a CA store; mount the host bundle the same way.
  docker run --rm --user 1000:1000 -v "$here/startcheck.py:/startcheck.py:ro" -v "${STARTCHECK_CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}:/run/ate/trust-bundle.pem:ro" \
    -e SSL_CERT_FILE=/run/ate/trust-bundle.pem --entrypoint python3 "$img" /startcheck.py "${STARTCHECK_SECONDS:-8}" || rc=1
done
exit $rc
