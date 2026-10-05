#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# test-enterprise-linux-container.sh - run the Linux install lane
# (scripts/test-enterprise-unix-install.sh) inside a disposable container
# that boots systemd as PID 1. CI uses it for the rpm lane on a RHEL-compatible
# image, since the hosted Linux runner is Ubuntu; it also runs the deb lane
# on any systemd-enabled Debian or Ubuntu image.
#
# The container is privileged so systemd and the units' sandboxing (mount and
# user namespaces, seccomp filters) behave as on a host. The checkout and the
# package directory are mounted read-only, and the container is always
# removed afterwards.
#
# Usage:
#   test-enterprise-linux-container.sh --image REF --package FILE --version VERSION [--results DIR]
#
#   --image REF     a systemd image whose entrypoint boots /sbin/init, for
#                   example registry.access.redhat.com/ubi9/ubi-init@sha256:...
#                   (it needs python3 and the distribution's package manager)
#   --package FILE  the .rpm or .deb to test
#   --version V     the product version the package's binaries report
#   --results DIR   where to keep the lifecycle results (default: a new
#                   temporary directory)

set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=""
package=""
version=""
results=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --image) image=${2:?--image needs a value}; shift 2 ;;
        --package) package=${2:?--package needs a value}; shift 2 ;;
        --version) version=${2:?--version needs a value}; shift 2 ;;
        --results) results=${2:?--results needs a value}; shift 2 ;;
        -h | --help) sed -n '4,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$image" ] && [ -n "$package" ] && [ -n "$version" ] || {
    echo "usage: $0 --image REF --package FILE --version VERSION [--results DIR]" >&2
    exit 2
}
[ -f "$package" ] || { echo "$package does not exist" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }

package_dir=$(cd "$(dirname "$package")" && pwd)
package_name=$(basename "$package")
results=${results:-$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-install-lane.XXXXXX")}
mkdir -p "$results"
results=$(cd "$results" && pwd)

name="defenseclaw-install-lane-$$-$(date +%s)"
cleanup() {
    status=$?
    if docker inspect "$name" >/dev/null 2>&1; then
        # The lane writes its results as root; hand them back to the caller.
        docker exec "$name" chown -R "$(id -u):$(id -g)" /lane-results >/dev/null 2>&1 || true
        if [ "$status" -ne 0 ]; then
            echo "-- container journal (bounded)" >&2
            docker exec "$name" journalctl --no-pager -n 60 2>&1 | tail -n 60 >&2 || true
        fi
        docker rm -f "$name" >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap cleanup EXIT

docker run --detach --name "$name" --privileged \
    --volume "$repo:/src:ro" \
    --volume "$package_dir:/lane-package:ro" \
    --volume "$results:/lane-results" \
    "$image" >/dev/null

# Wait for systemd to finish booting; "degraded" only means an unrelated
# unit of the image failed.
state=""
for _ in $(seq 1 90); do
    state=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
    case "$state" in
        running | degraded) break ;;
    esac
    sleep 1
done
case "$state" in
    running | degraded) echo "container systemd is $state" ;;
    *)
        echo "systemd in $image did not finish booting (state '$state')" >&2
        exit 1
        ;;
esac

docker exec "$name" bash /src/scripts/test-enterprise-unix-install.sh \
    --package "/lane-package/$package_name" --version "$version" --results /lane-results
