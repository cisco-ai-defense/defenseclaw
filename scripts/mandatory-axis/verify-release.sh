#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
axis=/home/cisco/sources/axis
test "$(git -C "$axis" rev-parse HEAD)" = e32f69b3c411f25975940cbcfd1101a3682783c9
test -s "$axis/Cargo.lock"
test "$(sha256sum "$axis/Cargo.lock" | awk '{print $1}')" = "$(sha256sum "$root/third_party/axis/Cargo.lock" | awk '{print $1}')"
echo "mandatory AXIS source and lock verification: PASS"
