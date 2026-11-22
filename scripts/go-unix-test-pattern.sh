#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# go-unix-test-pattern.sh - print a go test -run pattern for the unix and
# darwin tests of one Go package: the Test functions of its _darwin_test.go,
# _unix_test.go and hook_foreign_guard*_test.go files and of every test file
# whose //go:build line names darwin, unix, !windows or !linux. The macOS
# jobs of CI (Unix Standalone Lifecycle, darwin cli, hookcli and gateway
# parts) run these; Linux runs every test of the package in the go-test jobs.
#
# Usage: go-unix-test-pattern.sh <package-dir>   (from the repository root)
# Prints ^(TestA|TestB|...)$ and exits 1 when the package has no such test.
set -euo pipefail

case "${1:-}" in
  -h | --help)
    sed -n '5,13p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac
if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
  echo "usage: $0 <package-dir>" >&2
  exit 2
fi

names=()
for file in "$1"/*_test.go; do
  case "$file" in
    *_windows_test.go | *_linux_test.go) continue ;;
    # The open-loop throughput tests measure wall-clock answers and run
    # alone, without -race, in Go Throughput Test; on a shared macOS runner
    # they only report INCONCLUSIVE and use the job time.
    */gap0490_open_loop_test.go) continue ;;
    *_darwin_test.go | *_unix_test.go | */hook_foreign_guard*_test.go) ;;
    *) grep -Eq '^//go:build .*(darwin|unix|!windows|!linux)' "$file" || continue ;;
  esac
  # shellcheck disable=SC2207 # test names never contain spaces
  names+=($(sed -n 's/^func \(Test[A-Za-z0-9_]*\)(t \*testing\.T).*/\1/p' "$file"))
done
if [ "${#names[@]}" -eq 0 ]; then
  echo "no unix or darwin tests in $1" >&2
  exit 1
fi
IFS="|"
echo "^(${names[*]})\$"
