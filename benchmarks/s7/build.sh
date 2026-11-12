#!/bin/bash
[ "$(uname -s)" = Linux ] || { echo refusing; exit 99; }
set -e
cd ~/dc-eh/wt/s7-bench
gofmt -w internal/gateway/s7bench_engine.go benchmarks/cmd/s7bench/main.go
git add internal/gateway/s7bench_engine.go benchmarks/cmd/s7bench/main.go
if ! git diff --cached --quiet; then
  GIT_AUTHOR_NAME="Vineeth Sai Narajala" GIT_COMMITTER_NAME="Vineeth Sai Narajala" GIT_AUTHOR_EMAIL=vnarajal@cisco.com GIT_COMMITTER_EMAIL=vnarajal@cisco.com git commit -qm "${1:-bench(s7): harness update}"
fi
git log -1 --format=%h
cd ~/dc-eh
DC_BUILD_HOLDER=h-f33664dc DCB_BOX=dc-build-1 timeout 900 ~/dc-eh/bin/dcb s7-bench "export GOTOOLCHAIN=go1.26.4; mkdir -p .s7out; go build -tags s7bench -o .s7out/s7bench ./benchmarks/cmd/s7bench" 2>&1 | tail -20
DCB_BOX=dc-build-1 ~/dc-eh/bin/dcb get s7-bench .s7out 2>&1 | tail -2
ls -la ~/dc-eh/wt/s7-bench/.s7out/s7bench
