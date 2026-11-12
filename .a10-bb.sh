#!/bin/bash
# a10: cross-build the actor kit binaries on dc-build-1 (run through dcb sub-a10)
set -eu
V=${1:-0.1.0-a10.0}
mkdir -p dist/a10
for p in cmd/defenseclaw-actor-hook cmd/defenseclaw-actor-relay test/substrate/relayctl; do
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X github.com/defenseclaw/defenseclaw/internal/substrate/kit.Version=$V" -o dist/a10/$(basename $p) ./$p
done
ls -la dist/a10
