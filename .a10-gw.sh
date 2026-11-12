#!/bin/bash
# a10: cross-build the gateway on dc-build-1 and push a one-layer image to the E1 registry (run via dcb sub-a10).
set -euo pipefail
tag=a10-$(git rev-parse --short=10 HEAD)
mkdir -p /tmp/a10out /tmp/a10img/usr/local/bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/a10img/usr/local/bin/defenseclaw-gateway ./cmd/defenseclaw
tar -C /tmp/a10img --owner=0 --group=0 -cf /tmp/a10out/layer.tar usr
/home/ubuntu/dc-eh-build/a0-bin/crane append --insecure -b gcr.io/distroless/static-debian12:nonroot -f /tmp/a10out/layer.tar -t 10.0.1.218:5000/a10/defenseclaw-gateway:$tag --platform linux/amd64
echo "TAG $tag"
