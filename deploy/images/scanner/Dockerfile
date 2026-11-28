# The Agent Substrate skill scanner sidecar (GAP-0477): the gateway's
# `substrate scan-worker` and the release's own scanner runtime (CPython and
# the locked skill-scanner and plugin scanner tree of the managed Linux
# package), so a cluster scans with the engine and pins a laptop uses. The
# base is distroless cc (glibc and libstdc++ for the runtime's CPython and
# native wheels): no shell, no package manager. scripts/release/
# substrate-images.sh fills the context from the release archives and the
# defenseclaw-enterprise .deb of the same version.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

ARG TARGETARCH
ARG VERSION

LABEL org.opencontainers.image.title="defenseclaw-scanner" \
      org.opencontainers.image.description="DefenseClaw skill scanner sidecar for Agent Substrate" \
      org.opencontainers.image.source="https://github.com/cisco-ai-defense/defenseclaw" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

COPY LICENSE NOTICE THIRD_PARTY_LICENSES.txt /usr/share/doc/defenseclaw/
COPY --chmod=0755 linux-${TARGETARCH}/defenseclaw-gateway /usr/local/bin/defenseclaw-gateway
# The managed Linux layout: the launcher checks that the tree is root-owned
# and nobody else can write it (internal/managed), as on a package install.
COPY --chmod=0755 linux-${TARGETARCH}/defenseclaw-scanners /opt/defenseclaw/bin/defenseclaw-scanners
COPY linux-${TARGETARCH}/scanner-runtime /opt/defenseclaw/scanner-runtime
USER 65532:65532
# The scanners write caches under HOME; the chart mounts /tmp writable.
ENV HOME=/tmp
ENTRYPOINT ["/usr/local/bin/defenseclaw-gateway"]
CMD ["substrate", "scan-worker"]
