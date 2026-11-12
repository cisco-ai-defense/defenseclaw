# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# The defenseclaw-gateway image for Agent Substrate: the gateway, leader,
# controller, callout and chart hook Jobs all run this one binary
# (deploy/helm/defenseclaw-substrate). It holds the release's own Linux
# build, unchanged, on a static distroless base; it runs as 65532 and needs
# no shell. Built by scripts/release/substrate-images.sh.
#
# Context: linux-<arch>/defenseclaw-gateway for each target platform, plus
# LICENSE, NOTICE and THIRD_PARTY_LICENSES.txt.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETARCH
ARG VERSION
LABEL org.opencontainers.image.title="defenseclaw-gateway" \
      org.opencontainers.image.description="DefenseClaw gateway for Agent Substrate" \
      org.opencontainers.image.source="https://github.com/cisco-ai-defense/defenseclaw" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
COPY LICENSE NOTICE THIRD_PARTY_LICENSES.txt /usr/share/doc/defenseclaw/
COPY --chmod=0755 linux-${TARGETARCH}/defenseclaw-gateway /usr/local/bin/defenseclaw-gateway
USER 65532:65532
ENV DEFENSECLAW_HOME=/tmp/defenseclaw
ENTRYPOINT ["/usr/local/bin/defenseclaw-gateway"]
