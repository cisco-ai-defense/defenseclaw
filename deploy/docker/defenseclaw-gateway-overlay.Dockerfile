ARG BASE_IMAGE
FROM ${BASE_IMAGE}

COPY defenseclaw-gateway-galileo-linux-amd64 /usr/local/bin/defenseclaw-gateway

USER root
RUN chmod 0755 /usr/local/bin/defenseclaw-gateway
USER 1000:1000
