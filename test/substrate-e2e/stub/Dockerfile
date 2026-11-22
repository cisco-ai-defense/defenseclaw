# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
# The stub agent of the Substrate kind E2E (test only; never shipped).
FROM python:3.13-slim
COPY stub.py /opt/stub.py
RUN useradd --uid 10001 --create-home stub
USER 10001
WORKDIR /home/stub
ENTRYPOINT ["python3", "-u", "/opt/stub.py"]
