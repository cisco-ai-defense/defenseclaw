# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Compatibility-surface tests for local-observability CLI helpers."""

from __future__ import annotations

import json

from click.testing import CliRunner
from defenseclaw.commands.cmd_setup_local_observability import local_observability
from defenseclaw.observability.local_stack import CONTRACT, LocalStackController


def test_url_json_preserves_the_existing_contract() -> None:
    result = CliRunner().invoke(local_observability, ["url", "--json"], obj=object())
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == CONTRACT


def test_environment_contract_is_cross_platform_data() -> None:
    values = LocalStackController.environment_contract()
    assert values["OTEL_EXPORTER_OTLP_ENDPOINT"] == "http://127.0.0.1:4317"
    assert values["OTEL_EXPORTER_OTLP_PROTOCOL"] == "grpc"
    assert all("\n" not in value and "\r" not in value for value in values.values())
