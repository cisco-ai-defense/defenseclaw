# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-2604: a skipped MCP LLM analysis is one line and a partial sync."""

from __future__ import annotations

import logging
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_registry import _print_sync_reports
from defenseclaw.registries.sync import SyncReport
from defenseclaw.scanner.mcp import _capture_sdk_error_logs


def test_capture_includes_per_analyzer_loggers(capsys):
    # mcpscanner's get_logger gives each analyzer its own stdout handler
    # with propagation off.
    logger = logging.getLogger("mcpscanner.core.analyzers.base.TestLLMAnalyzer")
    logger.handlers = [logging.StreamHandler(sys.stdout)]
    logger.propagate = False
    errors: list[tuple[str, str]] = []
    try:
        with _capture_sdk_error_logs(errors):
            logger.error("AWS Bedrock error for threat analysis for ping")
    finally:
        logger.handlers = []
    assert errors == [
        (logger.name, "AWS Bedrock error for threat analysis for ping")
    ]
    assert "Bedrock" not in capsys.readouterr().out


def test_sync_report_with_skipped_llm_is_partial(capsys):
    report = SyncReport(source_id="local", fetched=1, scanned=1, promoted_mcps=1)
    report.partial.append("mcp:deepwiki: LLM analysis skipped (backend unreachable): x")
    _print_sync_reports([report])
    out = capsys.readouterr().out
    assert "partial" in out
    assert "mcp:deepwiki: LLM analysis skipped" in out
    assert report.ok()
    assert report.to_dict()["partial"] == report.partial
