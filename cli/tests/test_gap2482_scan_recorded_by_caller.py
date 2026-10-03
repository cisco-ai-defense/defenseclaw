# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-2482: a gateway-spawned plugin scan is recorded once, by the gateway."""

from __future__ import annotations

from unittest.mock import MagicMock

from defenseclaw.commands import _scan_ui


def test_record_scan_skips_when_the_caller_records(monkeypatch) -> None:
    logger = MagicMock()
    monkeypatch.setenv("DEFENSECLAW_SCAN_RECORDED_BY_CALLER", "1")
    _scan_ui.record_scan(logger, object())
    logger.log_scan.assert_not_called()


def test_record_scan_records_an_operator_scan(monkeypatch) -> None:
    logger = MagicMock()
    monkeypatch.delenv("DEFENSECLAW_SCAN_RECORDED_BY_CALLER", raising=False)
    result = object()
    _scan_ui.record_scan(logger, result, connector="hermes")
    logger.log_scan.assert_called_once_with(result, connector="hermes")
