# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The Redaction summary names the global default config.yaml sets (GAP-1394)."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from defenseclaw.config import default_config
from defenseclaw.observability.v8_status import operator_status_from_effective
from defenseclaw.tui.panels.setup import SetupWizard, wizard_state_summary


def _status(profile: str):
    effective = {
        "bucket_catalog_version": 1,
        "local": {"retention_days": 7},
        "buckets": [],
        "destinations": [],
        "warnings": [],
    }
    return operator_status_from_effective(
        effective, source="x", data_dir="y", plan_digest="z", default_redaction_profile=profile
    )


def test_redaction_summary_reads_the_configured_default() -> None:
    # The loaded Config has no observability.defaults, so the summary said
    # "none (unredacted)" after `setup redaction defaults set --profile content`.
    summary = wizard_state_summary(SetupWizard.REDACTION, default_config(), _status("content"))
    assert summary.startswith("Default profile: content (redacted)"), summary


def test_redaction_summary_without_status_keeps_the_config_value() -> None:
    cfg = {"observability": {"defaults": {"redaction_profile": "strict"}}}
    assert wizard_state_summary(SetupWizard.REDACTION, cfg).startswith("Default profile: strict")
    assert wizard_state_summary(SetupWizard.REDACTION, SimpleNamespace()).startswith("Default profile: none")
