# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""CLI output fixes: piped table width (GAP-1682) and deliberate
local-collector options in setup redaction (GAP-1577)."""

from __future__ import annotations

import dataclasses
import os
import sys

from defenseclaw import main as main_mod
from defenseclaw.commands import cmd_setup_redaction
from defenseclaw.observability.v8_status import V8DestinationStatus, V8OperatorStatus


class _Piped:
    def isatty(self) -> bool:
        return False


def test_piped_output_keeps_the_console_width(monkeypatch) -> None:
    monkeypatch.setenv("COLUMNS", "")
    monkeypatch.setattr(sys, "__stdout__", _Piped())
    monkeypatch.setattr(main_mod, "_attached_console_width", lambda: 220)
    main_mod._keep_console_width_when_piped()
    assert os.environ["COLUMNS"] == "220"


def test_an_explicit_columns_value_wins(monkeypatch) -> None:
    monkeypatch.setenv("COLUMNS", "100")
    monkeypatch.setattr(sys, "__stdout__", _Piped())
    monkeypatch.setattr(main_mod, "_attached_console_width", lambda: 220)
    main_mod._keep_console_width_when_piped()
    assert os.environ["COLUMNS"] == "100"


def _destination(name: str, endpoint: str) -> V8DestinationStatus:
    return V8DestinationStatus(
        name=name,
        kind="otlp",
        enabled=True,
        generated=False,
        capabilities=("logs",),
        selected_signals=("logs",),
        policy_form="concise_send",
        endpoint=endpoint,
        route_count=1,
        buckets=(),
        redaction_profiles=("sensitive",),
    )


def _status(*destinations: V8DestinationStatus, warnings) -> V8OperatorStatus:
    return V8OperatorStatus(
        source="config.yaml",
        data_dir=".",
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=90,
        local_path="audit.db",
        judge_bodies_path="judge_bodies.db",
        destinations=destinations,
        buckets=(),
        warnings=warnings,
    )


_WARNINGS = (
    ("tls_verification_disabled", "observability.destinations[local].tls", "explicitly unsafe TLS mode"),
    ("private_export_network_allowed", "observability.destinations[local].transport", "private collector"),
    ("tls_verification_disabled", "observability.destinations[remote].tls", "explicitly unsafe TLS mode"),
)


def test_redaction_status_notes_a_local_collector_once_and_still_warns_for_remote(capsys) -> None:
    status = _status(
        _destination("local", "127.0.0.1:14317"),
        _destination("remote", "collector.example.com:4317"),
        warnings=_WARNINGS,
    )
    cmd_setup_redaction._render_status(status)
    out, err = capsys.readouterr()
    assert "destinations[local]" not in err
    assert "warning: tls_verification_disabled: observability.destinations[remote].tls" in err
    assert out.count("note: local:") == 1
    assert "--plaintext and --allow-private-networks set on purpose for a collector on this machine" in out


def test_redaction_preview_skips_deliberate_local_collector_warnings(capsys) -> None:
    destinations = (_destination("local", "localhost:4318"), _destination("remote", "10.0.0.5:4317"))
    preview = dataclasses.make_dataclass(
        "Preview",
        ["changes", "newly_unredacted", "no_longer_unredacted", "locked_profiles", "warnings"],
    )((), 0, 0, (), _WARNINGS)
    cmd_setup_redaction._render_preview(preview, destinations)
    err = capsys.readouterr().err
    assert "destinations[local]" not in err
    assert "destinations[remote]" in err
