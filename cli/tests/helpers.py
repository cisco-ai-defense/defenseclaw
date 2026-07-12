# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Shared test helpers — temp stores, configs, Click runner setup."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.config import (
    ClawConfig,
    Config,
    GatewayConfig,
    MCPScannerConfig,
    OpenShellConfig,
    ScannersConfig,
    SkillActionsConfig,
    SkillScannerConfig,
    default_config,
    prepare_fresh_v8_config,
)
from defenseclaw.context import AppContext
from defenseclaw.db import Store
from defenseclaw.models import Event, ScanResult


class _CommandReadModelFixture:
    """Test-only stand-in for canonical gateway projections.

    Command unit tests need existing SQLite read models but must not require a
    live gateway. Production never imports this class; gateway integration
    tests prove the real generated-family pipeline separately.
    """

    def __init__(self, store: Store) -> None:
        self.store = store

    def log_scan(self, result: ScanResult) -> None:
        scan_id = str(uuid.uuid4())
        self.store.insert_scan_result(
            scan_id,
            result.scanner,
            result.target,
            result.timestamp,
            int(result.duration.total_seconds() * 1000),
            len(result.findings),
            result.max_severity(),
            result.to_json(),
        )
        for finding in result.findings:
            self.store.insert_finding(
                str(uuid.uuid4()),
                scan_id,
                finding.severity,
                finding.title,
                finding.description,
                finding.location,
                finding.remediation,
                finding.scanner,
                "[]",
            )
        self.log_action(
            "scan",
            result.target,
            f"scanner={result.scanner} findings={len(result.findings)}",
            severity=result.max_severity(),
        )

    def log_action(
        self,
        action: str,
        target: str,
        details: str,
        *,
        severity: str = "INFO",
    ) -> None:
        self.store.log_event(
            Event(action=action, target=target, details=details, severity=severity)
        )

    def log_activity(
        self,
        *,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        before=None,
        after=None,
        diff=None,
        version_from: str = "",
        version_to: str = "",
        severity: str = "INFO",
    ) -> None:
        activity_id = str(uuid.uuid4())
        target_type = target_type or "unknown"
        target_id = target_id or "unknown"
        payload = {
            "activity_id": activity_id,
            "actor": actor,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "before": before,
            "after": after,
            "diff": diff or [],
            "version_from": version_from,
            "version_to": version_to,
        }
        self.store.insert_activity_event(
            activity_id,
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            before_json=json.dumps(before) if before is not None else "",
            after_json=json.dumps(after) if after is not None else "",
            diff_json=json.dumps(diff or []),
            version_from=version_from,
            version_to=version_to,
        )
        self.store.log_event(
            Event(
                action=action,
                target=f"{target_type}:{target_id}",
                actor=actor,
                details=json.dumps(payload),
                severity=severity,
            )
        )

    def log_alert(self, source: str, severity: str, summary: str, details=None) -> None:
        self.store.log_event(
            Event(
                action="alert",
                target=source,
                details=json.dumps(
                    {"source": source, "summary": summary, "details": details or {}}
                ),
                severity=severity or "WARN",
            )
        )

    def close(self) -> None:
        return


def make_temp_store() -> tuple[Store, str]:
    """Create a temporary SQLite store. Returns (store, db_path)."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)
    store.init()
    return store, tmp.name


def make_temp_config(tmp_dir: str | None = None) -> Config:
    """Create a Config pointing at a temp directory."""
    if tmp_dir is None:
        tmp_dir = tempfile.mkdtemp(prefix="dclaw-test-")
    cfg = prepare_fresh_v8_config(default_config())
    cfg.data_dir = tmp_dir
    cfg.audit_db = os.path.join(tmp_dir, "audit.db")
    cfg.quarantine_dir = os.path.join(tmp_dir, "quarantine")
    cfg.plugin_dir = os.path.join(tmp_dir, "plugins")
    cfg.policy_dir = os.path.join(tmp_dir, "policies")
    cfg.environment = "macos"
    cfg.claw = ClawConfig(mode="openclaw", home_dir=tmp_dir)
    cfg.scanners = ScannersConfig(
        skill_scanner=SkillScannerConfig(binary="skill-scanner"),
        mcp_scanner=MCPScannerConfig(binary="mcp-scanner"),
    )
    cfg.openshell = OpenShellConfig(binary="openshell")
    cfg.gateway = GatewayConfig(host="127.0.0.1", api_port=18970)
    cfg.skill_actions = SkillActionsConfig()
    return cfg


def make_app_context(tmp_dir: str | None = None) -> tuple[AppContext, str, str]:
    """Build a fully wired AppContext with temp store and config.

    Returns (app, tmp_dir, db_path).
    """
    if tmp_dir is None:
        tmp_dir = tempfile.mkdtemp(prefix="dclaw-test-")
    cfg = make_temp_config(tmp_dir)
    db_path = cfg.audit_db
    store = Store(db_path)
    store.init()
    logger = _CommandReadModelFixture(store)

    app = AppContext()
    app.cfg = cfg
    app.store = store
    app.logger = logger
    return app, tmp_dir, db_path


def invoke_with_app(cli_group, args: list[str], app: AppContext | None = None):
    """Invoke a Click command with the given AppContext pre-loaded.

    Returns the CliRunner Result.
    """
    if app is None:
        app, _, _ = make_app_context()
    runner = CliRunner()
    return runner.invoke(cli_group, args, obj=app, catch_exceptions=False)


def make_separate_stderr_runner() -> CliRunner:
    """Create a Click runner with stderr captured separately across Click versions."""
    try:
        return CliRunner(mix_stderr=False)  # type: ignore[call-arg]
    except TypeError:
        return CliRunner()


def cleanup_app(app: AppContext, db_path: str, tmp_dir: str) -> None:
    """Close store and clean up temp files."""
    import shutil

    if app.store:
        app.store.close()
    try:
        os.unlink(db_path)
    except OSError:
        pass
    try:
        shutil.rmtree(tmp_dir)
    except OSError:
        pass
