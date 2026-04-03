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

import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.config import Config, GatewayConfig, MCPScannerConfig, ScannersConfig, SkillScannerConfig, SkillActionsConfig, OpenShellConfig, ClawConfig, InspectLLMConfig, CiscoAIDefenseConfig
from defenseclaw.context import AppContext
from defenseclaw.db import Store
from defenseclaw.logger import Logger


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
    return Config(
        data_dir=tmp_dir,
        audit_db=os.path.join(tmp_dir, "audit.db"),
        quarantine_dir=os.path.join(tmp_dir, "quarantine"),
        plugin_dir=os.path.join(tmp_dir, "plugins"),
        policy_dir=os.path.join(tmp_dir, "policies"),
        environment="macos",
        claw=ClawConfig(mode="openclaw", home_dir=tmp_dir),
        scanners=ScannersConfig(
            skill_scanner=SkillScannerConfig(binary="skill-scanner"),
            mcp_scanner=MCPScannerConfig(binary="mcp-scanner"),
        ),
        openshell=OpenShellConfig(binary="openshell-sandbox"),
        gateway=GatewayConfig(host="127.0.0.1", api_port=18970),
        skill_actions=SkillActionsConfig(),
    )


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
    logger = Logger(store)

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
