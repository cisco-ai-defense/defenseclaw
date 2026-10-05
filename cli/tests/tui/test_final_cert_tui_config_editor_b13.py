# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI batch 13: config editor Value column at 160 columns (GAP-2253)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402


async def test_config_editor_value_column_fits_default_paths_at_160(tmp_path, monkeypatch) -> None:
    # GAP-2253: the device key path and the token env name
    # were cut in a 24-cell Value column next to a 38% aside.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows expanduser
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    from defenseclaw.config import default_config

    cfg = default_config()
    cfg.gateway.device_key_file = str(tmp_path / ".defenseclaw" / "device.key")
    cfg.gateway.token_env = "DEFENSECLAW_GATEWAY_TOKEN"
    app = snapshot_app(tmp_path, setup_config=cfg)
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.press("0", "c", "tab", "tab")
        await pilot.pause()
        await pilot.pause()
        assert app.setup_model.sections[app.setup_model.active_section].name == "Gateway"
        _columns, rows = app._setup_table()  # noqa: SLF001
        values = {row[0]: row[1] for row in rows}
        assert values["Device Key File"] == os.path.join("~", ".defenseclaw", "device.key")
        assert values["Token Env"] == "DEFENSECLAW_GATEWAY_TOKEN"
        assert app._setup_config_value_room([row[0] for row in rows], [row[2] for row in rows]) >= 34  # noqa: SLF001
