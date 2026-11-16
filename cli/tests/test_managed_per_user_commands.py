# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The managed Windows binary answers every per-user command (GAP-0795).

internal/cli/embed/per-user-commands.json is the list the Go binary reads to
give each per-user command the managed answer. This test keeps it equal to the
per-user CLI's own command table, so a command added there is covered as soon as
it is listed (the Go test runs the whole list).
"""

from __future__ import annotations

import json
from pathlib import Path

from defenseclaw.main import cli

_TABLE = Path(__file__).resolve().parents[2] / "internal" / "cli" / "embed" / "per-user-commands.json"


def test_go_per_user_command_table_matches_the_python_cli():
    listed = json.loads(_TABLE.read_text(encoding="utf-8"))["commands"]
    actual = sorted(cli.commands)
    assert listed == actual, (
        "internal/cli/embed/per-user-commands.json must list the per-user CLI's top-level commands; "
        f"missing {sorted(set(actual) - set(listed))}, extra {sorted(set(listed) - set(actual))}"
    )
