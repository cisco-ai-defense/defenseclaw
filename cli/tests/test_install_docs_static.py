# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_quickstart_docs_do_not_pipe_main_installer() -> None:
    for rel in ("README.md", "docs/QUICKSTART.md"):
        text = (ROOT / rel).read_text()
        assert "raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.sh" not in text
        assert "VERSION=" in text
        assert 'VERSION="$VERSION" bash' in text
