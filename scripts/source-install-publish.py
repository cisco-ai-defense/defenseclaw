#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Repository wrapper for the wheel-shipped install publication helper."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cli"))

from defenseclaw.install_publish import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
