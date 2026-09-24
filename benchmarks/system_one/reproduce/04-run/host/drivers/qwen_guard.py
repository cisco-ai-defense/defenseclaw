#!/usr/bin/env python3
"""The programme's existing three-layer payload guard, pointed at a new results path.

This is $WORK/jev_guard.py with two changes and no others:
  * RESULTS moves to outputs/openjev-qwen/validation/guard, so the previous batch's
    guard-results file is not overwritten;
  * the report `kind` names this batch.
Every rule, pattern, forbidden key and prose exemption is imported from that file, so the two
batches are gated by identical code.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("jev_guard", "$WORK/jev_guard.py")
jg = importlib.util.module_from_spec(spec)
sys.modules["jev_guard"] = jg
spec.loader.exec_module(jg)

jg.RESULTS = Path("$WORK/.system-one-data/outputs/openjev-qwen/validation/guard")
raise SystemExit(jg.main(sys.argv))
