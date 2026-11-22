#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501
"""The fixture root a run rewrites its corpus to does not depend on the run label or directory (rel-1-0-10 GAP-0495, GAP-0736)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import s7gate as G  # noqa: E402, N812


class FixtureRoot(unittest.TestCase):
    def test_two_run_directories_share_one_root_and_one_rewritten_byte_stream(self):
        with (
            tempfile.TemporaryDirectory() as td,
            mock.patch.dict(os.environ, {"S7_FIXTURE_ROOT": os.path.join(td, "fx")}),
        ):
            a, b = os.path.join(td, "runs", "wr3-rel"), os.path.join(td, "runs", "wr3-head")
            self.assertEqual(G.fixture_root(a), G.fixture_root(b))
            self.assertNotIn("wr3", G.fixture_root(a))
            src = os.path.join(td, "c.jsonl")
            Path(src).write_text('{"command":"cat /home/alice/.ssh/config"}\n')
            outs = []
            for run in (a, b):
                os.makedirs(run)
                dst = os.path.join(run, "rw.jsonl")
                G.rewrite_corpus(src, dst, G.make_fixture(run))
                outs.append(Path(dst).read_bytes())
            self.assertEqual(outs[0], outs[1], "the label must not be in the rewritten corpus")

    def test_default_root_is_label_free(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("S7_FIXTURE_ROOT", None)
            self.assertTrue(G.fixture_root("/x/runs/anything").endswith(os.path.join("s7c", "fx")))

    def test_compare_refuses_runs_with_different_fixture_roots(self):
        with tempfile.TemporaryDirectory() as td:
            for name, root in (("base", "/r1/fx"), ("cand", "/r2/fx")):
                os.makedirs(os.path.join(td, name, "scores"))
                Path(td, name, "RUN.json").write_text(json.dumps({"fixture_root": root}))
            args = mock.Mock(base=os.path.join(td, "base"), cand=os.path.join(td, "cand"), allow_unlabelled=False)
            with self.assertRaises(SystemExit) as cm:
                G.cmd_compare(args)
            self.assertEqual(cm.exception.code, 3)


if __name__ == "__main__":
    unittest.main()
