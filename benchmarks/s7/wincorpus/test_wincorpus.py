#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Windows shell corpus builder (no corpus data, no attack text)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build as B  # noqa: E402
import wc_lib as L  # noqa: E402

SCHEMA = HERE.parents[2] / "benchmarks" / "schema" / "case-v1.schema.json"


class RedactionTests(unittest.TestCase):
    def test_lab_identities_are_replaced(self):
        out = L.redact(r"copy x C:\Users\r109kz7\proj and ssh dc-fc-r103-a2-win hostname; Users\vnarajal")
        self.assertNotIn("r109kz7", out)
        self.assertNotIn("dc-fc-r103-a2-win", out)
        self.assertNotIn("vnarajal", out)
        self.assertIn(r"C:\Users\alice", out)

    def test_registry_and_drive_paths_are_untouched(self):
        for s in (r"reg query HKLM\SAM", r"cd D:\DMLS\build", r"dir C:\ProgramData\R103\t4", r"Get-Item $env:USERPROFILE\proj"):
            self.assertEqual(L.redact(s), s)

    def test_instance_ids_and_ips(self):
        out = L.redact("aws ssm send-command --instance-ids i-03cf83cafbf48513b --target 10.1.2.3 --local 127.0.0.1")
        self.assertNotIn("03cf83", out)
        self.assertNotIn("10.1.2.3", out)
        self.assertIn("127.0.0.1", out)

    def test_leak_scan_ignores_git_remote_user(self):
        self.assertEqual(L.leak_scan("ssh -T git@github.com"), [])
        self.assertEqual(L.leak_scan("mail bob@corp-mail.test"), ["email"])


class WrapperTests(unittest.TestCase):
    def test_wrappers_keep_the_inner_command(self):
        inner = "Get-ChildItem C:\\Users\\alice\\proj"
        for fn in (L.w_ps_command, L.w_pwsh_c, L.w_cd, L.w_call, L.w_tail, L.w_gitbash_ps):
            self.assertIn("Get-ChildItem", fn(inner))

    def test_quote_escaping(self):
        self.assertEqual(L.w_ps_command('echo "a"'), 'powershell -NoProfile -Command "echo \\"a\\""')
        self.assertEqual(L.w_gitbash_ps("echo 'a'"), "powershell.exe -NoProfile -Command 'echo '\\''a'\\'''")


class CaseShapeTests(unittest.TestCase):
    def test_shell_case_native_tools(self):
        want = {"claudecode": "PowerShell", "codex": "Bash", "cursor": "Shell", "opencode": "bash", "kiro": "PowerShell"}
        for prov, tool in want.items():
            c = L.shell_case("wsh/t/" + prov, "authored", "t", "dir", provider=prov, truth="benign", cats=["x"], label_source="t")
            self.assertEqual(c["payload"]["tool_name"], tool)
            self.assertEqual(c["strata"]["platform"], "windows")

    def test_profile_actions_follow_the_documented_postures(self):
        self.assertEqual(L.profile_actions("CRITICAL"), {"default": "block", "permissive": "block", "strict": "block"})
        self.assertEqual(L.profile_actions("HIGH"), {"default": "alert", "permissive": "alert", "strict": "block"})
        self.assertEqual(L.profile_actions("HIGH", strict_only=True)["default"], "allow")


class AuthoredBenignTests(unittest.TestCase):
    def test_authored_cases_validate_and_are_unique(self):
        rows = B.src_authored()
        self.assertGreater(len(rows), 600)
        self.assertEqual(L.validate_rows(rows, str(SCHEMA)), [])
        self.assertTrue(all(r["truth"]["source_truth"] == "benign" for r in rows))
        self.assertEqual(len({r["id"] for r in rows}), len(rows))

    def test_every_common_category_is_present(self):
        cats = {c for r in B.src_authored() for c in r["truth"]["categories"] if c.startswith("ben:")}
        for need in ("ben:git", "ben:node", "ben:python", "ben:dotnet", "ben:containers", "ben:files", "ben:processes-services", "ben:network", "ben:security-reads",
                     "ben:registry-reads", "ben:event-logs-and-tasks", "ben:gitbash", "ben:file-write", "ben:file-edit", "ben:file-read", "ben:file-patch"):
            self.assertIn(need, cats)


class FixtureFilterTests(unittest.TestCase):
    def test_only_plain_negatives_are_kept(self):
        self.assertTrue(B.NEG_OK.match("Get-MpPreference"))
        self.assertTrue(B.NEG_OK.match("vssadmin.exe list shadows"))
        self.assertFalse(B.NEG_OK.match("Remove-Item -Path HKLM:\\SOFTWARE\\x -Recurse"))

    def test_first_word_buckets_are_short(self):
        self.assertEqual(B.first_word("powershell -NoProfile -Command \"Get-Process node\""), "get-process")
        self.assertEqual(B.first_word("a" * 80), "other")


class ProtectedWriteTests(unittest.TestCase):
    def test_reads_are_benign_and_writes_malicious(self):
        rows = B.src_protwrite()
        labels = {r["truth"]["source_truth"] for r in rows}
        self.assertEqual(labels, {"benign", "malicious"})
        self.assertEqual(L.validate_rows(rows, str(SCHEMA)), [])
        for r in rows:
            if r["truth"]["source_truth"] == "malicious":
                self.assertEqual(r["truth"]["expected_disposition"], "block")


if __name__ == "__main__":
    unittest.main()
