#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501  (regex and data tables read better on one line; the checked-in corpus tooling has always been long-line)
"""Unit tests for the Windows shell corpus builder (no corpus data, no attack text)."""
from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build as B  # noqa: E402, N812
import wc_lib as L  # noqa: E402, N812

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


class RedactionCategoryTests(unittest.TestCase):
    """One group per redaction category. Every value below is synthetic (documentation style); no real lab value is in this file."""

    def setUp(self):
        L.reset()
        self._clear_denylist()

    tearDown = setUp

    @staticmethod
    def _clear_denylist():
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl") as f:
            f.flush()
            L.load_denylist(f.name)

    def assert_gone(self, out, *values):
        for v in values:
            self.assertNotIn(v.lower(), out.lower(), v)

    def test_windows_computer_names(self):
        out = L.redact(r"Get-ADComputer -Server EC2AMAZ-A1B2C3D.lab-corp.local; ping WIN-ABCDEFGHIJK; copy x \\FILESRV01\share\y; Invoke-Command -ComputerName SRV02 { 1 }; schtasks /query /s SRV03 /fo list")
        self.assert_gone(out, "EC2AMAZ-A1B2C3D", "WIN-ABCDEFGHIJK", "FILESRV01", "SRV02", "SRV03", "lab-corp")
        self.assertIn("LABPC1.labdomain1.example.com", out)
        self.assertIn(r"\\LABPC", out)

    def test_computer_name_non_hosts_are_kept(self):
        for s in (r"dir \\?\C:\x", r"dir \\.\pipe\x", r"dir \\wsl$\Ubuntu\home", r"Invoke-Command -ComputerName localhost { 1 }", r"copy a \\localhost\c$\b",
                  r"C:\\Users\\Public\\x", r"Invoke-Command -ComputerName $target { 1 }", "win-x64-cli and win-installer"):
            self.assertEqual(L.redact(s), s, s)

    def test_sids(self):
        out = L.redact("reg unload HKU\\S-1-5-21-1111111111-2222222222-3333333333-1105 && icacls x /grant *S-1-5-21-1111111111-2222222222-3333333333-500:F S-1-5-18 S-1-5-21-4444444444-5555555555-6666666666")
        self.assert_gone(out, "1111111111", "2222222222", "3333333333", "4444444444")
        self.assertIn("-1105", out)     # the RID is not identifying and keeps the meaning (-500 = administrator)
        self.assertIn("-500", out)
        self.assertIn("S-1-5-18", out)
        sids = {m.group(0) for m in L._SID.finditer(out)}
        self.assertEqual(len(sids), 3)

    def test_ad_and_dns_domains(self):
        out = L.redact(r"nltest /dsgetdc:corplab.local; Resolve-DnsName dc01.corplab.local; net use \\fs1\x /user:CORPLAB\jdoe; runas /user:CORPLAB\svcbuild cmd")
        self.assert_gone(out, "corplab", "jdoe", "svcbuild")
        self.assertIn("labdomain1.example.com", out)
        self.assertIn("LABDOM1", out)
        # the same domain keeps one number in the DNS and the NetBIOS spelling
        self.assertRegex(out, r"/user:LABDOM1\\labuser1;")

    def test_domains_that_are_not_domains(self):
        for s in (r"type C:\proj\.claude\settings.local.json", "cat .env.local", "p = Path.home()", r"reg query HKLM\SOFTWARE\Policies", r"icacls x /grant BUILTIN\Administrators:F",
                  r"whoami /groups | findstr NT AUTHORITY\SYSTEM", r"cd C:\TEMP\work", "git config user.email dev@example.com"):
            self.assertEqual(L.redact(s), s, s)

    def test_user_names_and_upns(self):
        out = L.redact(r"Add-LocalGroupMember -Group Administrators -Member jdoe@lab-corp.local; runas /user:LABCO\bsmith notepad; Get-Process -IncludeUserName -User LABCO\bsmith; whoami > C:\Users\carol\out.txt; Users\vnarajal")
        self.assert_gone(out, "jdoe", "bsmith", "lab-corp", "LABCO", "carol", "vnarajal")
        both = L.redact(r"a LABCO\bsmith b /user:LABCO\bsmith").split()
        self.assertEqual(both[1], both[3].split(":")[1])    # one user, one placeholder
        self.assertIn("Administrators", out)

    def test_builtin_accounts_are_kept(self):
        s = r"net localgroup Administrators /add; runas /user:LABCO\Administrator cmd; icacls x /grant LABCO\Guest:R"
        self.assertEqual(L.redact(s).count("Administrator"), 2)
        self.assertIn(r"\Guest", L.redact(s))

    def test_home_paths(self):
        for src, want in ((r"C:\Users\bob\proj", r"C:\Users\alice\proj"), ("C:/Users/bob/proj", "C:/Users/alice/proj"), (r"C:\\Users\\bob\\proj", r"C:\\Users\\alice\\proj"),
                          ("/c/Users/bob/proj", "/c/Users/alice/proj"), ("/mnt/c/Users/bob/proj", "/mnt/c/Users/alice/proj"), ("/Users/bob/proj", "/Users/alice/proj"),
                          ("/home/bob/.ssh/config", "/home/alice/.ssh/config"), ("/home/ubuntu/dc-eh/x", "/home/alice/dc-eh/x")):
            self.assertEqual(L.redact(src), want, src)
        for keep in (r"C:\Users\alice\x", r"C:\Users\Public\x", "/home/alice/x", "/home/$USER/x", "/home/user/x", "~/x"):
            self.assertEqual(L.redact(keep), keep, keep)

    def test_hostnames(self):
        out = L.redact("scp -q dc-fc-r103-a2-win:C:/x . ; ssh ec2-user@ip-10-0-1-2.ec2.internal; curl http://ec2-3-4-5-6.compute-1.amazonaws.com/x; ssh defenseclaw-dev ls; scp dc-ent-rhel:/y .")
        self.assert_gone(out, "dc-fc-r103-a2-win", "ip-10-0-1-2", "ec2-3-4-5-6", "defenseclaw-dev", "dc-ent-rhel")
        again = L.redact("dc-ent-rhel dc-ent-rhel").split()
        self.assertEqual(again[0], again[1])        # the same host always gets the same placeholder
        self.assertIn(again[0], out)
        self.assertEqual(len(set(re.findall(r"labhost\d+", out))), 5)

    def test_ipv4(self):
        out = L.redact("ssh 10.1.2.3 then 172.16.0.9 then 10.1.2.3 and 127.0.0.1 and 198.51.100.7 and 6.10.0.19041.1")
        self.assert_gone(out, "10.1.2.3", "172.16.0.9")
        self.assertEqual(out.split()[1], out.split()[5])
        self.assertNotEqual(out.split()[1], out.split()[3])
        self.assertIn("127.0.0.1", out)
        self.assertIn("198.51.100.7", out)
        self.assertIn("6.10.0.19041.1", out)

    def test_ipv6(self):
        out = L.redact("ping 2600:1f18:abcd:1234::5 ; ping fe80::1234:abcd:ef01:2345%eth0 ; ping ::1 ; ping :: ; ping 2001:db8::9 ; at 12:30:45 ; cls::method ; std::string")
        self.assert_gone(out, "2600:1f18", "fe80::1234", "eth0")
        for keep in ("ping ::1 ;", "ping :: ;", "2001:db8::9", "12:30:45", "std::string"):
            self.assertIn(keep, out)
        self.assertIn("2001:db8::1 ;", out)

    def test_instance_resource_and_account_ids(self):
        out = L.redact("aws ec2 stop-instances --instance-ids i-0a1b2c3d4e5f60718 i-0a1b2c3d --security-group-ids sg-0a1b2c3d4e5f60718 --subnet-id subnet-0a1b2c3d --profile 123456789012")
        self.assert_gone(out, "0a1b2c3d4e5f60718", "i-0a1b2c3d ", "subnet-0a1b2c3d", "123456789012")
        self.assertIn("i-0123456789abcdef0", out)
        self.assertIn("000000000000", out)

    def test_mac_addresses(self):
        out = L.redact("Get-NetAdapter | where MacAddress -eq 0A-1B-2C-3D-4E-5F ; ip link set dev eth0 address 0a:1b:2c:3d:4e:5f ; ff:ff:ff:ff:ff:ff ; 1e:cc:88:d5:07:ee:15:56:5d:d3:2d:05:59:aa:bb:cc:dd:ee:ff:00")
        self.assert_gone(out, "0A-1B-2C-3D-4E-5F", "0a:1b:2c:3d:4e:5f")
        self.assertIn("ff:ff:ff:ff:ff:ff", out)
        self.assertIn("1e:cc:88:d5:07:ee:15:56:5d:d3:2d:05:59:aa:bb:cc:dd:ee:ff:00", out)   # a 20-byte thumbprint is not a MAC
        self.assertRegex(out, r"00-00-5E-00-53-01")   # the separator style is kept
        self.assertIn("00:00:5E:00:53:01", out)       # and the same address gets the same placeholder

    def test_owner_names(self):
        self.assertEqual(L.redact("git -C /x log --author=vnarajal --author=Vineeth"), "git -C /x log --author=alice --author=alice")

    def test_stable_and_idempotent(self):
        text = (r"ssh -T dc-ent-win-1; net use \\FILESRV01\x /user:LABCO\bsmith; reg unload HKU\S-1-5-21-1111111111-2222222222-3333333333-1105; ping 10.1.2.3 2600:1f18::5; "
                "EC2AMAZ-A1B2C3D.corp-lab.local 0a:1b:2c:3d:4e:5f i-0a1b2c3d4e5f60718 jdoe@corp-lab.local C:\\Users\\bob\\x")
        once = L.redact(text)
        self.assertEqual(L.redact(once), once)
        L.reset()
        self.assertEqual(L.redact(text), once)    # a fresh build numbers the same input the same way

    def test_denylist_catches_values_no_pattern_knows(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl") as f:
            for cat, v in (("netbios", "ZEBRA"), ("labdomain", "zebra.example.org"), ("labuser", "quagga9"), ("domuser", "ZEBRA\\quagga9"), ("computername", "OKAPI07"), ("hostalias", "kudu-gw"), ("ip", "203.0.113.77"), ("sid", "S-1-5-21-7-8-9")):
                f.write(json.dumps({"cat": cat, "v": v}) + "\n")
            f.flush()
            self.assertEqual(L.load_denylist(f.name), 8)
        raw = "cd C:\\okapi && OKAPI07 zebra.example.org ZEBRA\\\\quagga9 zebra\\QUAGGA9 kudu-gw 203.0.113.77 S-1-5-21-7-8-9-1001"
        self.assertIn("denylist:", ",".join(L.leak_scan(raw)))
        out = L.redact(raw)
        self.assert_gone(out, "okapi07", "zebra", "quagga9", "kudu-gw", "203.0.113.77", "-7-8-9")
        self.assertEqual(L.leak_scan(out), [])
        self.assertIn("-1001", out)

    def test_leak_scan_flags_each_category_and_passes_the_redacted_text(self):
        raw = {
            "ipv4": "ssh 10.1.2.3", "ipv6": "ping 2600:1f18::5", "mac": "mac 0a:1b:2c:3d:4e:5f", "sid": "S-1-5-21-1111111111-2222222222-3333333333-500", "computername": "EC2AMAZ-A1B2C3D",
            "ec2dns": "ip-10-0-1-2.ec2.internal", "unc": r"\\FILESRV01\share", "compflag": "Get-Service -ComputerName SRV02", "email": "mail bob@corp-mail.test", "upn": "jdoe@corp-lab.local",
            "idctx": r"net use /user:LABCO\bsmith", "domuser": r"LABCO\bsmith", "privfqdn": "dc01.corp-lab.local", "labhost": "dc-ent-win-1", "userdir": r"C:\Users\bob\x",
            "userdir_bare": r"copy Users\bob\x", "homedir": "/home/bob/x", "person": "vnarajal", "instance": "i-0a1b2c3d4e5f60718", "awsres": "sg-0a1b2c3d4e5f60718", "account": "token 123456789012",
        }
        self.assertEqual(set(raw) - set(L.LEAK_PATTERNS), set())
        self.assertEqual(set(L.LEAK_PATTERNS) - set(raw) - {"secret"}, set(), "add a raw sample for the new category")
        for cat, text in raw.items():
            self.assertIn(cat, L.leak_scan(text), cat)
            self.assertEqual(L.leak_scan(L.redact(text)), [], cat)

    def test_row_pass_covers_payload_truth_and_original_id_but_not_provenance(self):
        row = L.shell_case("wsh/t/1", "real-owner", r"orig dc-ent-win-1 C:\Users\bob\s.jsonl", r"ssh dc-ent-win-1 dir C:\Users\bob", truth="benign", cats=["x"], label_source="t")
        row["truth"]["exclusion_reason"] = "host 10.1.2.3"
        self.assertNotEqual(L.scan_row(row), [])
        out = L.redact_row(row)
        self.assertEqual(L.scan_row(out), [])
        self.assertEqual(out["id"], row["id"])
        self.assertEqual(out["source"]["dataset"], row["source"]["dataset"])
        self.assertEqual(out["strata"], row["strata"])


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
