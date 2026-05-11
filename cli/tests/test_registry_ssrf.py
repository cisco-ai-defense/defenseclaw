# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the registry SSRF guard.

The guard's job is fail-closed by default: every operator-supplied URL
must resolve to a publicly routable host before we hand it to
:mod:`requests`. These tests exercise the guard with a stub resolver
so the suite never touches real DNS.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.registries.ssrf import (
    SSRFError,
    guard_git_url,
    guard_url,
    resolve_and_pin,
)


def stub(addr_map):
    def _resolve(host):
        return list(addr_map.get(host, []))
    return _resolve


class TestSchemes(unittest.TestCase):
    # 8.8.8.8 is globally routable and not in any of the
    # private/reserved/loopback/link-local/multicast/unspecified
    # ranges that the guard rejects, so it's a stable "public" stand-in
    # for tests. RFC5737 documentation prefixes (192.0.2.0/24,
    # 198.51.100.0/24, 203.0.113.0/24) are flagged as `is_reserved`
    # by Python's ipaddress module and would be rejected here.
    PUBLIC_IP = "8.8.8.8"

    def test_https_public_ok(self):
        guard_url(
            "https://catalog.example.com/manifest.yaml",
            resolver=stub({"catalog.example.com": [self.PUBLIC_IP]}),
        )

    def test_http_public_ok_but_caller_should_warn(self):
        # HTTP is allowed by the guard (publishers occasionally serve
        # plain HTTP behind a corporate WAF); the surrounding
        # CLI/adapter is expected to surface a warning. The guard
        # itself must accept it so policy-driven downgrades don't
        # break ingest.
        guard_url(
            "http://catalog.example.com/manifest.yaml",
            resolver=stub({"catalog.example.com": [self.PUBLIC_IP]}),
        )

    def test_file_scheme_rejected(self):
        with self.assertRaises(SSRFError):
            guard_url("file:///etc/passwd")

    def test_ftp_scheme_rejected(self):
        with self.assertRaises(SSRFError):
            guard_url("ftp://example.com/x")

    def test_javascript_scheme_rejected(self):
        with self.assertRaises(SSRFError):
            guard_url("javascript:alert(1)")


class TestHostShape(unittest.TestCase):
    def test_missing_host_rejected(self):
        with self.assertRaises(SSRFError):
            guard_url("https:///foo")

    def test_localhost_literal_rejected(self):
        with self.assertRaises(SSRFError):
            guard_url("https://localhost/manifest")

    def test_unresolvable_host_rejected(self):
        with self.assertRaises(SSRFError):
            guard_url(
                "https://nope.example",
                resolver=stub({}),
            )


class TestPrivateRanges(unittest.TestCase):
    def test_loopback_blocked(self):
        for ip in ("127.0.0.1", "::1"):
            with self.subTest(ip=ip):
                with self.assertRaises(SSRFError):
                    guard_url(
                        "https://loop.example/m",
                        resolver=stub({"loop.example": [ip]}),
                    )

    def test_link_local_blocked(self):
        with self.assertRaises(SSRFError):
            guard_url(
                "https://ll.example/m",
                resolver=stub({"ll.example": ["169.254.169.254"]}),
            )

    def test_rfc1918_blocked_by_default(self):
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.1"):
            with self.subTest(ip=ip):
                with self.assertRaises(SSRFError):
                    guard_url(
                        "https://corp.example/m",
                        resolver=stub({"corp.example": [ip]}),
                    )

    def test_rfc1918_allowed_when_opted_in(self):
        # Operators with on-prem registries set --allow-private. The
        # guard accepts the *same* URL it would reject without the
        # flag — no behavioural drift between the two paths.
        guard_url(
            "https://corp.example/m",
            allow_private=True,
            resolver=stub({"corp.example": ["10.0.0.1"]}),
        )

    def test_dual_stack_resolves_one_private_one_public(self):
        # An attacker can publish a hostname whose A record is public
        # but whose AAAA record is link-local — guard must reject if
        # *any* address is disallowed.
        with self.assertRaises(SSRFError):
            guard_url(
                "https://mixed.example/m",
                resolver=stub({"mixed.example": ["8.8.8.8", "fe80::1"]}),
            )

    def test_unspecified_blocked(self):
        with self.assertRaises(SSRFError):
            guard_url(
                "https://zero.example/m",
                resolver=stub({"zero.example": ["0.0.0.0"]}),
            )

    # --- CGNAT / RFC 6598 ----------------------------------------------
    # Python's ``ipaddress.is_private`` predates RFC 6598 and does NOT
    # cover 100.64.0.0/10, so the previous implementation accepted CGNAT
    # webhook URLs at config-time even though the Go-side dial guard
    # blocks them at runtime. These tests pin the validator-parity fix:
    # CGNAT is rejected by default, the existing ``--allow-private``
    # opt-in still wins, and a CGNAT-aware operator can flip the
    # dedicated ``DEFENSECLAW_ALLOW_CGNAT=1`` env switch the Go side
    # honours.

    def test_cgnat_blocked_by_default(self):
        for ip in ("100.64.0.5", "100.99.42.7", "100.127.255.254"):
            with self.subTest(ip=ip):
                with patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("DEFENSECLAW_ALLOW_CGNAT", None)
                    with self.assertRaises(SSRFError) as cm:
                        guard_url(
                            "https://tail.example/m",
                            resolver=stub({"tail.example": [ip]}),
                        )
                    self.assertIn("CGNAT", str(cm.exception))

    def test_cgnat_allowed_with_env_optin(self):
        with patch.dict(os.environ, {"DEFENSECLAW_ALLOW_CGNAT": "1"}):
            guard_url(
                "https://tail.example/m",
                resolver=stub({"tail.example": ["100.64.0.5"]}),
            )

    def test_cgnat_allowed_with_allow_private(self):
        # --allow-private already meant "yes I know this looks
        # internal" — CGNAT should ride along with it so operators
        # don't have to set two flags to authorise one decision.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEFENSECLAW_ALLOW_CGNAT", None)
            guard_url(
                "https://corp.example/m",
                allow_private=True,
                resolver=stub({"corp.example": ["100.64.0.5"]}),
            )

    def test_cgnat_boundary_addresses(self):
        # First and last address of 100.64.0.0/10 (100.64.0.0 .. 100.127.255.255).
        # 100.63.255.255 sits one octet below the block and must NOT be
        # treated as CGNAT.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEFENSECLAW_ALLOW_CGNAT", None)
            for ip in ("100.64.0.0", "100.127.255.255"):
                with self.subTest(ip=ip, expected="blocked"):
                    with self.assertRaises(SSRFError):
                        guard_url(
                            "https://b.example/m",
                            resolver=stub({"b.example": [ip]}),
                        )
            # 100.63.255.255 is just outside CGNAT and is globally
            # routable; the guard must let it through.
            guard_url(
                "https://just-below.example/m",
                resolver=stub({"just-below.example": ["100.63.255.255"]}),
            )

    def test_cgnat_check_v4_only(self):
        # 64:ff9b::/96 is NAT64; it isn't CGNAT and must not get caught
        # by the v4 CGNAT regex masquerading as a v6 address.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEFENSECLAW_ALLOW_CGNAT", None)
            # Pure public IPv6 must still pass.
            guard_url(
                "https://v6.example/m",
                resolver=stub({"v6.example": ["2606:4700::1"]}),
            )


class TestResolveAndPin(unittest.TestCase):
    """H-2: callers must be able to retrieve a vetted IP literal so the
    underlying TCP connect can bypass the host-resolver and defeat
    DNS-rebind. The IP we return must be the one that survived the
    SSRF policy — never the second-resolution answer.
    """

    PUBLIC_IP = "8.8.8.8"

    def test_returns_pinned_public_ip(self):
        ip, host, port = resolve_and_pin(
            "https://catalog.example.com/manifest.yaml",
            resolver=stub({"catalog.example.com": [self.PUBLIC_IP]}),
        )
        self.assertEqual(ip, self.PUBLIC_IP)
        self.assertEqual(host, "catalog.example.com")
        self.assertEqual(port, 443)

    def test_default_http_port(self):
        _, _, port = resolve_and_pin(
            "http://catalog.example.com/manifest.yaml",
            resolver=stub({"catalog.example.com": [self.PUBLIC_IP]}),
        )
        self.assertEqual(port, 80)

    def test_explicit_port_preserved(self):
        _, _, port = resolve_and_pin(
            "https://catalog.example.com:8443/manifest.yaml",
            resolver=stub({"catalog.example.com": [self.PUBLIC_IP]}),
        )
        self.assertEqual(port, 8443)

    def test_rejects_disallowed_ip_before_returning_pin(self):
        with self.assertRaises(SSRFError):
            resolve_and_pin(
                "https://corp.example/m",
                resolver=stub({"corp.example": ["10.0.0.1"]}),
            )

    def test_first_safe_ip_wins(self):
        ip, _, _ = resolve_and_pin(
            "https://multi.example/m",
            resolver=stub({"multi.example": ["8.8.8.8", "1.1.1.1"]}),
        )
        # Stable mirror of urllib3.util.connection — always the first
        # entry in the resolver's iteration order.
        self.assertEqual(ip, "8.8.8.8")


class TestGitGuard(unittest.TestCase):
    def test_https_git_url_passes(self):
        guard_git_url(
            "https://example.com/acme/registry.git",
            allow_private=False,
            resolver=stub({"example.com": ["8.8.8.8"]}),
        )

    def test_ssh_git_url_rejected(self):
        with self.assertRaises(SSRFError):
            guard_git_url("ssh://git@github.com/acme/registry.git")

    def test_git_protocol_rejected(self):
        with self.assertRaises(SSRFError):
            guard_git_url("git://github.com/acme/registry.git")

    def test_file_url_rejected(self):
        with self.assertRaises(SSRFError):
            guard_git_url("file:///srv/registry.git")


if __name__ == "__main__":
    unittest.main()
