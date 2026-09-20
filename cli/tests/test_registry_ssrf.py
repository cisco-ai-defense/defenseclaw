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

import asyncio
import os
import platform
import socket
import sys
import unittest
from unittest.mock import patch

import anyio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.registries.ssrf import (
    SSRFError,
    analyzer_dns_resolution,
    guard_git_url,
    guard_url,
    pinned_async_getaddrinfo,
    pinned_getaddrinfo,
    resolve_and_pin,
)

_UVLOOP_SUPPORTED = (
    sys.platform not in {"win32", "cygwin"}
    and platform.python_implementation() != "PyPy"
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

    def test_loopback_allowed_when_opted_in(self):
        for ip in ("127.0.0.1", "::1"):
            with self.subTest(ip=ip):
                guard_url(
                    "https://loop.example/m",
                    allow_private=True,
                    resolver=stub({"loop.example": [ip]}),
                )

    def test_link_local_blocked(self):
        with self.assertRaises(SSRFError):
            guard_url(
                "https://ll.example/m",
                resolver=stub({"ll.example": ["169.254.169.254"]}),
            )

    def test_link_local_allowed_when_opted_in(self):
        guard_url(
            "https://ll.example/m",
            allow_private=True,
            resolver=stub({"ll.example": ["fe80::1"]}),
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


class TestPinnedGetaddrinfo(unittest.TestCase):
    """F-0344: the getaddrinfo pin closes the DNS-rebind TOCTOU window for
    clients (e.g. the async-httpx MCP scanner SDK) that re-resolve the host
    at connect time instead of honouring a urllib3-level connect pin."""

    def test_pinned_host_resolves_to_vetted_ip(self):
        # Inside the pin, a lookup for the vetted host returns the pinned
        # IP — NOT whatever a (rebinding) DNS would now answer.
        with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
            infos = socket.getaddrinfo("rebind.example", 443)
        addrs = {info[4][0] for info in infos}
        self.assertEqual(addrs, {"93.184.216.34"})

    def test_anyio_bytes_hostname_resolves_to_vetted_ip(self):
        calls = []

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            calls.append((host, port, family, type, proto, flags))
            return [
                (
                    family,
                    type or socket.SOCK_STREAM,
                    proto,
                    "",
                    (str(host), port),
                )
            ]

        with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
            with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
                infos = anyio.run(anyio.getaddrinfo, "rebind.example", 443)

        self.assertEqual(infos[0][4][0], "93.184.216.34")
        self.assertEqual(calls[0][0], "93.184.216.34")

    def test_bytes_hostname_accepts_keyword_family(self):
        calls = []

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            calls.append((host, port, family, type, proto, flags))
            return [(family, type, proto, "", (str(host), port))]

        with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
            with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
                socket.getaddrinfo(
                    b"rebind.example",
                    8443,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                    flags=socket.AI_NUMERICHOST,
                )

        self.assertEqual(
            calls,
            [
                (
                    "93.184.216.34",
                    8443,
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    socket.AI_NUMERICHOST,
                )
            ],
        )

    def test_unicode_hostname_matches_anyio_alabel(self):
        calls = []

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            calls.append(host)
            return [(family, type, proto, "", (str(host), port))]

        with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
            with pinned_getaddrinfo("faß.example", 443, "93.184.216.34"):
                socket.getaddrinfo(b"xn--fa-hia.example", 443)

        self.assertEqual(calls, ["93.184.216.34"])

    def test_invalid_host_shapes_are_refused_before_resolving(self):
        calls = []

        def fake_getaddrinfo(*args, **kwargs):
            calls.append((args, kwargs))
            return []

        bad_hosts = (
            ("none", None),
            ("non-ascii-bytes", b"\xff.example"),
            ("nul", "bad\x00.example"),
            ("surrogate", "\ud800.example"),
        )
        with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
            with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
                for case, host in bad_hosts:
                    with self.subTest(case=case):
                        with self.assertRaises(SSRFError):
                            socket.getaddrinfo(host, 443)

        self.assertEqual(calls, [])

    def test_unexpected_public_host_is_refused(self):
        calls = []

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            calls.append((host, port))
            return [
                (
                    socket.AF_INET,
                    type or socket.SOCK_STREAM,
                    proto,
                    "",
                    ("8.8.8.8", port),
                )
            ]

        with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
            with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
                for host in ("proxy.example", b"proxy.example"):
                    with self.subTest(host=host):
                        with self.assertRaises(SSRFError):
                            socket.getaddrinfo(host, 443)

        self.assertEqual(calls, [])

    def test_analyzer_dns_scope_allows_public_host_and_resets(self):
        calls = []

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            calls.append((host, port))
            return [
                (
                    socket.AF_INET,
                    type or socket.SOCK_STREAM,
                    proto,
                    "",
                    ("8.8.8.8", port),
                )
            ]

        with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
            with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
                with analyzer_dns_resolution():
                    infos = socket.getaddrinfo("analyzer.example", 443)
                with self.assertRaises(SSRFError):
                    socket.getaddrinfo("analyzer.example", 443)

        self.assertEqual(calls, [("analyzer.example", 443)])
        self.assertEqual({info[4][0] for info in infos}, {"8.8.8.8"})

    def test_analyzer_dns_scope_rejects_unconfigured_private_host(self):
        for address in (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "::ffff:127.0.0.1",
        ):
            with self.subTest(address=address):
                calls = []

                def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
                    calls.append((host, port))
                    return [
                        (
                            socket.AF_INET,
                            type or socket.SOCK_STREAM,
                            proto,
                            "",
                            (address, port),
                        )
                    ]

                with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
                    with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
                        with analyzer_dns_resolution("trusted.internal"):
                            with self.assertRaises(SSRFError):
                                socket.getaddrinfo("redirect.example", 443)

                self.assertEqual(calls, [("redirect.example", 443)])

    def test_analyzer_dns_scope_allows_configured_private_host_only(self):
        calls = []

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            calls.append((host, port))
            return [
                (
                    socket.AF_INET,
                    type or socket.SOCK_STREAM,
                    proto,
                    "",
                    ("127.0.0.1", port),
                )
            ]

        with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
            with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
                with analyzer_dns_resolution("analyzer.internal"):
                    infos = socket.getaddrinfo("analyzer.internal", 443)

        self.assertEqual(calls, [("analyzer.internal", 443)])
        self.assertEqual({info[4][0] for info in infos}, {"127.0.0.1"})

    def test_analyzer_dns_scope_rejects_mixed_public_private_answers(self):
        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, proto, "", ("8.8.8.8", port)),
                (socket.AF_INET, socket.SOCK_STREAM, proto, "", ("127.0.0.1", port)),
            ]

        with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
            with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
                with analyzer_dns_resolution():
                    with self.assertRaises(SSRFError):
                        socket.getaddrinfo("redirect.example", 443)

    def test_analyzer_dns_scope_resets_on_exception(self):
        with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
            with self.assertRaises(RuntimeError):
                with analyzer_dns_resolution():
                    raise RuntimeError("boom")
            with self.assertRaises(SSRFError):
                socket.getaddrinfo("analyzer.example", 443)

    def test_analyzer_dns_scope_is_task_local(self):
        calls = []

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            node = host.decode("ascii") if isinstance(host, bytes) else str(host)
            calls.append(node)
            return [
                (
                    socket.AF_INET,
                    type or socket.SOCK_STREAM,
                    proto,
                    "",
                    ("8.8.8.8", port),
                )
            ]

        async def run_lookups():
            async def analyzer_lookup():
                with analyzer_dns_resolution():
                    return await anyio.getaddrinfo("analyzer.example", 443)

            async def transport_lookup():
                with self.assertRaises(SSRFError):
                    await anyio.getaddrinfo("proxy.example", 443)

            async with pinned_async_getaddrinfo():
                return await asyncio.gather(analyzer_lookup(), transport_lookup())

        with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
            with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
                results = anyio.run(run_lookups)

        self.assertEqual(calls, ["analyzer.example"])
        self.assertEqual({info[4][0] for info in results[0]}, {"8.8.8.8"})

    def test_getaddrinfo_restored_after_block(self):
        original = socket.getaddrinfo
        with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
            pass
        self.assertIs(socket.getaddrinfo, original)

    def test_getaddrinfo_restored_on_exception(self):
        original = socket.getaddrinfo
        with self.assertRaises(RuntimeError):
            with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
                raise RuntimeError("boom")
        self.assertIs(socket.getaddrinfo, original)

    def test_async_getaddrinfo_restored_after_block(self):
        async def check_restoration():
            loop = asyncio.get_running_loop()
            original = loop.getaddrinfo
            had_override = "getaddrinfo" in vars(loop)
            async with pinned_async_getaddrinfo():
                self.assertNotEqual(loop.getaddrinfo, original)
            self.assertEqual(loop.getaddrinfo, original)
            self.assertEqual("getaddrinfo" in vars(loop), had_override)

        anyio.run(check_restoration)

    def test_async_getaddrinfo_restored_on_exception(self):
        async def check_restoration():
            loop = asyncio.get_running_loop()
            original = loop.getaddrinfo
            with self.assertRaises(RuntimeError):
                async with pinned_async_getaddrinfo():
                    raise RuntimeError("boom")
            self.assertEqual(loop.getaddrinfo, original)

        anyio.run(check_restoration)

    def test_async_getaddrinfo_restored_on_cancellation(self):
        async def check_restoration():
            loop = asyncio.get_running_loop()
            original = loop.getaddrinfo
            had_override = "getaddrinfo" in vars(loop)
            entered = asyncio.Event()

            async def hold_scope():
                async with pinned_async_getaddrinfo():
                    entered.set()
                    await asyncio.Event().wait()

            task = asyncio.create_task(hold_scope())
            await entered.wait()
            self.assertNotEqual(loop.getaddrinfo, original)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(loop.getaddrinfo, original)
            self.assertEqual("getaddrinfo" in vars(loop), had_override)

        with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
            anyio.run(check_restoration)
            if _UVLOOP_SUPPORTED:
                anyio.run(
                    check_restoration,
                    backend_options={"use_uvloop": True},
                )

    def test_async_pin_preserves_instance_resolver_override(self):
        async def check_restoration():
            loop = asyncio.get_running_loop()

            async def previous_resolver(*_args, **_kwargs):
                return []

            loop.getaddrinfo = previous_resolver
            try:
                self.assertIs(vars(loop)["getaddrinfo"], previous_resolver)
                async with pinned_async_getaddrinfo():
                    self.assertIsNot(loop.getaddrinfo, previous_resolver)
                self.assertIs(loop.getaddrinfo, previous_resolver)
            finally:
                del loop.getaddrinfo

        with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
            anyio.run(check_restoration)
            if _UVLOOP_SUPPORTED:
                anyio.run(
                    check_restoration,
                    backend_options={"use_uvloop": True},
                )

    def test_overlapping_async_pin_scopes_restore_after_last_exit(self):
        async def check_overlap():
            loop = asyncio.get_running_loop()
            had_override = "getaddrinfo" in vars(loop)
            first_entered = asyncio.Event()
            second_entered = asyncio.Event()
            first_exited = asyncio.Event()

            async def first_scope():
                async with pinned_async_getaddrinfo():
                    first_entered.set()
                    await second_entered.wait()
                first_exited.set()

            async def second_scope():
                await first_entered.wait()
                async with pinned_async_getaddrinfo():
                    second_entered.set()
                    await first_exited.wait()
                    with self.assertRaises(SSRFError):
                        await anyio.getaddrinfo("localhost", 443)

            await asyncio.gather(first_scope(), second_scope())
            self.assertEqual("getaddrinfo" in vars(loop), had_override)

        with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
            anyio.run(check_overlap)
            if _UVLOOP_SUPPORTED:
                anyio.run(check_overlap, backend_options={"use_uvloop": True})

    @unittest.skipUnless(
        _UVLOOP_SUPPORTED,
        "uvloop does not support Windows, Cygwin, or PyPy",
    )
    def test_async_pin_covers_uvloop(self):
        calls = []

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            node = host.decode("ascii") if isinstance(host, bytes) else str(host)
            calls.append(node)
            address = "8.8.8.8" if node == "analyzer.example" else node
            return [
                (
                    socket.AF_INET,
                    type or socket.SOCK_STREAM,
                    proto,
                    "",
                    (address, port),
                )
            ]

        async def run_lookups():
            async with pinned_async_getaddrinfo():
                target = await anyio.getaddrinfo("rebind.example", 443)
                with analyzer_dns_resolution():
                    analyzer = await anyio.getaddrinfo("analyzer.example", 443)
                with self.assertRaises(SSRFError):
                    await anyio.getaddrinfo("proxy.example", 443)
                return target, analyzer

        with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
            with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
                target, analyzer = anyio.run(
                    run_lookups,
                    backend_options={"use_uvloop": True},
                )

        self.assertEqual(calls, ["93.184.216.34", "analyzer.example"])
        self.assertEqual({info[4][0] for info in target}, {"93.184.216.34"})
        self.assertEqual({info[4][0] for info in analyzer}, {"8.8.8.8"})

    def test_ip_literal_matching_pin_is_allowed(self):
        # A client that pre-resolves and re-calls getaddrinfo with the IP
        # literal equal to the pin is allowed through.
        with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
            for host in ("93.184.216.34", b"93.184.216.34"):
                infos = socket.getaddrinfo(host, 443)
                self.assertTrue(infos)

    def test_different_ip_literal_is_refused(self):
        with pinned_getaddrinfo("rebind.example", 443, "93.184.216.34"):
            with self.assertRaises(SSRFError):
                socket.getaddrinfo("127.0.0.1", 443)

    def test_ipv6_pin_forces_ipv6_family(self):
        calls = []

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            calls.append((host, port, family, type, proto, flags))
            return [(family, type, proto, "", (str(host), port, 0, 0))]

        with patch.object(socket, "getaddrinfo", fake_getaddrinfo):
            with pinned_getaddrinfo("v6.example", 443, "2001:4860:4860::8888"):
                socket.getaddrinfo(
                    "v6.example",
                    443,
                    socket.AF_UNSPEC,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                )

        self.assertEqual(calls[0][0], "2001:4860:4860::8888")
        self.assertEqual(calls[0][2], socket.AF_INET6)

    def test_incompatible_requested_family_is_refused(self):
        with pinned_getaddrinfo("v6.example", 443, "2001:4860:4860::8888"):
            with self.assertRaises(socket.gaierror):
                socket.getaddrinfo("v6.example", 443, family=socket.AF_INET)

    def test_unicode_url_uses_anyio_alabel_for_validation(self):
        seen = []

        def resolver(host):
            seen.append(host)
            return ["93.184.216.34"]

        ip, host, port = resolve_and_pin(
            "https://faß.example/mcp",
            resolver=resolver,
        )

        self.assertEqual(
            (ip, host, port),
            ("93.184.216.34", "xn--fa-hia.example", 443),
        )
        self.assertEqual(seen, ["xn--fa-hia.example"])

    # --- Private upstream allowlist tests ---

    def test_allowed_private_upstream_passes(self):
        with patch.dict(
            os.environ,
            {"DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS": "10.50.2.100"},
        ):
            guard_url(
                "https://llm.internal/v1",
                resolver=stub({"llm.internal": ["10.50.2.100"]}),
            )

    def test_allowed_private_upstream_other_ip_still_blocked(self):
        with patch.dict(
            os.environ,
            {"DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS": "10.50.2.100"},
        ):
            with self.assertRaises(SSRFError):
                guard_url(
                    "https://other.internal/v1",
                    resolver=stub({"other.internal": ["10.50.2.101"]}),
                )

    def test_allowed_private_upstream_loopback_never_exempted(self):
        with patch.dict(
            os.environ,
            {"DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS": "127.0.0.1"},
        ):
            with self.assertRaises(SSRFError):
                guard_url(
                    "https://loopback.internal/v1",
                    resolver=stub({"loopback.internal": ["127.0.0.1"]}),
                )

    def test_mapped_loopback_never_exempted(self):
        with patch.dict(
            os.environ,
            {"DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS": "127.0.0.1"},
        ):
            with self.assertRaises(SSRFError):
                guard_url(
                    "https://loopback.internal/v1",
                    resolver=stub({"loopback.internal": ["::ffff:127.0.0.1"]}),
                )

    def test_mapped_metadata_never_exempted(self):
        with patch.dict(
            os.environ,
            {"DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS": "169.254.169.254"},
        ):
            with self.assertRaises(SSRFError):
                guard_url(
                    "https://metadata.internal/v1",
                    resolver=stub({"metadata.internal": ["::ffff:169.254.169.254"]}),
                )

    def test_ipv6_metadata_never_exempted(self):
        with patch.dict(
            os.environ,
            {"DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS": "fd00:ec2::254"},
        ):
            with self.assertRaises(SSRFError):
                guard_url(
                    "https://metadata.internal/v1",
                    resolver=stub({"metadata.internal": ["fd00:ec2::254"]}),
                )

    def test_allowed_private_upstream_multiple_ips(self):
        with patch.dict(
            os.environ,
            {"DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS": "10.50.2.100,172.16.0.5"},
        ):
            guard_url(
                "https://gw1.internal/v1",
                resolver=stub({"gw1.internal": ["10.50.2.100"]}),
            )
            guard_url(
                "https://gw2.internal/v1",
                resolver=stub({"gw2.internal": ["172.16.0.5"]}),
            )

    def test_allowed_private_upstream_unset_blocks_all(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS", None)
            with self.assertRaises(SSRFError):
                guard_url(
                    "https://llm.internal/v1",
                    resolver=stub({"llm.internal": ["10.50.2.100"]}),
                )


if __name__ == "__main__":
    unittest.main()
