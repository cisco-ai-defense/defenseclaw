# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""URL safety guards for registry adapters.

Registry sources are operator-provided URLs that DefenseClaw will fetch
on the operator's behalf — exactly the pattern that earns a finding in
:mod:`policies.guardrail` and the codebase rules. We refuse to fetch
anything that resolves to localhost, link-local, multicast, or
RFC1918/ULA private addresses by default. Operators that genuinely
need to ingest from a private host must opt in with ``--allow-private``;
the flag is plumbed all the way through the CLI surface so an
"oops, my URL was internal" mistake stays explicit.

This module is intentionally pure-Python and stdlib-only so it can be
unit-tested without network access — :func:`guard_url` performs DNS
resolution via :func:`socket.getaddrinfo`, but that lookup can be
mocked in tests by passing a custom ``resolver`` callback.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import socket
import threading
from collections.abc import Callable, Iterator
from urllib.parse import urlparse

# RFC 6598 carrier-grade NAT range. Python's ``ipaddress.is_private``
# does NOT include this block — it predates RFC 6598 — so we have to
# match it explicitly to stay in lockstep with the Go-side gateway
# guard (``internal/gateway/provider.go`` ``isUnsafeIP``). Operators
# running over Tailscale or other CGNAT-routed overlays opt in via
# ``DEFENSECLAW_ALLOW_CGNAT=1``, the same env var the Go side honours.
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def _cgnat_allowed() -> bool:
    """Return True when the operator has opted into dialing CGNAT.

    Read at call time (not at import) so tests can toggle the env var
    with :func:`unittest.mock.patch.dict` and so a long-running process
    picks up a config change without restart.
    """
    return os.environ.get("DEFENSECLAW_ALLOW_CGNAT") == "1"

ALLOWED_SCHEMES = frozenset({"http", "https"})
"""Schemes accepted for HTTP-style fetches.

``file://`` URLs are intentionally NOT allowed in published manifests
or in HTTP-kind sources — operators that want to ingest local files
register the source with ``kind=file`` and a filesystem path instead,
which routes through a dedicated adapter that doesn't go through this
module.
"""


class SSRFError(ValueError):
    """Raised when a URL fails the SSRF guard."""


# Dependency-injected resolver type so tests can avoid hitting DNS.
Resolver = Callable[[str], list[str]]


def _default_resolver(host: str) -> list[str]:
    """Resolve *host* via getaddrinfo, returning a list of literal IPs.

    Returns ``[host]`` if *host* is already an IP literal so callers
    can pass IPs through without a DNS query. Empty list on failure —
    callers should treat that as "could not validate, refuse".
    """
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    # info[4] is a sockaddr tuple; the first element is always the host
    # for both AF_INET (str) and AF_INET6 (str). Cast explicitly so the
    # set is typed as Set[str] for mypy — getaddrinfo()'s stub returns
    # Tuple[Any, ...] which leaks an Any/int union otherwise.
    return list({str(info[4][0]) for info in infos})


def guard_url(
    url: str,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> None:
    """Validate *url* against the SSRF policy.

    Raises :class:`SSRFError` on any of:

    * scheme outside :data:`ALLOWED_SCHEMES`
    * empty / non-DNS-resolvable host
    * resolved IP in the loopback / link-local / multicast / unspecified
      range (always blocked)
    * resolved IP in RFC1918 / ULA / shared-CGNAT / RFC6598 ranges
      when *allow_private* is False (the default).

    The default fail-closed posture matches the project guidance for
    operator-provided URLs (codeguard-0-api-web-services).
    """
    resolve_and_pin(url, allow_private=allow_private, resolver=resolver)


def resolve_and_pin(
    url: str,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> tuple[str, str, int]:
    """Validate *url* and return ``(safe_ip, host, port)`` for pinning.

    This is the rebind-safe extension of :func:`guard_url`. It performs
    the same allow-list / scheme / IP-range checks, then returns the
    first IP literal that survived the policy. Callers can then open
    the underlying TCP connection against that exact IP (preserving
    ``Host:`` and TLS SNI), eliminating the time-of-check vs.
    time-of-use window that exists when :mod:`requests` is allowed to
    resolve the hostname a second time.

    The function intentionally returns a single IP rather than the full
    resolved set. urllib3 uses the first address from
    :func:`socket.getaddrinfo`; we mirror that to keep DNS-policy
    behaviour predictable across adapter versions and to avoid leaking
    DNS round-robin into deterministic test runs.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFError(
            f"unsupported URL scheme {scheme!r}; expected http or https"
        )
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise SSRFError("URL is missing a host component")

    if host in {"localhost", "ip6-localhost"}:
        raise SSRFError("refusing to fetch from localhost")

    resolve = resolver or _default_resolver
    addrs = resolve(host)
    if not addrs:
        raise SSRFError(f"could not resolve host {host!r}")

    safe_ip: str | None = None
    for addr in addrs:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
        ):
            raise SSRFError(
                f"host {host!r} resolves to disallowed address {addr}"
            )
        if not allow_private and ip.is_private:
            raise SSRFError(
                f"host {host!r} resolves to private address {addr} "
                "(use --allow-private to opt in)"
            )
        # CGNAT (RFC 6598, 100.64.0.0/10) is not covered by
        # ipaddress.is_private but the Go-side dial guard refuses it,
        # so a CGNAT URL accepted here would still fail at dispatch
        # time. Refuse here too to keep config-time validation in
        # lockstep with runtime, unless the operator has explicitly
        # opted into a CGNAT overlay with DEFENSECLAW_ALLOW_CGNAT=1.
        if (
            not allow_private
            and not _cgnat_allowed()
            and ip.version == 4
            and ip in _CGNAT_NETWORK
        ):
            raise SSRFError(
                f"host {host!r} resolves to RFC 6598 CGNAT address {addr} "
                "(set DEFENSECLAW_ALLOW_CGNAT=1 to opt in, "
                "or use --allow-private)"
            )
        if safe_ip is None:
            safe_ip = addr
    if safe_ip is None:
        # Every addrinfo entry was non-IP-literal junk (highly unusual,
        # but possible with a custom resolver returning hostnames).
        raise SSRFError(f"could not pin a usable IP for host {host!r}")
    port = parsed.port or (443 if scheme == "https" else 80)
    return safe_ip, host, port


# ---------------------------------------------------------------------------
# DNS-rebind defense at the resolver chokepoint
# ---------------------------------------------------------------------------
#
# ``resolve_and_pin`` validates the hostname once. A client library then
# resolves the SAME hostname AGAIN when it opens the socket — a low-TTL
# rebind can answer "safe" the first time and "unsafe" the second,
# defeating the guard. The adapters' ``_PinnedConnect`` closes this for
# ``urllib3``-based clients, but the MCP scanner SDK connects with async
# ``httpx``/``anyio`` (``sse_client`` / ``streamablehttp_client``), which
# never touches urllib3. Both stacks ultimately resolve through
# :func:`socket.getaddrinfo`, so pinning there covers every client.

_GETADDRINFO_PIN_LOCK = threading.Lock()


@contextlib.contextmanager
def pinned_getaddrinfo(host: str, port: int, ip: str) -> Iterator[None]:
    """Pin :func:`socket.getaddrinfo` to *ip* for the (*host*, *port*) pair.

    While the block is active, a lookup for the vetted ``host:port`` is
    answered with the pre-validated ``ip`` (so no second, rebindable DNS
    query happens at connect time). A lookup for the same host on a
    *different* port is also re-pointed at the vetted IP (clients may dial
    a derived port). A lookup for any *other* host raises :class:`SSRFError`
    so a library cannot side-channel a request to an unvetted destination
    during the pinned operation.

    Held under a process-wide lock for the duration of the block because it
    monkeypatches a module global; concurrent pinned fetches serialise on
    connect, matching the adapter ``_PinnedConnect`` contract.
    """
    target_host = (host or "").strip().lower()
    family_ip = ipaddress.ip_address(ip)
    with _GETADDRINFO_PIN_LOCK:
        original = socket.getaddrinfo

        def _pinned(node, service, *args, **kwargs):  # type: ignore[no-untyped-def]
            asked = (str(node).strip().lower() if node is not None else "")
            if asked == target_host:
                # Resolve to the vetted IP literal. Preserve the requested
                # service/port so a derived port still connects correctly;
                # the Host header / TLS SNI continue to carry the hostname
                # because those travel independently of the dial address.
                fam = socket.AF_INET6 if family_ip.version == 6 else socket.AF_INET
                return original(ip, service, fam, *args[1:], **kwargs)
            # An IP literal that equals our pin is fine (some clients
            # pre-resolve and re-call getaddrinfo with the IP).
            try:
                if ipaddress.ip_address(asked) == family_ip:
                    return original(ip, service, *args, **kwargs)
            except ValueError:
                pass
            raise SSRFError(
                f"unexpected DNS resolution for {asked!r} during pinned "
                f"fetch of {target_host!r} (possible DNS rebinding)"
            )

        socket.getaddrinfo = _pinned  # type: ignore[assignment]
        try:
            yield
        finally:
            socket.getaddrinfo = original  # type: ignore[assignment]


def guard_git_url(
    url: str,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> None:
    """Validate a git clone URL.

    Accepts ``https://`` and ``http://`` URLs (delegates to
    :func:`guard_url`) and rejects ``ssh://`` / ``git://`` / ``file://``
    / shell-shorthand forms entirely. SSH-based git is intentionally
    out of scope: it requires private key material and key trust
    decisions that don't belong in an automated ingest pipeline.

    The ``resolver`` parameter is plumbed through to :func:`guard_url`
    so tests can stub DNS without hitting the network.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFError(
            f"git URL scheme {scheme!r} not allowed; use http(s) for catalog clones"
        )
    guard_url(url, allow_private=allow_private, resolver=resolver)
