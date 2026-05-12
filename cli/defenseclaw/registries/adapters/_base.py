# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared HTTP helpers for registry adapters.

We deliberately keep this layer paper-thin so the security-relevant
guards stay visible and uniform across every adapter:

* :func:`http_get` performs an SSRF check against the URL, rejects
  redirects to disallowed hosts, caps the response body at
  :data:`MAX_MANIFEST_BYTES`, and applies a fixed timeout.
* :func:`auth_header` reads the auth token from the env var named on
  the source (never the literal token), strips whitespace, and refuses
  to pass through control characters.

All adapters call :func:`http_get` rather than :mod:`requests` directly
so a single point of audit covers the whole ingest path.
"""

from __future__ import annotations

import os
import re
import socket
from urllib.parse import urljoin, urlparse

import requests
from urllib3.util import connection as _urllib3_connection

from defenseclaw.config import RegistrySource
from defenseclaw.registries.ssrf import (
    Resolver,
    SSRFError,
    resolve_and_pin,
)

MAX_MANIFEST_BYTES = 8 * 1024 * 1024
"""Hard cap on a fetched manifest payload (8 MiB).

A vendor-neutral catalog with 10k entries fits easily inside this
budget. Anything larger almost certainly indicates an attack
(zip-bomb-style nested structures), a misconfigured server, or a
runaway publisher; we'd rather refuse and force a config fix than
balloon the operator's RAM during sync.
"""

MAX_SKILL_ARCHIVE_BYTES = 128 * 1024 * 1024
"""Hard cap on a fetched skill archive payload (128 MiB)."""

DEFAULT_TIMEOUT = 30.0
"""Per-request timeout (seconds) for adapter HTTP calls."""

USER_AGENT = "defenseclaw-registry-sync/1"

_CTL_RE = re.compile(r"[\x00-\x1f\x7f]")


class IngestError(RuntimeError):
    """Raised when an adapter fails to fetch or parse a manifest."""


def http_get(
    url: str,
    *,
    auth_env: str = "",
    accept: str = "application/json, application/yaml, text/yaml, text/plain;q=0.9, */*;q=0.5",
    allow_private: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = MAX_MANIFEST_BYTES,
    payload_label: str = "manifest",
    resolver: Resolver | None = None,
) -> bytes:
    """Fetch *url* with the SSRF / size / redirect guards applied.

    Raises :class:`IngestError` on any of:

    * the URL fails :func:`defenseclaw.registries.ssrf.guard_url`;
    * a redirect points to a host that fails the SSRF guard (we
      validate every hop, not just the original URL);
    * the response body exceeds ``max_bytes``;
    * the underlying :mod:`requests` call raises.

    The optional ``resolver`` is plumbed through to :func:`guard_url`
    so tests can stub DNS without hitting the network. Production
    callers leave it None — the guard then falls back to
    :func:`socket.getaddrinfo`.
    """
    try:
        ip, host, port = resolve_and_pin(
            url, allow_private=allow_private, resolver=resolver
        )
    except SSRFError as exc:
        raise IngestError(str(exc)) from exc

    base_headers = {"User-Agent": USER_AGENT, "Accept": accept}
    auth = auth_header(auth_env)
    request_headers = dict(base_headers)
    if auth:
        request_headers["Authorization"] = auth

    pin = _PinnedConnect(host, port, ip)
    try:
        with pin, requests.get(
            url,
            headers=request_headers,
            timeout=timeout,
            stream=True,
            allow_redirects=False,
        ) as resp:
            # Manual redirect handling so we can validate every hop
            # against the SSRF policy. Cap at 5 hops to bound work.
            current_url = url
            hops = 0
            while resp.is_redirect and hops < 5:
                location = resp.headers.get("Location")
                if not location:
                    raise IngestError(
                        "redirect with empty Location header from "
                        f"{current_url}"
                    )
                if not location.lower().startswith(("http://", "https://")):
                    # Relative redirect — resolve against the previous URL.
                    location = urljoin(current_url, location)
                try:
                    next_ip, next_host, next_port = resolve_and_pin(
                        location,
                        allow_private=allow_private,
                        resolver=resolver,
                    )
                except SSRFError as exc:
                    raise IngestError(
                        f"redirect blocked by SSRF guard: {exc}"
                    ) from exc
                # Defence in depth: drop Authorization on cross-origin
                # redirects so a publisher (or compromised CDN edge)
                # that issues a 30x to an attacker-controlled host
                # can't harvest the operator's registry token. We
                # match browser/curl behaviour: same scheme + host +
                # port keeps the header, anything else strips it.
                next_headers = dict(base_headers)
                if auth and _same_origin(current_url, location):
                    next_headers["Authorization"] = auth
                resp.close()
                # Re-pin the next hop without releasing the lock so a
                # concurrent adapter can never sneak its own pin into
                # the window between hops. The Authorization header is
                # already correctly stripped above for cross-origin
                # hops via _same_origin().
                pin.repin(next_host, next_port, next_ip)
                resp = requests.get(  # noqa: PLW2901  - intentional reassign
                    location,
                    headers=next_headers,
                    timeout=timeout,
                    stream=True,
                    allow_redirects=False,
                )
                current_url = location
                hops += 1
            if resp.is_redirect:
                raise IngestError(
                    f"too many redirects ({hops}) starting from {url}"
                )
            resp.raise_for_status()

            # Content-Length is advisory but if the publisher claims
            # something larger than our cap, refuse before we read a
            # byte. Real bodies still get the streaming check below.
            cl = resp.headers.get("Content-Length")
            if cl:
                try:
                    if int(cl) > max_bytes:
                        raise IngestError(
                            f"{payload_label} is {cl} bytes (max {max_bytes})"
                        )
                except ValueError:
                    pass

            buf = bytearray()
            for chunk in resp.iter_content(chunk_size=65536):
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise IngestError(
                        f"{payload_label} exceeds {max_bytes} bytes"
                    )
            return bytes(buf)
    except requests.RequestException as exc:
        raise IngestError(f"fetch failed: {exc}") from exc


def _same_origin(a: str, b: str) -> bool:
    """Return True when *a* and *b* share scheme, host, and port.

    Used by :func:`http_get` to decide whether the ``Authorization``
    header survives a redirect. Any URL that fails to parse, lacks a
    scheme, or lacks a host is treated as a different origin (fail
    closed) so a malformed Location can't trick us into preserving
    credentials.
    """
    try:
        ap = urlparse(a)
        bp = urlparse(b)
    except (TypeError, ValueError):
        return False
    if not ap.scheme or not bp.scheme:
        return False
    if not ap.hostname or not bp.hostname:
        return False
    if ap.scheme.lower() != bp.scheme.lower():
        return False
    if ap.hostname.lower() != bp.hostname.lower():
        return False
    # urlparse normalises an absent port to None; treat None as the
    # scheme default so http://host -> http://host:80 still matches.
    default_a = 443 if ap.scheme.lower() == "https" else 80
    default_b = 443 if bp.scheme.lower() == "https" else 80
    return (ap.port or default_a) == (bp.port or default_b)


def auth_header(auth_env: str) -> str:
    """Build a Bearer auth header from the env var named *auth_env*.

    Returns an empty string when *auth_env* is empty or unset. The
    token is stripped of leading/trailing whitespace; ASCII control
    characters cause a refusal so a corrupted env value can't smuggle
    a header injection.
    """
    if not auth_env:
        return ""
    raw = os.environ.get(auth_env, "")
    if not raw:
        return ""
    token = raw.strip()
    if not token:
        return ""
    if _CTL_RE.search(token):
        raise IngestError(
            f"auth token from ${auth_env} contains control characters"
        )
    if token.lower().startswith(("bearer ", "token ")):
        return token
    return f"Bearer {token}"


def normalize_url(source: RegistrySource) -> str:
    """Return the source URL after stripping whitespace.

    Centralised so adapters never accidentally read a raw, untrimmed
    config field — copy-paste config edits frequently leave trailing
    newlines that break the SSRF guard's host extraction.
    """
    return (source.url or "").strip()


# ---------------------------------------------------------------------------
# DNS-rebind defense — pin urllib3's connect to a vetted IP literal
# ---------------------------------------------------------------------------
#
# guard_url() resolves the hostname once via getaddrinfo to validate
# that no IP in the answer set is in the loopback / private / reserved
# ranges. urllib3 then resolves the same hostname AGAIN when opening
# the TCP connection — a malicious low-TTL DNS answer can return a
# safe IP on the first lookup and an unsafe IP on the second, defeating
# the SSRF guard entirely.
#
# _PinnedConnect monkeypatches ``urllib3.util.connection.create_connection``
# inside a ``with`` block to return a connection to a fixed, pre-vetted
# IP whenever the requested host matches the original URL host. The
# Host: header and TLS SNI continue to carry the original hostname so
# virtual hosting / certificate validation still work. Outside the
# block the original create_connection is restored.
#
# This is intentionally per-call rather than process-wide so concurrent
# adapters (which never share threads inside a single fetch) don't
# clobber each other's pins. Each fetch holds the lock for the
# duration of its connect() and releases it as soon as the request is
# done.

import threading  # noqa: E402  (needed only for _PinnedConnect)

_PIN_LOCK = threading.Lock()


class _PinnedConnect:
    """Context manager that pins urllib3 connect() to a vetted IP.

    Replaces ``urllib3.util.connection.create_connection`` while the
    block is active. Lookups for the pinned host go to the pinned IP
    and port; lookups for any other host (which can happen if a
    library quietly side-channels another HTTP call during the
    request) raise ``SSRFError`` so a request to e.g. an OCSP
    responder doesn't escape the guard. The original function is
    always restored on exit, even on exception.
    """

    def __init__(self, host: str, port: int, ip: str) -> None:
        self._host = host.lower()
        self._port = int(port)
        self._ip = ip
        self._original = None

    def repin(self, host: str, port: int, ip: str) -> None:
        """Update the pinned target without releasing the lock.

        Used when following a redirect: the same fetch holds the
        connect-pin lock for the duration of every hop; only the
        target IP / host / port change. Calling ``repin`` outside an
        active ``with`` block is a programming error and is detected
        by the assertion below — a release-then-acquire sequence is
        intentionally avoided so a concurrent adapter can never sneak
        a different pin into the window between hops.
        """
        assert self._original is not None, (
            "_PinnedConnect.repin() called outside an active context"
        )
        self._host = host.lower()
        self._port = int(port)
        self._ip = ip

    def __enter__(self) -> _PinnedConnect:
        _PIN_LOCK.acquire()
        self._original = _urllib3_connection.create_connection

        def _pinned_create_connection(
            address, *args, **kwargs
        ):  # type: ignore[no-untyped-def]
            asked_host, asked_port = address
            if (
                asked_host
                and asked_host.lower() == self._host
                and int(asked_port) == self._port
            ):
                # Direct connect to the vetted IP. We pass the IP as
                # the host so getaddrinfo is not invoked a second
                # time. requests still sends Host: <hostname> and
                # uses <hostname> for TLS SNI because urllib3 carries
                # those independently of the connect address.
                return self._original((self._ip, asked_port), *args, **kwargs)
            # Any other destination during this fetch is suspicious —
            # an HTTP layer should not be making side requests. Refuse.
            raise SSRFError(
                f"unexpected outbound connect to {asked_host}:{asked_port} "
                f"during pinned fetch of {self._host}:{self._port}"
            )

        _urllib3_connection.create_connection = _pinned_create_connection
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if self._original is not None:
                _urllib3_connection.create_connection = self._original
                self._original = None
        finally:
            try:
                _PIN_LOCK.release()
            except RuntimeError:
                # Lock already released. Safe to ignore — the next
                # acquire will block correctly.
                pass


# Silence unused-import warnings: socket is referenced only via
# urllib3's connect path under our pin, but keeping it imported
# documents the dependency surface for future readers.
_ = socket
