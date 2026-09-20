#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Verify one Sigstore blob with a small fail-closed transport retry budget."""

from __future__ import annotations

import argparse
import math
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from typing import BinaryIO

_MAX_ATTEMPTS = 3
_INITIAL_RETRY_DELAY_SECONDS = 2.0
_ATTEMPT_TIMEOUT_SECONDS = 120.0
_MAX_ATTEMPT_TIMEOUT_SECONDS = 300.0
_TIMEOUT_EXIT_CODE = 124
_TRANSIENT_TRANSPORT_MARKERS = (
    b"tls handshake timeout",
    b"i/o timeout",
    b"context deadline exceeded",
    b"connection reset by peer",
    b"connection refused",
    b"temporary failure in name resolution",
    b"no such host",
    b"unexpected eof",
    b"server misbehaving",
    b"service unavailable",
    b"bad gateway",
    b"gateway timeout",
    b"too many requests",
)


def _is_transient_transport_failure(stdout: bytes, stderr: bytes) -> bool:
    output = stdout.lower() + b"\n" + stderr.lower()
    return any(marker in output for marker in _TRANSIENT_TRANSPORT_MARKERS)


def _write_bytes(stream: BinaryIO, payload: bytes) -> None:
    if payload:
        stream.write(payload)
        stream.flush()


def _as_bytes(payload: bytes | str | None) -> bytes:
    if payload is None:
        return b""
    if isinstance(payload, bytes):
        return payload
    return payload.encode("utf-8", errors="replace")


def verify_with_retry(
    command: Sequence[str],
    *,
    max_attempts: int = _MAX_ATTEMPTS,
    initial_retry_delay_seconds: float = _INITIAL_RETRY_DELAY_SECONDS,
    attempt_timeout_seconds: float = _ATTEMPT_TIMEOUT_SECONDS,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    sleeper: Callable[[float], None] = time.sleep,
    stdout: BinaryIO | None = None,
    stderr: BinaryIO | None = None,
) -> int:
    """Run an exact cosign argv, retrying only recognized transport failures."""

    if max_attempts < 1 or max_attempts > _MAX_ATTEMPTS:
        raise ValueError(f"max_attempts must be between 1 and {_MAX_ATTEMPTS}")
    if initial_retry_delay_seconds < 0:
        raise ValueError("initial_retry_delay_seconds must be non-negative")
    if (
        not math.isfinite(attempt_timeout_seconds)
        or attempt_timeout_seconds <= 0
        or attempt_timeout_seconds > _MAX_ATTEMPT_TIMEOUT_SECONDS
    ):
        raise ValueError(
            "attempt_timeout_seconds must be positive and no greater than "
            f"{_MAX_ATTEMPT_TIMEOUT_SECONDS:g}",
        )
    stdout = stdout or sys.stdout.buffer
    stderr = stderr or sys.stderr.buffer
    exact_command = list(command)

    for attempt in range(1, max_attempts + 1):
        try:
            completed = runner(
                exact_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=attempt_timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            _write_bytes(stdout, _as_bytes(exc.stdout))
            _write_bytes(stderr, _as_bytes(exc.stderr))
            _write_bytes(
                stderr,
                (
                    "Sigstore verification timed out after "
                    f"{attempt_timeout_seconds:g}s "
                    f"(attempt {attempt}/{max_attempts}); mandatory verification "
                    "did not complete\n"
                ).encode(),
            )
            if attempt == max_attempts:
                return _TIMEOUT_EXIT_CODE
            delay = initial_retry_delay_seconds * (2 ** (attempt - 1))
            _write_bytes(
                stderr,
                (
                    "retrying mandatory verification "
                    f"({attempt + 1}/{max_attempts}) in {delay:g}s\n"
                ).encode(),
            )
            sleeper(delay)
            continue
        except OSError as exc:
            _write_bytes(stderr, f"could not execute cosign: {exc}\n".encode())
            return 127

        _write_bytes(stdout, completed.stdout)
        _write_bytes(stderr, completed.stderr)
        if completed.returncode == 0:
            return 0
        if attempt == max_attempts or not _is_transient_transport_failure(
            completed.stdout, completed.stderr
        ):
            return completed.returncode

        delay = initial_retry_delay_seconds * (2 ** (attempt - 1))
        _write_bytes(
            stderr,
            (
                "transient Sigstore transport failure; "
                f"retrying mandatory verification ({attempt + 1}/{max_attempts}) "
                f"in {delay:g}s\n"
            ).encode(),
        )
        sleeper(delay)

    raise AssertionError("bounded verification loop exhausted without returning")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--signature", required=True)
    parser.add_argument("--certificate-identity", required=True)
    parser.add_argument("--certificate-oidc-issuer", required=True)
    parser.add_argument("blob")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    command = [
        args.cosign,
        "verify-blob",
        "--certificate",
        args.certificate,
        "--signature",
        args.signature,
        "--certificate-identity",
        args.certificate_identity,
        "--certificate-oidc-issuer",
        args.certificate_oidc_issuer,
        args.blob,
    ]
    return verify_with_retry(command)


if __name__ == "__main__":
    raise SystemExit(main())
