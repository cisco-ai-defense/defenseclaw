# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Track credentials DefenseClaw copied from dotenv into ``os.environ``.

The registry intentionally stores only process-keyed digests.  It can identify
values inserted by the config loader without retaining another plaintext copy
of a credential or exposing that information outside this process.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class _Marker:
    value_digest: bytes
    dotenv_digest: bytes


_digest_key = secrets.token_bytes(32)
_lock = threading.RLock()
_markers: dict[tuple[str, str], _Marker] = {}
_active_data_dir: str | None = None
_active_dotenv_digest: bytes | None = None


def _normalize_data_dir(data_dir: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(os.path.expanduser(data_dir))))


def _digest(value: bytes) -> bytes:
    return hmac.new(_digest_key, value, hashlib.sha256).digest()


def _digest_value(value: str) -> bytes:
    return _digest(value.encode("utf-8", errors="surrogatepass"))


def _digest_file(path: str) -> bytes | None:
    try:
        digest = hmac.new(_digest_key, digestmod=hashlib.sha256)
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(64 * 1024), b""):
                digest.update(chunk)
        return digest.digest()
    except OSError:
        return None


def begin_dotenv_load(data_dir: str, dotenv_path: str) -> None:
    """Start a config load and discard provenance that can no longer apply."""
    global _active_data_dir, _active_dotenv_digest

    normalized = _normalize_data_dir(data_dir)
    dotenv_digest = _digest_file(dotenv_path)
    with _lock:
        if normalized != _active_data_dir:
            _markers.clear()
        _active_data_dir = normalized
        _active_dotenv_digest = dotenv_digest
        for marker_key, marker in list(_markers.items()):
            if marker_key[0] == normalized and marker.dotenv_digest != dotenv_digest:
                del _markers[marker_key]


def note_dotenv_candidate(data_dir: str, env_name: str, value: str, *, injected: bool) -> None:
    """Record a newly injected value, or validate an earlier injection marker."""
    normalized = _normalize_data_dir(data_dir)
    marker_key = (normalized, env_name)
    value_digest = _digest_value(value)
    with _lock:
        if normalized != _active_data_dir or _active_dotenv_digest is None:
            _markers.pop(marker_key, None)
            return
        candidate = _Marker(value_digest, _active_dotenv_digest)
        if injected:
            _markers[marker_key] = candidate
        elif _markers.get(marker_key) != candidate:
            _markers.pop(marker_key, None)


def was_injected_from_dotenv(data_dir: str, env_name: str, value: str) -> bool:
    """Return whether the current value is still the dotenv value we injected."""
    normalized = _normalize_data_dir(data_dir)
    marker_key = (normalized, env_name)
    with _lock:
        marker = _markers.get(marker_key)
        if normalized != _active_data_dir or marker is None:
            return False
        current_dotenv_digest = _digest_file(os.path.join(normalized, ".env"))
        if marker.value_digest != _digest_value(value) or marker.dotenv_digest != current_dotenv_digest:
            _markers.pop(marker_key, None)
            return False
        return True


def _reset_for_tests() -> None:
    """Clear process-local markers between isolated unit-test scenarios."""
    global _active_data_dir, _active_dotenv_digest

    with _lock:
        _markers.clear()
        _active_data_dir = None
        _active_dotenv_digest = None
