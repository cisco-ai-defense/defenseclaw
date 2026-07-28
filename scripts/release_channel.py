#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
"""Create, validate, or compare the canonical signed stable channel."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

# Release publication invokes this file directly from a clean checkout. Put the
# shipped CLI source tree on the import path explicitly instead of depending on
# an editable install or an ambient PYTHONPATH.
_CLI_ROOT = Path(__file__).resolve().parents[1] / "cli"
if str(_CLI_ROOT) not in sys.path:
    sys.path.insert(0, str(_CLI_ROOT))

from defenseclaw.release_channel import (  # noqa: E402 - direct-checkout bootstrap above.
    CHANNEL,
    CHECKSUM_RE,
    COMMIT_RE,
    FIELD_ORDER,
    MAX_CHANNEL_BYTES,
    MAX_CHECKSUMS_BYTES,
    POSIX_INSTALLER_NAME,
    REPOSITORY_RE,
    RESOLVER_NAME,
    SCHEMA,
    SHA256_RE,
    VERSION_RE,
    WINDOWS_INSTALLER_NAME,
    ChannelError,
    build_channel,
    channel_asset_digests_from_checksums,
    compare_channels,
    load_channel,
    parse_channel,
    release_asset_url,
    render_channel,
    render_channel_without_validation,
    resolver_digest_from_checksums,
    resolver_url,
    validate_channel,
    version_key,
)

__all__ = [
    "CHANNEL",
    "CHECKSUM_RE",
    "COMMIT_RE",
    "FIELD_ORDER",
    "MAX_CHANNEL_BYTES",
    "MAX_CHECKSUMS_BYTES",
    "POSIX_INSTALLER_NAME",
    "REPOSITORY_RE",
    "RESOLVER_NAME",
    "SCHEMA",
    "SHA256_RE",
    "VERSION_RE",
    "WINDOWS_INSTALLER_NAME",
    "ChannelError",
    "build_channel",
    "channel_asset_digests_from_checksums",
    "compare_channels",
    "load_channel",
    "parse_channel",
    "release_asset_url",
    "render_channel",
    "render_channel_without_validation",
    "resolver_digest_from_checksums",
    "resolver_url",
    "validate_channel",
    "version_key",
]


def _write_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ChannelError(f"writing release channel stalled: {path}")
            view = view[written:]
        os.fsync(descriptor)
        try:
            os.close(descriptor)
        finally:
            # A failed close must not be retried: POSIX leaves the descriptor's
            # state unspecified after close(2) reports an error.
            descriptor = None
    except (ChannelError, OSError) as exc:
        cleanup_errors: list[str] = []
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as cleanup_exc:
                cleanup_errors.append(f"close failed: {cleanup_exc}")
        if created:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as cleanup_exc:
                cleanup_errors.append(f"unlink failed: {cleanup_exc}")
        if isinstance(exc, ChannelError) and not cleanup_errors:
            raise
        cleanup = f" ({'; '.join(cleanup_errors)})" if cleanup_errors else ""
        raise ChannelError(f"could not create release channel {path}: {exc}{cleanup}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--repository", required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--commit", required=True)
    create.add_argument("--checksums", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--repository")
    validate.add_argument("--version")
    validate.add_argument("channel", type=Path)

    compare = subparsers.add_parser("compare")
    compare.add_argument("--current", type=Path, required=True)
    compare.add_argument("--candidate", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "create":
            digests = channel_asset_digests_from_checksums(args.checksums)
            channel = build_channel(
                repository=args.repository,
                version=args.version,
                commit=args.commit,
                resolver_sha256=digests[RESOLVER_NAME],
                posix_installer_sha256=digests[POSIX_INSTALLER_NAME],
                windows_installer_sha256=digests[WINDOWS_INSTALLER_NAME],
            )
            _write_new(args.output, render_channel(channel))
            print(f"stable channel candidate created: {args.version}")
        elif args.command == "validate":
            validate_channel(
                load_channel(args.channel),
                expected_repository=args.repository,
                expected_version=args.version,
            )
            print("stable channel document valid")
        elif args.command == "compare":
            print(compare_channels(load_channel(args.current), load_channel(args.candidate)))
        else:  # pragma: no cover
            raise AssertionError(args.command)
    except ChannelError as exc:
        print(f"release channel error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
