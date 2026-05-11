# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Git-clone manifest adapter — kind=git.

Performs a shallow ``git clone --depth 1`` of *source.url* into a
tempdir, then reads ``defenseclaw-registry.yaml`` (or
``defenseclaw-registry.json``) from the repo root.

Refuses anything that isn't an HTTP(S) URL — see
:func:`defenseclaw.registries.ssrf.guard_git_url`. SSH-based git is
intentionally out of scope: it requires private key material and
host-key trust decisions that don't belong in an automated ingest
pipeline.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from pathlib import Path

from defenseclaw.config import RegistrySource
from defenseclaw.registries.adapters._base import (
    MAX_MANIFEST_BYTES,
    IngestError,
    normalize_url,
)
from defenseclaw.registries.manifest import Manifest, parse_manifest
from defenseclaw.registries.ssrf import Resolver, SSRFError, guard_git_url

CLONE_TIMEOUT = 60.0
MANIFEST_NAMES = (
    "defenseclaw-registry.yaml",
    "defenseclaw-registry.yml",
    "defenseclaw-registry.json",
)


def fetch_git(
    source: RegistrySource,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> tuple[Manifest, bytes]:
    url = normalize_url(source)
    if not url:
        raise IngestError(f"source {source.id!r} has no URL")
    try:
        guard_git_url(url, allow_private=allow_private, resolver=resolver)
    except SSRFError as exc:
        raise IngestError(str(exc)) from exc

    # Token-in-URL injection is a real footgun (e.g. ``https://x:tok@host``)
    # — refuse so operators always go through the auth_env path. The guard
    # also blocks shell metacharacters that could escape into the subprocess
    # call below in case `git` ever forwards them to a helper.
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        raise IngestError(
            "git URL must not embed credentials; use --auth-env to pass a token"
        )
    if any(c in url for c in (" ", "`", "$")):
        raise IngestError("git URL contains disallowed shell metacharacters")

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if source.auth_env:
        token = os.environ.get(source.auth_env, "")
        if token:
            env["GIT_ASKPASS"] = "echo"
            env["GIT_HTTP_EXTRAHEADER"] = f"Authorization: Bearer {token}"

    with tempfile.TemporaryDirectory(prefix="dc-reg-git-") as tmp:
        cmd = [
            "git", "clone",
            "--depth", "1",
            "--no-tags",
            "--single-branch",
            "--",
            url,
            tmp,
        ]
        try:
            result = subprocess.run(  # noqa: S603 - argv list, no shell
                cmd,
                capture_output=True,
                text=True,
                timeout=CLONE_TIMEOUT,
                env=env,
                check=False,
            )
        except FileNotFoundError as exc:
            raise IngestError(
                "git binary not found; install git or use kind=http_yaml"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise IngestError(
                f"git clone timed out after {CLONE_TIMEOUT}s for "
                f"{shlex.quote(url)}"
            ) from exc
        if result.returncode != 0:
            raise IngestError(
                f"git clone failed (exit {result.returncode}): "
                f"{result.stderr.strip()[:240]}"
            )

        for name in MANIFEST_NAMES:
            candidate = Path(tmp) / name
            if candidate.is_file():
                size = candidate.stat().st_size
                if size > MAX_MANIFEST_BYTES:
                    raise IngestError(
                        f"manifest {name} is {size} bytes (max {MAX_MANIFEST_BYTES})"
                    )
                raw = candidate.read_bytes()
                manifest = parse_manifest(raw)
                return manifest, raw

        raise IngestError(
            f"no defenseclaw-registry manifest at repo root "
            f"(looked for {', '.join(MANIFEST_NAMES)})"
        )
