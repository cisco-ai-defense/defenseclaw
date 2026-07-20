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

"""Fail-closed GitHub release namespace probes and create reconciliation.

GitHub can return a transient error after accepting a mutating request.  A
release publisher must therefore never retry ``gh release create`` merely
because the client returned non-zero.  This helper distinguishes an HTTP 404
from transport/server failures and reconciles an ambiguous create against the
exact sealed candidate before deciding whether another create is safe.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.parse import quote

try:
    from scripts import release_candidate
except ModuleNotFoundError:  # Direct ``python scripts/release_api_retry.py`` execution.
    import release_candidate  # type: ignore[no-redef]

TRANSIENT_HTTP_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
DEFAULT_API_ATTEMPTS = 4
DEFAULT_API_DELAY_SECONDS = 2.0
DEFAULT_API_TIMEOUT_SECONDS = 20.0
# Preserve the former publication-custody convergence window: immutable
# release asset digests can take several observations to become available.
# The same window also makes an absence result strong enough to authorize a
# second create after an ambiguous client failure.
DEFAULT_RECONCILE_ATTEMPTS = 6
DEFAULT_RECONCILE_DELAY_SECONDS = 5.0
ABSENT_EXIT_CODE = 10
_HTTP_STATUS_RE = re.compile(r"^HTTP/\S+\s+(\d{3})(?:\s|$)")


class ReleaseAPIError(RuntimeError):
    """GitHub state could not be established safely."""


class ReconcileState(str, Enum):
    EXACT = "exact"
    ABSENT = "absent"


@dataclass(frozen=True)
class APIResponse:
    status: int | None
    body: str
    stderr: str
    returncode: int


Runner = Callable[..., subprocess.CompletedProcess[str]]
Sleeper = Callable[[float], None]


def _bounded_detail(value: str, *, limit: int = 500) -> str:
    detail = " ".join(value.strip().split())
    if len(detail) <= limit:
        return detail
    return f"{detail[:limit]}..."


def _parse_included_response(
    completed: subprocess.CompletedProcess[str],
) -> APIResponse:
    normalized = completed.stdout.replace("\r\n", "\n")
    first_line, _, remainder = normalized.partition("\n")
    match = _HTTP_STATUS_RE.match(first_line)
    status = int(match.group(1)) if match else None
    _, separator, body = remainder.partition("\n\n")
    if not separator:
        body = ""
    return APIResponse(
        status=status,
        body=body,
        stderr=completed.stderr,
        returncode=completed.returncode,
    )


class GitHubReleaseAPI:
    def __init__(
        self,
        *,
        repository: str,
        attempts: int = DEFAULT_API_ATTEMPTS,
        delay_seconds: float = DEFAULT_API_DELAY_SECONDS,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        runner: Runner = subprocess.run,
        sleep: Sleeper = time.sleep,
    ) -> None:
        if not repository or "/" not in repository:
            raise ValueError("repository must be OWNER/REPO")
        if attempts < 1:
            raise ValueError("attempts must be positive")
        if delay_seconds < 0:
            raise ValueError("delay_seconds cannot be negative")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.repository = repository
        self.attempts = attempts
        self.delay_seconds = delay_seconds
        self.timeout_seconds = timeout_seconds
        self._runner = runner
        self._sleep = sleep

    def _request(self, endpoint: str) -> APIResponse:
        try:
            completed = self._runner(
                [
                    "gh",
                    "api",
                    "--include",
                    "-H",
                    "Accept: application/vnd.github+json",
                    endpoint,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return APIResponse(
                status=None,
                body="",
                stderr="GitHub API request timed out",
                returncode=124,
            )
        return _parse_included_response(completed)

    def get_json(self, endpoint: str, *, absent_ok: bool) -> dict[str, object] | None:
        last: APIResponse | None = None
        for attempt in range(1, self.attempts + 1):
            response = self._request(endpoint)
            last = response
            if response.returncode == 0 and response.status is not None and 200 <= response.status < 300:
                try:
                    value = json.loads(response.body)
                except json.JSONDecodeError as exc:
                    raise ReleaseAPIError(f"GitHub returned invalid JSON for {endpoint}: {exc}") from exc
                if not isinstance(value, dict):
                    raise ReleaseAPIError(f"GitHub returned a non-object response for {endpoint}")
                return value
            if response.status == 404 and absent_ok:
                return None

            transient = response.status in TRANSIENT_HTTP_STATUSES or response.status is None
            if transient and attempt < self.attempts:
                self._sleep(self.delay_seconds * attempt)
                continue
            break

        if last is None:
            raise ReleaseAPIError(f"no GitHub API attempt was made for {endpoint}")
        if last.status == 404:
            detail = "required namespace does not exist"
        elif last.status is None:
            detail = _bounded_detail(last.stderr) or "transport failure without an HTTP status"
        else:
            detail = _bounded_detail(last.stderr) or f"HTTP {last.status}"
        raise ReleaseAPIError(
            f"could not establish GitHub state for {endpoint} after {self.attempts} attempt(s): {detail}"
        )

    def _endpoint(self, suffix: str) -> str:
        return f"repos/{self.repository}/{suffix}"

    def main_commit(self) -> str:
        payload = self.get_json(self._endpoint("git/ref/heads/main"), absent_ok=False)
        if payload is None:
            raise ReleaseAPIError("GitHub main ref unexpectedly does not exist")
        object_value = payload.get("object")
        if not isinstance(object_value, dict) or not isinstance(object_value.get("sha"), str):
            raise ReleaseAPIError("GitHub main ref response lacks object.sha")
        return object_value["sha"]

    def tag_ref(self, tag: str) -> dict[str, object] | None:
        encoded = quote(tag, safe="")
        return self.get_json(self._endpoint(f"git/ref/tags/{encoded}"), absent_ok=True)

    def release_by_tag(self, tag: str) -> dict[str, object] | None:
        encoded = quote(tag, safe="")
        return self.get_json(self._endpoint(f"releases/tags/{encoded}"), absent_ok=True)

    def resolve_tag_commit(self, payload: dict[str, object]) -> str:
        current = payload
        for _ in range(5):
            object_value = current.get("object")
            if not isinstance(object_value, dict):
                raise ReleaseAPIError("GitHub tag response lacks object metadata")
            object_type = object_value.get("type")
            object_sha = object_value.get("sha")
            if not isinstance(object_sha, str):
                raise ReleaseAPIError("GitHub tag response lacks object.sha")
            if object_type == "commit":
                return object_sha
            if object_type != "tag":
                raise ReleaseAPIError(f"GitHub tag points to unsupported object type {object_type!r}")
            next_value = self.get_json(
                self._endpoint(f"git/tags/{quote(object_sha, safe='')}"),
                absent_ok=False,
            )
            if next_value is None:
                raise ReleaseAPIError(f"GitHub annotated tag object {object_sha} unexpectedly does not exist")
            current = next_value
        raise ReleaseAPIError("GitHub annotated tag chain exceeds the depth bound")


def require_absent_namespace(
    api: GitHubReleaseAPI,
    *,
    tag: str,
    expected_main_commit: str | None = None,
) -> None:
    if expected_main_commit is not None:
        require_main_commit(api, expected_main_commit)
    tag_payload = api.tag_ref(tag)
    release_payload = api.release_by_tag(tag)
    if tag_payload is not None or release_payload is not None:
        occupied = []
        if tag_payload is not None:
            occupied.append("tag")
        if release_payload is not None:
            occupied.append("release")
        raise ReleaseAPIError(f"remote release namespace {tag!r} is occupied by {', '.join(occupied)}")


def require_main_commit(api: GitHubReleaseAPI, expected_commit: str) -> None:
    remote_main = api.main_commit()
    if remote_main != expected_commit:
        raise ReleaseAPIError(
            f"main advanced during certification: expected {expected_commit}, found {remote_main}"
        )


def _candidate_release_json(payload: dict[str, object]) -> dict[str, object]:
    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise ReleaseAPIError("GitHub release response lacks an assets list")
    return {
        "tagName": payload.get("tag_name"),
        "isDraft": payload.get("draft"),
        "isImmutable": payload.get("immutable"),
        "assets": [
            {"name": item.get("name"), "digest": item.get("digest")} if isinstance(item, dict) else item
            for item in assets
        ],
    }


def _verify_exact_candidate(
    *,
    tag_payload: dict[str, object],
    release_payload: dict[str, object],
    api: GitHubReleaseAPI,
    tag: str,
    expected_commit: str,
    candidate_root: Path,
    omit_windows_binaries: bool,
) -> None:
    remote_commit = api.resolve_tag_commit(tag_payload)
    if remote_commit != expected_commit:
        raise ReleaseAPIError(f"remote tag {tag!r} points to {remote_commit}, expected {expected_commit}")
    normalized = _candidate_release_json(release_payload)
    # Use a directory-backed path rather than reopening a named temporary file
    # while it is still held open.  The latter is not portable to Windows.
    with tempfile.TemporaryDirectory(prefix="defenseclaw-release-") as directory:
        release_json = Path(directory) / "published-release.json"
        release_json.write_text(json.dumps(normalized, sort_keys=True), encoding="utf-8")
        try:
            release_candidate.verify_published_release(
                candidate_root,
                release_json,
                tag,
                expected_commit,
                omit_windows_binaries=omit_windows_binaries,
            )
        except release_candidate.CandidateError as exc:
            raise ReleaseAPIError(str(exc)) from exc


def reconcile_create(
    api: GitHubReleaseAPI,
    *,
    tag: str,
    expected_commit: str,
    candidate_root: Path,
    omit_windows_binaries: bool,
    attempts: int = DEFAULT_RECONCILE_ATTEMPTS,
    delay_seconds: float = DEFAULT_RECONCILE_DELAY_SECONDS,
    sleep: Sleeper = time.sleep,
) -> ReconcileState:
    if attempts < 1:
        raise ValueError("attempts must be positive")
    if delay_seconds < 0:
        raise ValueError("delay_seconds cannot be negative")

    observed_remote = False
    last_mismatch = ""
    for attempt in range(1, attempts + 1):
        tag_payload = api.tag_ref(tag)
        release_payload = api.release_by_tag(tag)
        if tag_payload is None and release_payload is None:
            if attempt < attempts:
                sleep(delay_seconds)
                continue
            if not observed_remote:
                return ReconcileState.ABSENT
            last_mismatch = "remote namespace disappeared after being observed"
            break

        observed_remote = True
        if tag_payload is None or release_payload is None:
            last_mismatch = "remote tag/release namespace is only partially populated"
        else:
            try:
                _verify_exact_candidate(
                    tag_payload=tag_payload,
                    release_payload=release_payload,
                    api=api,
                    tag=tag,
                    expected_commit=expected_commit,
                    candidate_root=candidate_root,
                    omit_windows_binaries=omit_windows_binaries,
                )
            except ReleaseAPIError as exc:
                last_mismatch = str(exc)
            else:
                return ReconcileState.EXACT
        if attempt < attempts:
            sleep(delay_seconds)

    raise ReleaseAPIError(
        f"remote release namespace {tag!r} is not the exact sealed candidate: "
        f"{last_mismatch or 'unknown custody mismatch'}"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("require-absent", "reconcile-create", "prove-published"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--candidate-root", type=Path)
    parser.add_argument("--omit-windows-binaries", action="store_true")
    parser.add_argument("--check-main", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        api = GitHubReleaseAPI(repository=args.repository)
        if args.command == "require-absent":
            require_absent_namespace(
                api,
                tag=args.tag,
                expected_main_commit=args.commit if args.check_main else None,
            )
            print(f"remote release namespace is absent: {args.tag}")
            return 0
        if args.candidate_root is None:
            raise ReleaseAPIError(f"{args.command} requires --candidate-root")
        if args.check_main:
            require_main_commit(api, args.commit)
        state = reconcile_create(
            api,
            tag=args.tag,
            expected_commit=args.commit,
            candidate_root=args.candidate_root,
            omit_windows_binaries=args.omit_windows_binaries,
        )
        # Absence permits the next step to mutate the release namespace.  The
        # reconciliation window is deliberately long enough for GitHub's
        # eventual consistency, so recheck main at the mutation boundary.
        if state is ReconcileState.ABSENT and args.check_main:
            require_main_commit(api, args.commit)
        if state is ReconcileState.EXACT:
            print(f"exact immutable release custody verified: {args.tag}")
            return 0
        if args.command == "reconcile-create":
            print(f"remote release namespace remained absent: {args.tag}", file=sys.stderr)
            return ABSENT_EXIT_CODE
        raise ReleaseAPIError(f"published release {args.tag!r} is absent")
    except (OSError, ReleaseAPIError, ValueError) as exc:
        print(f"release API verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
