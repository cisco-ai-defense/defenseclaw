# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts import release_api_retry

COMMIT = "a" * 40
TAG = "0.8.6"
REPOSITORY = "example/defenseclaw"


def _completed(status: int | None, *, body: str = "{}", stderr: str = "") -> subprocess.CompletedProcess[str]:
    if status is None:
        stdout = ""
        returncode = 1
    else:
        stdout = f"HTTP/2.0 {status} status\ncontent-type: application/json\n\n{body}"
        returncode = 0 if 200 <= status < 300 else 1
    return subprocess.CompletedProcess(
        args=["gh", "api"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _api(responses: list[subprocess.CompletedProcess[str]], sleeps: list[float]) -> release_api_retry.GitHubReleaseAPI:
    queue = list(responses)

    def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        assert queue, "unexpected GitHub API request"
        return queue.pop(0)

    return release_api_retry.GitHubReleaseAPI(
        repository=REPOSITORY,
        attempts=3,
        delay_seconds=0.25,
        runner=runner,
        sleep=sleeps.append,
    )


def test_absence_is_only_an_explicit_404_after_transient_retry() -> None:
    sleeps: list[float] = []
    api = _api(
        [
            _completed(503, stderr="gh: unavailable (HTTP 503)"),
            _completed(404, body='{"message":"Not Found"}', stderr="gh: Not Found (HTTP 404)"),
        ],
        sleeps,
    )

    assert api.release_by_tag(TAG) is None
    assert sleeps == [0.25]


def test_transient_exhaustion_is_never_reported_as_absence() -> None:
    sleeps: list[float] = []
    api = _api(
        [
            _completed(503, stderr="first"),
            _completed(None, stderr="transport reset"),
            _completed(503, stderr="last"),
        ],
        sleeps,
    )

    with pytest.raises(release_api_retry.ReleaseAPIError, match="after 3 attempt"):
        api.tag_ref(TAG)
    assert sleeps == [0.25, 0.5]


def test_api_timeout_is_retried_and_never_reported_as_absence() -> None:
    sleeps: list[float] = []
    calls = 0

    def runner(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        assert kwargs["timeout"] == release_api_retry.DEFAULT_API_TIMEOUT_SECONDS
        if calls == 1:
            raise subprocess.TimeoutExpired(cmd=["gh", "api"], timeout=20)
        return _completed(404, body='{"message":"Not Found"}', stderr="gh: Not Found (HTTP 404)")

    api = release_api_retry.GitHubReleaseAPI(
        repository=REPOSITORY,
        attempts=2,
        delay_seconds=0.25,
        runner=runner,
        sleep=sleeps.append,
    )

    assert api.release_by_tag(TAG) is None
    assert calls == 2
    assert sleeps == [0.25]


def test_api_timeout_exhaustion_fails_closed() -> None:
    def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=["gh", "api"], timeout=20)

    api = release_api_retry.GitHubReleaseAPI(
        repository=REPOSITORY,
        attempts=2,
        delay_seconds=0,
        runner=runner,
        sleep=lambda _delay: None,
    )

    with pytest.raises(release_api_retry.ReleaseAPIError, match="timed out"):
        api.tag_ref(TAG)


def test_permanent_api_failure_does_not_retry_or_look_absent() -> None:
    sleeps: list[float] = []
    api = _api([_completed(403, stderr="forbidden")], sleeps)

    with pytest.raises(release_api_retry.ReleaseAPIError, match="forbidden"):
        api.release_by_tag(TAG)
    assert sleeps == []


def test_annotated_tag_chain_resolves_to_commit() -> None:
    sleeps: list[float] = []
    api = _api(
        [
            _completed(
                200,
                body='{"object":{"type":"commit","sha":"' + COMMIT + '"}}',
            ),
        ],
        sleeps,
    )

    commit = api.resolve_tag_commit({"object": {"type": "tag", "sha": "b" * 40}})

    assert commit == COMMIT
    assert sleeps == []


def test_annotated_tag_chain_depth_is_bounded() -> None:
    sleeps: list[float] = []
    api = _api(
        [
            _completed(
                200,
                body='{"object":{"type":"tag","sha":"' + str(index) * 40 + '"}}',
            )
            for index in range(1, 6)
        ],
        sleeps,
    )

    with pytest.raises(release_api_retry.ReleaseAPIError, match="exceeds the depth bound"):
        api.resolve_tag_commit({"object": {"type": "tag", "sha": "b" * 40}})
    assert sleeps == []


def test_cli_reports_invalid_repository_without_traceback(capsys: pytest.CaptureFixture[str]) -> None:
    result = release_api_retry.main(
        [
            "require-absent",
            "--repository",
            "invalid",
            "--tag",
            TAG,
            "--commit",
            COMMIT,
        ]
    )

    assert result == 1
    assert "repository must be OWNER/REPO" in capsys.readouterr().err


def test_cli_reports_os_failure_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_api(**_kwargs: object) -> object:
        raise FileNotFoundError("gh executable is unavailable")

    monkeypatch.setattr(release_api_retry, "GitHubReleaseAPI", fail_api)

    result = release_api_retry.main(
        [
            "require-absent",
            "--repository",
            REPOSITORY,
            "--tag",
            TAG,
            "--commit",
            COMMIT,
        ]
    )

    assert result == 1
    assert "gh executable is unavailable" in capsys.readouterr().err


class _NamespaceAPI:
    def __init__(
        self,
        observations: list[tuple[dict[str, object] | None, dict[str, object] | None]],
        *,
        main: str = COMMIT,
        tag_commit: str = COMMIT,
    ) -> None:
        self.observations = list(observations)
        self.main = main
        self.tag_commit = tag_commit
        self._current: tuple[dict[str, object] | None, dict[str, object] | None] | None = None

    def main_commit(self) -> str:
        return self.main

    def tag_ref(self, _tag: str) -> dict[str, object] | None:
        assert self.observations
        self._current = self.observations.pop(0)
        return self._current[0]

    def release_by_tag(self, _tag: str) -> dict[str, object] | None:
        assert self._current is not None
        return self._current[1]

    def resolve_tag_commit(self, _payload: dict[str, object]) -> str:
        return self.tag_commit


def test_namespace_preflight_checks_main_and_both_namespaces() -> None:
    absent = _NamespaceAPI([(None, None)])
    release_api_retry.require_absent_namespace(
        absent,
        tag=TAG,
        expected_main_commit=COMMIT,
    )

    advanced = _NamespaceAPI([(None, None)], main="b" * 40)
    with pytest.raises(release_api_retry.ReleaseAPIError, match="main advanced"):
        release_api_retry.require_absent_namespace(
            advanced,
            tag=TAG,
            expected_main_commit=COMMIT,
        )

    occupied = _NamespaceAPI([({"object": {}}, None)])
    with pytest.raises(release_api_retry.ReleaseAPIError, match="occupied by tag"):
        release_api_retry.require_absent_namespace(occupied, tag=TAG)

    release_only = _NamespaceAPI([(None, {"tag_name": TAG})])
    with pytest.raises(release_api_retry.ReleaseAPIError, match="occupied by release"):
        release_api_retry.require_absent_namespace(release_only, tag=TAG)


def test_ambiguous_create_retries_only_after_bounded_proof_of_absence(tmp_path: Path) -> None:
    api = _NamespaceAPI([(None, None), (None, None), (None, None)])
    sleeps: list[float] = []

    state = release_api_retry.reconcile_create(
        api,  # type: ignore[arg-type]
        tag=TAG,
        expected_commit=COMMIT,
        candidate_root=tmp_path,
        omit_windows_binaries=True,
        attempts=3,
        delay_seconds=0.5,
        sleep=sleeps.append,
    )

    assert state is release_api_retry.ReconcileState.ABSENT
    assert sleeps == [0.5, 0.5]


def test_ambiguous_create_accepts_exact_remote_candidate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tag_payload = {"object": {"type": "commit", "sha": COMMIT}}
    release_payload = {"tag_name": TAG, "draft": False, "immutable": True, "assets": []}
    api = _NamespaceAPI([(tag_payload, release_payload)])
    verified: list[tuple[str, str]] = []

    def verify(**kwargs: object) -> None:
        verified.append((str(kwargs["tag"]), str(kwargs["expected_commit"])))

    monkeypatch.setattr(release_api_retry, "_verify_exact_candidate", verify)

    state = release_api_retry.reconcile_create(
        api,  # type: ignore[arg-type]
        tag=TAG,
        expected_commit=COMMIT,
        candidate_root=tmp_path,
        omit_windows_binaries=True,
        attempts=1,
    )

    assert state is release_api_retry.ReconcileState.EXACT
    assert verified == [(TAG, COMMIT)]


def test_nonimmutable_remote_candidate_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        release_api_retry.release_candidate,
        "verify",
        lambda *_args, **_kwargs: None,
    )
    api = _NamespaceAPI([], tag_commit=COMMIT)

    with pytest.raises(release_api_retry.ReleaseAPIError, match="not immutable"):
        release_api_retry._verify_exact_candidate(
            tag_payload={"object": {"type": "commit", "sha": COMMIT}},
            release_payload={"tag_name": TAG, "draft": False, "immutable": False, "assets": []},
            api=api,  # type: ignore[arg-type]
            tag=TAG,
            expected_commit=COMMIT,
            candidate_root=tmp_path,
            omit_windows_binaries=True,
        )


def test_partial_remote_namespace_fails_closed_without_becoming_absent(tmp_path: Path) -> None:
    api = _NamespaceAPI(
        [
            ({"object": {}}, None),
            (None, None),
        ]
    )

    with pytest.raises(release_api_retry.ReleaseAPIError, match="disappeared after being observed"):
        release_api_retry.reconcile_create(
            api,  # type: ignore[arg-type]
            tag=TAG,
            expected_commit=COMMIT,
            candidate_root=tmp_path,
            omit_windows_binaries=True,
            attempts=2,
            delay_seconds=0,
        )


def test_wrong_remote_tag_commit_fails_closed(tmp_path: Path) -> None:
    tag_payload = {"object": {"type": "commit", "sha": "b" * 40}}
    release_payload = {"tag_name": TAG, "draft": False, "immutable": True, "assets": []}
    api = _NamespaceAPI([(tag_payload, release_payload)], tag_commit="b" * 40)

    with pytest.raises(release_api_retry.ReleaseAPIError, match="points to"):
        release_api_retry.reconcile_create(
            api,  # type: ignore[arg-type]
            tag=TAG,
            expected_commit=COMMIT,
            candidate_root=tmp_path,
            omit_windows_binaries=True,
            attempts=1,
            delay_seconds=0,
        )


def test_rest_release_shape_is_normalized_for_sealed_candidate_verification() -> None:
    normalized = release_api_retry._candidate_release_json(
        {
            "tag_name": TAG,
            "draft": False,
            "immutable": True,
            "assets": [{"name": "checksums.txt", "digest": "sha256:" + "c" * 64}],
        }
    )

    assert normalized == {
        "tagName": TAG,
        "isDraft": False,
        "isImmutable": True,
        "assets": [{"name": "checksums.txt", "digest": "sha256:" + "c" * 64}],
    }


@pytest.mark.parametrize(
    ("command", "state", "expected_exit"),
    [
        ("reconcile-create", release_api_retry.ReconcileState.ABSENT, release_api_retry.ABSENT_EXIT_CODE),
        ("prove-published", release_api_retry.ReconcileState.EXACT, 0),
    ],
)
def test_cli_reconciliation_exit_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    command: str,
    state: release_api_retry.ReconcileState,
    expected_exit: int,
) -> None:
    monkeypatch.setattr(release_api_retry, "GitHubReleaseAPI", lambda **_kwargs: object())
    monkeypatch.setattr(release_api_retry, "reconcile_create", lambda *_args, **_kwargs: state)

    result = release_api_retry.main(
        [
            command,
            "--repository",
            REPOSITORY,
            "--tag",
            TAG,
            "--commit",
            COMMIT,
            "--candidate-root",
            str(tmp_path),
        ]
    )

    assert result == expected_exit


def test_cli_publish_precheck_accepts_existing_exact_candidate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tag_payload = {"object": {"type": "commit", "sha": COMMIT}}
    release_payload = {"tag_name": TAG, "draft": False, "immutable": True, "assets": []}
    api = _NamespaceAPI([(tag_payload, release_payload)], main=COMMIT)
    monkeypatch.setattr(release_api_retry, "GitHubReleaseAPI", lambda **_kwargs: api)
    monkeypatch.setattr(release_api_retry, "_verify_exact_candidate", lambda **_kwargs: None)

    result = release_api_retry.main(
        [
            "reconcile-create",
            "--repository",
            REPOSITORY,
            "--tag",
            TAG,
            "--commit",
            COMMIT,
            "--candidate-root",
            str(tmp_path),
            "--check-main",
        ]
    )

    assert result == 0


def test_cli_publish_precheck_rechecks_main_after_absence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class ChangingMainAPI:
        def __init__(self) -> None:
            self.commits = iter((COMMIT, "b" * 40))

        def main_commit(self) -> str:
            return next(self.commits)

    api = ChangingMainAPI()
    monkeypatch.setattr(release_api_retry, "GitHubReleaseAPI", lambda **_kwargs: api)
    monkeypatch.setattr(
        release_api_retry,
        "reconcile_create",
        lambda *_args, **_kwargs: release_api_retry.ReconcileState.ABSENT,
    )

    result = release_api_retry.main(
        [
            "reconcile-create",
            "--repository",
            REPOSITORY,
            "--tag",
            TAG,
            "--commit",
            COMMIT,
            "--candidate-root",
            str(tmp_path),
            "--check-main",
        ]
    )

    assert result == 1
    assert "main advanced during certification" in capsys.readouterr().err


def test_cli_candidate_commands_require_candidate_root(capsys: pytest.CaptureFixture[str]) -> None:
    result = release_api_retry.main(
        [
            "prove-published",
            "--repository",
            REPOSITORY,
            "--tag",
            TAG,
            "--commit",
            COMMIT,
        ]
    )

    assert result == 1
    assert "requires --candidate-root" in capsys.readouterr().err
