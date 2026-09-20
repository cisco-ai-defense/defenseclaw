# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
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


def _comparison_payload(
    status: object,
    *,
    base_commit: object = COMMIT,
    merge_base_commit: object = COMMIT,
) -> str:
    return json.dumps(
        {
            "status": status,
            "base_commit": {"sha": base_commit},
            "merge_base_commit": {"sha": merge_base_commit},
        }
    )


def test_tag_absence_is_only_an_explicit_404_after_transient_retry() -> None:
    sleeps: list[float] = []
    api = _api(
        [
            _completed(503, stderr="gh: unavailable (HTTP 503)"),
            _completed(404, body='{"message":"Not Found"}', stderr="gh: Not Found (HTTP 404)"),
        ],
        sleeps,
    )

    assert api.tag_ref(TAG) is None
    assert sleeps == [0.25]


def test_release_absence_requires_successful_authenticated_listing() -> None:
    sleeps: list[float] = []
    api = _api([_completed(200, body="[]")], sleeps)

    assert api.release_by_tag(TAG) is None
    assert sleeps == []


def test_release_listing_includes_draft_with_no_tag_ref() -> None:
    sleeps: list[float] = []
    draft = {"tag_name": TAG, "draft": True, "immutable": False, "assets": []}
    api = _api([_completed(200, body=json.dumps([draft]))], sleeps)

    assert api.release_by_tag(TAG) == draft
    assert sleeps == []


def test_release_listing_paginates_before_declaring_absence() -> None:
    sleeps: list[float] = []
    first_page = [{"tag_name": f"old-{index}"} for index in range(100)]
    target = {"tag_name": TAG, "draft": True, "immutable": False, "assets": []}
    api = _api(
        [
            _completed(200, body=json.dumps(first_page)),
            _completed(200, body=json.dumps([target])),
        ],
        sleeps,
    )

    assert api.release_by_tag(TAG) == target
    assert sleeps == []


def test_release_rows_deduplicates_identical_pagination_overlap() -> None:
    sleeps: list[float] = []
    first_page = [
        {
            "id": index + 1,
            "tag_name": f"0.7.{index}",
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "assets": [],
        }
        for index in range(100)
    ]
    overlap = first_page[-1]
    newest = {
        "id": 101,
        "tag_name": TAG,
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "assets": [],
    }
    api = _api(
        [
            _completed(200, body=json.dumps(first_page)),
            _completed(200, body=json.dumps([overlap, newest])),
        ],
        sleeps,
    )

    rows = api.release_rows()

    assert len(rows) == 101
    assert rows.count(overlap) == 1
    assert rows[-1] == newest
    assert sleeps == []


def test_release_rows_rejects_conflicting_pagination_overlap() -> None:
    sleeps: list[float] = []
    first_page = [
        {
            "id": index + 1,
            "tag_name": f"0.7.{index}",
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "assets": [],
        }
        for index in range(100)
    ]
    changed = dict(first_page[-1], draft=True)
    api = _api(
        [
            _completed(200, body=json.dumps(first_page)),
            _completed(200, body=json.dumps([changed])),
        ],
        sleeps,
    )

    with pytest.raises(
        release_api_retry.ReleaseAPIError,
        match="changed while paginating",
    ):
        api.release_rows()


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

    assert api.tag_ref(TAG) is None
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


@pytest.mark.parametrize("status", ["identical", "ahead"])
def test_release_commit_on_main_accepts_exact_tip_or_advanced_main(status: str) -> None:
    requested: list[list[str]] = []

    def runner(*args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        requested.append(list(args[0]))  # type: ignore[arg-type]
        return _completed(200, body=_comparison_payload(status))

    api = release_api_retry.GitHubReleaseAPI(
        repository=REPOSITORY,
        attempts=1,
        runner=runner,
    )

    release_api_retry.require_commit_on_main(api, COMMIT)

    assert requested[0][-1] == f"repos/{REPOSITORY}/compare/{COMMIT}...main"


@pytest.mark.parametrize("status", ["behind", "diverged"])
def test_release_commit_on_main_rejects_rewound_or_diverged_main(status: str) -> None:
    sleeps: list[float] = []
    api = _api(
        [
            _completed(
                200,
                body=_comparison_payload(status, merge_base_commit="b" * 40),
            )
        ],
        sleeps,
    )

    with pytest.raises(release_api_retry.ReleaseAPIError, match=rf"comparison status: {status}"):
        release_api_retry.require_commit_on_main(api, COMMIT)
    assert sleeps == []


@pytest.mark.parametrize(
    "payload",
    [
        _comparison_payload(None),
        _comparison_payload([]),
        _comparison_payload("ahead", base_commit="b" * 40),
        json.dumps(
            {
                "status": "ahead",
                "base_commit": {"sha": COMMIT},
                "merge_base_commit": {},
            }
        ),
        _comparison_payload("ahead", merge_base_commit="b" * 40),
    ],
)
def test_release_commit_on_main_rejects_malformed_comparison(payload: str) -> None:
    sleeps: list[float] = []
    api = _api([_completed(200, body=payload)], sleeps)

    with pytest.raises(release_api_retry.ReleaseAPIError, match="GitHub main comparison response"):
        release_api_retry.require_commit_on_main(api, COMMIT)
    assert sleeps == []


def test_release_commit_on_main_rejects_noncanonical_commit_without_api_request() -> None:
    class NoRequestAPI:
        def compare_commit_to_main(self, _expected_commit: str) -> str:
            raise AssertionError("comparison must not run")

    with pytest.raises(release_api_retry.ReleaseAPIError, match="exact 40-character"):
        release_api_retry.require_commit_on_main(NoRequestAPI(), "a" * 39)  # type: ignore[arg-type]


def test_release_commit_on_main_fails_closed_on_api_error() -> None:
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
        release_api_retry.require_commit_on_main(api, COMMIT)
    assert sleeps == [0.25, 0.5]


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
        main_relation: str = "identical",
        tag_commit: str = COMMIT,
        release_rows: list[dict[str, object]] | None = None,
    ) -> None:
        self.observations = list(observations)
        self.main_relation = main_relation
        self.tag_commit = tag_commit
        self.rows = list(release_rows or [])
        self.compared_commits: list[str] = []
        self._current: tuple[dict[str, object] | None, dict[str, object] | None] | None = None

    def compare_commit_to_main(self, expected_commit: str) -> str:
        self.compared_commits.append(expected_commit)
        return self.main_relation

    def tag_ref(self, _tag: str) -> dict[str, object] | None:
        assert self.observations
        self._current = self.observations.pop(0)
        return self._current[0]

    def release_by_tag(self, _tag: str) -> dict[str, object] | None:
        assert self._current is not None
        return self._current[1]

    def resolve_tag_commit(self, _payload: dict[str, object]) -> str:
        return self.tag_commit

    def release_rows(self) -> list[dict[str, object]]:
        return list(self.rows)


def test_namespace_preflight_checks_main_ancestry_and_both_namespaces() -> None:
    absent = _NamespaceAPI([(None, None)])
    release_api_retry.require_absent_namespace(
        absent,
        tag=TAG,
        expected_main_commit=COMMIT,
    )
    assert absent.compared_commits == [COMMIT]

    rewound = _NamespaceAPI([(None, None)], main_relation="behind")
    with pytest.raises(release_api_retry.ReleaseAPIError, match="not reachable"):
        release_api_retry.require_absent_namespace(
            rewound,
            tag=TAG,
            expected_main_commit=COMMIT,
        )

    occupied = _NamespaceAPI([({"object": {}}, None)])
    with pytest.raises(release_api_retry.ReleaseAPIError, match="occupied by tag"):
        release_api_retry.require_absent_namespace(occupied, tag=TAG)

    release_only = _NamespaceAPI([(None, {"tag_name": TAG})])
    with pytest.raises(release_api_retry.ReleaseAPIError, match="occupied by release"):
        release_api_retry.require_absent_namespace(release_only, tag=TAG)


def test_releasable_namespace_admits_absence_or_exact_same_commit_tag_only() -> None:
    absent = _NamespaceAPI([(None, None)])
    assert (
        release_api_retry.require_releasable_namespace(
            absent,  # type: ignore[arg-type]
            tag=TAG,
            expected_commit=COMMIT,
        )
        is release_api_retry.ReconcileState.ABSENT
    )
    assert absent.compared_commits == [COMMIT]

    tag_only = _NamespaceAPI([({"object": {"type": "commit", "sha": COMMIT}}, None)])
    assert (
        release_api_retry.require_releasable_namespace(
            tag_only,  # type: ignore[arg-type]
            tag=TAG,
            expected_commit=COMMIT,
        )
        is release_api_retry.ReconcileState.ABSENT
    )
    assert tag_only.compared_commits == [COMMIT]


def test_releasable_namespace_rejects_published_release_with_repair_direction() -> None:
    published = _NamespaceAPI(
        [
            (
                {"object": {"type": "commit", "sha": COMMIT}},
                {
                    "tag_name": TAG,
                    "draft": False,
                    "prerelease": False,
                    "immutable": True,
                    "assets": [],
                },
            )
        ]
    )
    with pytest.raises(
        release_api_retry.ReleaseAPIError,
        match=r"already contains a release.*operation=release.*operation=repair-channel",
    ):
        release_api_retry.require_releasable_namespace(
            published,  # type: ignore[arg-type]
            tag=TAG,
            expected_commit=COMMIT,
        )
    assert published.compared_commits == []


@pytest.mark.parametrize(
    ("tag_payload", "release_payload"),
    [
        (
            None,
            {
                "tag_name": TAG,
                "draft": False,
                "prerelease": False,
                "immutable": True,
                "assets": [],
            },
        ),
        (
            {"object": {}},
            {
                "tag_name": TAG,
                "draft": True,
                "prerelease": False,
                "immutable": False,
                "assets": [],
            },
        ),
        (
            {"object": {}},
            {
                "tag_name": TAG,
                "draft": False,
                "prerelease": True,
                "immutable": True,
                "assets": [],
            },
        ),
        (
            {"object": {}},
            {
                "tag_name": TAG,
                "draft": False,
                "prerelease": False,
                "immutable": False,
                "assets": [],
            },
        ),
    ],
)
def test_releasable_namespace_has_one_existing_release_refusal(
    tag_payload: dict[str, object] | None,
    release_payload: dict[str, object] | None,
) -> None:
    api = _NamespaceAPI([(tag_payload, release_payload)])
    with pytest.raises(
        release_api_retry.ReleaseAPIError,
        match=r"already contains a release.*operation=release.*investigate",
    ):
        release_api_retry.require_releasable_namespace(
            api,  # type: ignore[arg-type]
            tag=TAG,
            expected_commit=COMMIT,
        )


def test_releasable_namespace_rejects_another_commit() -> None:
    api = _NamespaceAPI(
        [({"object": {"type": "commit", "sha": "b" * 40}}, None)],
        tag_commit="b" * 40,
    )
    with pytest.raises(release_api_retry.ReleaseAPIError, match="points to"):
        release_api_retry.require_releasable_namespace(
            api,  # type: ignore[arg-type]
            tag=TAG,
            expected_commit=COMMIT,
        )


def test_repair_target_must_be_latest_immutable_stable_release() -> None:
    stable = {
        "tag_name": TAG,
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "assets": [],
    }
    api = _NamespaceAPI(
        [({"object": {"type": "commit", "sha": COMMIT}}, None)],
        release_rows=[
            {"tag_name": "nightly", "draft": False, "prerelease": False, "immutable": True},
            {
                "tag_name": "0.9.0",
                "draft": True,
                "prerelease": False,
                "immutable": False,
                "assets": [],
            },
            stable,
            dict(stable),
            {
                "tag_name": "0.8.5",
                "draft": False,
                "prerelease": False,
                "immutable": True,
                "assets": [],
            },
        ],
    )

    release_api_retry.require_latest_immutable_release(
        api,  # type: ignore[arg-type]
        tag=TAG,
        expected_commit=COMMIT,
    )

    assert api.compared_commits == [COMMIT]


def test_repair_target_rejects_rollback_below_latest_immutable_release() -> None:
    api = _NamespaceAPI(
        [],
        release_rows=[
            {
                "tag_name": TAG,
                "draft": False,
                "prerelease": False,
                "immutable": True,
                "assets": [],
            },
            {
                "tag_name": "0.8.7",
                "draft": False,
                "prerelease": False,
                "immutable": True,
                "assets": [],
            },
        ],
    )

    with pytest.raises(
        release_api_retry.ReleaseAPIError,
        match=r"not the latest immutable stable release '0\.8\.7'.*rollback",
    ):
        release_api_retry.require_latest_immutable_release(
            api,  # type: ignore[arg-type]
            tag=TAG,
            expected_commit=COMMIT,
        )
    assert api.compared_commits == []


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


def test_reconcile_create_accepts_only_persistent_exact_same_commit_tag(
    tmp_path: Path,
) -> None:
    tag_payload = {"object": {"type": "commit", "sha": COMMIT}}
    api = _NamespaceAPI([(tag_payload, None)] * 3)
    sleeps: list[float] = []

    state = release_api_retry.reconcile_create(
        api,  # type: ignore[arg-type]
        tag=TAG,
        expected_commit=COMMIT,
        candidate_root=tmp_path,
        omit_windows_binaries=True,
        attempts=3,
        delay_seconds=0.25,
        sleep=sleeps.append,
    )

    assert state is release_api_retry.ReconcileState.ABSENT
    assert sleeps == [0.25, 0.25]
    assert api.observations == []


def test_reconcile_create_accepts_persistent_tag_only_after_initial_absence(
    tmp_path: Path,
) -> None:
    tag_payload = {"object": {"type": "commit", "sha": COMMIT}}
    api = _NamespaceAPI(
        [
            (None, None),
            (tag_payload, None),
            (tag_payload, None),
        ]
    )
    sleeps: list[float] = []

    state = release_api_retry.reconcile_create(
        api,  # type: ignore[arg-type]
        tag=TAG,
        expected_commit=COMMIT,
        candidate_root=tmp_path,
        omit_windows_binaries=True,
        attempts=3,
        delay_seconds=0.25,
        sleep=sleeps.append,
    )

    assert state is release_api_retry.ReconcileState.ABSENT
    assert sleeps == [0.25, 0.25]
    assert api.observations == []


def test_reconcile_create_extends_final_absent_to_tag_only_transition_once(
    tmp_path: Path,
) -> None:
    tag_payload = {"object": {"type": "commit", "sha": COMMIT}}
    api = _NamespaceAPI(
        [
            (None, None),
            (tag_payload, None),
            (tag_payload, None),
        ]
    )
    sleeps: list[float] = []

    state = release_api_retry.reconcile_create(
        api,  # type: ignore[arg-type]
        tag=TAG,
        expected_commit=COMMIT,
        candidate_root=tmp_path,
        omit_windows_binaries=True,
        attempts=2,
        delay_seconds=0.25,
        sleep=sleeps.append,
    )

    assert state is release_api_retry.ReconcileState.ABSENT
    assert sleeps == [0.25, 0.25]
    assert api.observations == []


def test_reconcile_create_waits_for_release_listing_after_tag_only_observation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tag_payload = {"object": {"type": "commit", "sha": COMMIT}}
    release_payload = {
        "tag_name": TAG,
        "draft": False,
        "immutable": True,
        "assets": [],
    }
    api = _NamespaceAPI(
        [
            (tag_payload, None),
            (tag_payload, release_payload),
        ]
    )
    sleeps: list[float] = []
    verified: list[dict[str, object]] = []
    monkeypatch.setattr(
        release_api_retry,
        "_verify_exact_candidate",
        lambda **kwargs: verified.append(kwargs),
    )

    state = release_api_retry.reconcile_create(
        api,  # type: ignore[arg-type]
        tag=TAG,
        expected_commit=COMMIT,
        candidate_root=tmp_path,
        omit_windows_binaries=True,
        attempts=3,
        delay_seconds=0.25,
        sleep=sleeps.append,
    )

    assert state is release_api_retry.ReconcileState.EXACT
    assert sleeps == [0.25]
    assert len(verified) == 1
    assert verified[0]["release_payload"] == release_payload
    assert api.observations == []


def test_reconcile_create_rejects_nonpersistent_tag_only_state(tmp_path: Path) -> None:
    tag_payload = {"object": {"type": "commit", "sha": COMMIT}}
    api = _NamespaceAPI(
        [
            (tag_payload, None),
            (None, None),
            (tag_payload, None),
        ]
    )
    sleeps: list[float] = []

    with pytest.raises(
        release_api_retry.ReleaseAPIError,
        match="tag-only state did not persist",
    ):
        release_api_retry.reconcile_create(
            api,  # type: ignore[arg-type]
            tag=TAG,
            expected_commit=COMMIT,
            candidate_root=tmp_path,
            omit_windows_binaries=True,
            attempts=3,
            delay_seconds=0.25,
            sleep=sleeps.append,
        )

    assert sleeps == [0.25]
    assert len(api.observations) == 1


def test_reconcile_create_attempts_one_requires_delayed_tag_only_confirmation(
    tmp_path: Path,
) -> None:
    tag_payload = {"object": {"type": "commit", "sha": COMMIT}}
    api = _NamespaceAPI([(tag_payload, None), (tag_payload, None)])
    sleeps: list[float] = []

    state = release_api_retry.reconcile_create(
        api,  # type: ignore[arg-type]
        tag=TAG,
        expected_commit=COMMIT,
        candidate_root=tmp_path,
        omit_windows_binaries=True,
        attempts=1,
        delay_seconds=0.25,
        sleep=sleeps.append,
    )

    assert state is release_api_retry.ReconcileState.ABSENT
    assert sleeps == [0.25]
    assert api.observations == []


def test_reconcile_create_attempts_one_waits_for_eventually_visible_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tag_payload = {"object": {"type": "commit", "sha": COMMIT}}
    release_payload = {
        "tag_name": TAG,
        "draft": False,
        "immutable": True,
        "assets": [],
    }
    api = _NamespaceAPI(
        [
            (tag_payload, None),
            (tag_payload, release_payload),
        ]
    )
    verified: list[dict[str, object]] = []
    sleeps: list[float] = []
    monkeypatch.setattr(
        release_api_retry,
        "_verify_exact_candidate",
        lambda **kwargs: verified.append(kwargs),
    )

    state = release_api_retry.reconcile_create(
        api,  # type: ignore[arg-type]
        tag=TAG,
        expected_commit=COMMIT,
        candidate_root=tmp_path,
        omit_windows_binaries=True,
        attempts=1,
        delay_seconds=0.25,
        sleep=sleeps.append,
    )

    assert state is release_api_retry.ReconcileState.EXACT
    assert sleeps == [0.25]
    assert len(verified) == 1
    assert verified[0]["release_payload"] == release_payload
    assert api.observations == []


def test_reconcile_create_rejects_mismatched_tag_only_commit_immediately(
    tmp_path: Path,
) -> None:
    tag_payload = {"object": {"type": "commit", "sha": "b" * 40}}
    api = _NamespaceAPI(
        [
            (tag_payload, None),
            (tag_payload, None),
            (tag_payload, None),
        ],
        tag_commit="b" * 40,
    )
    sleeps: list[float] = []

    with pytest.raises(release_api_retry.ReleaseAPIError, match="points to"):
        release_api_retry.reconcile_create(
            api,  # type: ignore[arg-type]
            tag=TAG,
            expected_commit=COMMIT,
            candidate_root=tmp_path,
            omit_windows_binaries=True,
            attempts=3,
            delay_seconds=0.25,
            sleep=sleeps.append,
        )

    assert sleeps == []
    assert len(api.observations) == 2


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
            release_payload={
                "tag_name": TAG,
                "draft": False,
                "prerelease": False,
                "immutable": False,
                "assets": [],
            },
            api=api,  # type: ignore[arg-type]
            tag=TAG,
            expected_commit=COMMIT,
            candidate_root=tmp_path,
            omit_windows_binaries=True,
        )


def test_partial_remote_namespace_fails_closed_without_becoming_absent(tmp_path: Path) -> None:
    api = _NamespaceAPI(
        [
            (None, {"tag_name": TAG}),
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
            "prerelease": True,
            "immutable": True,
            "assets": [{"name": "checksums.txt", "digest": "sha256:" + "c" * 64}],
        }
    )

    assert normalized == {
        "tagName": TAG,
        "isDraft": False,
        "isPrerelease": True,
        "isImmutable": True,
        "assets": [{"name": "checksums.txt", "digest": "sha256:" + "c" * 64}],
    }


def test_exact_candidate_reconciliation_carries_prerelease_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[dict[str, object]] = []

    def verify_published(
        _root: Path,
        release_json: Path,
        _tag: str,
        _commit: str,
        *,
        omit_windows_binaries: bool,
    ) -> None:
        assert omit_windows_binaries is True
        observed.append(json.loads(release_json.read_text(encoding="utf-8")))

    monkeypatch.setattr(
        release_api_retry.release_candidate,
        "verify_published_release",
        verify_published,
    )
    api = _NamespaceAPI([], tag_commit=COMMIT)

    release_api_retry._verify_exact_candidate(
        tag_payload={"object": {"type": "commit", "sha": COMMIT}},
        release_payload={
            "tag_name": TAG,
            "draft": False,
            "prerelease": True,
            "immutable": True,
            "assets": [],
        },
        api=api,  # type: ignore[arg-type]
        tag=TAG,
        expected_commit=COMMIT,
        candidate_root=tmp_path,
        omit_windows_binaries=True,
    )

    assert observed == [
        {
            "tagName": TAG,
            "isDraft": False,
            "isPrerelease": True,
            "isImmutable": True,
            "assets": [],
        }
    ]


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


def test_cli_publish_precheck_accepts_existing_exact_candidate_without_rechecking_main(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tag_payload = {"object": {"type": "commit", "sha": COMMIT}}
    release_payload = {
        "tag_name": TAG,
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "assets": [],
    }
    api = _NamespaceAPI([(tag_payload, release_payload)], main_relation="diverged")
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
        def compare_commit_to_main(self, expected_commit: str) -> str:
            assert expected_commit == COMMIT
            return "diverged"

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
    assert "not reachable from protected main" in capsys.readouterr().err


def test_cli_publish_precheck_accepts_absence_after_main_advances(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class AdvancedMainAPI:
        def compare_commit_to_main(self, expected_commit: str) -> str:
            assert expected_commit == COMMIT
            return "ahead"

    monkeypatch.setattr(
        release_api_retry,
        "GitHubReleaseAPI",
        lambda **_kwargs: AdvancedMainAPI(),
    )
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

    assert result == release_api_retry.ABSENT_EXIT_CODE


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
