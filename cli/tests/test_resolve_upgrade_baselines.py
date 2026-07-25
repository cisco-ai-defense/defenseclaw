# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import urllib.error
from pathlib import Path
from types import ModuleType

import pytest

from scripts import release_candidate

ROOT = Path(__file__).resolve().parents[2]


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RESOLVER = _load(
    ROOT / "scripts" / "resolve_upgrade_baselines.py",
    "resolve_upgrade_baselines_test",
)


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _release(
    version: str,
    *,
    runtime_config: int = 8,
    windows: bool = False,
) -> tuple[dict[str, object], dict[str, bytes]]:
    manifest = json.dumps(
        {
            "schema_version": 2,
            "release_version": version,
            "runtime_config_version": runtime_config,
        },
        sort_keys=True,
    ).encode()
    payload_digests: dict[str, str] = {
        "upgrade-manifest.json": _digest(manifest),
    }
    for name in RESOLVER._required_posix_assets(version):
        payload_digests[name] = _digest(f"payload:{name}".encode())
    # Candidate checksums cover sealed Windows bytes even when publication
    # intentionally omits them. Only GitHub's actual immutable asset inventory
    # establishes platform availability.
    windows_assets = RESOLVER._required_windows_assets(version)
    for name in windows_assets:
        payload_digests[name] = _digest(f"payload:{name}".encode())
    checksums = "".join(f"{digest}  {name}\n" for name, digest in sorted(payload_digests.items())).encode()
    downloaded = {
        f"https://downloads.example/{version}/checksums.txt": checksums,
        f"https://downloads.example/{version}/checksums.txt.pem": b"certificate\n",
        f"https://downloads.example/{version}/checksums.txt.sig": b"signature\n",
        f"https://downloads.example/{version}/upgrade-manifest.json": manifest,
    }
    if tuple(map(int, version.split("."))) >= RESOLVER.SIGSTORE_BUNDLE_START_VERSION:
        downloaded[f"https://downloads.example/{version}/checksums.txt.bundle"] = (
            b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n'
        )
    assets: list[dict[str, object]] = []
    for name, digest in payload_digests.items():
        if name in windows_assets and not windows:
            continue
        assets.append(
            {
                "name": name,
                "digest": f"sha256:{digest}",
                "browser_download_url": f"https://downloads.example/{version}/{name}",
            }
        )
    proof_names = ["checksums.txt", "checksums.txt.pem", "checksums.txt.sig"]
    if tuple(map(int, version.split("."))) >= RESOLVER.SIGSTORE_BUNDLE_START_VERSION:
        proof_names.append("checksums.txt.bundle")
    for name in proof_names:
        url = f"https://downloads.example/{version}/{name}"
        assets.append(
            {
                "name": name,
                "digest": f"sha256:{_digest(downloaded[url])}",
                "browser_download_url": url,
            }
        )
    return (
        {
            "tag_name": version,
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "assets": assets,
        },
        downloaded,
    )


def _resolve(
    target: str,
    releases_and_downloads: list[tuple[dict[str, object], dict[str, bytes]]],
    *,
    candidate_runtime_config_version: int = 8,
    checked_policy_path: Path | None = None,
    verify=None,
) -> dict[str, object]:
    releases = [item[0] for item in releases_and_downloads]
    downloads = {
        url: payload for _, release_downloads in releases_and_downloads for url, payload in release_downloads.items()
    }

    def download(url: str, maximum: int) -> bytes:
        payload = downloads[url]
        assert 0 < len(payload) <= maximum
        return payload

    return RESOLVER.resolve_effective_policy(
        target_version=target,
        candidate_runtime_config_version=candidate_runtime_config_version,
        releases=releases,
        checked_policy_path=checked_policy_path or ROOT / "release" / "upgrade-baselines.json",
        download=download,
        verify=verify or (lambda *_: None),
    )


def test_086_discovers_085_without_editing_the_checked_floor(tmp_path: Path) -> None:
    checked_before = (ROOT / "release" / "upgrade-baselines.json").read_bytes()
    policy = _resolve("0.8.6", [_release("0.8.5")])

    assert policy["published_baselines"][:3] == ["0.8.5", "0.8.4", "0.8.3"]
    assert policy["published_baseline_config_versions"]["0.8.5"] == 8
    assert "0.8.5" not in policy["platform_published_baselines"]["windows"]
    assert (ROOT / "release" / "upgrade-baselines.json").read_bytes() == checked_before

    path = tmp_path / "effective.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    generator = _load(
        ROOT / "scripts" / "generate-upgrade-manifest.py",
        "generate_upgrade_manifest_effective_test",
    )
    generator.UPGRADE_BASELINES_PATH = path
    manifest_policy = generator.release_upgrade_policy("0.8.6")
    assert manifest_policy["tested_source_versions"][:3] == [
        "0.8.5",
        "0.8.4",
        "0.8.3",
    ]
    assert manifest_policy["platform_tested_source_versions"]["windows"] == []


def test_manifest_generator_accepts_effective_policy_for_first_windows_release(
    tmp_path: Path,
) -> None:
    policy = _resolve("0.8.7", [_release("0.8.5"), _release("0.8.6")])
    policy["platform_published_baselines"]["windows"] = []
    path = tmp_path / "effective.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    generator = _load(
        ROOT / "scripts" / "generate-upgrade-manifest.py",
        "generate_upgrade_manifest_first_windows_release_test",
    )
    generator.UPGRADE_BASELINES_PATH = path

    assert generator.platform_published_upgrade_baselines("0.8.7") == {
        "windows": [],
    }
    generated = generator.release_upgrade_policy("0.8.7")
    assert generated["tested_source_versions"]
    assert generated["platform_tested_source_versions"] == {"windows": []}


def test_087_discovers_all_newer_immutable_stables_without_a_policy_edit() -> None:
    policy = _resolve("0.8.7", [_release("0.8.5"), _release("0.8.6")])

    assert policy["published_baselines"][:4] == [
        "0.8.6",
        "0.8.5",
        "0.8.4",
        "0.8.3",
    ]
    assert policy["published_baseline_config_versions"]["0.8.6"] == 8


def test_candidate_below_checked_head_discovers_release_above_eligible_floor(
    tmp_path: Path,
) -> None:
    checked_policy = tmp_path / "upgrade-baselines.json"
    checked_policy.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "published_baselines": ["0.8.4", "0.8.1", "0.8.0"],
                "published_baseline_config_versions": {
                    "0.8.4": 7,
                    "0.8.1": 6,
                    "0.8.0": 6,
                },
                "platform_published_baselines": {"windows": ["0.8.0"]},
            }
        ),
        encoding="utf-8",
    )

    policy = _resolve(
        "0.8.3",
        [_release("0.8.2")],
        checked_policy_path=checked_policy,
    )

    assert policy["published_baselines"] == ["0.8.2", "0.8.1", "0.8.0"]


def test_legacy_candidate_filters_checked_baselines_that_are_not_older() -> None:
    policy = _resolve("0.8.3", [])

    assert policy["published_baselines"][:3] == ["0.8.2", "0.8.1", "0.8.0"]
    assert "0.8.4" not in policy["published_baselines"]
    assert "0.8.3" not in policy["published_baselines"]
    assert "0.8.4" not in policy["published_baseline_config_versions"]


def test_ineligible_newer_config_does_not_reject_legacy_candidate() -> None:
    policy = _resolve("0.8.3", [], candidate_runtime_config_version=6)

    assert policy["published_baselines"][0] == "0.8.2"
    assert set(policy["published_baseline_config_versions"].values()) <= {5, 6}


def test_eligible_newer_config_still_rejects_candidate() -> None:
    with pytest.raises(
        RESOLVER.BaselineResolutionError,
        match="eligible checked baseline config version is newer",
    ):
        _resolve("0.8.5", [], candidate_runtime_config_version=6)


def test_candidate_at_or_below_support_floor_requires_explicit_fixture() -> None:
    checked_policy = json.loads((ROOT / "release" / "upgrade-baselines.json").read_text(encoding="utf-8"))
    support_floor = checked_policy["published_baselines"][-1]
    assert tuple(map(int, support_floor.split("."))) > (0, 0, 0)

    for candidate in ("0.0.0", support_floor):
        with pytest.raises(
            RESOLVER.BaselineResolutionError,
            match="no supported published baseline",
        ):
            _resolve(candidate, [])


def test_actual_complete_windows_assets_control_platform_availability(
    tmp_path: Path,
) -> None:
    policy = _resolve("0.8.7", [_release("0.8.5"), _release("0.8.6", windows=True)])

    windows = policy["platform_published_baselines"]["windows"]
    assert windows[0] == "0.8.6"
    assert "0.8.5" not in windows

    path = tmp_path / "effective.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    generator = _load(
        ROOT / "scripts" / "generate-upgrade-manifest.py",
        "generate_upgrade_manifest_windows_effective_test",
    )
    generator.UPGRADE_BASELINES_PATH = path
    generated = generator.release_upgrade_policy("0.8.7")
    assert generated["platform_tested_source_versions"]["windows"] == ["0.8.6"]


def test_windows_capability_matches_the_actual_native_release_asset_set() -> None:
    assert RESOLVER._required_windows_assets("0.8.7") == {
        "DefenseClawSetup-x64.exe",
        "DefenseClawSetup-x64.exe.sha256",
        "DefenseClawSetup-x64.exe.provenance.json",
        "DefenseClawSetup-x64.exe.sbom.json",
        "defenseclaw_0.8.7_protocol2_windows_amd64.dcgateway",
        "defenseclaw_0.8.7_protocol2_windows_amd64.dcgateway.sbom.json",
        "defenseclaw_0.8.7_protocol2_windows_arm64.dcgateway",
        "defenseclaw_0.8.7_protocol2_windows_arm64.dcgateway.sbom.json",
    }
    assert "defenseclaw_0.8.7_windows_amd64.zip.sbom.json" not in (release_candidate.runtime_asset_names("0.8.7"))


def test_intentional_historical_exclusions_are_not_rediscovered() -> None:
    excluded, downloads = _release("0.7.0")
    policy = _resolve("0.8.6", [(excluded, downloads), _release("0.8.5")])

    assert "0.7.0" not in policy["published_baselines"]


def test_nonimmutable_stable_in_the_dynamic_range_fails_closed() -> None:
    release, downloads = _release("0.8.5")
    release["immutable"] = False

    with pytest.raises(RESOLVER.BaselineResolutionError, match="not immutable"):
        _resolve("0.8.6", [(release, downloads)])


def test_sigstore_failure_fails_closed() -> None:
    def reject(*_: Path) -> None:
        raise RESOLVER.BaselineResolutionError("signature rejected")

    with pytest.raises(RESOLVER.BaselineResolutionError, match="signature rejected"):
        _resolve("0.8.6", [_release("0.8.5")], verify=reject)


def test_manifest_must_be_covered_by_authenticated_checksums() -> None:
    release, downloads = _release("0.8.5")
    downloads = dict(downloads)
    manifest_url = "https://downloads.example/0.8.5/upgrade-manifest.json"
    downloads[manifest_url] = b"{}"
    for asset in release["assets"]:
        if asset["name"] == "upgrade-manifest.json":
            asset["digest"] = f"sha256:{_digest(downloads[manifest_url])}"

    with pytest.raises(RESOLVER.BaselineResolutionError, match="authenticated checksums"):
        _resolve("0.8.6", [(release, downloads)])


def test_github_asset_digest_mismatch_fails_before_signature_use() -> None:
    release, downloads = _release("0.8.5")
    release = copy.deepcopy(release)
    for asset in release["assets"]:
        if asset["name"] == "checksums.txt":
            asset["digest"] = f"sha256:{'0' * 64}"

    with pytest.raises(RESOLVER.BaselineResolutionError, match="GitHub asset digest mismatch"):
        _resolve("0.8.6", [(release, downloads)])


def test_checksum_proof_bundle_is_required_but_not_self_referential() -> None:
    release, downloads = _release("0.8.7")

    checksums = downloads["https://downloads.example/0.8.7/checksums.txt"]
    assert b"checksums.txt.bundle" not in checksums
    policy = _resolve("0.8.8", [(release, downloads)])

    assert policy["published_baselines"][0] == "0.8.7"


def test_release_before_bundle_threshold_authenticates_without_bundle() -> None:
    release, downloads = _release("0.8.6")

    assert all(asset["name"] != "checksums.txt.bundle" for asset in release["assets"])

    policy = _resolve("0.8.7", [(release, downloads)])
    assert policy["published_baselines"][0] == "0.8.6"


def test_checksum_proof_bundle_must_have_exact_immutable_custody() -> None:
    release, downloads = _release("0.8.7")
    release = copy.deepcopy(release)
    for asset in release["assets"]:
        if asset["name"] == "checksums.txt.bundle":
            asset["digest"] = f"sha256:{'0' * 64}"

    with pytest.raises(
        RESOLVER.BaselineResolutionError,
        match=r"GitHub asset digest mismatch for 0\.8\.7/checksums\.txt\.bundle",
    ):
        _resolve("0.8.8", [(release, downloads)])


def test_checksum_proof_bundle_cannot_be_omitted_from_new_release() -> None:
    release, downloads = _release("0.8.7")
    release = copy.deepcopy(release)
    release["assets"] = [asset for asset in release["assets"] if asset["name"] != "checksums.txt.bundle"]

    with pytest.raises(
        RESOLVER.BaselineResolutionError,
        match=r"immutable release 0\.8\.7 lacks authentication assets.*checksums\.txt\.bundle",
    ):
        _resolve("0.8.8", [(release, downloads)])


def test_checksum_proof_exception_does_not_admit_unknown_release_assets() -> None:
    release, downloads = _release("0.8.7")
    release = copy.deepcopy(release)
    release["assets"].append(
        {
            "name": "unexpected.bin",
            "digest": f"sha256:{_digest(b'unexpected')}",
            "browser_download_url": "https://downloads.example/0.8.7/unexpected.bin",
        }
    )

    with pytest.raises(
        RESOLVER.BaselineResolutionError,
        match=r"signed checksum and immutable GitHub asset disagree for 0\.8\.7/unexpected\.bin",
    ):
        _resolve("0.8.8", [(release, downloads)])


def test_checksum_proof_exception_does_not_relax_payload_digest_binding() -> None:
    release, downloads = _release("0.8.7")
    release = copy.deepcopy(release)
    for asset in release["assets"]:
        if asset["name"] == "upgrade-manifest.json":
            asset["digest"] = f"sha256:{'0' * 64}"

    with pytest.raises(
        RESOLVER.BaselineResolutionError,
        match=r"GitHub asset digest mismatch for 0\.8\.7/upgrade-manifest\.json",
    ):
        _resolve("0.8.8", [(release, downloads)])


def test_dynamic_runtime_config_cannot_exceed_the_candidate() -> None:
    with pytest.raises(RESOLVER.BaselineResolutionError, match="release/config identity"):
        _resolve("0.8.6", [_release("0.8.5", runtime_config=9)])


def test_candidate_validator_consumes_the_same_effective_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _resolve("0.8.6", [_release("0.8.5")])
    path = tmp_path / "effective.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    monkeypatch.setattr(release_candidate, "UPGRADE_BASELINES_PATH", path)

    configured, platforms = release_candidate._load_upgrade_baseline_policy("0.8.6")

    assert configured[:2] == ["0.8.5", "0.8.4"]
    assert "0.8.5" not in platforms["windows"]


def test_candidate_validator_rejects_effective_config_newer_than_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _resolve("0.8.6", [_release("0.8.5")])
    policy["published_baseline_config_versions"]["0.8.5"] = 9
    path = tmp_path / "effective.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    monkeypatch.setattr(release_candidate, "UPGRADE_BASELINES_PATH", path)

    with pytest.raises(release_candidate.CandidateError, match="policy is invalid"):
        release_candidate._load_upgrade_baseline_policy("0.8.6")


def test_sigstore_verification_uses_bounded_wrapper_and_exact_release_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        observed.extend(command)
        assert kwargs == {"check": False, "timeout": 400}
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(RESOLVER.subprocess, "run", run)
    RESOLVER._verify_sigstore(
        tmp_path / "checksums.txt",
        tmp_path / "checksums.txt.pem",
        tmp_path / "checksums.txt.sig",
        repository="cisco-ai-defense/defenseclaw",
        cosign="cosign",
    )

    assert str(ROOT / "scripts/verify-sigstore-blob.py") in observed
    identity = observed[observed.index("--certificate-identity") + 1]
    assert identity == (
        "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main"
    )
    assert observed[observed.index("--certificate-oidc-issuer") + 1] == ("https://token.actions.githubusercontent.com")


class _DownloadResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.headers: dict[str, str] = {"Content-Length": str(len(payload))}

    def __enter__(self) -> _DownloadResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, maximum: int) -> bytes:
        return self.payload[:maximum]


def _http_error(url: str, status: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, status, f"HTTP {status}", None, None)


def test_download_retries_transient_http_and_network_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = "https://api.github.com/repos/example/project/releases/assets/1"
    responses: list[object] = [
        _http_error(url, 500),
        urllib.error.URLError("connection reset"),
        _DownloadResponse(b"authenticated release asset"),
    ]
    sleeps: list[float] = []

    def urlopen(_request: object, *, timeout: int) -> _DownloadResponse:
        assert timeout == 60
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        assert isinstance(response, _DownloadResponse)
        return response

    monkeypatch.setattr(RESOLVER.urllib.request, "urlopen", urlopen)

    assert RESOLVER._download(url, 64, sleeper=sleeps.append) == b"authenticated release asset"
    assert responses == []
    assert sleeps == [1.0, 2.0]


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
def test_download_fails_fast_for_permanent_http_errors(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    url = "https://api.github.com/repos/example/project/releases/assets/1"
    calls = 0
    sleeps: list[float] = []

    def urlopen(_request: object, *, timeout: int) -> _DownloadResponse:
        nonlocal calls
        calls += 1
        assert timeout == 60
        raise _http_error(url, status)

    monkeypatch.setattr(RESOLVER.urllib.request, "urlopen", urlopen)

    with pytest.raises(RESOLVER.BaselineResolutionError, match=f"HTTP Error {status}"):
        RESOLVER._download(url, 64, sleeper=sleeps.append)
    assert calls == 1
    assert sleeps == []


def test_download_transient_failure_exhaustion_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = "https://api.github.com/repos/example/project/releases/assets/1"
    calls = 0
    sleeps: list[float] = []

    def urlopen(_request: object, *, timeout: int) -> _DownloadResponse:
        nonlocal calls
        calls += 1
        assert timeout == 60
        raise _http_error(url, 503)

    monkeypatch.setattr(RESOLVER.urllib.request, "urlopen", urlopen)

    with pytest.raises(
        RESOLVER.BaselineResolutionError,
        match=r"after 4 attempts: HTTP Error 503",
    ):
        RESOLVER._download(url, 64, sleeper=sleeps.append)
    assert calls == RESOLVER.MAX_DOWNLOAD_ATTEMPTS
    assert sleeps == [1.0, 2.0, 4.0]
