# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from scripts import historical_release_auth

PEM = b"-----BEGIN CERTIFICATE-----\nZmFrZS1jZXJ0aWZpY2F0ZQ==\n-----END CERTIFICATE-----\n"


def _release_fixture(
    tmp_path: Path,
    *,
    version: str = "0.8.3",
    signed: bool = True,
) -> tuple[Path, Path, Path, str]:
    release = tmp_path / "release"
    release.mkdir(parents=True)
    asset_name = f"defenseclaw-{version}-py3-none-any.whl"
    payload = b"published historical wheel"
    (release / asset_name).write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    checksum_lines = [f"{hashlib.sha256(b'other').hexdigest()}  source/nested.txt"]
    if signed:
        checksum_lines.append(f"{digest}  {asset_name}")
    (release / "checksums.txt").write_text("\n".join(checksum_lines) + "\n")
    (release / "checksums.txt.sig").write_text("historical-signature\n")
    (release / "checksums.txt.pem").write_bytes(base64.b64encode(PEM) + b"\n")
    cosign = tmp_path / "cosign"
    cosign.write_bytes(b"fake cosign")
    policy = tmp_path / "pins.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "signed_wheel_coverage_starts_at": "0.6.1",
                "signed_checksum_exceptions": (
                    {} if signed else {version: {asset_name: digest}}
                ),
            }
        )
    )
    return release, cosign, policy, asset_name


def _successful_runner(commands: list[list[str]]):
    def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        assert kwargs["check"] is False
        assert kwargs["capture_output"] is True
        assert kwargs["timeout"] == 60
        certificate = Path(command[command.index("--certificate") + 1])
        assert certificate.read_bytes() == PEM
        return subprocess.CompletedProcess(command, 0, stdout="Verified OK", stderr="")

    return run


def test_legacy_base64_certificate_is_normalized(tmp_path: Path) -> None:
    encoded = tmp_path / "checksums.txt.pem"
    encoded.write_bytes(base64.b64encode(PEM) + b"\n")

    assert historical_release_auth.normalized_certificate_bytes(encoded) == PEM


def test_windows_named_and_opened_timestamp_views_do_not_false_positive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "checksums.txt"
    payload = b"authenticated checksums\n"
    path.write_bytes(payload)
    real_lstat = Path.lstat
    lstat_calls: list[Path] = []

    def timestamp_skewed_lstat(candidate: Path):
        lstat_calls.append(candidate)
        info = real_lstat(candidate)

        class _TimestampSkewedStat:
            st_ctime_ns = info.st_ctime_ns + 1

            def __getattr__(self, name: str):
                return getattr(info, name)

        return _TimestampSkewedStat()

    monkeypatch.setattr(Path, "lstat", timestamp_skewed_lstat)

    assert historical_release_auth._read_bounded_regular_file(
        path,
        "historical checksums",
        max_bytes=1024,
    ) == payload
    assert lstat_calls == [path, path]


def test_oversized_historical_trust_input_fails_before_verification(tmp_path: Path) -> None:
    release, cosign, policy, asset = _release_fixture(tmp_path)
    (release / "checksums.txt.pem").write_bytes(
        b"A" * (historical_release_auth.MAX_CERTIFICATE_BYTES + 1)
    )

    with pytest.raises(
        historical_release_auth.HistoricalReleaseAuthError,
        match="invalid size",
    ):
        historical_release_auth.authenticate_release_assets(
            version="0.8.3",
            release_dir=release,
            assets=[asset],
            cosign=cosign,
            pin_policy=policy,
            runner=lambda *_args, **_kwargs: pytest.fail("cosign must not run"),
        )


def test_signed_checksum_authentication_uses_exact_main_workflow_identity(
    tmp_path: Path,
) -> None:
    release, cosign, policy, asset = _release_fixture(tmp_path)
    commands: list[list[str]] = []

    authenticated = historical_release_auth.authenticate_release_assets(
        version="0.8.3",
        release_dir=release,
        assets=[asset],
        cosign=cosign,
        pin_policy=policy,
        runner=_successful_runner(commands),
    )

    assert authenticated == {asset: "signed-checksums"}
    assert len(commands) == 1
    command = commands[0]
    assert command[command.index("--certificate-identity") + 1] == (
        "https://github.com/cisco-ai-defense/defenseclaw/"
        ".github/workflows/release.yaml@refs/heads/main"
    )
    assert "--certificate-identity-regexp" not in command


def test_cosign_and_parser_share_privately_staged_trust_inputs(tmp_path: Path) -> None:
    release, cosign, policy, asset = _release_fixture(tmp_path)
    original_checksums = (release / "checksums.txt").read_bytes()
    original_signature = (release / "checksums.txt.sig").read_bytes()

    def mutate_sources_after_verification(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        staged_certificate = Path(command[command.index("--certificate") + 1])
        staged_signature = Path(command[command.index("--signature") + 1])
        staged_checksums = Path(command[-1])

        assert staged_checksums != release / "checksums.txt"
        assert staged_signature != release / "checksums.txt.sig"
        assert staged_certificate != release / "checksums.txt.pem"
        assert staged_checksums.parent == staged_signature.parent == staged_certificate.parent
        assert staged_checksums.read_bytes() == original_checksums
        assert staged_signature.read_bytes() == original_signature
        assert staged_certificate.read_bytes() == PEM
        if os.name != "nt":
            assert staged_checksums.parent.stat().st_mode & 0o777 == 0o700
            for path in (staged_checksums, staged_signature, staged_certificate):
                assert path.stat().st_mode & 0o777 == 0o600

        mutated_payload = b"post-cosign pathname replacement"
        (release / asset).write_bytes(mutated_payload)
        (release / "checksums.txt").write_text(
            f"{hashlib.sha256(mutated_payload).hexdigest()}  {asset}\n"
        )
        (release / "checksums.txt.sig").write_text("replacement signature\n")
        (release / "checksums.txt.pem").write_bytes(PEM)
        return subprocess.CompletedProcess(command, 0, stdout="Verified OK", stderr="")

    with pytest.raises(
        historical_release_auth.HistoricalReleaseAuthError,
        match="signed checksum mismatch",
    ):
        historical_release_auth.authenticate_release_assets(
            version="0.8.3",
            release_dir=release,
            assets=[asset],
            cosign=cosign,
            pin_policy=policy,
            runner=mutate_sources_after_verification,
        )


def test_reviewed_digest_authenticates_wheel_omitted_from_old_signed_manifest(
    tmp_path: Path,
) -> None:
    release, cosign, policy, asset = _release_fixture(
        tmp_path,
        version="0.4.0",
        signed=False,
    )

    authenticated = historical_release_auth.authenticate_release_assets(
        version="0.4.0",
        release_dir=release,
        assets=[asset],
        cosign=cosign,
        pin_policy=policy,
        runner=_successful_runner([]),
    )

    assert authenticated == {asset: "reviewed-digest-exception"}


def test_uncovered_unpinned_or_mutated_historical_asset_fails_closed(
    tmp_path: Path,
) -> None:
    release, cosign, policy, asset = _release_fixture(
        tmp_path,
        version="0.4.0",
        signed=False,
    )
    policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "signed_wheel_coverage_starts_at": "0.6.1",
                "signed_checksum_exceptions": {},
            }
        )
    )
    with pytest.raises(
        historical_release_auth.HistoricalReleaseAuthError,
        match="no reviewed digest exception",
    ):
        historical_release_auth.authenticate_release_assets(
            version="0.4.0",
            release_dir=release,
            assets=[asset],
            cosign=cosign,
            pin_policy=policy,
            runner=_successful_runner([]),
        )

    release, cosign, policy, asset = _release_fixture(tmp_path / "mutated")
    (release / asset).write_bytes(b"mutated")
    with pytest.raises(
        historical_release_auth.HistoricalReleaseAuthError,
        match="signed checksum mismatch",
    ):
        historical_release_auth.authenticate_release_assets(
            version="0.8.3",
            release_dir=release,
            assets=[asset],
            cosign=cosign,
            pin_policy=policy,
            runner=_successful_runner([]),
        )


def test_reviewed_digest_exception_cannot_bypass_signed_wheel_boundary(
    tmp_path: Path,
) -> None:
    release, cosign, policy, asset = _release_fixture(
        tmp_path,
        version="0.8.3",
        signed=False,
    )

    with pytest.raises(
        historical_release_auth.HistoricalReleaseAuthError,
        match="older than the signed-wheel coverage boundary",
    ):
        historical_release_auth.authenticate_release_assets(
            version="0.8.3",
            release_dir=release,
            assets=[asset],
            cosign=cosign,
            pin_policy=policy,
            runner=_successful_runner([]),
        )


def test_reviewed_digest_exceptions_are_limited_to_unsigned_legacy_wheels() -> None:
    policy = json.loads(
        historical_release_auth.DEFAULT_PIN_POLICY.read_text(encoding="utf-8")
    )

    assert policy == {
        "schema_version": 1,
        "signed_wheel_coverage_starts_at": "0.6.1",
        "signed_checksum_exceptions": {
            "0.6.0": {
                "defenseclaw-0.6.0-py3-none-any.whl": (
                    "9d5e24280de6e092cc50f7f3335c58609c8e3fdeb9cb759e0c1d3e58ba9b6f74"
                )
            },
            "0.5.0": {
                "defenseclaw-0.5.0-py3-none-any.whl": (
                    "f27d87c00fa2cbade5aae06a2fb4f08e760d883cccbb216f935f34f7c9c587bd"
                )
            },
            "0.4.0": {
                "defenseclaw-0.4.0-py3-none-any.whl": (
                    "0cbf156cae9c32d08672d505564d4e9119dce200edb2bbf6d50a7cfb6d8a4458"
                )
            },
        },
    }
