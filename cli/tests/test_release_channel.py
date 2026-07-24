# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts import release_candidate, release_channel

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "cisco-ai-defense/defenseclaw"
VERSION = "0.8.8"
COMMIT = "a" * 40
RESCUE = ROOT / "scripts/defenseclaw-rescue.sh"
PUBLISHER = ROOT / "scripts/publish-release-channel.sh"
WORKFLOW = ROOT / ".github/workflows/release.yaml"
DOC = ROOT / "docs/RELEASE_CHANNEL.md"


def _record(*, digest: str = "b" * 64) -> dict[str, str]:
    return release_channel.build_channel(
        repository=REPOSITORY,
        version=VERSION,
        commit=COMMIT,
        resolver_sha256=digest,
    )


def test_channel_manifest_canonically_binds_immutable_resolver(tmp_path: Path) -> None:
    checksums = tmp_path / "checksums.txt"
    checksums.write_text(
        f"{'1' * 64}  unrelated.bin\n{'b' * 64}  defenseclaw-upgrade.sh\n",
        encoding="ascii",
    )

    digest = release_channel.resolver_digest_from_checksums(checksums)
    payload = release_channel.render_channel(_record(digest=digest))
    parsed = release_channel.parse_channel(payload)

    assert digest == "b" * 64
    assert list(parsed) == list(release_channel.FIELD_ORDER)
    assert parsed == {
        "schema": "defenseclaw-release-channel-v1",
        "channel": "stable",
        "repository": REPOSITORY,
        "target_version": VERSION,
        "target_tag": VERSION,
        "target_ref": f"refs/tags/{VERSION}",
        "target_commit": COMMIT,
        "resolver_name": "defenseclaw-upgrade.sh",
        "resolver_url": (f"https://github.com/{REPOSITORY}/releases/download/{VERSION}/defenseclaw-upgrade.sh"),
        "resolver_sha256": "b" * 64,
    }
    assert payload.endswith(b"\n")
    assert len(payload.splitlines()) == 10


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("target_tag", "v0.8.8", "tag does not equal"),
        ("target_ref", "refs/heads/main", "exact immutable tag ref"),
        ("target_commit", "A" * 40, "lowercase Git object ID"),
        ("resolver_name", "bootstrap.sh", "reviewed POSIX resolver"),
        (
            "resolver_url",
            "https://attacker.invalid/defenseclaw-upgrade.sh",
            "not derived",
        ),
        ("resolver_sha256", "B" * 64, "lowercase SHA-256"),
    ],
)
def test_channel_manifest_rejects_unbound_target_fields(
    field: str,
    value: str,
    message: str,
) -> None:
    record = _record()
    record[field] = value

    with pytest.raises(release_channel.ChannelError, match=message):
        release_channel.validate_channel(record)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        release_channel.render_channel_without_validation(_record()).rstrip(b"\n"),
        release_channel.render_channel_without_validation(_record()).replace(
            b"channel=stable\nrepository=",
            b"repository=cisco-ai-defense/defenseclaw\nchannel=",
        ),
        release_channel.render_channel_without_validation(_record()) + b"extra=x\n",
        release_channel.render_channel_without_validation(_record()).replace(
            b"stable\n",
            b"stabl\xc3\xa9\n",
            1,
        ),
    ],
)
def test_channel_parser_rejects_noncanonical_wire_encodings(payload: bytes) -> None:
    with pytest.raises(release_channel.ChannelError):
        release_channel.parse_channel(payload)


def test_channel_comparison_is_idempotent_and_monotonic() -> None:
    current = _record()
    assert release_channel.compare_channels(current, dict(current)) == "same"

    advanced = release_channel.build_channel(
        repository=REPOSITORY,
        version="0.8.9",
        commit="c" * 40,
        resolver_sha256="d" * 64,
    )
    assert release_channel.compare_channels(current, advanced) == "advance"

    with pytest.raises(release_channel.ChannelError, match="roll back"):
        release_channel.compare_channels(advanced, current)

    conflict = dict(current)
    conflict["target_commit"] = "e" * 40
    with pytest.raises(release_channel.ChannelError, match="already-published"):
        release_channel.compare_channels(current, conflict)


def test_channel_checksum_extraction_rejects_missing_duplicate_or_malformed(
    tmp_path: Path,
) -> None:
    checksums = tmp_path / "checksums.txt"
    checksums.write_text(f"{'a' * 64}  other.bin\n", encoding="ascii")
    with pytest.raises(release_channel.ChannelError, match="does not bind"):
        release_channel.resolver_digest_from_checksums(checksums)

    checksums.write_text(
        f"{'a' * 64}  defenseclaw-upgrade.sh\n{'b' * 64}  defenseclaw-upgrade.sh\n",
        encoding="ascii",
    )
    with pytest.raises(release_channel.ChannelError, match="duplicate"):
        release_channel.resolver_digest_from_checksums(checksums)

    checksums.write_text(
        f"{'a' * 64} *defenseclaw-upgrade.sh\n",
        encoding="ascii",
    )
    with pytest.raises(release_channel.ChannelError, match="invalid"):
        release_channel.resolver_digest_from_checksums(checksums)


def _write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


def _rescue_fixture(
    tmp_path: Path,
    *,
    channel_payload: bytes | None = None,
    resolver_payload: bytes | None = None,
    cosign_exit: int = 0,
) -> tuple[dict[str, str], Path]:
    fixture = tmp_path / "fixture"
    fake_bin = tmp_path / "bin"
    fixture.mkdir()
    fake_bin.mkdir()
    resolver_payload = resolver_payload or (
        b"#!/usr/bin/env bash\n"
        b"printf 'resolver-args:'\n"
        b"printf ' <%s>' \"$@\"\n"
        b"printf '\\n'\n"
        b"# DefenseClaw upgrade resolver complete v1\n"
    )
    (fixture / "resolver.sh").write_bytes(resolver_payload)
    digest = hashlib.sha256(resolver_payload).hexdigest()
    channel_payload = channel_payload or release_channel.render_channel(_record(digest=digest))
    (fixture / "stable.txt").write_bytes(channel_payload)
    (fixture / "stable.txt.bundle").write_text("fixture bundle\n", encoding="ascii")

    _write_executable(
        fake_bin / "curl",
        """#!/usr/bin/env bash
set -euo pipefail
destination=""
url=""
while (($#)); do
  case "$1" in
    --output) destination="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
printf '%s\\n' "$url" >> "$RESCUE_CURL_LOG"
case "$url" in
  */release-channel/stable.txt) source="$RESCUE_FIXTURE/stable.txt" ;;
  */release-channel/stable.txt.bundle) source="$RESCUE_FIXTURE/stable.txt.bundle" ;;
  */releases/download/*/defenseclaw-upgrade.sh) source="$RESCUE_FIXTURE/resolver.sh" ;;
  *) printf 'unexpected URL: %s\\n' "$url" >&2; exit 90 ;;
esac
cp "$source" "$destination"
""",
    )
    _write_executable(
        fake_bin / "cosign",
        f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$RESCUE_COSIGN_LOG"
exit {cosign_exit}
""",
    )
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "RESCUE_FIXTURE": str(fixture),
            "RESCUE_CURL_LOG": str(tmp_path / "curl.log"),
            "RESCUE_COSIGN_LOG": str(tmp_path / "cosign.log"),
            "TMPDIR": str(tmp_path),
        }
    )
    return env, fixture


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_authenticates_channel_then_executes_exact_tagged_resolver(
    tmp_path: Path,
) -> None:
    env, _fixture = _rescue_fixture(tmp_path)

    completed = subprocess.run(
        [str(RESCUE), "--yes", "--recover-corrupt-audit"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert f"Authenticated stable resolver {VERSION} ({COMMIT})" in completed.stdout
    assert (f"resolver-args: <--version> <{VERSION}> <--yes> <--recover-corrupt-audit>") in completed.stdout
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8").splitlines()
    assert curl_log[:2] == [
        f"https://raw.githubusercontent.com/{REPOSITORY}/release-channel/stable.txt",
        f"https://raw.githubusercontent.com/{REPOSITORY}/release-channel/stable.txt.bundle",
    ]
    assert curl_log[2] == (f"https://github.com/{REPOSITORY}/releases/download/{VERSION}/defenseclaw-upgrade.sh")
    cosign_log = (tmp_path / "cosign.log").read_text(encoding="utf-8")
    assert "verify-blob" in cosign_log
    assert "--bundle" in cosign_log
    assert (f"https://github.com/{REPOSITORY}/.github/workflows/release.yaml@refs/heads/main") in cosign_log


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_rejects_signed_but_redirected_channel_before_resolver_download(
    tmp_path: Path,
) -> None:
    payload = release_channel.render_channel_without_validation(_record()).replace(
        (f"resolver_url=https://github.com/{REPOSITORY}/releases/download/{VERSION}/defenseclaw-upgrade.sh").encode(),
        b"resolver_url=https://attacker.invalid/defenseclaw-upgrade.sh",
    )
    env, _fixture = _rescue_fixture(tmp_path, channel_payload=payload)

    completed = subprocess.run(
        [str(RESCUE), "--yes"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "resolver URL is not derived" in completed.stderr
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8").splitlines()
    assert len(curl_log) == 2
    assert all("attacker.invalid" not in line for line in curl_log)


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_signature_failure_stops_before_channel_parse_or_resolver_download(
    tmp_path: Path,
) -> None:
    env, _fixture = _rescue_fixture(
        tmp_path,
        channel_payload=b"not a channel\n",
        cosign_exit=42,
    )

    completed = subprocess.run(
        [str(RESCUE), "--yes"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 42
    assert "unsupported channel schema" not in completed.stderr
    assert len((tmp_path / "curl.log").read_text().splitlines()) == 2


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
@pytest.mark.parametrize(
    "forbidden",
    ["--version", "--version=0.8.7", "--allow-unverified"],
)
def test_rescue_refuses_target_or_authentication_override_before_network(
    tmp_path: Path,
    forbidden: str,
) -> None:
    env, _fixture = _rescue_fixture(tmp_path)

    completed = subprocess.run(
        [str(RESCUE), forbidden],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert not (tmp_path / "curl.log").exists()


def test_release_workflow_advances_channel_only_after_immutable_custody() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    publish = workflow["jobs"]["publish-release"]
    assert publish["permissions"] == {"contents": "write", "id-token": "write"}
    names = [step.get("name") for step in publish["steps"]]
    assert names.index("Prove published asset custody") < names.index("Sign and advance authenticated stable channel")
    channel_step = next(
        step for step in publish["steps"] if step.get("name") == "Sign and advance authenticated stable channel"
    )
    assert channel_step["run"] == "scripts/publish-release-channel.sh"
    assert channel_step["env"]["RELEASE_CHECKSUMS"].endswith("/release-candidate/dist/checksums.txt")

    publisher = PUBLISHER.read_text(encoding="utf-8")
    assert "cosign sign-blob" in publisher
    assert "scripts/verify-sigstore-blob.py" in publisher
    assert 'scripts/release_channel.py" compare' in publisher
    assert "git/matching-refs/heads/${CHANNEL_BRANCH}" in publisher
    assert '"parents": [parent] if parent else []' in publisher
    assert "-F force=false" in publisher
    assert "force=true" not in publisher
    assert "git push" not in publisher


def test_rescue_is_an_immutable_signed_asset_from_088_forward(
    tmp_path: Path,
) -> None:
    assert "defenseclaw-rescue.sh" not in release_candidate.payload_asset_names("0.8.7", "unverified")
    assert "defenseclaw-rescue.sh" in release_candidate.payload_asset_names("0.8.8", "unverified")
    assert release_candidate.RESOLVER_ASSET_SOURCES["defenseclaw-rescue.sh"] == RESCUE
    assert release_candidate._validated_resolver_source("defenseclaw-rescue.sh") == RESCUE
    assert RESCUE.read_bytes().splitlines()[-1] == (release_candidate.RESCUE_COMPLETENESS_MARKER)
    staged = tmp_path / "staged"
    staged.mkdir()
    release_candidate.stage_resolvers(staged, "0.8.8")
    assert (staged / "defenseclaw-rescue.sh").read_bytes() == RESCUE.read_bytes()


def test_release_channel_scripts_have_valid_bash_syntax() -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable")
    subprocess.run(
        [bash, "-n", str(RESCUE), str(PUBLISHER)],
        cwd=ROOT,
        check=True,
    )


def test_release_channel_documentation_preserves_trust_boundary() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "mutable pointer to immutable code",
        "`release-channel` branch",
        "`release.yaml@main` Fulcio identity",
        "Do not stream a raw branch or release response directly into a shell.",
        "The bootstrap rejects an operator-supplied `--version`",
        "non-forced, fast-forward Git",
    ):
        assert required in text
