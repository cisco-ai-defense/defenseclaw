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

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
UPGRADE_SCRIPT = ROOT / "scripts" / "upgrade.sh"


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _manifest(version: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "release_version": version,
        "controller_upgrade_protocol": 2,
        "min_upgrade_protocol": 1,
        "migration_failure_policy": "warn",
        "required_cli_migrations": [],
    }
    if version == "0.8.5":
        payload.update(
            {
                "min_upgrade_protocol": 2,
                "minimum_source_version": "0.8.4",
                "required_bridge_version": "0.8.4",
                "auto_bridge_from": [
                    "0.8.3",
                    "0.8.2",
                    "0.8.1",
                    "0.8.0",
                    "0.7.2",
                    "0.7.1",
                    "0.6.6",
                    "0.6.5",
                    "0.6.4",
                    "0.6.3",
                    "0.6.2",
                    "0.6.1",
                    "0.6.0",
                    "0.5.0",
                    "0.4.0",
                ],
                "required_cli_migrations": ["0.8.5"],
                "migration_failure_policy": "fail",
            }
        )
    return payload


@pytest.fixture
def resolver_env(tmp_path: Path):
    def build(current_version: str) -> tuple[dict[str, str], Path, Path]:
        fixtures = tmp_path / "fixtures"
        fake_bin = tmp_path / "bin"
        home = tmp_path / "home"
        fixtures.mkdir(exist_ok=True)
        fake_bin.mkdir(exist_ok=True)
        home.mkdir(exist_ok=True)

        for version in ("0.8.4", "0.8.5"):
            release_dir = fixtures / version
            release_dir.mkdir(exist_ok=True)
            manifest = json.dumps(_manifest(version), sort_keys=True).encode()
            (release_dir / "upgrade-manifest.json").write_bytes(manifest)
            digest = hashlib.sha256(manifest).hexdigest()
            (release_dir / "checksums.txt").write_text(
                f"{digest}  upgrade-manifest.json\n",
                encoding="utf-8",
            )
            (release_dir / "checksums.txt.sig").write_text("test-signature\n", encoding="utf-8")
            (release_dir / "checksums.txt.pem").write_text("test-certificate\n", encoding="utf-8")

        _write_executable(
            fake_bin / "defenseclaw",
            f"#!/usr/bin/env bash\n"
            f"if [[ \"${{1:-}}\" == \"--version\" ]]; then echo 'DefenseClaw {current_version}'; exit 0; fi\n"
            f"exit 97\n",
        )
        _write_executable(
            fake_bin / "defenseclaw-gateway",
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$*\" >> \"${MUTATION_LOG}\"\n"
            "exit 98\n",
        )
        _write_executable(
            fake_bin / "cosign",
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$*\" >> \"${COSIGN_LOG}\"\n"
            "exit 0\n",
        )
        _write_executable(
            fake_bin / "curl",
            """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${CURL_LOG}"
if [[ " $* " == *'%{http_code}'* ]]; then
    printf '200'
    exit 0
fi
out=''
url=''
want_out=0
for arg in "$@"; do
    if [[ "${want_out}" -eq 1 ]]; then
        out="${arg}"
        want_out=0
        continue
    fi
    if [[ "${arg}" == '-o' ]]; then
        want_out=1
    elif [[ "${arg}" == http* ]]; then
        url="${arg}"
    fi
done
if [[ "${url}" == */releases/latest ]]; then
    printf '{"tag_name":"0.8.5"}\n'
    exit 0
fi
version=''
case "${url}" in
    */releases/download/0.8.4/*) version='0.8.4' ;;
    */releases/download/0.8.5/*) version='0.8.5' ;;
esac
[[ -n "${version}" && -n "${out}" ]] || exit 96
name="${url##*/}"
cp "${FIXTURE_ROOT}/${version}/${name}" "${out}"
""",
        )

        mutation_log = tmp_path / "mutations.log"
        curl_log = tmp_path / "curl.log"
        cosign_log = tmp_path / "cosign.log"
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{fake_bin}:{env['PATH']}",
                "HOME": str(home),
                "DEFENSECLAW_HOME": str(home / ".defenseclaw"),
                "FIXTURE_ROOT": str(fixtures),
                "MUTATION_LOG": str(mutation_log),
                "CURL_LOG": str(curl_log),
                "COSIGN_LOG": str(cosign_log),
                "NO_COLOR": "1",
            }
        )
        return env, mutation_log, curl_log

    return build


def _run(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(UPGRADE_SCRIPT), "--yes", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )


def test_explicit_hard_cut_from_0_8_3_refuses_before_mutation(resolver_env) -> None:
    env, mutation_log, _curl_log = resolver_env("0.8.3")

    result = _run(env, "--version", "0.8.5", "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "0.8.5 requires the 0.8.4 upgrade bridge" in output
    assert "No changes were made" in output
    assert not mutation_log.exists()
    assert not Path(env["DEFENSECLAW_HOME"]).exists()


def test_normal_latest_resolves_verified_two_hop_plan(resolver_env) -> None:
    env, mutation_log, curl_log = resolver_env("0.8.3")

    result = _run(env, "--plan")

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "0.8.3 → 0.8.4 bridge → fresh controller → 0.8.5" in output
    assert "No changes were made" in output
    assert not mutation_log.exists()
    assert not Path(env["DEFENSECLAW_HOME"]).exists()
    downloads = curl_log.read_text(encoding="utf-8")
    assert "/releases/download/0.8.5/upgrade-manifest.json" in downloads
    assert "/releases/download/0.8.4/upgrade-manifest.json" in downloads


def test_unpublished_source_outside_matrix_fails_closed(resolver_env) -> None:
    env, mutation_log, _curl_log = resolver_env("0.3.0")

    result = _run(env, "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "outside the tested automatic bridge matrix" in output
    assert "--version 0.8.4" in output
    assert "re-run it without --version" in output
    assert "No changes were made" in output
    assert not Path(env["DEFENSECLAW_HOME"]).exists()
    assert not mutation_log.exists()


def test_existing_state_with_unknown_version_refuses_before_release_download(resolver_env) -> None:
    env, mutation_log, curl_log = resolver_env("0.8.3")
    fake_bin = Path(env["PATH"].split(os.pathsep, 1)[0])
    _write_executable(fake_bin / "defenseclaw", "#!/usr/bin/env bash\nexit 97\n")
    data_home = Path(env["DEFENSECLAW_HOME"])
    data_home.mkdir()
    marker = data_home / "partial-state"
    marker.write_bytes(b"preserve\n")

    result = _run(env, "--version", "0.8.4", "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "Could not determine the installed DefenseClaw version" in output
    assert "No changes were made" in output
    assert "Do not copy target artifacts" in output
    assert marker.read_bytes() == b"preserve\n"
    assert not mutation_log.exists()
    assert not curl_log.exists()


def test_bridge_source_resolves_direct_hard_cut(resolver_env) -> None:
    env, mutation_log, curl_log = resolver_env("0.8.4")

    result = _run(env, "--plan")

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "0.8.4 → 0.8.5" in output
    assert "bridge → fresh controller" not in output
    assert not mutation_log.exists()
    downloads = curl_log.read_text(encoding="utf-8")
    assert "/releases/download/0.8.4/upgrade-manifest.json" not in downloads


def test_modern_resolver_requires_cosign_before_mutation(resolver_env) -> None:
    env, mutation_log, _curl_log = resolver_env("0.8.3")
    (Path(env["PATH"].split(os.pathsep, 1)[0]) / "cosign").unlink()

    result = _run(env, "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "requires Sigstore provenance verification" in output
    assert "No changes were made" in output
    assert not mutation_log.exists()


def test_modern_resolver_uses_exact_release_workflow_identity(resolver_env) -> None:
    env, mutation_log, _curl_log = resolver_env("0.8.3")

    result = _run(env, "--plan")

    assert result.returncode == 0, result.stdout + result.stderr
    invocation = Path(env["COSIGN_LOG"]).read_text(encoding="utf-8")
    assert "--certificate-identity " in invocation
    assert (
        "https://github.com/cisco-ai-defense/defenseclaw/"
        ".github/workflows/release.yaml@refs/heads/main"
    ) in invocation
    assert "--certificate-identity-regexp" not in invocation
    assert not mutation_log.exists()
