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
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
UPGRADE_SCRIPT = ROOT / "scripts" / "upgrade.sh"

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="upgrade.sh staged-resolver contracts require a native POSIX shell; Windows upgrades use the native installer",
)


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _manifest(version: str) -> dict[str, object]:
    published_sources = [
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
    ]
    windows_sources = ["0.8.3", "0.8.2", "0.8.1", "0.8.0"]
    if version == "0.8.5":
        published_sources.insert(0, "0.8.4")
        windows_sources = []
    elif version in {"0.8.6", "0.8.7", "0.8.8"}:
        post_cut_sources = ["0.8.5", "0.8.4"]
        if version in {"0.8.7", "0.8.8"}:
            post_cut_sources.insert(0, "0.8.6")
        if version == "0.8.8":
            post_cut_sources.insert(0, "0.8.7")
        published_sources[0:0] = post_cut_sources
        windows_sources = [item for item in post_cut_sources if item not in {"0.8.5", "0.8.4"}]
    gateways = {
        platform_name: {
            arch: f"defenseclaw_{version}_protocol2_{platform_name}_{arch}.dcgateway" for arch in ("amd64", "arm64")
        }
        for platform_name in ("darwin", "linux", "windows")
    }
    payload: dict[str, object] = {
        "schema_version": 2,
        "release_version": version,
        "controller_upgrade_protocol": 2,
        "min_upgrade_protocol": 1,
        "migration_failure_policy": "warn",
        "required_cli_migrations": [],
        "runtime_config_version": 7 if version == "0.8.4" else 8,
        "release_artifacts": {
            "wheel": f"defenseclaw-{version}-2-py3-none-any.dcwheel",
            "gateways": gateways,
        },
        "tested_source_versions": published_sources,
        "platform_tested_source_versions": {"windows": windows_sources},
    }
    if version in {"0.8.5", "0.8.6", "0.8.7", "0.8.8"}:
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


def _protected(payload: bytes) -> bytes:
    return b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n" + bytes(value ^ 0xA5 for value in payload)


def _clean_086_package_files() -> dict[str, bytes]:
    return {
        "defenseclaw/__init__.py": b'__version__ = "0.8.6"\n',
        "defenseclaw/config.py": (
            b"import os\n"
            b"from types import SimpleNamespace\n"
            b"def load():\n"
            b"    home = os.environ['DEFENSECLAW_HOME']\n"
            b"    return SimpleNamespace(data_dir=home, claw=SimpleNamespace(home_dir=os.path.join(os.environ['HOME'], '.openclaw')))\n"
        ),
        "defenseclaw/observability/__init__.py": b"",
        "defenseclaw/observability/v8_config.py": (
            b"import copy, json\n"
            b"class Validated:\n"
            b"    def __init__(self, source): self._source = source\n"
            b"    @property\n"
            b"    def source(self): return copy.deepcopy(self._source)\n"
            b"def load_validate_v8(data, *, source_name='config.yaml'):\n"
            b"    if isinstance(data, bytes): data = data.decode('utf-8')\n"
            b"    source = json.loads(data) if isinstance(data, str) else dict(data)\n"
            b"    if type(source.get('config_version')) is not int or source['config_version'] != 8: raise ValueError('invalid v8 config')\n"
            b"    return Validated(source)\n"
        ),
        "defenseclaw/_data/local_observability_stack/README.md": b"authenticated clean 0.8.6 stack\n",
    }


def _clean_086_wheel() -> bytes:
    output = io.BytesIO()
    package_files = _clean_086_package_files()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in package_files.items():
            archive.writestr(name, payload)
        archive.writestr(
            "defenseclaw-0.8.6.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: defenseclaw\nVersion: 0.8.6\n",
        )
        archive.writestr(
            "defenseclaw-0.8.6.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr("defenseclaw-0.8.6.dist-info/RECORD", "")
    return output.getvalue()


def _clean_086_gateway_archive() -> bytes:
    payload = b"#!/usr/bin/env bash\nif [[ \"${1:-}\" == \"--version\" ]]; then echo 'DefenseClaw gateway 0.8.6'; exit 0; fi\nexit 0\n"
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        info = tarfile.TarInfo("defenseclaw")
        info.mode = 0o755
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _release_provenance(version: str, bridge_checksums_sha256: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_version": version,
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "policy_commit": "3" * 40,
        "policy_tree": "4" * 40,
        "release_source_map_sha256": "5" * 64,
        "source_install_identity": {
            "schema_version": 1,
            "source_release": version,
            "source_install_compatibility_epoch": 2,
            "runtime_config_version": 8,
        },
        "bridge": {
            "version": "0.8.4",
            "commit": "6" * 40,
            "tree": "7" * 40,
            "checksums_sha256": bridge_checksums_sha256,
        },
    }


@pytest.fixture
def resolver_env(tmp_path: Path):
    def build(current_version: str) -> tuple[dict[str, str], Path, Path]:
        fixtures = tmp_path / "fixtures"
        fake_bin = tmp_path / "bin"
        home = tmp_path / "home"
        fixtures.mkdir(exist_ok=True)
        fake_bin.mkdir(exist_ok=True)
        home.mkdir(exist_ok=True)

        bridge_checksums_sha256 = ""
        for version in ("0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8"):
            release_dir = fixtures / version
            release_dir.mkdir(exist_ok=True)
            manifest_payload = _manifest(version)
            manifest = json.dumps(manifest_payload, sort_keys=True).encode()
            (release_dir / "upgrade-manifest.json").write_bytes(manifest)
            checksum_rows = [f"{hashlib.sha256(manifest).hexdigest()}  upgrade-manifest.json"]
            release_artifacts = manifest_payload["release_artifacts"]
            assert isinstance(release_artifacts, dict)
            wheel_name = release_artifacts["wheel"]
            assert isinstance(wheel_name, str)
            wheel = release_dir / wheel_name
            wheel_payload = _clean_086_wheel() if version == "0.8.6" else b"resolver target wheel fixture"
            wheel.write_bytes(_protected(wheel_payload))
            checksum_rows.append(f"{hashlib.sha256(wheel.read_bytes()).hexdigest()}  {wheel.name}")
            gateways = release_artifacts["gateways"]
            assert isinstance(gateways, dict)
            for platform_gateways in gateways.values():
                assert isinstance(platform_gateways, dict)
                for gateway_name in platform_gateways.values():
                    assert isinstance(gateway_name, str)
                    gateway = release_dir / gateway_name
                    gateway_payload = (
                        _clean_086_gateway_archive()
                        if version == "0.8.6"
                        else f"gateway fixture {gateway_name}\n".encode()
                    )
                    gateway.write_bytes(_protected(gateway_payload) if version == "0.8.6" else gateway_payload)
                    checksum_rows.append(f"{hashlib.sha256(gateway.read_bytes()).hexdigest()}  {gateway.name}")
            if version in {"0.8.5", "0.8.6", "0.8.7", "0.8.8"}:
                provenance = (
                    json.dumps(
                        _release_provenance(version, bridge_checksums_sha256),
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n"
                ).encode()
                (release_dir / "release-provenance.json").write_bytes(provenance)
                checksum_rows.append(f"{hashlib.sha256(provenance).hexdigest()}  release-provenance.json")
            checksums_path = release_dir / "checksums.txt"
            checksums_path.write_text("\n".join(checksum_rows) + "\n", encoding="utf-8")
            if version == "0.8.4":
                bridge_checksums_sha256 = hashlib.sha256(checksums_path.read_bytes()).hexdigest()
            (release_dir / "checksums.txt.sig").write_text("test-signature\n", encoding="utf-8")
            (release_dir / "checksums.txt.pem").write_text("test-certificate\n", encoding="utf-8")

        _write_executable(
            fake_bin / "defenseclaw",
            f"#!/usr/bin/env bash\n"
            f'if [[ "${{1:-}}" == "--version" ]]; then echo \'DefenseClaw {current_version}\'; exit 0; fi\n'
            f"exit 97\n",
        )
        _write_executable(
            fake_bin / "defenseclaw-gateway",
            "#!/usr/bin/env bash\n"
            f'if [[ "${{1:-}}" == "--version" ]]; then echo \'DefenseClaw gateway {current_version}\'; exit 0; fi\n'
            'printf \'%s\\n\' "$*" >> "${MUTATION_LOG}"\n'
            "exit 98\n",
        )
        managed_bin = home / ".local" / "bin"
        managed_bin.mkdir(parents=True)
        shutil.copy2(fake_bin / "defenseclaw-gateway", managed_bin / "defenseclaw-gateway")
        _write_executable(
            fake_bin / "cosign",
            '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >> "${COSIGN_LOG}"\nexit 0\n',
        )
        _write_executable(
            fake_bin / "uv",
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'printf \'%s\\n\' "$*" >> "${UV_LOG}"\n'
            'if [[ "$#" -eq 10'
            ' && "$1" == "--no-config"'
            ' && "$2" == "pip"'
            ' && "$3" == "install"'
            ' && "$4" == "--python"'
            ' && "$5" == "${DEFENSECLAW_HOME}/.venv/bin/python"'
            ' && "$6" == "--dry-run"'
            ' && "$7" == "--quiet"'
            ' && "$8" == "--only-binary"'
            ' && "$9" == "litellm"'
            ' && "${10}" == */authenticated-source-0.8.6/defenseclaw-0.8.6-2-py3-none-any.whl ]]; then\n'
            "    exit 0\n"
            "fi\n"
            "exit 99\n",
        )
        _write_executable(
            fake_bin / "sha256sum",
            """#!/usr/bin/env bash
set -euo pipefail
case "${1##*/}" in
    cosign-darwin-amd64) sha='5715d61dd00a9b6dcb344de14910b434145855b7f82690b94183c553ac1b68be' ;;
    cosign-darwin-arm64) sha='ff497a698f125f3130b04f000b2cb0dd163bcaf00b5e776ef536035e6d0b3f3e' ;;
    cosign-linux-amd64) sha='7c78a7f2efc00088bd788a758db6e0928e79f3e0eb83eb5d3c499ed98da4c4f4' ;;
    cosign-linux-arm64) sha='b7c23659a50a59fd8eec44b87188e9062157d0c87796cac7b38727e5390c4917' ;;
    *)
        sha="$(python3 - "$1" <<'PY'
import hashlib
import sys
print(hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest())
PY
)"
        ;;
esac
printf '%s  %s\n' "${sha}" "$1"
""",
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
    if [[ "${arg}" == '-o' || "${arg}" == '--output' ]]; then
        want_out=1
    elif [[ "${arg}" == http* ]]; then
        url="${arg}"
    fi
done
if [[ "${url}" == */releases/latest ]]; then
    printf '{"tag_name":"0.8.7"}\n'
    exit 0
fi
if [[ "${url}" == https://github.com/sigstore/cosign/releases/download/* ]]; then
    [[ -n "${out}" ]] || exit 95
    cat > "${out}" <<'COSIGN'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${COSIGN_LOG}"
exit 0
COSIGN
    exit 0
fi
version=''
case "${url}" in
    */releases/download/0.8.4/*) version='0.8.4' ;;
    */releases/download/0.8.5/*) version='0.8.5' ;;
    */releases/download/0.8.6/*) version='0.8.6' ;;
    */releases/download/0.8.7/*) version='0.8.7' ;;
    */releases/download/0.8.8/*) version='0.8.8' ;;
esac
[[ -n "${version}" && -n "${out}" ]] || exit 96
name="${url##*/}"
cp "${FIXTURE_ROOT}/${version}/${name}" "${out}"
""",
        )

        mutation_log = tmp_path / "mutations.log"
        curl_log = tmp_path / "curl.log"
        cosign_log = tmp_path / "cosign.log"
        uv_log = tmp_path / "uv.log"
        env = os.environ.copy()
        for name in tuple(env):
            if name in {
                "DEFENSECLAW_DISABLE_REDACTION",
                "DEFENSECLAW_JSONL_DISABLE",
                "DEFENSECLAW_PERSIST_JUDGE",
            } or name.startswith(("OTEL_", "DEFENSECLAW_OTEL_", "OPENCLAW_OTEL_")):
                env.pop(name)
        env.update(
            {
                "PATH": f"{fake_bin}:{env['PATH']}",
                "HOME": str(home),
                "DEFENSECLAW_HOME": str(home / ".defenseclaw"),
                "FIXTURE_ROOT": str(fixtures),
                "MUTATION_LOG": str(mutation_log),
                "CURL_LOG": str(curl_log),
                "COSIGN_LOG": str(cosign_log),
                "UV_LOG": str(uv_log),
                "NO_COLOR": "1",
            }
        )
        return env, mutation_log, curl_log

    return build


def test_resolver_env_excludes_ambient_observability_decisions(
    resolver_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    names = (
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "DEFENSECLAW_OTEL_TRACES_ENDPOINT",
        "OPENCLAW_OTEL_TLS_INSECURE",
        "DEFENSECLAW_DISABLE_REDACTION",
    )
    for name in names:
        monkeypatch.setenv(name, "ambient")

    env, _mutation_log, _curl_log = resolver_env("0.8.6")

    assert all(name not in env for name in names)


def _install_clean_086_state(env: dict[str, str]) -> tuple[Path, Path]:
    data_home = Path(env["DEFENSECLAW_HOME"])
    data_home.mkdir()
    config_path = data_home / "config.yaml"
    clean_config = {
        "cisco_ai_defense": {"api_key_env": "CISCO_AI_DEFENSE_API_KEY"},
        "claw": {"mode": "codex"},
        "guardrail": {
            "connector": "codex",
            "enabled": True,
            "scanner_mode": "local",
        },
        "llm": {"api_key_env": "DEFENSECLAW_LLM_KEY"},
        "config_version": 8,
        "observability": {},
        "gateway": {"token_env": "DEFENSECLAW_GATEWAY_TOKEN"},
    }
    config_path.write_text(
        json.dumps(clean_config, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    stack = data_home / "observability-stack"

    site_packages = data_home / ".venv" / "lib" / "python3.12" / "site-packages"
    package_root = site_packages / "defenseclaw"
    package_root.mkdir(parents=True)
    for name, payload in _clean_086_package_files().items():
        relative = Path(name).relative_to("defenseclaw")
        destination = package_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    python_wrapper = data_home / ".venv" / "bin" / "python"
    python_wrapper.parent.mkdir(parents=True)
    _write_executable(
        python_wrapper,
        "#!/usr/bin/env bash\n"
        f"export PYTHONPATH={str(site_packages)!r}\n"
        "args=()\n"
        "for arg in \"$@\"; do [[ \"${arg}\" == \"-I\" ]] || args+=(\"${arg}\"); done\n"
        f"exec {str(sys.executable)!r} \"${{args[@]}}\"\n",
    )

    gateway_payload = (
        b"#!/usr/bin/env bash\n"
        b"if [[ \"${1:-}\" == \"--version\" ]]; then echo 'DefenseClaw gateway 0.8.6'; exit 0; fi\n"
        b"exit 0\n"
    )
    gateway = Path(env["HOME"]) / ".local" / "bin" / "defenseclaw-gateway"
    gateway.write_bytes(gateway_payload)
    gateway.chmod(0o755)
    return config_path, stack


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


@pytest.mark.skipif(os.name == "nt", reason="POSIX resolver controller-home guard")
@pytest.mark.parametrize("invalid_kind", ("relative", "control-character"))
def test_invalid_controller_home_stops_before_derived_paths_or_mutation(
    tmp_path: Path,
    invalid_kind: str,
) -> None:
    home = tmp_path / "home"
    fake_bin = tmp_path / "bin"
    home.mkdir()
    fake_bin.mkdir()
    python_calls = tmp_path / "python-calls.log"
    mutation_log = tmp_path / "mutations.log"
    _write_executable(
        fake_bin / "python3",
        f'#!/bin/sh\nprintf "%s\\n" python >> "$PYTHON_CALL_LOG"\nexec {str(sys.executable)!r} "$@"\n',
    )
    _write_executable(
        fake_bin / "curl",
        '#!/bin/sh\nprintf "%s\\n" curl >> "$MUTATION_LOG"\nexit 97\n',
    )
    environment = os.environ.copy()
    invalid_home = "relative-controller-home" if invalid_kind == "relative" else f"{tmp_path}/controller\nhome"
    environment.update(
        {
            "PATH": f"{fake_bin}:{environment['PATH']}",
            "HOME": str(home),
            "DEFENSECLAW_HOME": invalid_home,
            "PYTHON_CALL_LOG": str(python_calls),
            "MUTATION_LOG": str(mutation_log),
            "NO_COLOR": "1",
        }
    )

    completed = subprocess.run(
        ["bash", str(UPGRADE_SCRIPT), "--yes", "--version", "0.8.5", "--plan"],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "DEFENSECLAW_HOME must be an absolute stable controller path; no changes were made." in output
    assert python_calls.read_text(encoding="utf-8").splitlines() == ["python"]
    assert not mutation_log.exists()
    if invalid_kind == "relative":
        assert not (tmp_path / invalid_home).exists()
    assert not (home / ".defenseclaw").exists()
    assert not (home / ".local").exists()


def _rewrite_manifest(env: dict[str, str], version: str, payload: dict[str, object]) -> None:
    release_dir = Path(env["FIXTURE_ROOT"]) / version
    manifest = json.dumps(payload, sort_keys=True).encode()
    (release_dir / "upgrade-manifest.json").write_bytes(manifest)
    (release_dir / "checksums.txt").write_text(
        f"{hashlib.sha256(manifest).hexdigest()}  upgrade-manifest.json\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize("current_version", ("0.8.3", "0.8.0"))
def test_explicit_final_target_still_resolves_verified_two_hop_plan(
    resolver_env,
    current_version: str,
) -> None:
    env, mutation_log, curl_log = resolver_env(current_version)

    result = _run(env, "--version", "0.8.5", "--plan")

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert f"{current_version} → 0.8.4 bridge → fresh controller → 0.8.5" in output
    assert "No changes were made" in output
    assert not mutation_log.exists()
    assert not Path(env["DEFENSECLAW_HOME"]).exists()
    assert not Path(env["UV_LOG"]).exists()
    downloads = curl_log.read_text(encoding="utf-8")
    assert "/releases/download/0.8.5/upgrade-manifest.json" in downloads
    assert "/releases/download/0.8.4/upgrade-manifest.json" in downloads


@pytest.mark.parametrize("target_version", ("0.8.7", "0.8.8"))
@pytest.mark.parametrize("current_version", ("0.8.3", "0.7.1"))
def test_explicit_post_cut_target_stages_hard_cut_release(
    resolver_env,
    current_version: str,
    target_version: str,
) -> None:
    env, mutation_log, curl_log = resolver_env(current_version)

    result = _run(env, "--version", target_version, "--plan")

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert f"{current_version} → 0.8.4 bridge → fresh controller → 0.8.5 → {target_version}" in output
    assert "No changes were made" in output
    assert not mutation_log.exists()
    downloads = curl_log.read_text(encoding="utf-8")
    assert f"/releases/download/{target_version}/upgrade-manifest.json" in downloads
    assert "/releases/download/0.8.5/upgrade-manifest.json" in downloads
    assert "/releases/download/0.8.4/upgrade-manifest.json" in downloads


def test_bridge_manifest_runtime_config_boundary_is_fail_closed(resolver_env) -> None:
    env, mutation_log, _curl_log = resolver_env("0.8.3")
    manifest = _manifest("0.8.4")
    manifest["runtime_config_version"] = 8
    _rewrite_manifest(env, "0.8.4", manifest)

    result = _run(env, "--version", "0.8.4", "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "invalid runtime_config_version contract" in output
    assert not Path(env["DEFENSECLAW_HOME"]).exists()
    assert not mutation_log.exists()


def test_bridge_manifest_cannot_redirect_protected_artifact_name(resolver_env) -> None:
    env, mutation_log, _curl_log = resolver_env("0.8.3")
    manifest = _manifest("0.8.4")
    release_artifacts = manifest["release_artifacts"]
    assert isinstance(release_artifacts, dict)
    release_artifacts["wheel"] = "defenseclaw-0.8.4-py3-none-any.dcwheel"
    _rewrite_manifest(env, "0.8.4", manifest)

    result = _run(env, "--version", "0.8.4", "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "invalid release_artifacts contract" in output
    assert not Path(env["DEFENSECLAW_HOME"]).exists()
    assert not mutation_log.exists()


def test_normal_latest_resolves_verified_two_hop_plan(resolver_env) -> None:
    env, mutation_log, curl_log = resolver_env("0.8.3")

    result = _run(env, "--plan")

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "0.8.3 → 0.8.4 bridge → fresh controller → 0.8.5 → 0.8.7" in output
    assert "No changes were made" in output
    assert not mutation_log.exists()
    assert not Path(env["DEFENSECLAW_HOME"]).exists()
    downloads = curl_log.read_text(encoding="utf-8")
    assert "/releases/download/0.8.7/upgrade-manifest.json" in downloads
    assert "/releases/download/0.8.5/upgrade-manifest.json" in downloads
    assert "/releases/download/0.8.4/upgrade-manifest.json" in downloads
    assert "defenseclaw_0.8.5_protocol2_" in downloads
    assert "defenseclaw_0.8.4_protocol2_" in downloads
    assert "defenseclaw-0.8.5-2-py3-none-any.dcwheel" in downloads
    assert "defenseclaw-0.8.4-2-py3-none-any.dcwheel" in downloads


def test_unpublished_source_outside_matrix_fails_closed(resolver_env) -> None:
    env, mutation_log, _curl_log = resolver_env("0.3.0")

    result = _run(env, "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "outside the published-baseline test matrix" in output
    assert "There is no tested in-place upgrade path from 0.3.0" in output
    assert "Remain on 0.3.0" in output
    assert "contact DefenseClaw support" in output
    assert "--version" not in output
    assert "No changes were made" in output
    assert not Path(env["DEFENSECLAW_HOME"]).exists()
    assert not mutation_log.exists()


def test_explicit_bridge_from_unpublished_source_fails_closed(resolver_env) -> None:
    env, mutation_log, _curl_log = resolver_env("0.3.0")

    result = _run(env, "--version", "0.8.4", "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "outside the published-baseline test matrix for 0.8.4" in output
    assert "There is no tested in-place upgrade path from 0.3.0" in output
    assert "--version" not in output
    assert "No changes were made" in output
    assert not Path(env["DEFENSECLAW_HOME"]).exists()
    assert not mutation_log.exists()


@pytest.mark.parametrize(
    "current_version",
    ["0.7.0", "0.7.3"],
)
def test_unpublished_source_does_not_infer_forward_recovery_edge(
    resolver_env,
    current_version: str,
) -> None:
    env, mutation_log, _curl_log = resolver_env(current_version)

    result = _run(env, "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "outside the published-baseline test matrix" in output
    assert f"There is no tested in-place upgrade path from {current_version}" in output
    assert f"Remain on {current_version}" in output
    assert "--version" not in output
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


def test_component_version_mismatch_refuses_before_release_download_or_mutation(resolver_env) -> None:
    env, mutation_log, curl_log = resolver_env("0.8.5")
    managed_bin = Path(env["HOME"]) / ".local" / "bin"
    _write_executable(
        managed_bin / "defenseclaw-gateway",
        "#!/usr/bin/env bash\n"
        'if [[ "${1:-}" == "--version" ]]; then echo \'DefenseClaw gateway 0.8.3\'; exit 0; fi\n'
        'printf \'%s\\n\' "$*" >> "${MUTATION_LOG}"\n'
        "exit 98\n",
    )

    result = _run(env, "--version", "0.8.5", "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "Installed component versions are inconsistent: CLI 0.8.5, gateway 0.8.3" in output
    assert "package manager or manual artifact copy" in output
    assert "restore the CLI from the same signed 0.8.3 release" in output
    assert "No changes were made" in output
    assert not mutation_log.exists()
    assert not curl_log.exists()


def test_manual_hard_cut_artifacts_over_v7_state_refuse_before_release_download(resolver_env) -> None:
    env, mutation_log, curl_log = resolver_env("0.8.5")
    data_home = Path(env["DEFENSECLAW_HOME"])
    data_home.mkdir()
    (data_home / "config.yaml").write_text("config_version: 7\n", encoding="utf-8")

    result = _run(env, "--version", "0.8.5", "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "config-v8 migration state is absent or invalid" in output
    assert "Unsupported manual overwrite detected" in output
    assert "restore the exact 0.8.4 CLI, gateway, config, environment, and migration cursor" in output
    assert "No changes were made" in output
    assert not mutation_log.exists()
    assert not curl_log.exists()


@pytest.mark.parametrize(
    ("local_stack", "unrelated_change"),
    ((False, False), (True, False), (False, True)),
    ids=("retained-clean-no-stack", "exact-authenticated-stack", "valid-unrelated-llm-change"),
)
def test_clean_086_missing_cursor_authenticates_recovery_without_mutation(
    resolver_env,
    local_stack: bool,
    unrelated_change: bool,
) -> None:
    env, mutation_log, curl_log = resolver_env("0.8.6")
    config_path, stack = _install_clean_086_state(env)
    if local_stack:
        stack.mkdir()
        (stack / "README.md").write_bytes(b"authenticated clean 0.8.6 stack\n")
    if unrelated_change:
        document = json.loads(config_path.read_text(encoding="utf-8"))
        document["llm"]["model"] = "operator-selected-model"
        config_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    before = config_path.read_bytes()

    result = _run(env, "--version", "0.8.7", "--plan")

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "Authenticated the exact clean 0.8.6 missing-cursor compatibility state" in output
    assert "0.8.6 → 0.8.7" in output
    assert config_path.read_bytes() == before
    assert not (Path(env["DEFENSECLAW_HOME"]) / ".migration_state.json").exists()
    assert not mutation_log.exists()
    uv_invocation = Path(env["UV_LOG"]).read_text(encoding="utf-8").split()
    assert uv_invocation[:4] == ["--no-config", "pip", "install", "--python"]
    assert uv_invocation[4] == f"{env['DEFENSECLAW_HOME']}/.venv/bin/python"
    assert uv_invocation[5:9] == ["--dry-run", "--quiet", "--only-binary", "litellm"]
    assert Path(uv_invocation[9]).name == "defenseclaw-0.8.6-2-py3-none-any.whl"
    downloads = curl_log.read_text(encoding="utf-8")
    assert "/releases/download/0.8.6/release-provenance.json" in downloads
    assert "defenseclaw-0.8.6-2-py3-none-any.dcwheel" in downloads


def test_same_version_086_cursor_bootstrap_preserves_unrelated_v8_config_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from defenseclaw.migrations import run_migrations

    data_home = tmp_path / "data"
    data_home.mkdir()
    config_path = data_home / "config.yaml"
    config_path.write_text(
        json.dumps(
            {
                "config_version": 8,
                "llm": {
                    "api_key_env": "DEFENSECLAW_LLM_KEY",
                    "model": "operator-selected-model",
                },
                "observability": {},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    before = config_path.read_bytes()
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)

    count = run_migrations(
        "0.8.6",
        "0.8.6",
        str(tmp_path / "openclaw"),
        str(data_home),
        upgrade_handles_local_bundle=True,
    )

    assert count == 0
    assert config_path.read_bytes() == before
    cursor = json.loads((data_home / ".migration_state.json").read_text(encoding="utf-8"))
    assert "0.8.5" in cursor["applied"]


@pytest.mark.parametrize(
    "near_miss",
    (
        "cursor",
        "legacy-root",
        "observability",
        "stack",
        "migration-backup",
        "pending-cursor-retry",
        "receipt",
    ),
)
def test_clean_086_missing_cursor_recovery_rejects_near_miss_state(
    resolver_env,
    near_miss: str,
) -> None:
    env, mutation_log, _curl_log = resolver_env("0.8.6")
    config_path, stack = _install_clean_086_state(env)
    if near_miss == "cursor":
        (Path(env["DEFENSECLAW_HOME"]) / ".migration_state.json").write_text("{broken", encoding="utf-8")
    elif near_miss == "legacy-root":
        document = json.loads(config_path.read_text(encoding="utf-8"))
        document["otel"] = {}
        config_path.write_text(json.dumps(document), encoding="utf-8")
    elif near_miss == "observability":
        document = json.loads(config_path.read_text(encoding="utf-8"))
        document["observability"] = {"destinations": [{"name": "custom"}]}
        config_path.write_text(json.dumps(document), encoding="utf-8")
    elif near_miss == "stack":
        stack.mkdir()
        (stack / "README.md").write_bytes(b"operator drift\n")
    elif near_miss == "migration-backup":
        Path(f"{config_path}.pre-observability-migration.bak").write_bytes(b"residue\n")
    elif near_miss == "pending-cursor-retry":
        (Path(env["DEFENSECLAW_HOME"]) / ".migration_state.fresh.pending.json").write_text(
            "{}\n",
            encoding="utf-8",
        )
    else:
        (Path(env["DEFENSECLAW_HOME"]) / ".upgrade-receipts").mkdir()
    before = config_path.read_bytes()

    result = _run(env, "--version", "0.8.7", "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert (
        "config-v8 migration state is absent or invalid" in output
        if near_miss == "cursor"
        else "not the exact clean missing-cursor shape" in output
    )
    assert config_path.read_bytes() == before
    assert not mutation_log.exists()


def test_bridge_source_refreshes_before_direct_hard_cut(resolver_env) -> None:
    env, mutation_log, curl_log = resolver_env("0.8.4")

    result = _run(env, "--version", "0.8.5", "--plan")

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "Refresh authenticated 0.8.4 bridge → fresh controller → 0.8.5" in output
    assert not mutation_log.exists()
    downloads = curl_log.read_text(encoding="utf-8")
    assert "/releases/download/0.8.4/upgrade-manifest.json" in downloads
    assert "/releases/download/0.8.5/upgrade-manifest.json" in downloads


@pytest.mark.parametrize("target_version", ("0.8.7", "0.8.8"))
def test_bridge_source_stages_hard_cut_before_post_cut_target(resolver_env, target_version: str) -> None:
    env, mutation_log, curl_log = resolver_env("0.8.4")

    result = _run(env, "--version", target_version, "--plan")

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert f"Refresh authenticated 0.8.4 bridge → fresh controller → 0.8.5 → {target_version}" in output
    assert not mutation_log.exists()
    downloads = curl_log.read_text(encoding="utf-8")
    assert f"/releases/download/{target_version}/upgrade-manifest.json" in downloads
    assert "/releases/download/0.8.5/upgrade-manifest.json" in downloads
    assert "/releases/download/0.8.4/upgrade-manifest.json" in downloads


@pytest.mark.skipif(os.name == "nt", reason="POSIX release-owned resolver")
def test_modern_resolver_bootstraps_cosign_before_mutation(resolver_env) -> None:
    env, mutation_log, _curl_log = resolver_env("0.8.3")
    fake_bin = Path(env["PATH"].split(os.pathsep, 1)[0])
    (fake_bin / "cosign").unlink()
    controlled_system_bin = fake_bin.parent / "system-bin"
    controlled_system_bin.mkdir()
    for directory in os.defpath.split(os.pathsep):
        source_directory = Path(directory)
        if not source_directory.is_dir():
            continue
        for candidate in source_directory.iterdir():
            destination = controlled_system_bin / candidate.name
            if candidate.name == "cosign" or destination.exists() or not os.access(candidate, os.X_OK):
                continue
            destination.symlink_to(candidate)
    env["PATH"] = f"{fake_bin}:{controlled_system_bin}"
    assert shutil.which("cosign", path=env["PATH"]) is None

    result = _run(env, "--plan")

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "Cosign was not found; authenticating temporary Cosign 2.6.3" in output
    assert "Temporary Cosign verifier authenticated" in output
    assert not mutation_log.exists()


def test_modern_resolver_uses_exact_release_workflow_identity(resolver_env) -> None:
    env, mutation_log, _curl_log = resolver_env("0.8.3")

    result = _run(env, "--plan")

    assert result.returncode == 0, result.stdout + result.stderr
    invocation = Path(env["COSIGN_LOG"]).read_text(encoding="utf-8")
    assert "--certificate-identity " in invocation
    assert (
        "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main"
    ) in invocation
    assert "--certificate-identity-regexp" not in invocation
    assert not mutation_log.exists()


def test_hard_cut_provenance_is_required_before_any_resolver_mutation(resolver_env) -> None:
    env, mutation_log, _curl_log = resolver_env("0.8.3")
    (Path(env["FIXTURE_ROOT"]) / "0.8.5" / "release-provenance.json").unlink()

    result = _run(env, "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "release-provenance.json" in output
    assert "before services are stopped" in output
    assert not mutation_log.exists()


def test_staged_bridge_checksums_must_match_hard_cut_provenance_pre_stop(
    resolver_env,
) -> None:
    env, mutation_log, _curl_log = resolver_env("0.8.3")
    bridge_checksums = Path(env["FIXTURE_ROOT"]) / "0.8.4" / "checksums.txt"
    bridge_checksums.write_bytes(bridge_checksums.read_bytes() + b"\n")

    result = _run(env, "--plan")

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "Authenticated 0.8.4 checksums do not match release-provenance.json" in output
    assert "before services are stopped" in output
    assert not mutation_log.exists()
