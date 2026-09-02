# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""A fresh wheel owns the complete stack bundle and Python controller."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE = REPO_ROOT / "bundles" / "local_observability_stack"


def _is_generated_grafana_credential(relative_path: str) -> bool:
    name = Path(relative_path).name
    return name in {".grafana-admin-password", ".grafana-access-mode"} or (
        name.startswith(("..grafana-admin-password.", "..grafana-access-mode.")) and name.endswith(".tmp")
    )


def test_generated_grafana_credentials_are_ignored_in_source_checkouts() -> None:
    ignored = set((BUNDLE / ".gitignore").read_text(encoding="utf-8").splitlines())
    assert ".grafana-admin-password" in ignored
    assert "..grafana-admin-password.*.tmp" in ignored
    assert ".grafana-access-mode" in ignored
    assert "..grafana-access-mode.*.tmp" in ignored


def test_golden_ci_bridge_cleanup_uses_the_managed_reset_contract() -> None:
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    cleanup = "bundles/local_observability_stack/bin/openclaw-observability-bridge reset"
    assert cleanup in workflow
    assert cleanup + " --yes" not in workflow


def _copy_make_bundle_inputs(destination: Path) -> None:
    for relative in (
        Path("policies"),
        Path("bundles/llm"),
        Path("bundles/local_observability_stack"),
        Path("bundles/splunk_local_bridge"),
        Path("bundles/splunk_o11y_dashboards"),
        Path("schemas/config/v8"),
        Path("schemas/telemetry/runtime"),
        Path("skills/codeguard"),
    ):
        shutil.copytree(REPO_ROOT / relative, destination / relative)
    for relative in (
        Path("Makefile"),
        Path("scripts/gen_envvars_docs.py"),
        Path("scripts/install-openshell-sandbox.sh"),
        Path("scripts/telemetry_runtime_assets.py"),
        Path("internal/envvars/registry.json"),
        Path("cli/defenseclaw/__init__.py"),
        Path("cli/defenseclaw/envvars.py"),
    ):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / relative, target)


@pytest.mark.skipif(shutil.which("make") is None, reason="make is required")
@pytest.mark.parametrize("without_rsync", [False, True])
def test_make_bundle_data_purges_generated_grafana_credentials(
    tmp_path: Path,
    without_rsync: bool,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _copy_make_bundle_inputs(source)

    marker = b"generated-grafana-" + b"credential-marker"
    source_bundle = source / "bundles/local_observability_stack"
    staged_bundle = source / "cli/defenseclaw/_data/local_observability_stack"
    staged_bundle.mkdir(parents=True)
    reserved_names = (
        ".grafana-admin-password",
        "..grafana-admin-password.interrupted-write.tmp",
        ".grafana-access-mode",
        "..grafana-access-mode.interrupted-write.tmp",
    )
    for bundle in (source_bundle, staged_bundle):
        for name in reserved_names:
            (bundle / name).write_bytes(marker)

    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    if without_rsync:
        if os.name == "nt":
            pytest.skip("the native Windows make path already has no rsync")
        command_dir = tmp_path / "commands-without-rsync"
        command_dir.mkdir()
        for command in ("cp", "mkdir", "python3", "rm"):
            executable = shutil.which(command)
            assert executable is not None
            (command_dir / command).symlink_to(executable)
        environment["PATH"] = str(command_dir)
    completed = subprocess.run(
        [shutil.which("make"), "-s", "_bundle-data"],
        cwd=source,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-4000:]

    assert all((source_bundle / name).read_bytes() == marker for name in reserved_names)
    assert not any((staged_bundle / name).exists() for name in reserved_names)
    assert (staged_bundle / "README.md").read_bytes() == (source_bundle / "README.md").read_bytes()


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is required to build wheels")
def test_wheel_resolves_complete_stack_outside_source_checkout(tmp_path: Path) -> None:
    output = tmp_path / "wheel"
    env = os.environ.copy()
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [shutil.which("uv"), "build", "--wheel", "--out-dir", str(output)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-4000:]
    wheel = next(output.glob("defenseclaw-*.whl"))
    expected_assets = {
        path.relative_to(BUNDLE).as_posix()
        for path in BUNDLE.rglob("*")
        if path.is_file() and not _is_generated_grafana_credential(path.relative_to(BUNDLE).as_posix())
    }
    prefix = "defenseclaw/_data/local_observability_stack/"
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        packaged_assets = {name.removeprefix(prefix) for name in names if name.startswith(prefix)}
        assert not any(_is_generated_grafana_credential(name) for name in packaged_assets)
        assert expected_assets <= packaged_assets
        for relative_path in expected_assets:
            assert archive.read(prefix + relative_path) == (BUNDLE / Path(relative_path)).read_bytes(), (
                f"packaged local-observability asset drifted: {relative_path}"
            )
        assert "defenseclaw/observability/local_stack.py" in names
        entry_points = next(name for name in names if name.endswith(".dist-info/entry_points.txt"))
        assert "defenseclaw-observability = defenseclaw.observability.local_stack:main" in archive.read(
            entry_points
        ).decode("utf-8")
        archive.extractall(tmp_path / "site")

    probe = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            (
                "import pathlib,sys;sys.path.insert(0,sys.argv[1]);"
                "from defenseclaw.paths import bundled_local_observability_dir;"
                "p=bundled_local_observability_dir();"
                "assert p.is_dir();assert (p/'docker-compose.yml').is_file();"
                "assert sys.argv[2] not in str(p);print(p)"
            ),
            str(tmp_path / "site"),
            str(REPO_ROOT),
        ],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
    assert "_data" in probe.stdout
