# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""A fresh wheel owns the complete stack bundle and Python controller."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE = REPO_ROOT / "bundles" / "local_observability_stack"


def test_grafana_provisions_the_documented_defenseclaw_folder() -> None:
    provider = (BUNDLE / "grafana/provisioning/dashboards/dashboards.yml").read_text(encoding="utf-8")
    # Grafana requires foldersFromFilesStructure to be unset when a provider
    # names a folder. The dashboard JSON files live at the path root.
    assert "folder: DefenseClaw" in provider
    assert "foldersFromFilesStructure:" not in provider


FLEET_TEMPLATES = {
    "docker-compose.fleet.yml",
    "prometheus/examples/fleet.yml",
    "grafana/dashboards/defenseclaw-fleet.json",
}


# A fake docker that records each Compose call and renders the Grafana sign-in
# mode the given files produce, as real Compose does: the base file alone keeps
# anonymous read-only Viewer access; the password overlay turns it off.
_FAKE_DOCKER = """#!/bin/sh
set -eu
test "$1" = compose
shift
files=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -f) shift; test -f "$1"; files="$files $(basename "$1")" ;;
    --project-directory|--project-name) echo "$1=$2" >> "$COMPOSE_LOG"; shift ;;
    *) break ;;
  esac
  shift
done
case "$1" in
  config)
    case "$files" in
      *docker-compose.password.yml*) [ -z "${FAKE_OVERLAY_IGNORED:-}" ] && anonymous='"false"' || anonymous='"true"' ;;
      *) anonymous='"true"' ;;
    esac
    printf 'services:\n  grafana:\n    environment:\n      GF_AUTH_ANONYMOUS_ENABLED: %s\n      GF_AUTH_ANONYMOUS_ORG_ROLE: %s\n' "$anonymous" "${FAKE_ANONYMOUS_ROLE:-Viewer}" ;;
  up)
    test -f grafana/dashboards/defenseclaw-fleet.json
    test -f prometheus/scrape.d/fleet.yml
    echo "up files:$files password:${GRAFANA_ADMIN_PASSWORD:-}" >> "$COMPOSE_LOG" ;;
  *) exit 64 ;;
esac
"""


def _run_fleet_recipe(
    tmp_path: Path, mode: str | None, **extra_env: str
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    home = tmp_path / "home"
    stack = home / ".defenseclaw/observability-stack"
    shutil.copytree(BUNDLE, stack)
    for generated in (".grafana-access-mode", ".grafana-admin-password"):
        (stack / generated).unlink(missing_ok=True)
    if mode is not None:
        # What `defenseclaw setup local-observability up` leaves behind.
        (stack / ".grafana-access-mode").write_text(mode + "\n", encoding="utf-8")
        (stack / ".grafana-admin-password").write_text("saved-test-password", encoding="utf-8")
    assets = tmp_path / "extracted-assets"
    for relative in FLEET_TEMPLATES:
        source = stack / relative
        target = assets / "bundles/local_observability_stack" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        source.unlink()
    shutil.rmtree(stack / "prometheus/scrape.d", ignore_errors=True)
    commands = tmp_path / "bin"
    commands.mkdir()
    docker = commands / "docker"
    docker.write_text(_FAKE_DOCKER, encoding="utf-8")
    docker.chmod(0o755)
    page = (REPO_ROOT / "docs-site/content/docs/edge-connector/install.mdx").read_text(encoding="utf-8")
    section = page.split("## Grafana dashboard\n", 1)[1].split("## Benchmark\n", 1)[0]
    recipe = re.search(r"```bash\n(.*?)```", section, re.DOTALL)
    assert recipe is not None
    log = tmp_path / "compose.log"
    environment = os.environ.copy()
    environment.pop("GRAFANA_ADMIN_PASSWORD", None)
    environment.update(
        HOME=str(home),
        PATH=str(commands) + os.pathsep + environment["PATH"],
        DCLAW_FLEET_API_TOKEN="provided by the test credential store",
        COMPOSE_LOG=str(log),
        **extra_env,
    )
    result = subprocess.run(
        ["bash", "-euc", recipe[1].replace("/path/to/extracted-assets", str(assets))],
        cwd=assets,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    return result, stack, log


@pytest.mark.skipif(os.name == "nt", reason="documented POSIX shell recipe")
@pytest.mark.parametrize(
    ("mode", "want_files", "want_password"),
    [
        ("password", " docker-compose.yml docker-compose.password.yml docker-compose.fleet.yml", "saved-test-password"),
        ("no-password", " docker-compose.yml docker-compose.fleet.yml", ""),
    ],
)
def test_fleet_dashboard_recipe_keeps_the_saved_grafana_sign_in(
    tmp_path: Path, mode: str, want_files: str, want_password: str
) -> None:
    result, stack, log = _run_fleet_recipe(tmp_path, mode)
    assert result.returncode == 0, result.stdout + result.stderr
    for relative in ("grafana/dashboards/defenseclaw-fleet.json", "prometheus/scrape.d/fleet.yml"):
        assert (stack / relative).is_file()
    calls = log.read_text(encoding="utf-8").splitlines()
    ups = [line for line in calls if line.startswith("up ")]
    # One start, in the managed project, with the saved sign-in overlay and
    # its password (anonymous Viewer only where setup chose no-password).
    assert ups == [f"up files:{want_files} password:{want_password}"], calls
    assert "--project-name=defenseclaw-observability" in calls, calls


@pytest.mark.skipif(os.name == "nt", reason="documented POSIX shell recipe")
@pytest.mark.parametrize(
    ("mode", "extra_env"),
    [
        (None, {}),  # no stack made by setup: the sign-in mode is unknown
        ("anonymous", {}),  # unrecognized saved mode
        ("password", {"FAKE_OVERLAY_IGNORED": "1"}),  # Compose renders anonymous access anyway
    ],
)
def test_fleet_dashboard_recipe_starts_nothing_without_the_saved_sign_in(
    tmp_path: Path, mode: str | None, extra_env: dict[str, str]
) -> None:
    result, _stack, log = _run_fleet_recipe(tmp_path, mode, **extra_env)
    assert result.returncode != 0, result.stdout + result.stderr
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    assert not [line for line in calls if line.startswith("up ")], calls


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
        Path("edge-connector"),
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
        Path("scripts/refuse-sudo-user-checkout.sh"),
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
        for command in ("bash", "cp", "id", "mkdir", "python3", "rm", "stat"):
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


_COUNT_WORDS = (
    "one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|"
    "sixteen|seventeen|eighteen|nineteen|twenty"
)


def _seeded_dashboard_uids(bundle: Path, data_dir: Path) -> set[str]:
    from unittest.mock import patch

    from defenseclaw.bundle_refresh import refresh_local_observability_stack

    data_dir.mkdir()
    with patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=bundle):
        result = refresh_local_observability_stack(str(data_dir))
    assert result.errors == []
    dashboards = Path(result.seeded_dest) / "grafana" / "dashboards"
    return {json.loads(path.read_text(encoding="utf-8"))["uid"] for path in dashboards.glob("*.json")}


def test_documented_dashboard_counts_match_both_install_paths(tmp_path: Path) -> None:
    """Docs counts match what a wheel and what a source checkout actually seed.

    A wheel stages ``bundles/`` through ``make _bundle-data``, which drops the
    optional Fleet templates; an editable install seeds ``bundles/`` as is.
    """
    from defenseclaw import paths

    if paths._REPO_ROOT.resolve() == REPO_ROOT.resolve():
        assert paths.bundled_local_observability_dir().resolve() == BUNDLE.resolve()
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    staged_out = set(re.findall(r'_data/\$\$d/((?:grafana|prometheus)/[^"]+|docker-compose\.fleet\.yml)"', makefile))
    assert staged_out == FLEET_TEMPLATES

    wheel_bundle = tmp_path / "wheel-bundle"
    shutil.copytree(
        BUNDLE,
        wheel_bundle,
        ignore=lambda directory, names: [
            name
            for name in names
            if (Path(directory) / name).relative_to(BUNDLE).as_posix() in FLEET_TEMPLATES
            or _is_generated_grafana_credential(name)
        ],
    )
    wheel = _seeded_dashboard_uids(wheel_bundle, tmp_path / "wheel-home")
    source = _seeded_dashboard_uids(BUNDLE, tmp_path / "source-home")
    assert source == wheel | {"defenseclaw-fleet"} and "defenseclaw-fleet" not in wheel

    docs = REPO_ROOT / "docs-site/content/docs"
    pages = {
        "run-grafana-locally": (docs / "how-to/observability/run-grafana-locally.mdx").read_text(encoding="utf-8"),
        "dashboards": (docs / "reference/observability/dashboards.mdx").read_text(encoding="utf-8"),
        "bundle README": (BUNDLE / "README.md").read_text(encoding="utf-8"),
    }
    for name, page in pages.items():
        flat = " ".join(page.split())
        core_counts = re.findall(r"\b(\d+) (?:bundled |core )?(?:Grafana |DefenseClaw )?dashboards\b", flat)
        source_counts = re.findall(r"\b(\d+) from a source checkout\b", flat)
        assert core_counts and {int(count) for count in core_counts} == {len(wheel)}, name
        assert source_counts and {int(count) for count in source_counts} == {len(source)}, name
        spelled = re.finditer(rf"\b(?:{_COUNT_WORDS})\b(?:\s+\S+){{0,3}}\s+dashboards?\b", flat, re.IGNORECASE)
        assert [match[0] for match in spelled if "splunk" not in match[0].lower()] == [], name


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
        and path.relative_to(BUNDLE).as_posix() not in FLEET_TEMPLATES
    }
    prefix = "defenseclaw/_data/local_observability_stack/"
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        packaged_assets = {name.removeprefix(prefix) for name in names if name.startswith(prefix)}
        assert FLEET_TEMPLATES.isdisjoint(packaged_assets)
        assert not any(name.startswith("defenseclaw/_data/edge-connector/") for name in names)
        assert not any(_is_generated_grafana_credential(name) for name in packaged_assets)
        assert expected_assets <= packaged_assets
        dashboard_uids = {
            json.loads(archive.read(prefix + name))["uid"]
            for name in packaged_assets
            if name.startswith("grafana/dashboards/") and name.endswith(".json")
        }
        docs = REPO_ROOT / "docs-site/content/docs"
        reference = (docs / "reference/observability/dashboards.mdx").read_text(encoding="utf-8")
        documented_uids = set(re.findall(r"^\| \*\*.+?\*\* \(`([^`]+)`\)", reference, re.MULTILINE))
        assert documented_uids == dashboard_uids
        for page in (reference, (docs / "how-to/observability/run-grafana-locally.mdx").read_text(encoding="utf-8")):
            counts = re.findall(r"\b(\d+) (?:bundled )?(?:Grafana |DefenseClaw )?dashboards\b", page)
            assert counts and all(int(count) == len(dashboard_uids) for count in counts)
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


@pytest.mark.skipif(os.name == "nt", reason="documented POSIX shell recipe")
@pytest.mark.parametrize("role", ["Admin", "Editor"])
def test_fleet_dashboard_recipe_refuses_anonymous_access_that_is_not_read_only(tmp_path: Path, role: str) -> None:
    # fix/r104-windows: Grafana recipes never enable anonymous Admin. An
    # effective config that would make anonymous visitors Admin or Editor
    # starts nothing.
    result, _stack, log = _run_fleet_recipe(tmp_path, "no-password", FAKE_ANONYMOUS_ROLE=role)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "would not be read-only (Viewer)" in result.stderr, result.stderr
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    assert not [line for line in calls if line.startswith("up ")], calls
