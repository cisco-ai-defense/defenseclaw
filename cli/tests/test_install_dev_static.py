# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALL_DEV = ROOT / "scripts" / "install-dev.sh"
MAKEFILE = ROOT / "Makefile"


def _make_target_prerequisites(text: str, target: str) -> list[str]:
    logical_lines: list[str] = []
    pending = ""
    for physical_line in text.splitlines():
        line = physical_line.rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        logical_lines.append(pending + line.lstrip() if pending else line)
        pending = ""
    if pending:
        logical_lines.append(pending.rstrip())

    prerequisites: list[str] = []
    matched = False
    for line in logical_lines:
        if line.startswith("\t") or line.lstrip().startswith("#"):
            continue
        declaration = line.split(";", 1)[0]
        target_expression, separator, prerequisite_expression = declaration.partition(":")
        if separator and target in target_expression.split():
            matched = True
            prerequisites.extend(
                token for token in prerequisite_expression.split() if token != "|"
            )

    assert matched, f"missing Make target: {target}"
    return prerequisites


def test_make_target_prerequisites_handle_complete_rule_syntax() -> None:
    text = (
        "# sample: ignored\n"
        "sample: pycli \\\n"
        "  extra\n"
        "sample: repeated | order-only\n"
    )

    assert _make_target_prerequisites(text, "sample") == [
        "pycli",
        "extra",
        "repeated",
        "order-only",
    ]


def test_dev_install_syncs_openclaw_embed_before_go_build() -> None:
    text = INSTALL_DEV.read_text(encoding="utf-8")
    sync = 'make -C "${REPO_ROOT}" sync-openclaw-extension'
    build = 'GOOS="${OS}" GOARCH="${ARCH_NORMALIZED}" go build'
    assert sync in text
    assert build in text
    assert text.index(sync) < text.index(build)


@pytest.mark.skipif(os.name == "nt", reason="requires a POSIX make recipe shell")
def test_make_go_build_args_do_not_replace_inherited_goflags(tmp_path: Path) -> None:
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is unavailable")

    probe = tmp_path / "probe.mk"
    probe.write_text(
        "_go-build-args-probe:\n"
        "\t@printf '%s\\n' \"$$GOFLAGS\" '$(GO_BUILD_ARGS)'\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["GOFLAGS"] = "-mod=readonly"

    completed = subprocess.run(
        [
            make,
            "--no-print-directory",
            "-f",
            str(MAKEFILE),
            "-f",
            str(probe),
            "_go-build-args-probe",
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout.splitlines() == [
        "-mod=readonly",
        f'-ldflags "-X main.version={_make_version()}"',
    ]


def _make_version() -> str:
    text = MAKEFILE.read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("VERSION"):
            return line.split(":=", 1)[1].strip()
    raise AssertionError("Makefile VERSION is missing")


def test_gateway_targets_use_non_reserved_go_build_args() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")

    assert 'GO_BUILD_ARGS := -ldflags "-X main.version=$(VERSION)"' in text
    assert "GOFLAGS     :=" not in text
    assert text.count("go build $(GO_BUILD_ARGS)") == 2


@pytest.mark.skipif(os.name == "nt", reason="requires a POSIX make recipe shell")
def test_openclaw_embed_sync_keeps_the_tracked_placeholder(tmp_path: Path) -> None:
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is unavailable")

    checkout = tmp_path / "checkout"
    embed_dir = checkout / "internal/gateway/connector/openclaw_extension"
    plugin_dir = checkout / "plugin"
    (plugin_dir / "dist").mkdir(parents=True)
    embed_dir.mkdir(parents=True)
    placeholder = ROOT / "internal/gateway/connector/openclaw_extension/.placeholder"
    shutil.copy2(placeholder, embed_dir / placeholder.name)
    (plugin_dir / "package.json").write_text('{"name":"fixture"}\n', encoding="utf-8")
    (plugin_dir / "openclaw.plugin.json").write_text("{}\n", encoding="utf-8")
    (plugin_dir / "dist/index.js").write_text("export {};\n", encoding="utf-8")

    completed = subprocess.run(
        [
            make,
            "--no-print-directory",
            "-f",
            str(MAKEFILE),
            "sync-openclaw-extension",
            f"PLUGIN_DIR={plugin_dir}",
        ],
        cwd=checkout,
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (embed_dir / ".placeholder").read_bytes() == placeholder.read_bytes()
    assert (embed_dir / "package.json").is_file()
    assert (embed_dir / "dist/index.js").is_file()


def test_optional_developer_entry_points_do_not_abort_make_install() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")

    assert (
        '"$(CURDIR)/$(VENV_BIN)/litellm$(EXE)" "$(INSTALL_DIR)/litellm$(EXE)" || true;'
        in text
    )
    assert '"$$src" "$(INSTALL_DIR)/$$tool$(EXE)" || true;' in text


def test_make_python_recipes_use_cross_platform_venv_path() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")

    assert "$(VENV)/bin/python" not in text
    assert "$(VENV_BIN)/python$(EXE) -m pytest cli/tests -q" in text


def test_local_make_workflow_uses_one_test_ready_python_environment() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    pycli = text[text.index("\npycli:") : text.index("\ndev-pycli:")]

    assert "uv sync --frozen --python 3.12" in pycli
    assert "--no-dev" not in pycli
    assert "pycli" in _make_target_prerequisites(text, "dev-pycli")

    for target in (
        "cli-test",
        "cli-test-cov",
        "cli-test-snap",
        "py-connector-matrix-test",
        "test-verbose",
        "test-file",
        "check-audit-actions",
        "check-audit-no-raw-literals",
        "check-error-codes",
        "check-schemas",
        "telemetry-generate",
        "telemetry-check",
        "check-observability-v8-hard-cut",
        "check-grafana-dashboards",
        "check-llm-catalog",
        "py-lint",
    ):
        assert "pycli" in _make_target_prerequisites(text, target)


def test_skip_install_never_publishes_unclaimed_shared_cli() -> None:
    text = INSTALL_DEV.read_text(encoding="utf-8")
    install_cli = text[
        text.index("install_python_cli()") : text.index("build_go_gateway()")
    ]

    guard = install_cli.index('if [[ "${SKIP_INSTALL:-false}" == false ]]')
    publish = install_cli.index("source_install_ownership publish-cli")
    alternate = install_cli.index("else", guard)
    skipped = install_cli.index("Skipping shared CLI publication (--skip-install)")
    assert guard < publish < alternate < skipped
    assert 'SKIP_INSTALL="${skip_install}"' in text
    assert "export SKIP_INSTALL" in text
