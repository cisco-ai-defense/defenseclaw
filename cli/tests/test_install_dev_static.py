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

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALL_DEV = ROOT / "scripts" / "install-dev.sh"
MAKEFILE = ROOT / "Makefile"


def test_dev_install_syncs_openclaw_embed_before_go_build() -> None:
    text = INSTALL_DEV.read_text()
    sync = 'make -C "${REPO_ROOT}" sync-openclaw-extension'
    build = 'GOOS="${OS}" GOARCH="${ARCH_NORMALIZED}" go build'
    assert sync in text
    assert build in text
    assert text.index(sync) < text.index(build)


def test_optional_developer_entry_points_do_not_abort_make_install() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")

    assert (
        '"$(CURDIR)/$(VENV_BIN)/litellm$(EXE)" "$(INSTALL_DIR)/litellm$(EXE)" || true;'
        in text
    )
    assert '"$$src" "$(INSTALL_DIR)/$$tool$(EXE)" || true;' in text


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
