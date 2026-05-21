# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the bash install-script emitter (Phase 7 patch).

The emitted script is the operator's "audit before running" artifact.
We assert structural invariants that keep it idempotent and safe:

* Header pins ``set -euo pipefail`` and creates ``$POLICIES_ROOT``.
* Every emitted file has a corresponding heredoc with a unique
  randomized delimiter.
* The footer activates the named policy through ``defenseclaw policy
  activate <name>``.
* Shell metacharacters in the policy name are quoted (no command
  injection).
"""

from __future__ import annotations

import re
import shlex
import subprocess

from defenseclaw.tui.creator.emit import emit
from defenseclaw.tui.creator.emit_script import emit_install_script
from defenseclaw.tui.creator.presets import load_preset


def _delimiters(script: str) -> list[str]:
    return re.findall(r"<<'(DC_EOF_[A-F0-9]+)'", script)


def test_header_includes_safe_bash_modes():
    script = emit_install_script(load_preset("default"))
    assert script.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in script
    assert 'POLICIES_ROOT="${HOME}/.defenseclaw/policies"' in script


def test_each_emitted_file_has_a_heredoc_block():
    policy = load_preset("default")
    policy.name = "smoke-test"
    files = emit(policy)
    script = emit_install_script(policy)

    delimiters = _delimiters(script)
    # One delimiter per file.
    assert len(delimiters) == len(files)
    # Delimiters are unique so a literal collision in one file
    # can't terminate another.
    assert len(set(delimiters)) == len(delimiters)


def test_footer_quotes_policy_name_against_injection():
    policy = load_preset("default")
    # Inject a metacharacter that would be a disaster if naively
    # interpolated. The emitter must wrap the name in single quotes
    # with escaped embedded quotes.
    policy.name = "evil'; rm -rf /tmp; #"
    script = emit_install_script(policy)

    # The activate line MUST have the name quoted; we look for the
    # exact bash-safe form.
    expected_quoted = "'evil'\\''; rm -rf /tmp; #'"
    assert f"defenseclaw policy activate {expected_quoted}" in script


def test_script_passes_bash_n_syntax_check():
    """Sanity-check that the emitted script parses as bash so a
    typo in the heredoc construction can't ship to operators.
    """

    policy = load_preset("default")
    policy.name = "syntax-probe"
    script = emit_install_script(policy)

    proc = subprocess.run(
        ["bash", "-n"],
        input=script,
        check=False,
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 0, proc.stderr


def test_targets_are_under_policies_root():
    policy = load_preset("default")
    policy.name = "target-check"
    script = emit_install_script(policy)
    # Every cat target should be relative to ${POLICIES_ROOT}.
    for line in script.splitlines():
        if line.startswith("cat > "):
            target = line[len("cat > ") :].split(" ")[0]
            assert target.startswith('"${POLICIES_ROOT}/'), target


def test_heredocs_use_randomized_delimiter_token_format():
    script = emit_install_script(load_preset("default"))
    for delim in _delimiters(script):
        assert delim.startswith("DC_EOF_")
        # Random hex (4 bytes -> 8 chars) appended after the prefix.
        suffix = delim[len("DC_EOF_") :]
        assert re.fullmatch(r"[A-F0-9]{8}", suffix), suffix
