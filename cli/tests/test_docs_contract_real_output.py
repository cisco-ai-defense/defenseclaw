# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Pages that quote command output quote what the command prints."""

import io
import os
import re
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
from click.testing import CliRunner
from defenseclaw import config, ux
from defenseclaw.commands import cmd_doctor, cmd_guardrail, cmd_setup
from defenseclaw.commands.cmd_doctor import _DoctorResult
from defenseclaw.context import AppContext

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"


def _page(rel: str) -> str:
    return (DOCS / rel).read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _text_blocks(text: str) -> list[str]:
    return re.findall(r"```text\n(.*?)```", text, flags=re.S)


# GAP-0567: the Hermes page said doctor reports no failed check, but doctor
# fails the Hermes hooks row while any Hermes host runs and passes once all
# are closed. The page quotes both rows as doctor prints them.
@pytest.mark.parametrize(("running", "tag"), [(True, "[FAIL]"), (False, "[PASS]")])
def test_hermes_page_quotes_the_doctor_row(tmp_path, running, tag):
    hook = tmp_path / ".hermes" / "config.yaml"
    hook.parent.mkdir()
    hook.write_text("hooks:\n  - command: /x/hooks/hermes-hook.sh\n", encoding="utf-8")
    cfg = mock.MagicMock()
    cfg.data_dir = str(tmp_path)
    r = _DoctorResult()
    out = io.StringIO()
    with (
        mock.patch.object(cmd_doctor, "_hook_health_paths_from_lock", return_value=[str(hook)]),
        mock.patch.object(cmd_doctor, "_hermes_host_running", return_value=running),
        # A registration the execution probe proves (W5b): the page quotes the
        # host-state rows, not the probe's own setup failure.
        mock.patch.object(cmd_doctor, "hermes_config_path", return_value=str(hook)),
        mock.patch.object(cmd_doctor, "_hermes_registered_execution_problem", return_value=""),
        mock.patch.object(cmd_doctor, "_json_mode", False),
        mock.patch.object(cmd_doctor.ux, "_color_enabled", return_value=False),
        mock.patch.object(ux, "_configured_unicode_output", True),
        mock.patch.dict(os.environ, {"TERM": "xterm-256color"}),
        cmd_doctor._doctor_label_suffix("[hermes]"),
        redirect_stdout(out),
    ):
        cmd_doctor._check_hook_health(cfg, "hermes", r)
    row = r.checks[-1]
    assert row["status"] == ("fail" if running else "pass")
    page = _flat(_page("connectors/hermes.mdx"))
    example = "/home/alice/.hermes/config.yaml"
    detail = _flat(row["detail"].replace(str(hook), example))
    assert detail in page, detail
    if running:
        line = out.getvalue().splitlines()[0].strip().replace(str(hook), example)
        assert line.startswith(f"{tag} Hermes hooks [hermes]"), line
        assert line + "\n" in _text_blocks(_page("connectors/hermes.mdx")), line
    assert "reports no failed check" not in page
    # Setup prints a restart hint, not a pending_reload state, and doctor
    # has no such row.
    hint = f"! ({cmd_setup._pending_reload_hint('hermes')})"
    reference = _flat(_page("connectors/hermes.mdx"))
    assert hint in page and hint in reference
    assert re.findall(r"`[^`]*pending_reload[^`]*`", page) == ['`"status": "pending_reload"`'], page
    assert re.findall(r"`[^`]*pending_reload[^`]*`", reference) == ['`"status": "pending_reload"`'], reference


def test_hermes_reload_state_is_scoped_to_windows():
    connector = _page("connectors/hermes.mdx")
    setup = connector.split("## Setup\n", 1)[1].split("\n### Check it", 1)[0]
    check = connector.split("### Check it\n", 1)[1].split("\n### What setup hermes actually does", 1)[0]
    reference = _page("connectors/hermes.mdx")
    reference_setup = reference.split("### What setup hermes actually does\n", 1)[1].split("\n## Files", 1)[0]
    reference_files = reference.split("## Files DefenseClaw will modify\n", 1)[1].split("\n### Inventory", 1)[0]
    state_file = "hermes-direct-native-state.json"

    # The native writer is called only inside the Windows branch. Unix uses
    # hermes-hook.sh and does not create this direct-native state file.
    source = (ROOT / "internal/gateway/connector/hook_only.go").read_text(encoding="utf-8")
    writer = source.split("func setupHermesFiles(", 1)[1].split("func hermesConfiguredHookCommand(", 1)[0]
    assert 'if runtime.GOOS == "windows" {\n\t\tif err = writeHermesDirectNativeState(' in writer
    for section in (setup, check, reference_setup):
        assert "macOS and Linux" in section and "Windows" in section
    assert state_file in setup and state_file in check and state_file in reference_setup
    assert "macOS and Linux do not write" in setup
    assert "macOS and Linux have no" in check
    assert 'Windows only | `hooks/' + state_file + '`' in reference_files


def _fail_mode_view(tmp_path, body: str) -> str:
    (tmp_path / "config.yaml").write_text(body, encoding="utf-8")
    app = AppContext()
    app.cfg = config.load(data_dir=tmp_path)
    gc = app.cfg.guardrail

    def installed(_cfg, name, **_kw):
        mode = gc.effective_hook_fail_mode(name)
        return SimpleNamespace(runtime=mode, desired=mode, effective=mode, drift=(), note="")

    with mock.patch.object(cmd_guardrail, "resolve_connector_fail_mode", side_effect=installed):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
    assert result.exit_code == 0, result.output
    return result.output


_ROSTER = (
    "config_version: 9\n"
    "guardrail:\n"
    "  enabled: true\n"
    "  connector: claudecode\n"
    "{global_line}"
    "  connectors:\n"
    "    claudecode: {{}}\n"
    "    codex: {{rule_pack: strict}}\n"
)


# GAP-0576: each quoted block is the command's real output for its
# configuration. An explicit saved value wins over the tier; the page shows
# the unset example so its mixed default/strict rows are meaningful.
@pytest.mark.parametrize(("unicode_output", "term"), [(True, "xterm-256color"), (False, "xterm-256color"), (True, "dumb")])
def test_fail_mode_page_quotes_the_real_output(tmp_path, unicode_output, term):
    blocks = _text_blocks(_page("reference/fail-modes.mdx"))
    with (
        mock.patch.object(ux, "_configured_unicode_output", unicode_output),
        mock.patch.dict(os.environ, {"TERM": term}),
    ):
        if not ux.unicode_output_enabled():
            blocks = [ux.ascii_presentation_text(block) for block in blocks]
        unset_view = _fail_mode_view(tmp_path, _ROSTER.format(global_line=""))
        open_view = _fail_mode_view(tmp_path, _ROSTER.format(global_line="  hook_fail_mode: open\n"))
        closed_view = _fail_mode_view(tmp_path, _ROSTER.format(global_line="  hook_fail_mode: closed\n"))
    assert open_view != closed_view
    assert unset_view.strip("\n") + "\n" in blocks, unset_view
