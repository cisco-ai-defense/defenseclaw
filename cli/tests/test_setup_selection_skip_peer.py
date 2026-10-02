"""GAP-1052: a peer whose executable probe fails (for example a version probe
timeout on a loaded host) must not abort ``setup <connector>`` for the
connector being set up; the verified subset is published as the receipt."""

import json
import os
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import click
from defenseclaw.agent_selection import SetupAgentSelection, publish_setup_agent_selections
from defenseclaw.commands import cmd_setup

from tests.helpers import record_test_setup_agent_selections


def test_skipped_peer_publishes_verified_subset_receipt():
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = os.path.realpath(tmp)
        record_test_setup_agent_selections(data_dir, ["amp", "claudecode"])
        receipt = os.path.join(data_dir, "agent_selection.json")
        _, _, generation = cmd_setup._capture_protected_setup_file(
            receipt, cmd_setup._AGENT_SELECTION_MAX_BYTES, "agent_selection.json"
        )
        amp = SetupAgentSelection(
            connector="amp",
            executable=os.path.join(data_dir, "amp.exe"),
            raw_version="0.0.1",
            normalized_version="0.0.1",
            sha256="a" * 64,
        )
        with patch("defenseclaw.platform_support.host_os", return_value="windows"), patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            return_value=({"amp": amp}, {"claudecode": "cannot select claudecode executable: version probe timed out"}),
        ):
            verified = cmd_setup._record_windows_setup_agent_selections(
                data_dir,
                ("amp", "claudecode"),
                _prior_snapshot=SimpleNamespace(agent_selection_generation=generation),
                required={"amp"},
            )

        assert verified is not None
        assert verified.connectors == ("amp",)
        assert verified.record_for("amp") == amp
        with open(receipt, encoding="utf-8") as fh:
            assert set(json.load(fh)["selections"]) == {"amp"}


def test_skipped_peer_is_not_required_by_the_readiness_wait():
    """GAP-1052: the gateway may refuse a peer whose executable did not verify;
    setup of the selected connector must still converge."""
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = os.path.realpath(tmp)
        record_test_setup_agent_selections(data_dir, ["codex", "claudecode"])
        receipt = os.path.join(data_dir, "agent_selection.json")
        _, _, generation = cmd_setup._capture_protected_setup_file(
            receipt, cmd_setup._AGENT_SELECTION_MAX_BYTES, "agent_selection.json"
        )
        codex = SetupAgentSelection(
            connector="codex",
            executable=os.path.join(data_dir, "codex.exe"),
            raw_version="0.159.3",
            normalized_version="0.159.3",
            sha256="b" * 64,
        )
        with click.Context(click.Command("setup")), patch(
            "defenseclaw.platform_support.host_os", return_value="windows"
        ), patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            return_value=({"codex": codex}, {"claudecode": "version probe timed out"}),
        ):
            cmd_setup._record_windows_setup_agent_selections(
                data_dir,
                ("codex", "claudecode"),
                _prior_snapshot=SimpleNamespace(agent_selection_generation=generation),
                required={"codex"},
            )
            unverified = cmd_setup._unverified_setup_peers()

        assert unverified == {"claudecode"}
        keep, tolerated = cmd_setup._partition_unconvergeable_peers(
            os.path.join(data_dir, "hook_contract_lock.json"),
            {"codex", "claudecode"},
            required={"codex"},
            unverified=unverified,
        )
        assert keep == {"codex"}
        assert "claudecode" in tolerated
        # The connector being set up is never skipped.
        keep, _ = cmd_setup._partition_unconvergeable_peers(
            os.path.join(data_dir, "hook_contract_lock.json"),
            {"codex", "claudecode"},
            required={"codex"},
            unverified=frozenset({"codex"}),
        )
        assert keep == {"codex", "claudecode"}


def test_windows_selection_phase_prints_progress(capsys):
    """GAP-1571: the executable re-verification ran for minutes in silence."""
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = os.path.realpath(tmp)
        record_test_setup_agent_selections(data_dir, ["amp"])
        receipt = os.path.join(data_dir, "agent_selection.json")
        _, _, generation = cmd_setup._capture_protected_setup_file(
            receipt, cmd_setup._AGENT_SELECTION_MAX_BYTES, "agent_selection.json"
        )
        amp = SetupAgentSelection(
            connector="amp",
            executable=os.path.join(data_dir, "amp.exe"),
            raw_version="0.0.1",
            normalized_version="0.0.1",
            sha256="a" * 64,
        )
        with patch("defenseclaw.platform_support.host_os", return_value="windows"), patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            side_effect=lambda target, _names: (publish_setup_agent_selections(target, {"amp": amp}), ({"amp": amp}, {}))[1],
        ):
            cmd_setup._record_windows_setup_agent_selections(
                data_dir,
                ("amp",),
                _prior_snapshot=SimpleNamespace(agent_selection_generation=generation),
            )

    out = capsys.readouterr().out
    assert "Verifying 1 agent executable(s) (amp)" in out
    assert "Verified 1 agent executable(s) in" in out
