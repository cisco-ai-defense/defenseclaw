"""GAP-1052: a peer whose executable probe fails (for example a version probe
timeout on a loaded host) must not abort ``setup <connector>`` for the
connector being set up; the verified subset is published as the receipt."""

import json
import os
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

from defenseclaw.agent_selection import SetupAgentSelection
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
