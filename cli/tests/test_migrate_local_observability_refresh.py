"""GAP-1367: migrate explains a Docker it cannot query in plain words."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from defenseclaw import migrations
from defenseclaw.bundle_refresh import LocalObservabilityUpgradeError


@pytest.mark.parametrize("wired", [False, True])
def test_unknown_docker_state_is_plain_and_quiet_for_an_unused_stack(tmp_path, capsys, wired):
    (tmp_path / "observability-stack").mkdir()
    refusal = LocalObservabilityUpgradeError("docker_state_unknown", "stack_state")
    with (
        patch("defenseclaw.bundle_refresh.upgrade_local_observability_stack", side_effect=refusal),
        patch(
            "defenseclaw.commands.cmd_setup_local_observability._local_destination_enabled",
            return_value=wired,
        ),
        patch.object(migrations, "_allocate_observability_v8_bundle_backup", return_value=str(tmp_path / "b")),
    ):
        migrations._refresh_local_observability_bundle(str(tmp_path), "1.0.1")
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "docker_state_unknown" not in output
    if wired:
        assert "docker group" in output
        assert "defenseclaw setup local-observability status" in output
    else:
        assert output == ""
