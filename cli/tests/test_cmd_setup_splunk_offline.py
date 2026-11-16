from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands.cmd_setup import setup
from defenseclaw.logger import CanonicalObservabilityUnavailableError

from tests.helpers import cleanup_app, make_app_context


def test_enterprise_setup_accepts_offline_audit_after_save() -> None:
    app, root, db_path = make_app_context()

    class OfflineLogger:
        def log_action(self, *_args, **_kwargs):
            raise CanonicalObservabilityUnavailableError("gateway unavailable")

    app.logger = OfflineLogger()
    try:
        with (
            patch("defenseclaw.commands.cmd_setup._setup_enterprise") as configure,
            patch("defenseclaw.commands.cmd_setup._print_splunk_status"),
            patch("defenseclaw.commands.cmd_setup.print_redaction_status_hint"),
            patch("defenseclaw.commands.cmd_setup._print_splunk_next_steps"),
        ):
            result = CliRunner().invoke(
                setup,
                ["splunk", "--enterprise", "--hec-endpoint", "https://example.com/hec",
                 "--hec-token", "fixture-value", "--skip-test", "--non-interactive"],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        configure.assert_called_once()
        assert "gateway" in result.output.lower()
        assert "fixture-value" not in result.output
    finally:
        cleanup_app(app, db_path, root)
