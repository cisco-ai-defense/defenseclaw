from __future__ import annotations

import json

from click.testing import CliRunner
from defenseclaw import __version__
from defenseclaw.main import cli


def test_version_json_is_exact_and_does_not_require_config() -> None:
    result = CliRunner().invoke(cli, ["--version-json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "schema_version": 1,
        "name": "defenseclaw-cli",
        "version": __version__,
    }
