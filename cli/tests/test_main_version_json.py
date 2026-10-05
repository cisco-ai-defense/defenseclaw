from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

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


def test_launcher_version_json_answers_before_importing_the_command_tree() -> None:
    # The Windows launcher runs this module as __main__; Setup bounds the probe.
    script = (
        "import json, runpy, sys\n"
        "sys.argv = ['defenseclaw', '--version-json']\n"
        "try:\n"
        "    runpy.run_module('defenseclaw.main', run_name='__main__')\n"
        "except SystemExit as exc:\n"
        "    code = exc.code\n"
        "loaded = sorted(m for m in sys.modules if m == 'click' or m.startswith('defenseclaw.commands'))\n"
        "sys.stderr.write(json.dumps({'code': code, 'loaded': loaded}))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stderr) == {"code": 0, "loaded": []}
    assert result.stdout == CliRunner().invoke(cli, ["--version-json"]).output
