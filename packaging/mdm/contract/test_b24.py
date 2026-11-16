"""Regression checks for Unix MDM cancellation and detection contracts."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile

import pytest

MDM = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("platform", ["linux", "macos"])
@pytest.mark.parametrize("had_anchor", [False, True])
def test_cancel_restores_as_found_anchor(platform, had_anchor):
    source = (MDM / platform / "defenseclaw-enterprise.sh").read_text()
    assert source.rstrip().endswith('dc_main "$@"')
    source = source.rsplit('dc_main "$@"', 1)[0]
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        stage = root / "stage"
        stage.mkdir()
        anchor = root / "bundle-anchors.json"
        previous = stage / "bundle-anchors.previous.json"
        if had_anchor:
            previous.write_text("old-anchor\n")
        anchor.write_text("new-anchor\n")
        harness = f'''
DC_STAGE={shlex.quote(str(stage))}
DC_ANCHORS={shlex.quote(str(anchor))}
DC_ANCHORS_PREVIOUS={shlex.quote(str(previous) if had_anchor else '')}
DC_ANCHORS_CHANGED=1
DC_ACTION=ensure
DC_LOG=""
dc_put_anchors() {{ cp "$1" "$DC_ANCHORS"; }}
trap dc_cleanup EXIT
trap 'dc_stop_child; dc_fail_result "$DC_EXIT_FAILURE" mdm_cancelled "the MDM run was cancelled; the lifecycle was stopped"' TERM
kill -TERM "$$"
'''
        script = root / "cancel.sh"
        script.write_text(source + harness)
        result = subprocess.run(["sh", str(script)], text=True, capture_output=True, timeout=10)
        assert result.returncode == 1, (result.stdout, result.stderr)
        assert 'mdm_cancelled' in result.stdout
        if had_anchor:
            assert anchor.read_text() == "old-anchor\n"
        else:
            assert not anchor.exists()
        assert not stage.exists()


@pytest.mark.parametrize("platform", ["linux", "macos"])
def test_stop_child_reaps_cancelled_lifecycle(platform):
    source = (MDM / platform / "defenseclaw-enterprise.sh").read_text()
    source = source.rsplit('dc_main "$@"', 1)[0]
    with tempfile.TemporaryDirectory() as folder:
        script = Path(folder) / "stop-child.sh"
        script.write_text(source + '''
sleep 30 >/dev/null 2>&1 &
DC_CHILD=$!
child=$DC_CHILD
dc_stop_child
[ -z "$DC_CHILD" ] && ! kill -0 "$child" 2>/dev/null
''')
        result = subprocess.run(["sh", str(script)], text=True, capture_output=True, timeout=10)
        assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.parametrize("platform", ["linux", "macos"])
@pytest.mark.parametrize("anchor_present", [False, True])
def test_failed_anchor_restore_keeps_bundle_mode_and_backup(platform, anchor_present):
    source = (MDM / platform / "defenseclaw-enterprise.sh").read_text()
    source = source.rsplit('dc_main "$@"', 1)[0]
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        stage = root / "stage"
        stage.mkdir()
        anchor = root / "bundle-anchors.json"
        previous = stage / "bundle-anchors.previous.json"
        if anchor_present:
            anchor.write_text("new-anchor\n")
        previous.write_text("old-anchor\n")
        harness = f'''
DC_STAGE={shlex.quote(str(stage))}
DC_ANCHORS={shlex.quote(str(anchor))}
DC_ANCHORS_PREVIOUS={shlex.quote(str(previous))}
DC_ANCHORS_CHANGED=1
DC_LOG=""
dc_put_anchors() {{ return 1; }}
dc_cleanup
'''
        script = root / "restore-failure.sh"
        script.write_text(source + harness)
        result = subprocess.run(["sh", str(script)], text=True, capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert anchor.exists()
        assert anchor.read_text() != "new-anchor\n"
        assert anchor.read_text() == ""
        assert previous.read_text() == "old-anchor\n"


@pytest.mark.parametrize("platform", ["linux", "macos"])
def test_failed_anchor_restore_after_write_keeps_previous_anchor_and_backup(platform):
    source = (MDM / platform / "defenseclaw-enterprise.sh").read_text()
    source = source.rsplit('dc_main "$@"', 1)[0]
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        stage = root / "stage"
        stage.mkdir()
        anchor = root / "bundle-anchors.json"
        previous = stage / "bundle-anchors.previous.json"
        anchor.write_text("new-anchor\n")
        previous.write_text("old-anchor\n")
        harness = f'''
DC_STAGE={shlex.quote(str(stage))}
DC_ANCHORS={shlex.quote(str(anchor))}
DC_ANCHORS_PREVIOUS={shlex.quote(str(previous))}
DC_ANCHORS_CHANGED=1
DC_LOG=""
dc_trusted_path() {{ return 1; }}
dc_put_anchors() {{ cp "$1" "$DC_ANCHORS" && dc_trusted_path "$DC_ANCHORS"; }}
dc_cleanup
'''
        script = root / "restore-trust-failure.sh"
        script.write_text(source + harness)
        result = subprocess.run(["sh", str(script)], text=True, capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert anchor.read_text() == "old-anchor\n"
        assert previous.read_text() == "old-anchor\n"


@pytest.mark.parametrize("platform", ["linux", "macos"])
def test_exit_detection_reports_lifecycle_busy_without_health_flag(platform):
    source = (MDM / platform / "detect.sh").read_text()
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        gateway = root / "gateway"
        gateway.write_text('''#!/bin/sh
case "$*" in
  *status*) printf '{"installed":true,"installed_version":"1.0.3"}\\n' ;;
  *verify*) printf '{"ok":false,"errors":[{"code":"lifecycle_busy"}]}\\n'; exit 75 ;;
esac
''')
        gateway.chmod(0o755)
        original = 'gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway group=macos' if platform == 'macos' else 'gateway=/opt/defenseclaw/bin/defenseclaw-gateway group=linux'
        source = source.replace(original, f'gateway={shlex.quote(str(gateway))} group={"macos" if platform == "macos" else "linux"}', 1)
        source = source.replace('[ "$(id -u)" = 0 ] || dc_report 0 unknown "run as root"', 'true', 1)
        hook = f'dc_platform() {{ echo {"darwin" if platform == "macos" else "linux"}; }}\ndc_trusted_path() {{ return 0; }}\n'
        source = source.replace('[ "$(dc_platform)" = "$DC_SCRIPT_OS" ]', hook + '[ "$(dc_platform)" = "$DC_SCRIPT_OS" ]', 1)
        script = root / "detect.sh"
        script.write_text(source)
        for args, code, text in [([], 75, 'lifecycle is busy'), (['--min-version', '1.0.4'], 75, 'lifecycle is busy'), (['--require-healthy', '--format', 'value'], 0, 'busy'), (['--format', 'value'], 0, '1.0.3')]:
            result = subprocess.run(['sh', str(script), *args], text=True, capture_output=True, timeout=10, env={**os.environ, 'LC_ALL': 'C'})
            assert result.returncode == code, (args, result.stdout, result.stderr)
            assert text in result.stdout + result.stderr
