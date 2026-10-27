"""rel-1-0-2:GAP-0483: a rollback keeps the setup of the sandboxes that keep running.

A Codex Docker sandbox set up on 1.0.2 kept running through ``defenseclaw
rollback`` (to 1.0.1) and ``defenseclaw upgrade`` (to 1.0.2 again). Both
restored data from before the setup: sandboxes were off, ``sandbox list``
refused and every hook of the sandbox was blocked as "gateway unreachable",
although the rollback had promised only a restart window. The installer now
has the newer gateway of the two copy the setup (``sandbox carry-state``)
into the install it makes live; statecarry_test.go covers the copy itself.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = ROOT / "scripts" / "install.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(os.name == "nt" or BASH is None, reason="POSIX installer")


def _text() -> str:
    return INSTALL_SH.read_text(encoding="utf-8")


def _functions(*names: str) -> str:
    text = _text()
    helpers = text[text.index("version_key() {") : text.index("sha256_of() {")]
    bodies = []
    for name in names:
        start = text.index(f"{name}() {{")
        bodies.append(text[start : text.index("\n}\n", start) + 3])
    return helpers + "".join(bodies)


def _run(script: Path, tmp_path: Path, **env: str) -> subprocess.CompletedProcess[str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    environment = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env}
    return subprocess.run([BASH, str(script)], capture_output=True, text=True, env=environment, timeout=60, check=False)


def _gateway(path: Path, calls: Path, *, carries: bool, rc: int = 0) -> Path:
    usage = "defenseclaw-gateway sandbox carry-state [flags]" if carries else "defenseclaw-gateway sandbox [command]"
    path.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{calls}"\n'
        f'case "$*" in *--help*) printf "Usage:\\n  %s\\n" "{usage}"; exit 0;; esac\n'
        f'[ "{rc}" = 0 ] && echo "Kept the sandbox setup (the openshell settings and the state of sandbox wv102-b-codex)"\n'
        f"exit {rc}\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _carry_script(tmp_path: Path, home: Path, call: str, config: str = "") -> Path:
    script = tmp_path / "carry.sh"
    script.write_text(
        'set -euo pipefail\ninfo() { echo "info: $*"; }\nwarn() { echo "warn: $*"; }\n'
        + _functions("carry_sandbox_state")
        + f'DEFENSECLAW_HOME="{home}" LOG="{tmp_path / "log"}"\n'
        + (f'DEFENSECLAW_CONFIG="{config}"\n' if config else "")
        + call
        + "\n",
        encoding="utf-8",
    )
    return script


def _slot(home: Path) -> Path:
    slot = home / "previous"
    (slot / "data").mkdir(parents=True)
    (slot / "data" / "config.yaml").write_text("config_version: 9\nopenshell:\n  enabled: true\n", encoding="utf-8")
    return slot


def test_the_newer_gateway_carries_the_sandbox_setup_into_the_install_made_live(tmp_path: Path) -> None:
    calls = tmp_path / "calls"
    home = tmp_path / "dc"
    slot = _slot(home)
    older = _gateway(tmp_path / "older", calls, carries=False)
    newer = _gateway(tmp_path / "newer", calls, carries=True)

    proc = _run(
        _carry_script(tmp_path, home, f'carry_sandbox_state "{slot}" always "{tmp_path / "missing"}" "{older}" "{newer}"'),
        tmp_path,
    )

    assert proc.returncode == 0, proc.stderr
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "sandbox carry-state --help",
        "sandbox carry-state --help",
        f"sandbox carry-state --from-data {slot}/data --from-config {slot}/data/config.yaml "
        f"--data-dir {home} --config {home}/config.yaml",
    ]
    assert "info: Kept the sandbox setup (the openshell settings and the state of sandbox wv102-b-codex)" in proc.stdout


def test_an_upgrade_after_an_earlier_rollback_carries_only_into_an_install_without_a_setup(tmp_path: Path) -> None:
    calls = tmp_path / "calls"
    home = tmp_path / "dc"
    slot = _slot(home)
    newer = _gateway(tmp_path / "newer", calls, carries=True)

    proc = _run(_carry_script(tmp_path, home, f'carry_sandbox_state "{slot}" if-unset "{newer}"'), tmp_path)

    assert proc.returncode == 0, proc.stderr
    assert calls.read_text(encoding="utf-8").splitlines()[-1].endswith(f"--config {home}/config.yaml --only-if-unset")


@pytest.mark.parametrize("inside", [True, False])
def test_the_config_of_the_install_left_follows_defenseclaw_config(tmp_path: Path, inside: bool) -> None:
    # A config.yaml outside the data dir is kept as previous/external-config.yaml;
    # one inside it moves with the data.
    calls = tmp_path / "calls"
    home = tmp_path / "dc"
    slot = _slot(home)
    if inside:
        config, left = home / "conf" / "dc.yaml", slot / "data" / "conf" / "dc.yaml"
    else:
        config, left = tmp_path / "etc" / "dc.yaml", slot / "external-config.yaml"
    left.parent.mkdir(parents=True, exist_ok=True)
    left.write_text("openshell: {enabled: true}\n", encoding="utf-8")
    newer = _gateway(tmp_path / "newer", calls, carries=True)

    proc = _run(_carry_script(tmp_path, home, f'carry_sandbox_state "{slot}" always "{newer}"', str(config)), tmp_path)

    assert proc.returncode == 0, proc.stderr
    assert f"--from-config {left} --data-dir {home} --config {config}" in calls.read_text(encoding="utf-8")


def test_a_failed_carry_is_named_and_the_installer_goes_on(tmp_path: Path) -> None:
    calls = tmp_path / "calls"
    home = tmp_path / "dc"
    slot = _slot(home)
    broken = _gateway(tmp_path / "broken", calls, carries=True, rc=1)

    proc = _run(_carry_script(tmp_path, home, f'carry_sandbox_state "{slot}" always "{broken}"; echo went-on'), tmp_path)

    assert proc.returncode == 0, proc.stderr
    assert "warn: Could not keep the sandbox setup of the install just replaced" in proc.stdout
    assert "went-on" in proc.stdout


def test_no_slot_data_means_no_call(tmp_path: Path) -> None:
    calls = tmp_path / "calls"
    home = tmp_path / "dc"
    newer = _gateway(tmp_path / "newer", calls, carries=True)

    proc = _run(_carry_script(tmp_path, home, f'carry_sandbox_state "{home / "previous"}" always "{newer}"'), tmp_path)

    assert proc.returncode == 0, proc.stderr
    assert not calls.exists()


@pytest.mark.parametrize(
    ("first", "second", "carries"),
    [
        ("1.0.2", "1.0.1", True),
        ("1.0.1", "1.0.3", True),
        ("1.0.2", "1.0.0", False),  # 1.0.0 keeps sandbox records and openshell keys of its own shape
        ("1.0.2", "0.8.10", False),
        ("", "1.0.1", False),
        ("1.0.2rc1", "1.0.1", False),
    ],
)
def test_the_setup_carries_only_between_releases_that_keep_it_alike(
    tmp_path: Path, first: str, second: str, carries: bool
) -> None:
    script = tmp_path / "since.sh"
    script.write_text(
        'set -euo pipefail\nreadonly SANDBOX_STATE_SINCE="1.0.1"\n'
        + _functions("sandbox_state_carries")
        + f'if sandbox_state_carries "{first}" "{second}"; then echo yes; else echo no; fi\n',
        encoding="utf-8",
    )

    assert _run(script, tmp_path).stdout.strip() == ("yes" if carries else "no")
    assert 'readonly SANDBOX_STATE_SINCE="1.0.1"' in _text()


def test_a_rollback_to_a_release_that_cannot_take_over_says_the_hooks_stay_blocked(tmp_path: Path) -> None:
    text = _text()
    start = text.index("warn_running_sandboxes() {")
    func = text[start : text.index("\n}\n", start) + 3]
    bin_dir, venv = tmp_path / "bin", tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    bin_dir.mkdir()
    (venv / "bin" / "python").symlink_to(sys.executable)
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_text(
        '#!/bin/sh\n[ "$*" = "sandbox list --output json" ] && echo \'{"sandboxes": [{"name": "wv102-b-codex", "phase": "ready"}]}\'\n',
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    script = tmp_path / "warn.sh"
    script.write_text(
        f'set -euo pipefail\nBIN_DIR="{bin_dir}"\nVENV="{venv}"\n'
        'gateway_pid() { printf 42; }\nwarn() { echo "WARN $*"; }\n' + func + 'warn_running_sandboxes "1.0.0"\n',
        encoding="utf-8",
    )

    out = _run(script, tmp_path).stdout

    assert out.startswith(
        "WARN Sandbox wv102-b-codex is running: DefenseClaw 1.0.0 cannot take over its sandbox setup, "
        "so its hooks fail closed and its agent's tool calls are refused until you run 'defenseclaw rollback' again"
    ), out


@pytest.mark.parametrize(
    ("listing", "opening"),
    [
        ('{"sandboxes": [{"name": "one", "phase": "ready"}]}', "WARN Sandbox one is running:"),
        ('{"sandboxes": [{"name": "one", "phase": "ready"}, {"name": "two", "phase": "ready"}]}',
         "WARN 2 sandboxes are running (one, two):"),
    ],
)
def test_a_rollback_to_a_0x_release_names_the_installer_command_not_defenseclaw_rollback(
    tmp_path: Path, listing: str, opening: str
) -> None:
    bin_dir, venv = tmp_path / "bin", tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    bin_dir.mkdir()
    (venv / "bin" / "python").symlink_to(sys.executable)
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_text(
        f"#!/bin/sh\n[ \"$*\" = \"sandbox list --output json\" ] && printf '%s\\n' '{listing}'\n",
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    previous = tmp_path / "previous"
    script = tmp_path / "warn.sh"
    script.write_text(
        f'set -euo pipefail\nBIN_DIR="{bin_dir}"\nVENV="{venv}"\nPREVIOUS="{previous}"\n'
        'gateway_pid() { printf 42; }\nwarn() { echo "WARN $*"; }\n'
        + _functions("warn_running_sandboxes") + 'warn_running_sandboxes "0.8.10"\n',
        encoding="utf-8",
    )

    proc = _run(script, tmp_path)

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith(opening), proc.stdout
    assert f"until you run 'bash {previous}/installer/install.sh --rollback' again" in proc.stdout
    assert "defenseclaw rollback" not in proc.stdout


def test_the_rollback_carries_the_setup_after_the_swap_and_before_the_gateway_starts() -> None:
    text = _text()
    rollback = text[text.index('if [[ "${ROLLBACK}" == true ]]; then') : text.index("# ── Stage: nothing live changes")]
    order = [
        'sandbox_state_carries "${current}" "${back_to}" || stranded="${back_to}"',
        'warn_running_sandboxes "${stranded}"\n    ask_yes_no "${question}"',
        "swap_with_previous || swapped=$?",
        'prune_orphaned_hooks "${BIN_DIR}/defenseclaw-gateway" "${PREVIOUS}/bin/defenseclaw-gateway"',
        'carry_sandbox_state "${PREVIOUS}" always "${PREVIOUS}/bin/defenseclaw-gateway" "${BIN_DIR}/defenseclaw-gateway"',
        "start_gateway || rollback_rc=$?",
    ]
    positions = [rollback.index(needle) for needle in order]
    assert positions == sorted(positions)
    # A roll forward: the gateway now live is the newer one.
    assert 'carry_sandbox_state "${PREVIOUS}" always "${BIN_DIR}/defenseclaw-gateway" "${PREVIOUS}/bin/defenseclaw-gateway"' in rollback


def test_an_upgrade_after_a_rollback_by_an_earlier_release_brings_the_setup_back() -> None:
    text = _text()
    swap = text[text.index("swap_in() {") : text.index("swap_app() {")]
    migrate = swap.index('"${VENV}/bin/defenseclaw" "${args[@]}" || return 1')
    carry = swap.index('carry_sandbox_state "${PREVIOUS}" if-unset "${BIN_DIR}/defenseclaw-gateway"')
    assert migrate < carry
    assert '[[ -f "${PREVIOUS}/ROLLED_BACK" ]] && sandbox_state_carries "${rolled}" "${VERSION}"' in swap
    # The data previous/ holds is parked only after the swap is final.
    finish = text[text.index("finish_swap() {") :][:600]
    assert "keep_rolled_back_data" in finish


def _legacy_refusal(tmp_path: Path, previous: str, listing: str, *, version: str = "1.0.5", running: bool = True):
    bin_dir, venv = tmp_path / "bin", tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    bin_dir.mkdir()
    (venv / "bin" / "python").symlink_to(sys.executable)
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_text(
        f"#!/bin/sh\n[ \"$*\" = \"sandbox list --output json\" ] && printf '%s\\n' '{listing}'\n",
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    script = tmp_path / "refuse.sh"
    script.write_text(
        f'set -euo pipefail\nBIN_DIR="{bin_dir}"\nVENV="{venv}"\nVERSION="{version}"\n'
        + ("gateway_pid() { printf 42; }\n" if running else "gateway_pid() { return 1; }\n")
        + 'err() { echo "ERR $*" >&2; }\n'
        + _functions("refuse_legacy_sandboxes")
        + f'refuse_legacy_sandboxes "{previous}"\necho went-on\n',
        encoding="utf-8",
    )
    return _run(script, tmp_path)


_LEGACY_LISTING = (
    '{"sandboxes": ['
    '{"name": "np5-legacy", "phase": "ready", "driver": "vm"}, '
    '{"name": "dock", "phase": "ready"}, '
    '{"name": "vm-done", "phase": "completed", "driver": "vm"}, '
    '{"name": "dock-done", "phase": "completed", "driver": "docker"}, '
    '{"name": "vm-gone", "phase": "error", "driver": "vm", "phase_reason": "ProcessExited: exit 0"}, '
    '{"name": "off", "phase": "stopped", "driver": "vm"}'
    ']}'
)


@pytest.mark.parametrize("previous", ["1.0.0", "1.0.2", "1.0.3"])
def test_an_upgrade_from_1_0_3_or_older_refuses_while_its_sandboxes_hold_compute(tmp_path: Path, previous: str) -> None:
    """rel-1-0-4:GAP-0901: a 1.0.3 MicroVM kept running through the per-user
    upgrade with its old broker; the installer now refuses first and names
    each sandbox with the command that ends it."""
    proc = _legacy_refusal(tmp_path, previous, _LEGACY_LISTING)

    assert proc.returncode == 1, proc
    assert "went-on" not in proc.stdout
    assert f"ERR Sandboxes of DefenseClaw {previous} are running; nothing was changed." in proc.stderr
    assert "DefenseClaw stops no sandbox for you" in proc.stderr
    assert "np5-legacy (ready): save the work you need, then defenseclaw sandbox stop np5-legacy" in proc.stderr
    assert "dock (ready): save the work you need, then defenseclaw sandbox stop dock" in proc.stderr
    assert (
        "vm-done (completed MicroVM, which OpenShell does not stop): defenseclaw sandbox delete vm-done "
        "(it deletes the sandbox with its work)" in proc.stderr
    )
    for gone in ("dock-done", "vm-gone", "off"):
        assert gone not in proc.stderr


@pytest.mark.parametrize(
    ("previous", "listing", "version", "running"),
    [
        ("1.0.4", _LEGACY_LISTING, "1.0.5", True),  # its gateway counts its own sandboxes
        ("0.8.10", _LEGACY_LISTING, "1.0.5", True),  # no OpenShell sandboxes before 1.0
        ("1.0.3", _LEGACY_LISTING, "1.0.3", True),  # not an upgrade to a release that reports them
        ("1.0.3", _LEGACY_LISTING, "1.0.5", False),  # no gateway runs to ask
        ("1.0.3", '{"sandboxes": [{"name": "off", "phase": "stopped", "driver": "vm"}]}', "1.0.5", True),
        ("1.0.3", "", "1.0.5", True),  # sandboxes off: the listing fails
    ],
)
def test_the_legacy_sandbox_refusal_lets_other_upgrades_go_on(
    tmp_path: Path, previous: str, listing: str, version: str, running: bool
) -> None:
    proc = _legacy_refusal(tmp_path, previous, listing, version=version, running=running)

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "went-on"
    assert proc.stderr == ""


def test_the_legacy_sandbox_refusal_runs_before_the_upgrade_question_and_the_swap() -> None:
    text = _text()
    order = [
        'refuse_legacy_sandboxes "${PREV_VERSION}"\nwarn_running_sandboxes\n',
        'ask_yes_no "Upgrade DefenseClaw ${PREV_VERSION} → ${VERSION}?"',
        "assert_locks_ours\nassert_no_loaded_plugin_agents\n",
    ]
    positions = [text.index(needle) for needle in order]
    assert positions == sorted(positions)


def test_the_upgrade_page_states_the_legacy_sandbox_refusal() -> None:
    page = " ".join((ROOT / "docs-site/content/docs/get-started/upgrade.mdx").read_text(encoding="utf-8").split())
    assert "An upgrade from 1.0.3 or earlier refuses, and changes nothing, while that release's gateway runs a sandbox." in page
    assert "`defenseclaw sandbox stop NAME`, or `defenseclaw sandbox delete NAME`" in page
    assert "When the gateway is not running the installer cannot ask it, so end your sandboxes before you upgrade." in page
