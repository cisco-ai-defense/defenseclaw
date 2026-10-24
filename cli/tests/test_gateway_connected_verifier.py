"""GAP-1138: the Python CLI's connected-socket check works on every supported install.

The check runs the gateway's ``hook-verify-connected`` on the socket urllib3
just connected. It must find that helper wherever a supported install puts
the gateway, give it the time the caller allows, and read the kernel's
socket tables where a hardened ``/proc`` still has them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import pytest
from defenseclaw import doctor_gateway, gateway
from defenseclaw.commands import cmd_doctor

posix_only = pytest.mark.skipif(os.name == "nt", reason="the fake helper is a POSIX shell script")

# The fixtures empty PATH; the fake helper names sleep by its path.
_SLEEP = shutil.which("sleep") or "/bin/sleep"
# conftest stubs this reader for every test; this module tests the real one.
_linux_foreign_listener_accounts = cmd_doctor._linux_foreign_listener_accounts


class _ConnectedSocket:
    def __init__(self, timeout: float | None = None) -> None:
        self._timeout = timeout

    def gettimeout(self):
        return self._timeout

    def getpeername(self):
        return ("127.0.0.1", 18970)

    def getsockname(self):
        return ("127.0.0.1", 43000)


def _helper(path, body: str = "", *, mode: int = 0o700) -> str:
    """A stand-in gateway whose hook-verify-connected records its argv."""
    path.parent.mkdir(parents=True, exist_ok=True)
    marker = path.parent / f"{path.name}.ran"
    path.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > \'{marker}\'\n{body}exit 0\n', encoding="ascii")
    path.chmod(mode)
    return str(path)


def _ran(helper: str) -> list[str]:
    marker = f"{helper}.ran"
    if not os.path.exists(marker):
        return []
    with open(marker, encoding="ascii") as stream:
        return stream.read().split()


@pytest.fixture
def per_user_host(tmp_path, monkeypatch):
    """A per-user host with no gateway in ~/.local/bin, on no PATH."""
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_BIN", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
    monkeypatch.setattr(gateway.sys, "argv", [str(tmp_path / "pytest")])
    monkeypatch.setattr(gateway, "canonical_install_path", lambda: str(home / ".local" / "bin" / "defenseclaw-gateway"))
    with mock.patch("defenseclaw.upgrade_shim.managed_descriptor", return_value=""):
        yield tmp_path


@posix_only
@pytest.mark.parametrize("location", ["DEFENSECLAW_GATEWAY_BIN", "PATH", "launcher folder", "~/.local/bin"])
def test_per_user_check_runs_the_gateway_of_each_supported_location(per_user_host, monkeypatch, location) -> None:
    # Only ~/.local/bin was tried: every request of an install elsewhere was
    # refused before it was sent.
    bin_dir = per_user_host / "opt-bin"
    helper = _helper(bin_dir / "defenseclaw-gateway")
    if location == "DEFENSECLAW_GATEWAY_BIN":
        monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", helper)
    elif location == "PATH":
        monkeypatch.setenv("PATH", str(bin_dir))
    elif location == "launcher folder":
        monkeypatch.setattr(gateway.sys, "argv", [str(bin_dir / "defenseclaw")])
    else:
        helper = _helper(per_user_host / "home" / ".local" / "bin" / "defenseclaw-gateway")

    gateway._verify_connected_gateway_socket(_ConnectedSocket(), "127.0.0.1", 18970)

    assert _ran(helper) == ["hook-verify-connected", "--local", "127.0.0.1:43000", "--remote", "127.0.0.1:18970"]


@posix_only
@pytest.mark.parametrize("unsafe", ["group-writable helper", "group-writable folder", "symlinked helper"])
def test_per_user_check_never_runs_a_helper_another_account_can_change(per_user_host, monkeypatch, unsafe) -> None:
    bin_dir = per_user_host / "opt-bin"
    target = per_user_host / "real" / "defenseclaw-gateway"
    if unsafe == "group-writable helper":
        helper = _helper(bin_dir / "defenseclaw-gateway", mode=0o770)
        candidate = helper
    elif unsafe == "group-writable folder":
        helper = _helper(bin_dir / "defenseclaw-gateway")
        bin_dir.chmod(0o770)
        candidate = helper
    else:
        helper = _helper(target)
        bin_dir.mkdir()
        candidate = str(bin_dir / "defenseclaw-gateway")
        os.symlink(helper, candidate)
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", candidate)

    with pytest.raises(gateway.GatewayListenerNotOwnedError):
        gateway._verify_connected_gateway_socket(_ConnectedSocket(), "127.0.0.1", 18970)
    assert _ran(helper) == []

    # A safe gateway at a later supported location is used instead.
    safe = _helper(per_user_host / "home" / ".local" / "bin" / "defenseclaw-gateway")
    gateway._verify_connected_gateway_socket(_ConnectedSocket(), "127.0.0.1", 18970)
    assert _ran(helper) == [] and _ran(safe)[0] == "hook-verify-connected"


@posix_only
def test_a_windows_package_uses_only_its_own_gateway(per_user_host, monkeypatch) -> None:
    # Its gateway is missing: a gateway on PATH must not stand in for it.
    on_path = _helper(per_user_host / "opt-bin" / "defenseclaw-gateway")
    monkeypatch.setenv("PATH", str(per_user_host / "opt-bin"))
    monkeypatch.setattr(gateway, "packaged_windows_install_root", lambda: str(per_user_host / "pkg"))
    monkeypatch.setattr(gateway, "packaged_windows_gateway_path", lambda: None)
    with pytest.raises(gateway.GatewayListenerNotOwnedError):
        gateway._verify_connected_gateway_socket(_ConnectedSocket(), "127.0.0.1", 18970)
    assert _ran(on_path) == []

    packaged = _helper(per_user_host / "pkg" / "bin" / "defenseclaw-gateway")
    monkeypatch.setattr(gateway, "packaged_windows_gateway_path", lambda: packaged)
    gateway._verify_connected_gateway_socket(_ConnectedSocket(), "127.0.0.1", 18970)
    assert _ran(packaged)[0] == "hook-verify-connected" and _ran(on_path) == []


@pytest.mark.parametrize(
    ("budget", "expected"),
    [
        (5, 6.0),  # the CLI's default timeout
        (3.3, 4.3),
        (1, 4.0),  # never shorter than the 3 s it always had
        (60, 11.0),  # the gateway's own wait is 10 s
        (None, 11.0),
        (object(), 11.0),  # urllib3's default-timeout sentinel
        (0, 11.0),
        (float("inf"), 11.0),
        (float("nan"), 11.0),
    ],
)
def test_verifier_gets_the_callers_budget(budget, expected) -> None:
    assert gateway._connected_verifier_timeout(budget) == expected


@posix_only
@pytest.mark.parametrize(("socket_timeout", "expected"), [(5.0, 6.0), (60.0, 11.0), (None, 11.0)])
def test_verifier_budget_is_the_connected_sockets_timeout(per_user_host, monkeypatch, socket_timeout, expected) -> None:
    # urllib3 and http.client create the socket with the caller's connect
    # timeout; that is the budget the helper gets.
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", _helper(per_user_host / "opt-bin" / "defenseclaw-gateway"))
    with mock.patch.object(gateway.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
        gateway._verify_connected_gateway_socket(_ConnectedSocket(socket_timeout), "127.0.0.1", 18970)
    assert run.call_args.kwargs["timeout"] == expected


class _Gateway(BaseHTTPRequestHandler):
    received: list[str] = []

    def do_GET(self) -> None:
        type(self).received.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_args) -> None:
        pass


@pytest.fixture
def local_gateway():
    _Gateway.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@posix_only
@pytest.mark.parametrize("deployment", ["per-user", "managed"])
def test_cli_waits_for_a_gateway_that_accepts_after_three_seconds(
    per_user_host, monkeypatch, local_gateway, deployment
) -> None:
    # Socket activation: the connection waits on systemd's listener and the
    # gateway accepts it after 3.3 s. The helper was killed at 3 s, so the
    # CLI sent nothing; the release client got its answer within its 5 s.
    helper = _helper(per_user_host / "opt-bin" / "defenseclaw-gateway", f"{_SLEEP} 3.3\n")
    if deployment == "managed":
        monkeypatch.setattr(
            gateway, "_managed_connected_verifier_spec", lambda: (helper, "defenseclaw-gateway.service")
        )
        monkeypatch.setattr(gateway, "_trusted_connected_verifier_binary", lambda binary, *, managed: binary)
    else:
        monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", helper)
    monkeypatch.setattr(gateway, "_unproven_per_user_gateway_target", lambda *_args: "")
    client = gateway.OrchestratorClient(host="127.0.0.1", port=local_gateway, timeout=5, token="t")

    started = time.monotonic()
    assert client.status() == {}
    assert time.monotonic() - started >= 3.3
    assert _Gateway.received == ["/status"]
    assert ("--managed-service" in _ran(helper)) == (deployment == "managed")


@posix_only
def test_cli_sends_nothing_when_the_check_outlasts_its_budget(per_user_host, monkeypatch, local_gateway) -> None:
    helper = _helper(per_user_host / "opt-bin" / "defenseclaw-gateway", f"{_SLEEP} 5\n")
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", helper)
    monkeypatch.setattr(gateway, "_unproven_per_user_gateway_target", lambda *_args: "")
    monkeypatch.setattr(gateway, "_CONNECTED_VERIFIER_MIN_WAIT", 0.3)
    monkeypatch.setattr(gateway, "_CONNECTED_VERIFIER_MARGIN", 0.2)
    client = gateway.OrchestratorClient(host="127.0.0.1", port=local_gateway, timeout=0.3, token="t")

    with pytest.raises(gateway.requests.ConnectionError):
        client.status()
    assert _Gateway.received == []


_TABLE_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def _self_net_only(tmp_path, port: int, *, state: str = "0A", remote: str = "00000000:0000", uid: int = 1000):
    """A /proc mounted subset=pid: /proc/self/net, but no /proc/net link."""
    proc_root = tmp_path / "proc"
    net = proc_root / "self" / "net"
    net.mkdir(parents=True)
    (proc_root / "4242" / "fd").mkdir(parents=True)
    row = (
        f"   0: 0100007F:{port:04X} {remote} {state} 00000000:00000000 00:00000000 00000000 {uid:5d}        0 12345 1\n"
    )
    (net / "tcp").write_text(_TABLE_HEADER + row, encoding="ascii")
    (net / "tcp6").write_text(_TABLE_HEADER, encoding="ascii")
    os.symlink("socket:[12345]", proc_root / "4242" / "fd" / "3")
    return proc_root


@posix_only
def test_socket_tables_are_read_through_proc_self() -> None:
    assert doctor_gateway.linux_proc_net_table("tcp6") == "/proc/self/net/tcp6"
    assert gateway._foreign_loopback_listener_uncached.__defaults__ == ("/proc/self/net",)


@posix_only
def test_listener_preflight_reads_a_proc_without_the_net_link(tmp_path) -> None:
    # ProcSubset=pid and no lsof: the preflight read /proc/net/tcp, found no
    # table and refused every request to a healthy gateway.
    proc_root = _self_net_only(tmp_path, 18970)
    evidence = cmd_doctor._linux_gateway_listener_evidence(18970, host="127.0.0.1", proc_root=str(proc_root))
    assert (evidence.status, evidence.pid) == ("ok", 4242)


@posix_only
def test_connection_owner_reads_a_proc_without_the_net_link(tmp_path) -> None:
    proc_root = _self_net_only(tmp_path, 18970, state="01", remote="0100007F:A7F8")
    local = doctor_gateway._linux_proc_net_endpoint(f"0100007F:{18970:04X}")
    remote = doctor_gateway._linux_proc_net_endpoint("0100007F:A7F8")
    evidence = doctor_gateway._linux_connection_owner(4242, local, remote, proc_root=str(proc_root))
    assert evidence.status == "ok"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux socket tables")
def test_foreign_listener_accounts_read_a_proc_without_the_net_link(tmp_path) -> None:
    proc_root = _self_net_only(tmp_path, 18970, uid=os.getuid() + 1)
    assert str(os.getuid() + 1) in _linux_foreign_listener_accounts(18970, proc_root=str(proc_root))


_IN_NAMESPACE = textwrap.dedent(
    """
    import json, os, socket
    from defenseclaw import doctor_gateway
    from defenseclaw.commands import cmd_doctor

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    client = socket.create_connection(("127.0.0.1", port))
    server, _ = listener.accept()
    preflight = cmd_doctor._linux_gateway_listener_evidence(port, host="127.0.0.1")
    local = doctor_gateway._linux_proc_net_endpoint("0100007F:%04X" % port)
    remote = doctor_gateway._linux_proc_net_endpoint("0100007F:%04X" % client.getsockname()[1])
    owner = doctor_gateway._linux_connection_owner(os.getpid(), local, remote)
    print(json.dumps({
        "net_link": os.path.exists("/proc/net"),
        "pid": os.getpid(),
        "preflight": [preflight.status, preflight.pid],
        "owner": owner.status,
    }))
    """
)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc mount options")
@pytest.mark.parametrize("options", ["hidepid=2", "hidepid=2,subset=pid"])
def test_preflight_under_a_hardened_proc_mount(tmp_path, options) -> None:
    # The real mount, as the ordinary account, in a private mount and PID
    # namespace: the preflight and the connection owner must both read.
    tools = ["/usr/bin/unshare", "/usr/bin/setpriv", "/usr/bin/timeout"]
    if os.geteuid() == 0 or not all(os.path.exists(tool) for tool in tools):
        pytest.skip("needs an ordinary account with unshare, setpriv and timeout")
    if (
        subprocess.run(
            ["sudo", "-n", "/usr/bin/unshare", "--mount", "--propagation", "private", "true"],
            capture_output=True,
            check=False,
        ).returncode
        != 0
    ):
        pytest.skip("a private mount namespace is unavailable without a password")
    script = tmp_path / "in_namespace.py"
    script.write_text(_IN_NAMESPACE, encoding="utf-8")
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(gateway.__file__)))
    shell = (
        'mount -t proc -o "$1" proc /proc && /usr/bin/setpriv --reuid="$2" --regid="$3" --init-groups -- '
        '"$5" -I -c "import sys; sys.path.insert(0, sys.argv[1]); exec(open(sys.argv[2]).read())" "$4" "$6"'
    )
    run = subprocess.run(
        [
            "sudo",
            "-n",
            "/usr/bin/timeout",
            "-k",
            "5",
            "60",
            "/usr/bin/unshare",
            "--mount",
            "--propagation",
            "private",
            "--pid",
            "--fork",
            "--kill-child",
            "/bin/sh",
            "-c",
            shell,
            "sh",
            options,
            str(os.geteuid()),
            str(os.getegid()),
            package_root,
            sys.executable,
            str(script),
        ],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    result = json.loads(run.stdout.strip().splitlines()[-1])
    assert result["net_link"] == ("subset=pid" not in options)
    assert result["preflight"] == ["ok", result["pid"]]
    assert result["owner"] == "ok"
