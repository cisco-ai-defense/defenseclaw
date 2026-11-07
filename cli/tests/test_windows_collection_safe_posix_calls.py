"""Test modules must import on Windows.

A skip marker is evaluated when the module is imported, so a bare
``os.geteuid()`` in a ``skipif`` condition, a decorator default, a module-level
``if`` or an assignment raises ``AttributeError`` during collection on Windows
even when the module is skipped there.

This test does not read the source and guess. It collects the real test
modules in a child interpreter where the real ``os`` and ``sys`` modules answer
as Windows does to code that lives in the tests tree: the POSIX-only ``os``
attributes are absent, ``os.name`` is ``"nt"`` and ``sys.platform`` is
``"win32"``. The view sits on the module objects themselves (their attribute
lookup checks which file asks), so every route to the attribute is covered:
``os.x``, ``from os import x``, ``importlib.import_module("os").x``,
``__import__("os").x``, ``getattr(os, "x")``. Library code keeps the real
answers. A collection error that says ``os`` lacks one of those attributes is a
module that would fail to collect on the Windows Python shard, whatever form the
call takes (decorator, default, ``if``, assignment, class body, import).

The absent set is the Unix-only part of the ``os`` documentation. When a test
needs another name, add it to ``_UNIX_ONLY_NAMES`` or ``_UNIX_ONLY_PREFIXES``
in the child below.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_TESTS = Path(__file__).resolve().parent

# What the child runs. Collection errors that are not about a missing os
# attribute (other optional imports, for example) are not this test business.
_CHILD = r"""
import json, os, sys, types
import pytest

_getframe = sys._getframe
_real_os = os
_real_sys = sys


def norm(path):
    return os.path.normcase(os.path.realpath(path))


ROOT = norm(os.environ["WINDOWS_VIEW_ROOT"])

_UNIX_ONLY_NAMES = {
    "geteuid", "getuid", "getgid", "getegid", "getgroups", "getgrouplist", "getresuid", "getresgid",
    "getpgid", "getpgrp", "getsid", "getpriority", "getlogin_r", "getloadavg",
    "setsid", "setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid", "setresuid",
    "setresgid", "setgroups", "initgroups", "setpgid", "setpgrp", "setpriority", "setns", "unshare",
    "fork", "forkpty", "killpg", "wait", "wait3", "wait4", "waitid", "waitstatus_to_exitcode_unix",
    "chown", "lchown", "fchown", "lchmod", "chflags", "lchflags", "chroot", "fchdir", "sync",
    "fdatasync", "mkfifo", "mknod", "major", "minor", "makedev", "nice", "uname", "statvfs",
    "fstatvfs", "sysconf", "confstr", "pathconf", "fpathconf", "ctermid", "ttyname", "openpty",
    "login_tty", "tcgetpgrp", "tcsetpgrp", "plock", "lockf", "pread", "pwrite", "preadv", "pwritev",
    "readv", "writev", "sendfile", "pipe2", "posix_fadvise", "posix_fallocate", "posix_spawnp",
    "memfd_create", "eventfd", "eventfd_read", "eventfd_write", "pidfd_open", "copy_file_range",
    "splice", "getxattr", "setxattr", "listxattr", "removexattr", "sched_getaffinity",
    "sched_setaffinity", "O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_NDELAY", "O_NOCTTY",
    "O_SYNC", "O_DSYNC", "O_RSYNC", "O_CLOEXEC", "O_ASYNC", "O_DIRECT", "O_NOATIME", "O_PATH",
    "O_TMPFILE", "O_LARGEFILE",
}
_UNIX_ONLY_PREFIXES = (
    "sched_", "SCHED_", "EX_", "RTLD_", "POSIX_FADV_", "POSIX_SPAWN_", "PRIO_", "XATTR_",
    "F_LOCK", "F_TLOCK", "F_ULOCK", "F_TEST", "CLD_", "P_PID", "P_PGID", "P_ALL", "P_PIDFD",
)


def is_unix_only(name):
    if name in _UNIX_ONLY_NAMES or name.startswith(_UNIX_ONLY_PREFIXES):
        return True
    # The wait-status helpers and flags (WIFEXITED, WNOHANG, ...) are upper-case W names.
    return name.startswith("W") and name.isupper()


_asked = {}


def asked_from_tests(frame):
    filename = frame.f_globals.get("__file__") or "-"
    if filename not in _asked:
        _asked[filename] = norm(filename).startswith(ROOT)
    return _asked[filename]


class WindowsViewOs(types.ModuleType):
    def __getattribute__(self, name):
        if (name == "name" or is_unix_only(name)) and asked_from_tests(_getframe(1)):
            if name == "name":
                return "nt"
            raise AttributeError("module 'os' has no attribute '" + name + "'")
        return types.ModuleType.__getattribute__(self, name)


class WindowsViewSys(types.ModuleType):
    def __getattribute__(self, name):
        if name == "platform" and asked_from_tests(_getframe(1)):
            return "win32"
        return types.ModuleType.__getattribute__(self, name)


class Plugin:
    def __init__(self):
        self.errors = []

    def pytest_collectreport(self, report):
        if report.failed:
            self.errors.append([str(report.nodeid), str(report.longrepr)])


_real_os.__class__ = WindowsViewOs
_real_sys.__class__ = WindowsViewSys
plugin = Plugin()
try:
    pytest.main(sys.argv[2:], plugins=[plugin])
finally:
    _real_os.__class__ = types.ModuleType
    _real_sys.__class__ = types.ModuleType
sys.stdout.write("\n@@RESULT@@" + json.dumps(plugin.errors))
"""


def _os_attribute_errors(target: Path, rootdir: Path) -> dict[str, str]:
    """Modules under ``target`` that fail to import because os lacks an attribute."""
    proc = subprocess.run(
        [
            sys.executable, "-c", _CHILD, "x",
            "--collect-only", "-q", "-p", "no:cacheprovider", "-p", "no:randomly",
            "--rootdir", str(rootdir), "--confcutdir", str(rootdir),
            str(target),
        ],
        capture_output=True, text=True, timeout=600, check=False, cwd=rootdir,
        env={**os.environ, "WINDOWS_VIEW_ROOT": str(target)},
    )
    marker = "@@RESULT@@"
    assert marker in proc.stdout, f"child did not finish:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
    errors = json.loads(proc.stdout.rsplit(marker, 1)[1])
    return {
        node: text
        for node, text in errors
        if "module 'os' has no attribute" in text or ("cannot import name" in text and "from 'os'" in text)
    }


def test_every_test_module_imports_without_posix_only_os_attributes() -> None:
    bad = _os_attribute_errors(_TESTS, _TESTS.parent)
    bad.pop(f"tests/{Path(__file__).name}", None)
    assert not bad, f"collection on Windows would fail on a POSIX-only os attribute: {sorted(bad)}"


_UNSAFE = {
    "or_chain": "import os, pytest\n@pytest.mark.skipif(os.name == \"posix\" or os.geteuid() == 0, reason=\"x\")\ndef test_a(): pass\n",
    "and_chain_wrong_polarity": "import os, pytest\n@pytest.mark.skipif(os.name == \"nt\" and os.geteuid() == 0, reason=\"x\")\ndef test_a(): pass\n",
    "module_level_if": "import os\nif os.geteuid() == 0:\n    pass\ndef test_a(): pass\n",
    "function_default": "import os\ndef test_a(uid=os.geteuid()): pass\n",
    "bare_decorator": "import os, pytest\n@pytest.mark.skipif(os.geteuid() == 0, reason=\"x\")\ndef test_a(): pass\n",
    "assignment": "import os\nIS_ROOT = os.getuid() == 0\ndef test_a(): pass\n",
    "class_body": "import os\nclass TestA:\n    ROOT = os.getgid()\n    def test_a(self): pass\n",
    "other_attribute": "import os\nNAME = os.uname().sysname\ndef test_a(): pass\n",
    "importlib_import_module": "import importlib\nUID = importlib.import_module(\"os\").geteuid()\ndef test_a(): pass\n",
    "dunder_import": "UID = __import__(\"os\").geteuid()\ndef test_a(): pass\n",
    "resuid_triple": "import os\nUIDS = os.getresuid()\ndef test_a(): pass\n",
    "from_import_function": "from os import getresgid\ndef test_a(): pass\n",
    "from_import_geteuid": "import os\nfrom os import geteuid\ndef test_a(): pass\n",
    "getattr_literal": "import os\nUID = getattr(os, \"getresuid\")()\ndef test_a(): pass\n",
    "unix_only_flag": "import os\nFLAGS = os.O_NOFOLLOW\ndef test_a(): pass\n",
    "wait_status_helper": "import os\nOK = os.WIFEXITED(0)\ndef test_a(): pass\n",
    "or_chain_resuid": "import os, pytest\n@pytest.mark.skipif(hasattr(os, \"fork\") or os.getresuid()[0] == 0, reason=\"x\")\ndef test_a(): pass\n",
}

_SAFE = {
    # Windows lacks getuid as well as geteuid, so this guard is true there.
    "hasattr_sibling_attribute": "import os, pytest\n@pytest.mark.skipif(hasattr(os, \"getuid\") and os.geteuid() == 0, reason=\"x\")\ndef test_a(): pass\n",
    "short_circuit": "import os, pytest\n@pytest.mark.skipif(os.name == \"nt\" or os.geteuid() == 0, reason=\"x\")\ndef test_a(): pass\n",
    "hasattr_same_attribute": "import os, pytest\n@pytest.mark.skipif(hasattr(os, \"geteuid\") and os.geteuid() == 0, reason=\"x\")\ndef test_a(): pass\n",
    "platform_conditional": "import os, sys\nIS_ROOT = False if sys.platform == \"win32\" else os.geteuid() == 0\ndef test_a(): pass\n",
    "platform_if": "import os\nif os.name != \"nt\":\n    UID = os.geteuid()\ndef test_a(): pass\n",
    "runtime_only": "import os\ndef test_a():\n    assert os.geteuid() >= 0\n",
    "importlib_guarded": "import importlib\nm = importlib.import_module(\"os\")\nUID = m.getresuid() if hasattr(m, \"getresuid\") else None\ndef test_a(): pass\n",
    "try_except_attribute_error": "import os\ntry:\n    UIDS = os.getresuid()\nexcept AttributeError:\n    UIDS = ()\ndef test_a(): pass\n",
    "try_except_import_error": "try:\n    from os import getresgid\nexcept ImportError:\n    getresgid = None\ndef test_a(): pass\n",
    "getattr_default": "import os\nUID = getattr(os, \"getresuid\", lambda: ())()\ndef test_a(): pass\n",
    "platform_gate_on_flag": "import os, sys\nFLAGS = 0 if sys.platform == \"win32\" else os.O_NOFOLLOW\ndef test_a(): pass\n",
}


@pytest.fixture(scope="module")
def probe_results(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bool]:
    """Collect every probe module once; True means it failed on a missing os attribute."""
    root = tmp_path_factory.mktemp("windows_collect_probe")
    for name, source in {**{f"unsafe_{k}": v for k, v in _UNSAFE.items()}, **{f"safe_{k}": v for k, v in _SAFE.items()}}.items():
        (root / f"test_{name}.py").write_text(textwrap.dedent(source), encoding="utf-8")
    failed = _os_attribute_errors(root, root)
    flagged = {Path(node.split("::")[0]).stem.removeprefix("test_") for node in failed}
    return {path.stem.removeprefix("test_"): path.stem.removeprefix("test_") in flagged for path in root.glob("test_*.py")}


@pytest.mark.parametrize("name", [f"unsafe_{k}" for k in _UNSAFE])
def test_the_collection_probe_flags_an_unguarded_posix_attribute(name: str, probe_results: dict[str, bool]) -> None:
    assert probe_results[name]


@pytest.mark.parametrize("name", [f"safe_{k}" for k in _SAFE])
def test_the_collection_probe_allows_a_guarded_or_runtime_use(name: str, probe_results: dict[str, bool]) -> None:
    assert not probe_results[name]
