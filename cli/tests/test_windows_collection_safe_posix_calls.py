"""Test modules must import on Windows.

A skip marker is evaluated when the module is imported, so a bare
``os.geteuid()`` in a ``skipif`` condition, a decorator default, a module-level
``if`` or an assignment raises ``AttributeError`` during collection on Windows
even when the module is skipped there.

This test does not read the source and guess. It collects the real test
modules in a child interpreter where ``import os`` and ``import sys`` inside a
test module (conftest files included) give a Windows view: the POSIX-only
``os`` attributes are absent, ``os.name`` is ``"nt"`` and ``sys.platform`` is
``"win32"``. Library code keeps the real modules. A collection error that says
``os`` lacks one of those attributes is a module that would fail to collect on
the Windows Python shard, whatever form the call takes (decorator, default,
``if``, assignment, class body, ``from os import``).
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
import builtins, json, os, sys, types
import pytest

def norm(path):
    return os.path.normcase(os.path.realpath(path))


ROOT = norm(os.environ["WINDOWS_VIEW_ROOT"])
ABSENT = {
    "geteuid", "getuid", "getgid", "getegid", "getgroups", "getpgid", "getpgrp", "getsid",
    "setsid", "setuid", "setgid", "seteuid", "setegid", "fork", "forkpty", "killpg",
    "chown", "lchown", "fchown", "chroot", "mkfifo", "mknod", "nice", "uname", "statvfs",
    "getloadavg", "sched_getaffinity", "O_NOFOLLOW", "O_DIRECTORY",
}


class WindowsOs(types.ModuleType):
    def __init__(self):
        super().__init__("os")

    def __getattr__(self, name):
        if name in ABSENT:
            raise AttributeError("module 'os' has no attribute '" + name + "'")
        if name == "name":
            return "nt"
        return getattr(os, name)


class WindowsSys(types.ModuleType):
    def __init__(self):
        super().__init__("sys")

    def __getattr__(self, name):
        return "win32" if name == "platform" else getattr(sys, name)


views = {"os": WindowsOs(), "sys": WindowsSys()}
real_import = builtins.__import__


def windows_import(name, globals=None, locals=None, fromlist=(), level=0):
    top = name.partition(".")[0]
    if level == 0 and top in views and norm((globals or {}).get("__file__") or "-").startswith(ROOT):
        if not fromlist or name == top:
            return views[top]
    return real_import(name, globals, locals, fromlist, level)


class Plugin:
    def __init__(self):
        self.errors = []

    def pytest_collectreport(self, report):
        if report.failed:
            self.errors.append([str(report.nodeid), str(report.longrepr)])


builtins.__import__ = windows_import
plugin = Plugin()
try:
    pytest.main(sys.argv[2:], plugins=[plugin])
finally:
    builtins.__import__ = real_import
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
}

_SAFE = {
    # Windows lacks getuid as well as geteuid, so this guard is true there.
    "hasattr_sibling_attribute": "import os, pytest\n@pytest.mark.skipif(hasattr(os, \"getuid\") and os.geteuid() == 0, reason=\"x\")\ndef test_a(): pass\n",
    "short_circuit": "import os, pytest\n@pytest.mark.skipif(os.name == \"nt\" or os.geteuid() == 0, reason=\"x\")\ndef test_a(): pass\n",
    "hasattr_same_attribute": "import os, pytest\n@pytest.mark.skipif(hasattr(os, \"geteuid\") and os.geteuid() == 0, reason=\"x\")\ndef test_a(): pass\n",
    "platform_conditional": "import os, sys\nIS_ROOT = False if sys.platform == \"win32\" else os.geteuid() == 0\ndef test_a(): pass\n",
    "platform_if": "import os\nif os.name != \"nt\":\n    UID = os.geteuid()\ndef test_a(): pass\n",
    "runtime_only": "import os\ndef test_a():\n    assert os.geteuid() >= 0\n",
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
