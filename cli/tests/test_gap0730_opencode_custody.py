"""GAP-0730: one account of what refuses an OpenCode plugin destination.

The gateway checks the leaf folder first and stops there, so naming the leaf
sent the user to a fix that did not clear the refusal while a folder above it
was as open. The CLI preflight, doctor and bootstrap now list every refused
element, outermost first, with one command.
"""

from __future__ import annotations

import errno
import os
import struct
import sys
from pathlib import Path

import click
import pytest
from defenseclaw import connector_paths, file_permissions
from defenseclaw.commands import cmd_doctor, cmd_setup

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")


@pytest.fixture(autouse=True)
def _no_private_group(monkeypatch):
    monkeypatch.setattr("defenseclaw.file_permissions.owner_private_group", lambda *_: False)


def _tree(tmp_path: Path, config_mode: int, opencode_mode: int) -> tuple[Path, Path, Path]:
    config = tmp_path / ".config"
    opencode = config / "opencode"
    plugins = opencode / "plugins"
    plugins.mkdir(parents=True)
    config.chmod(config_mode)
    opencode.chmod(opencode_mode)
    plugins.chmod(0o700)
    return config, opencode, plugins / "defenseclaw.js"


def test_every_refused_folder_is_listed_outermost_first(tmp_path: Path) -> None:
    config, opencode, plugin = _tree(tmp_path, 0o775, 0o775)
    unsafe = connector_paths.opencode_unsafe_plugin_paths([str(plugin)])
    assert unsafe == [os.path.realpath(config), os.path.realpath(opencode)]
    advice = connector_paths.opencode_custody_text(unsafe)
    assert advice.command == f"chmod go-w {unsafe[0]} {unsafe[1]}"
    assert advice.named.startswith(unsafe[0]) and unsafe[1] in advice.named


def test_the_preflight_names_all_of_them_in_one_command(tmp_path: Path, monkeypatch) -> None:
    config, opencode, plugin = _tree(tmp_path, 0o775, 0o775)
    monkeypatch.setattr(connector_paths, "connector_config_files", lambda _name: [str(plugin)])
    with pytest.raises(click.ClickException) as caught:
        cmd_setup._preflight_opencode_plugin_folder()
    message = str(caught.value)
    assert f"chmod go-w {os.path.realpath(config)} {os.path.realpath(opencode)}" in message
    assert "No changes made" in message


def test_a_plugin_file_other_accounts_can_write_is_listed_last(tmp_path: Path) -> None:
    _, _, plugin = _tree(tmp_path, 0o755, 0o755)
    plugin.write_text("// managed plugin\n", encoding="utf-8")
    plugin.chmod(0o666)
    assert connector_paths.opencode_unsafe_plugin_paths([str(plugin)]) == [os.path.realpath(plugin)]


def test_private_folders_and_a_private_plugin_stay_accepted(tmp_path: Path, monkeypatch) -> None:
    _, _, plugin = _tree(tmp_path, 0o755, 0o755)
    plugin.write_text("// managed plugin\n", encoding="utf-8")
    plugin.chmod(0o600)
    assert connector_paths.opencode_unsafe_plugin_paths([str(plugin)]) == []
    monkeypatch.setattr(connector_paths, "connector_config_files", lambda _name: [str(plugin)])
    cmd_setup._preflight_opencode_plugin_folder()


def _problems(unsafe, path: Path) -> tuple[str, ...]:
    return next(found.problems for found in unsafe if found == str(path))


# Review 1: the diagnosis asks the gateway's other per-element questions too.
@pytest.mark.skipif(os.geteuid() == 0, reason="root-owned folders are trusted")
def test_a_foreign_owned_readable_folder_is_named_with_an_owner_repair(tmp_path: Path, monkeypatch) -> None:
    config, opencode, plugin = _tree(tmp_path, 0o755, 0o755)
    monkeypatch.setattr(file_permissions, "_plugin_trusted_owner", lambda uid: uid == 0)
    unsafe = connector_paths.opencode_unsafe_plugin_paths([str(plugin)])
    assert _problems(unsafe, opencode) == ("owner",)
    advice = connector_paths.opencode_custody_text(unsafe)
    assert advice.command == ""
    assert "administrator" in advice.action and str(opencode) in advice.action
    assert advice.why == "is owned by another account"


def test_an_access_list_that_grants_write_is_named_with_the_list_repair(tmp_path: Path, monkeypatch) -> None:
    _, opencode, plugin = _tree(tmp_path, 0o755, 0o755)
    monkeypatch.setattr(file_permissions, "plugin_acl_refused", lambda path: path == str(opencode))
    unsafe = connector_paths.opencode_unsafe_plugin_paths([str(plugin)])
    assert [str(found) for found in unsafe] == [str(opencode)] and unsafe[0].problems == ("acl",)
    expected = "chmod -N " if sys.platform == "darwin" else "setfacl -b "
    assert connector_paths.opencode_custody_text(unsafe).command == expected + str(opencode)


@pytest.mark.parametrize("target_mode", [0o700, 0o777])
def test_a_link_in_the_chain_is_named_and_never_given_a_chmod(tmp_path: Path, target_mode: int) -> None:
    real = tmp_path / "real"
    (real / "plugins").mkdir(parents=True)
    real.chmod(target_mode)
    (real / "plugins").chmod(0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    plugin = link / "plugins" / "defenseclaw.js"
    unsafe = connector_paths.opencode_unsafe_plugin_paths([str(plugin)])
    assert "link" in _problems(unsafe, link)
    advice = connector_paths.opencode_custody_text(unsafe)
    assert advice.command == "" and "chmod" not in advice.action
    assert advice.action.startswith("replace ") and str(link) in advice.action


def test_a_plugin_file_that_is_a_link_is_named(tmp_path: Path) -> None:
    _, _, plugin = _tree(tmp_path, 0o755, 0o755)
    target = tmp_path / "elsewhere.js"
    target.write_text("//\n", encoding="utf-8")
    plugin.symlink_to(target)
    assert _problems(connector_paths.opencode_unsafe_plugin_paths([str(plugin)]), plugin) == ("link",)


def _acl(*entries: tuple[int, int, int]) -> bytes:
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


USER_OBJ, USER, GROUP_OBJ, GROUP, MASK, OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux POSIX ACLs")
@pytest.mark.parametrize(
    "blob,refused",
    [
        (_acl((USER_OBJ, 7, 0), (GROUP_OBJ, 5, 0), (OTHER, 5, 0)), False),
        (_acl((USER_OBJ, 7, 0), (GROUP_OBJ, 7, 0), (OTHER, 5, 0)), True),
        (_acl((USER_OBJ, 7, 0), (GROUP_OBJ, 5, 0), (OTHER, 7, 0)), True),
        (_acl((USER_OBJ, 7, 0), (USER, 6, 4242), (GROUP_OBJ, 5, 0), (MASK, 7, 0), (OTHER, 5, 0)), True),
        (_acl((USER_OBJ, 7, 0), (USER, 6, 4242), (GROUP_OBJ, 5, 0), (MASK, 5, 0), (OTHER, 5, 0)), False),
        (_acl((USER_OBJ, 7, 0), (GROUP_OBJ, 5, 0)), True),
        (_acl((USER_OBJ, 7, 0), (USER, 4, 4242), (GROUP_OBJ, 5, 0), (OTHER, 5, 0)), True),
        (b"\x01\x00\x00\x00", True),
    ],
)
def test_the_linux_acl_rule_matches_the_gateways(monkeypatch, blob: bytes, refused: bool) -> None:
    def getxattr(_path: str, name: str, **_kw) -> bytes:
        if name == "system.posix_acl_access":
            return blob
        raise OSError(errno.ENODATA, "none")

    monkeypatch.setattr(file_permissions.os, "getxattr", getxattr)
    assert file_permissions.plugin_acl_refused("/x") is refused


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux POSIX ACLs")
def test_no_acl_and_an_nfs4_acl(monkeypatch) -> None:
    def none(_path: str, _name: str, **_kw) -> bytes:
        raise OSError(errno.ENODATA, "none")

    monkeypatch.setattr(file_permissions.os, "getxattr", none)
    assert file_permissions.plugin_acl_refused("/x") is False
    monkeypatch.setattr(file_permissions.os, "getxattr", lambda _p, name, **_kw: b"x" if name == "system.nfs4_acl" else none(_p, name))
    assert file_permissions.plugin_acl_refused("/x") is True


# Review 1 and 2: a long recorded reason keeps the repair, whole or said to be left out.
def test_a_long_recorded_reason_keeps_its_repair_whole() -> None:
    fix = 'icacls "C:\\Users\\lane\\.config\\opencode" /remove:g "HOST\\other"'
    reason = "validate plugin directory custody: " + "x" * 520 + f" (HOST\\other has write access there); fix: {fix}"
    bounded = cmd_doctor._bounded_recorded_reason(reason)
    assert bounded.endswith(f"; fix: {fix}")
    assert len(bounded) < len(reason)
    assert cmd_doctor._bounded_recorded_reason("short   reason\nhere") == "short reason here"
    long_without_fix = cmd_doctor._bounded_recorded_reason("y " * 400)
    assert len(long_without_fix) <= 401 and long_without_fix.endswith("…")


def test_a_repair_of_a_dozen_deep_folders_is_not_cut() -> None:
    steps = [f'icacls "C:\\Users\\lane\\{"deep-folder-" * 6}{n}" /remove:g "HOST\\other"' for n in range(12)]
    fix = "; ".join(steps)
    assert len(fix) > 1200
    bounded = cmd_doctor._bounded_recorded_reason(f"validate plugin directory custody: refused; fix: {fix}")
    assert bounded.endswith(f"; fix: {fix}")


def test_a_repair_past_the_limit_is_left_out_and_said_so() -> None:
    fix = "icacls " + "p" * 9000
    bounded = cmd_doctor._bounded_recorded_reason(f"refused; fix: {fix}")
    assert fix[:50] not in bounded and "too long for this row" in bounded and "gateway.log" in bounded


# Review 2: the macOS rule is the gateway's, not a stricter one.
def _darwin(monkeypatch, listing: str, *, standalone: bool = False, mode: str = "drwxr-xr-x+") -> None:
    monkeypatch.setattr(file_permissions, "_darwin_acl_output", lambda _path: (mode, listing))
    monkeypatch.setattr(file_permissions, "_plugin_standalone_scope", lambda: standalone)


@pytest.mark.parametrize(
    "listing",
    [
        " 0: group:admin allow list,add_file,search,add_subdirectory,delete_child",
        " 0: user:root allow write,append",
        " 0: group:wheel allow delete_child",
        " 0: user:other allow list,search,readattr",
        " 0: user:other deny write,append",
        " 0: user:other allow add_file,file_inherit,only_inherit",
    ],
)
def test_macos_entries_the_gateway_accepts_are_not_refused(monkeypatch, listing: str) -> None:
    _darwin(monkeypatch, listing)
    assert file_permissions._plugin_darwin_acl_refused("/x") is False


@pytest.mark.parametrize(
    "listing",
    [
        " 0: user:other allow list,add_file,search",
        " 0: group:everyone allow write",
        " 0: user:root allow read\n 1: user:other allow delete_child",
        " 0: user:other allow",
    ],
)
def test_macos_write_entries_for_other_principals_are_refused(monkeypatch, listing: str) -> None:
    _darwin(monkeypatch, listing)
    assert file_permissions._plugin_darwin_acl_refused("/x") is True


def test_the_standalone_profile_keeps_the_strict_macos_rule(monkeypatch) -> None:
    listing = " 0: group:admin allow add_file,only_inherit"
    _darwin(monkeypatch, listing, standalone=True)
    assert file_permissions._plugin_darwin_acl_refused("/x") is True
    _darwin(monkeypatch, listing, standalone=False)
    assert file_permissions._plugin_darwin_acl_refused("/x") is False


def test_a_macos_acl_that_cannot_be_read_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(file_permissions, "_darwin_acl_output", lambda _path: ("", ""))
    assert file_permissions._plugin_darwin_acl_refused("/x") is True
    monkeypatch.setattr(file_permissions, "_darwin_acl_output", lambda _path: ("drwxr-xr-x+", ""))
    assert file_permissions._plugin_darwin_acl_refused("/x") is True
    monkeypatch.setattr(file_permissions, "_darwin_acl_output", lambda _path: ("drwxr-xr-x", ""))
    assert file_permissions._plugin_darwin_acl_refused("/x") is False


# Review 2: every refused element gets its repair, and prose is never in the command.
def test_a_link_below_an_open_folder_gets_the_chmod_and_the_replacement(tmp_path: Path) -> None:
    config, opencode, _ = _tree(tmp_path, 0o777, 0o700)
    link = config / "linked"
    link.symlink_to(opencode)
    unsafe = connector_paths.opencode_unsafe_plugin_paths([str(link / "plugins" / "defenseclaw.js")])
    assert [str(found) for found in unsafe] == [os.path.realpath(config), str(link)]
    assert _problems(unsafe, link) == ("link",) and "mode" in _problems(unsafe, Path(os.path.realpath(config)))
    advice = connector_paths.opencode_custody_text(unsafe)
    assert advice.command == f"chmod go-w {unsafe[0]}"
    assert advice.manual.startswith(f"replace {link}")
    assert advice.action == f"run `{advice.command}`, then {advice.manual}"
    assert advice.remedy == advice.action


def test_a_mode_repair_and_an_owner_repair_are_not_joined(tmp_path: Path, monkeypatch) -> None:
    if os.geteuid() == 0:
        pytest.skip("root-owned folders are trusted")
    config, opencode, plugin = _tree(tmp_path, 0o775, 0o775)
    monkeypatch.setattr(file_permissions, "_plugin_trusted_owner", lambda uid: uid == 0)
    advice = connector_paths.opencode_custody_text(connector_paths.opencode_unsafe_plugin_paths([str(plugin)]))
    assert advice.command.startswith("chmod go-w ") and "administrator" not in advice.command
    assert "&&" not in advice.command and advice.manual.startswith("have an administrator give ")
    assert advice.remedy == advice.action


def test_a_command_alone_is_the_remedy(tmp_path: Path) -> None:
    _, _, plugin = _tree(tmp_path, 0o775, 0o755)
    advice = connector_paths.opencode_custody_text(connector_paths.opencode_unsafe_plugin_paths([str(plugin)]))
    assert advice.manual == "" and advice.remedy == advice.command


def test_a_link_the_gateway_accepts_does_not_hide_an_open_target(tmp_path: Path, monkeypatch) -> None:
    real = tmp_path / "real"
    (real / "opencode" / "plugins").mkdir(parents=True)
    (real / "opencode").chmod(0o700)
    (real / "opencode" / "plugins").chmod(0o700)
    real.chmod(0o777)
    link = tmp_path / "sys"
    link.symlink_to(real)
    plugin = link / "opencode" / "plugins" / "defenseclaw.js"
    real_check = file_permissions.plugin_link_refused
    monkeypatch.setattr(
        file_permissions, "plugin_link_refused", lambda path, info, *, leaf: False if path == str(link) else real_check(path, info, leaf=leaf)
    )
    unsafe = connector_paths.opencode_unsafe_plugin_paths([str(plugin)])
    assert [str(found) for found in unsafe] == [os.path.realpath(real)]
    assert connector_paths.opencode_custody_text(unsafe).command == f"chmod go-w {os.path.realpath(real)}"
    # A link the gateway refuses stays structural: its target is not judged.
    monkeypatch.setattr(file_permissions, "plugin_link_refused", real_check)
    assert [str(found) for found in connector_paths.opencode_unsafe_plugin_paths([str(plugin)])][-1] == str(link)
