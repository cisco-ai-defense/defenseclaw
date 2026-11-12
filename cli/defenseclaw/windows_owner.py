# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Make an elevated Windows process create files its own user owns.

An elevated administrator token (a UAC "Run as administrator" prompt, the
built-in Administrator, an elevated scheduled task or SSH session) names
BUILTIN\\Administrators as the default owner of every object it creates.
DefenseClaw's private-file checks require the account's own SID as owner, so
a per-user ``defenseclaw init`` run elevated left audit.db owned by
Administrators and ``doctor`` failed "Private files" (GAP-0050). The installer
(install.ps1 ``SwapDefaultOwner``) and the Windows CI harness
(``Set-CurrentUserAsDefaultOwner``) already set the token's default owner to
the user; the CLI does the same at start. Child processes (the gateway the CLI
starts) inherit the token and with it the owner.

Only the process's own token changes, only its default owner, and only to the
token's own user SID, which Windows always accepts as an owner. Nothing is
granted. A token that is not elevated already uses the user as owner, so the
call changes nothing there. A computer with a managed (enterprise) deployment
(the standalone marker or either profile's install root), a process that
deployment pinned (DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise) and
``defenseclaw enterprise`` commands are left alone: their elevated runs
write machine state whose checks expect an administrator owner. The Go hook,
gateway and ACP guard make the same change with the same exclusions
(internal/managed UseCurrentUserAsWindowsDefaultOwner, GAP-0063).
"""

from __future__ import annotations

import ntpath
import os

_TOKEN_QUERY = 0x0008
_TOKEN_ADJUST_DEFAULT = 0x0080
_TOKEN_USER = 1
_TOKEN_OWNER = 4


# The marker a machine-wide managed deployment registers (install.ps1 refuses
# a per-user install beside it for the same reason).
_MANAGED_MARKER_KEY = r"SOFTWARE\Cisco\DefenseClaw\Enterprise"
_CURRENT_VERSION_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
# The enterprise install roots under Program Files: Secure Client, standalone
# (internal/winpath EnterpriseRootsFor).
_ENTERPRISE_VENDOR_DIRS = (("Cisco", "Cisco Secure Client"), ("Cisco",))
_DEPLOYMENT_MODE_ENV = "DEFENSECLAW_DEPLOYMENT_MODE"
_MANAGED_ENTERPRISE = "managed_enterprise"


def use_current_user_as_default_owner(argv: list[str] | None = None) -> bool:
    """Set this process token's default owner to its user; True if changed.

    Never raises: a failure leaves the token as it was, and doctor still
    names an Administrators-owned file and its fix.
    """
    if os.name != "nt" or (argv and argv[0] == "enterprise"):
        return False
    try:
        if _managed_deployment_present():
            return False
        return _swap_default_owner()
    except Exception:  # noqa: BLE001 - never block the CLI on this
        return False


def _managed_deployment_present() -> bool:
    """A managed deployment, a process it pinned, or state that cannot be read.

    Only the standalone profile writes the marker: a Secure Client deployment,
    or a first standalone install before its marker is written, has only its
    install root, and the children of Setup and of the managed service carry
    the deployment pin (GAP-0063 review). A stray pin only keeps the token as
    it is.
    """
    if os.environ.get(_DEPLOYMENT_MODE_ENV, "").strip().lower() == _MANAGED_ENTERPRISE:
        return True
    return _managed_marker_present() or _enterprise_install_root_present()


def _enterprise_install_root_present() -> bool:
    program_files = _program_files_dir()
    if not program_files:
        return True  # unreadable: do not guess, leave the token alone
    for vendor in _ENTERPRISE_VENDOR_DIRS:
        try:
            os.lstat(os.path.join(program_files, *vendor, "DefenseClaw"))
        except FileNotFoundError:
            continue
        except OSError:
            return True
        return True
    return False


def _program_files_dir() -> str:
    """Program Files from the machine registration, not the environment; "" if unreadable.

    Like the Go resolver (winpath.TrustedProgramFiles, ValidateTrustedMachineRoot)
    it takes only a REG_SZ that is a canonical local drive-letter path, with no
    padding, environment reference, control character or forward slash
    (g072 review 3 N4); anything else is unreadable.
    """
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, _CURRENT_VERSION_KEY, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            value, kind = winreg.QueryValueEx(key, "ProgramFilesDir")
    except OSError:
        return ""
    if kind != winreg.REG_SZ or not isinstance(value, str) or not _canonical_machine_root(value):
        return ""
    return value


def _canonical_machine_root(value: str) -> bool:
    if not value or value != value.strip() or "%" in value or "/" in value:
        return False
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return False
    return (
        len(value) >= 3
        and value[0].isascii()
        and value[0].isalpha()
        and value[1:3] == ":\\"
        and ntpath.normpath(value) == value
    )


def _managed_marker_present() -> bool:
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, _MANAGED_MARKER_KEY, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ):
            return True
    except FileNotFoundError:
        return False
    except OSError:
        return True  # unreadable: do not guess, leave the token alone


def _swap_default_owner() -> bool:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    advapi32.SetTokenInformation.restype = wintypes.BOOL
    advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi32.EqualSid.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY | _TOKEN_ADJUST_DEFAULT, ctypes.byref(token)
    ):
        return False
    try:
        user = _token_information(advapi32, token, _TOKEN_USER)
        owner = _token_information(advapi32, token, _TOKEN_OWNER)
        if user is None or owner is None:
            return False
        # TOKEN_USER and TOKEN_OWNER both start with the SID pointer.
        user_sid = ctypes.c_void_p.from_buffer(user).value
        owner_sid = ctypes.c_void_p.from_buffer(owner).value
        if not user_sid or (owner_sid and advapi32.EqualSid(user_sid, owner_sid)):
            return False
        new_owner = ctypes.c_void_p(user_sid)  # TOKEN_OWNER {PSID Owner}
        return bool(
            advapi32.SetTokenInformation(token, _TOKEN_OWNER, ctypes.byref(new_owner), ctypes.sizeof(new_owner))
        )
    finally:
        kernel32.CloseHandle(token)


def _token_information(advapi32, token, info_class: int):
    import ctypes
    from ctypes import wintypes

    needed = wintypes.DWORD()
    advapi32.GetTokenInformation(token, info_class, None, 0, ctypes.byref(needed))
    if not needed.value:
        return None
    buffer = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetTokenInformation(token, info_class, buffer, needed, ctypes.byref(needed)):
        return None
    return buffer
