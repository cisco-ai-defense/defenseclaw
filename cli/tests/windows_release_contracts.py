# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Shared static markers for the Windows release uninstall contract."""

DEFERRED_UNINSTALL_REQUIRED_MARKERS = (
    '$expectedUninstallExitCode = if ($UninstallContract -ceq "deferred") {',
    "$uninstall.ExitCode -ne $expectedUninstallExitCode",
    'if ($UninstallContract -ceq "deferred") {',
    "Assert-ExactDeferredUninstallState",
    "Assert-NoReparsePathChain",
    "Assert-PrivatePathCustody",
    '$ownerRightsSid = "S-1-3-4"',
    "Assert-WindowsAMD64Executable",
    "Get-AuthenticodeSignature -FilePath $hookLauncher",
    "hook_launcher_sha256",
    "product_executables_authenticode_signed",
    "SignatureStatus]::NotSigned",
    "cleanup_boot_identifier",
    "uninstall_boot_identifier",
    "retired_launcher_path",
    "previous_maintenance_sha256",
    "verified_connectors",
    '"pending-reboot"',
    '"converged"',
    '"disabled"',
    '"DefenseClawDeferredUninstallCleanup"',
    "[Microsoft.Win32.RegistryValueKind]::String",
    "cleanup record does not bind the exact release Setup digest",
    "uninstall retained unrelated managed residue",
    "Same-boot uninstall Run value is not the exact absolute cached Setup command",
    "Wait-ForPathRemoval -Path $cacheRoot",
)

DEFERRED_UNINSTALL_FORBIDDEN_MARKERS = (
    "$uninstall.ExitCode -ne 0",
    "$uninstall.ExitCode -ne 3010",
    "$uninstall.ExitCode -notin @(0, 3010)",
    '"S-1-5-32-544"',
)
