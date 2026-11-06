// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// WindowsHookRuntimeMarkerFiles are the files DefenseClaw writes in the
// standalone hook runtime folder (C:\ProgramData\Cisco\DefenseClaw-HookRuntime):
// the machine policy summary every user's hook reads and the hot-config undo
// closure.
var WindowsHookRuntimeMarkerFiles = []string{"machine-policy.json", ".defenseclaw-hot-config-undo-closed"}

// windowsManagedFolderRecordLimit bounds the administrator record read.
const windowsManagedFolderRecordLimit = 4 << 20

// windowsManagedFolderLayout is StandaloneWindowsLayout; tests replace it.
var windowsManagedFolderLayout = StandaloneWindowsLayout

// WindowsDefenseClawFolderMarker is the one standalone decision of whether a
// machine folder is one DefenseClaw already manages, so that its in-place
// takeover is refused (g582 review 4 F2). It returns why, or "" for a folder
// DefenseClaw does not manage (one MDM, the vendor installer or a user
// created before the first install), which keeps the takeover.
//
//   - An administrator-only record outside the folder decides first: the
//     hook guardian ledger (protected_targets.json) names the folder itself
//     or a target anywhere under it (g582 review 5 S1), or the Setup
//     deployment record exists and the folder is the hook runtime folder,
//     any folder under it (the per-connector enrollment folders, g582 review
//     5 M2) or the vendor folder above it. Deleting a marker inside the
//     folder, or the folder that held the recorded target, therefore does
//     not turn a refusal into a takeover.
//   - Otherwise an entry directly in the folder counts when its name has
//     "defenseclaw" in it, is a hook runtime file (WindowsHookRuntimeMarkerFiles)
//     or is one of extra, and it is owned by SYSTEM, Administrators or
//     TrustedInstaller and is a non-reparse directory or single-link regular
//     file. A marker a user planted is owned by that user and does not
//     count.
//   - A folder that cannot be listed, or a candidate whose owner cannot be
//     read even with backup semantics, counts as managed (fail closed).
func WindowsDefenseClawFolderMarker(dir string, extra ...string) string {
	clean, err := filepath.Abs(dir)
	if err != nil {
		return "entries (the folder path cannot be resolved: " + err.Error() + ")"
	}
	clean = filepath.Clean(clean)
	if recorded := windowsManagedFolderRecorded(clean); recorded != "" {
		return recorded
	}
	entries, err := os.ReadDir(clean)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		return "entries (the folder cannot be listed: " + err.Error() + ")"
	}
	for _, entry := range entries {
		if !windowsDefenseClawEntryName(entry.Name(), extra) {
			continue
		}
		if reason, counts := windowsTrustedFolderMarker(filepath.Join(clean, entry.Name())); counts {
			return reason
		}
	}
	return ""
}

func windowsDefenseClawEntryName(name string, extra []string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "defenseclaw") {
		return true
	}
	for _, candidate := range WindowsHookRuntimeMarkerFiles {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	for _, candidate := range extra {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	return false
}

// windowsTrustedFolderMarker reports whether path counts as a DefenseClaw
// marker: owned by a trusted principal, no reparse point, a directory or a
// single-link regular file. An owner nobody can read counts.
func windowsTrustedFolderMarker(path string) (string, bool) {
	name := filepath.Base(path)
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	handle, err := openCanonicalObject(path, access)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		privilegedErr := canonicalRunWithRepairPrivileges(func() error {
			var openErr error
			handle, openErr = openCanonicalObject(path, access)
			return openErr
		})
		err = privilegedErr
	}
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return "", false
	}
	if err != nil {
		return name + " (it cannot be inspected: " + err.Error() + ")", true
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return name + " (it cannot be inspected: " + err.Error() + ")", true
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", false
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && info.NumberOfLinks != 1 {
		return "", false
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return name + " (its owner cannot be read: " + err.Error() + ")", true
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return name + " (its owner cannot be read)", true
	}
	if !IsWindowsTrustedAdminOwner(owner) {
		return "", false
	}
	return name, true
}

// windowsManagedFolderRecorded is the administrator-only record decision of
// WindowsDefenseClawFolderMarker, or "".
func windowsManagedFolderRecorded(dir string) string {
	ledger := ""
	if configured := strings.TrimSpace(os.Getenv(HookGuardianAuthorizationDirEnv)); configured != "" {
		ledger = filepath.Join(filepath.Clean(configured), HookGuardianAuthorizationFile)
	}
	layout, layoutErr := windowsManagedFolderLayout()
	if ledger == "" && layoutErr == nil && strings.TrimSpace(layout.GuardianAuthDir) != "" {
		ledger = filepath.Join(layout.GuardianAuthDir, HookGuardianAuthorizationFile)
	}
	if ledger != "" && windowsAdminOnlyRecord(ledger) && windowsLedgerNamesFolder(ledger, dir) {
		return "folder (the hook guardian ledger " + ledger + " protects a target in it)"
	}
	if layoutErr != nil || strings.TrimSpace(layout.HookRuntimeDir) == "" || strings.TrimSpace(layout.LifecycleDir) == "" {
		return ""
	}
	runtimeDir := filepath.Clean(layout.HookRuntimeDir)
	// No MDM, vendor installer or user creates folders inside the hook
	// runtime folder, so the record covers its whole subtree: a
	// per-connector enrollment folder whose enrollment.json and lock were
	// deleted is still DefenseClaw's (g582 review 5 M2).
	if !strings.EqualFold(dir, runtimeDir) && !strings.EqualFold(dir, filepath.Dir(runtimeDir)) &&
		!windowsPathUnder(dir, runtimeDir) {
		return ""
	}
	record := filepath.Join(layout.LifecycleDir, "deployment.json")
	if !windowsAdminOnlyRecord(record) {
		return ""
	}
	return "folder (the Setup deployment record " + record + " names the hook runtime folder " + runtimeDir + ")"
}

// windowsPathUnder reports whether path lies strictly under dir, compared
// case-insensitively on cleaned paths.
func windowsPathUnder(path, dir string) bool {
	dir = strings.ToLower(strings.TrimRight(filepath.Clean(dir), `\`))
	return dir != "" && strings.HasPrefix(strings.ToLower(filepath.Clean(path)), dir+`\`)
}

// OverrideWindowsManagedFolderLayoutForTest makes the record decision of
// WindowsDefenseClawFolderMarker read layout instead of the machine's
// standalone layout, so a test can stand temporary folders in for the hook
// runtime and lifecycle folders. Production code never calls it. restore
// puts the machine layout back.
func OverrideWindowsManagedFolderLayoutForTest(layout StandaloneLayout) (restore func()) {
	previous := windowsManagedFolderLayout
	windowsManagedFolderLayout = func() (StandaloneLayout, error) { return layout, nil }
	return func() { windowsManagedFolderLayout = previous }
}

// WindowsAdminOnlyRecord reports whether path is a regular file whose own
// descriptor no untrusted principal can write or owns (AssessCanonical as an
// AdminFile: canonical or trusted-only drift), the trust a standalone
// decision needs before it lets an administrator record outside a folder
// speak for that folder. A record it cannot judge (missing, a link, a
// reparse point, a descriptor nobody can read) is not trusted.
func WindowsAdminOnlyRecord(path string) bool {
	return windowsAdminOnlyRecord(path)
}

// windowsAdminOnlyRecord is WindowsAdminOnlyRecord. It only ever adds a
// refusal, so a record it cannot judge is not used.
func windowsAdminOnlyRecord(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	result, err := AssessCanonical(path, ObjectAdminFile, CanonicalOptions{Quiet: true})
	if err != nil {
		return false
	}
	return result.Outcome == CanonicalOK || result.Outcome == CanonicalAccepted
}

// windowsLedgerNamesFolder reports whether any string in the ledger is dir
// itself or an absolute path anywhere under dir: a vendor folder above a
// recorded policy folder stays recorded after the policy folder is renamed
// away (g582 review 5 S1).
func windowsLedgerNamesFolder(ledger, dir string) bool {
	file, err := os.Open(ledger)
	if err != nil {
		return false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, windowsManagedFolderRecordLimit+1))
	if err != nil || len(data) > windowsManagedFolderRecordLimit {
		return false
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return false
	}
	return windowsJSONNamesFolder(decoded, dir)
}

func windowsJSONNamesFolder(value any, dir string) bool {
	switch typed := value.(type) {
	case string:
		if !filepath.IsAbs(typed) {
			return false
		}
		clean := filepath.Clean(typed)
		return strings.EqualFold(clean, dir) || windowsPathUnder(clean, dir)
	case []any:
		for _, item := range typed {
			if windowsJSONNamesFolder(item, dir) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if windowsJSONNamesFolder(item, dir) {
				return true
			}
		}
	}
	return false
}
