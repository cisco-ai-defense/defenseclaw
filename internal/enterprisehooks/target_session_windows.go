// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// windowsEnterpriseStandaloneDeferredDataDirAbsent reports whether a pending
// proof may treat the data-directory validation error as "no runtime": only in
// a standalone process, and only when the directory itself does not exist.
// Reparse points, foreign owners, wrong types and every other inspection
// failure stay hard errors, and Secure Client keeps requiring the directory.
func windowsEnterpriseStandaloneDeferredDataDirAbsent(err error) bool {
	return windowsEnterpriseStandaloneProcess() && errors.Is(err, fs.ErrNotExist)
}

// windowsEnterpriseStandaloneDeferredDataDirAccountCreated reports, in a
// standalone process only, a data directory the account created itself
// before enrollment (windowsAccountCreatedDataDir). It holds no managed
// runtime, so it proves the pending state like an absent one; enrollment
// adopts it in the account's session.
func windowsEnterpriseStandaloneDeferredDataDirAccountCreated(dataDir string, target *windows.SID) bool {
	return windowsEnterpriseStandaloneProcess() && windowsAccountCreatedDataDirAt(dataDir, target)
}

// windowsAccountCreatedDataDirAt reads dataDir's owner and DACL and reports
// windowsAccountCreatedDataDir for it; any read failure reports false.
func windowsAccountCreatedDataDirAt(dataDir string, target *windows.SID) bool {
	extended, err := winpath.Extended(dataDir)
	if err != nil {
		return false
	}
	descriptor, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	ok, err := windowsAccountCreatedDataDir(dataDir, descriptor, target)
	return err == nil && ok
}

// WindowsAccountCreatedDataDir reports whether home's %USERPROFILE%\.defenseclaw
// is a data directory the account (sid) created itself before enrollment
// (windowsAccountCreatedDataDir), which the guardian adopts when the account
// next signs in and Upgrade/Repair leave alone. Status names such accounts.
func WindowsAccountCreatedDataDir(home, sid string) bool {
	target, err := windows.StringToSid(strings.TrimSpace(sid))
	if err != nil || strings.TrimSpace(home) == "" {
		return false
	}
	return windowsAccountCreatedDataDirAt(filepath.Join(filepath.Clean(home), ".defenseclaw"), target)
}

// WindowsLocalAccountSID reports whether sid is an account of this
// computer's own account database. Only such an account's failed name
// lookup shows it was deleted: a domain or Microsoft Entra account's lookup
// also fails while its directory cannot be reached.
func WindowsLocalAccountSID(sid string) bool {
	machine, err := windowsMachineAccountDomainSID()
	machine = strings.ToUpper(strings.TrimSpace(machine))
	return err == nil && machine != "" &&
		strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sid)), machine+"-")
}

func requireWindowsEnterpriseDeferredTargetPendingPlatform(target ManifestTarget) error {
	if !target.IsEnabled() || !target.IsDeferred() {
		return errors.New("enterprise hooks: pending proof requires an enabled deferred manifest target")
	}
	connectorName := strings.ToLower(strings.TrimSpace(target.Connector))
	_, perUser := windowsStandalonePerUserConnector(connectorName)
	switch {
	case connectorName == "codex" || connectorName == "claudecode" || connectorName == "cursor":
	case perUser && windowsEnterpriseStandaloneProcess():
	default:
		return fmt.Errorf(
			"enterprise hooks: deferred pending proof does not support connector %q",
			target.Connector,
		)
	}
	home, targetSID, err := validateWindowsEnterpriseHome(target.UserHome, target.SID)
	if err != nil {
		return err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, target.DataDir)
	if err != nil {
		return err
	}
	if err := validateWindowsUserPathElement(dataDir, targetSID, true, true, true); err != nil {
		if !windowsEnterpriseStandaloneDeferredDataDirAbsent(err) &&
			!windowsEnterpriseStandaloneDeferredDataDirAccountCreated(dataDir, targetSID) {
			return fmt.Errorf(
				"enterprise hooks: deferred target data directory is untrusted: %w",
				err,
			)
		}
		// Standalone writes every discovered row deferred, including users
		// DefenseClaw has never touched. An absent canonical data directory,
		// or one the account created itself before enrollment,
		// holds no runtime, so it proves the pending state as well as a
		// trusted empty one; the selector-absence proof below still runs.
	}
	hookExecutable, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return err
	}
	hookExecutable = filepath.Clean(hookExecutable)
	if err := windowsEnterpriseHookTrustCheck(hookExecutable); err != nil {
		return fmt.Errorf(
			"enterprise hooks: deferred target hook executable trust check failed: %w",
			err,
		)
	}
	return verifyWindowsManagedRuntimeSelectorTargetAbsentPlatform(
		WindowsManagedRuntimeSelectorSnapshotOptions{
			Connector:      connectorName,
			TargetSID:      targetSID.String(),
			DataDir:        dataDir,
			HookExecutable: hookExecutable,
		},
	)
}
