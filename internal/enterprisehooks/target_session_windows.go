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
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// windowsEnterpriseStandaloneDeferredDataDirAccountLink reports, in a
// standalone process only, a link or junction the account itself made at its
// canonical data directory or at that directory's hooks folder
// (windowsTargetOwnedDataDirLink). Refusing it failed the signed-out
// account's row and, through it, every administrator lifecycle on the
// computer (GAP-0193); the account stays pending until it signs in.
func windowsEnterpriseStandaloneDeferredDataDirAccountLink(home, dataDir string, target *windows.SID) bool {
	return windowsEnterpriseStandaloneProcess() && windowsTargetOwnedDataDirLink(home, dataDir, target) != ""
}

// WindowsAccountOwnedDataDirLink reports whether home's
// %USERPROFILE%\.defenseclaw, or its hooks folder, is a link or junction the
// account (sid) made itself (windowsTargetOwnedDataDirLink). The account
// stays pending until it next signs in, when the guardian moves the link
// aside and enrolls it. Status names such accounts.
func WindowsAccountOwnedDataDirLink(home, sid string) bool {
	return windowsAccountOwnedDataDirLinkPath(home, sid) != ""
}

// WindowsAccountOwnedRootDataDirLink reports only an account-owned link at
// the canonical folder itself. A link below a plain folder does not qualify.
func WindowsAccountOwnedRootDataDirLink(home, sid string) bool {
	root := filepath.Join(filepath.Clean(home), ".defenseclaw")
	return sameWindowsEnterprisePath(windowsAccountOwnedDataDirLinkPath(home, sid), root)
}

// WindowsForeignOwnedDataDirLink reports whether home's
// %USERPROFILE%\.defenseclaw, or its hooks folder, is a link or junction that
// the account (sid) does not own: one an administrator or another principal
// made, or whose owner cannot be read (GAP-0585). Nothing follows or repairs
// such a link, and no enrollment can move it aside, so the account stays
// unprotected until an administrator removes it. A caller leaves that one
// account out instead of failing the computer's lifecycle for it.
func WindowsForeignOwnedDataDirLink(home, sid string) bool {
	target, err := windows.StringToSid(strings.TrimSpace(sid))
	if err != nil || strings.TrimSpace(home) == "" {
		return false
	}
	home = filepath.Clean(home)
	_, owner, ok := windowsDataDirLink(home, filepath.Join(home, ".defenseclaw"))
	return ok && (owner == nil || !owner.Equals(target))
}

func windowsAccountOwnedDataDirLinkPath(home, sid string) string {
	target, err := windows.StringToSid(strings.TrimSpace(sid))
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	home = filepath.Clean(home)
	return windowsTargetOwnedDataDirLink(home, filepath.Join(home, ".defenseclaw"), target)
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
	switch {
	case connectorName == "codex" || connectorName == "claudecode" || connectorName == "cursor":
	case windowsProfilePerUserConnector(connectorName):
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
	if err := windowsDeferredTargetDataDirExactCheck(dataDir, targetSID); err != nil {
		if !windowsEnterpriseStandaloneDeferredDataDirAbsent(err) &&
			!windowsEnterpriseStandaloneDeferredDataDirAccountCreated(dataDir, targetSID) &&
			!windowsEnterpriseStandaloneDeferredDataDirAccountLink(home, dataDir, targetSID) {
			// Permission drift on an enrolled data directory is repaired by
			// the LocalSystem guardian, or accepted when no untrusted
			// principal can write it; structural failures stay fatal.
			if healErr := healWindowsEnterpriseDeferredTargetDataDir(home, dataDir, targetSID, err); healErr != nil {
				return fmt.Errorf(
					"enterprise hooks: deferred target data directory is untrusted: %w",
					healErr,
				)
			}
		}
		// Standalone writes every discovered row deferred, including users
		// DefenseClaw has never touched. An absent canonical data directory,
		// one the account created itself before enrollment, or a link the
		// account made there (never followed; the enrollment in its session
		// moves it aside) holds no runtime, so it proves the pending state as
		// well as a trusted empty one; the selector-absence proof below
		// still runs.
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

// Seams for tests.
var (
	windowsDeferredTargetDataDirExactCheck = func(path string, target *windows.SID) error {
		return validateWindowsUserPathElement(path, target, true, true, true)
	}
	windowsDeferredTargetDataDirWriterCheck = func(path string, target *windows.SID) error {
		return validateWindowsUserPathElement(path, target, true, true, false)
	}
)

// windowsDeferredTargetAccepted holds the accepted findings already logged, so
// a guardian tick does not repeat an unchanged one.
var windowsDeferredTargetAccepted sync.Map

// healWindowsEnterpriseDeferredTargetDataDir handles a deferred (signed-out)
// target whose data directory is not at its exact per-user descriptor, as
// after an ACL reset of the profile folder. There is no user session to
// impersonate, so the LocalSystem guardian restores the canonical per-user
// DACL itself through the privileged no-follow repair: the owner stays the
// target user (an administrator or orphaned owner is handed back to it), and
// reparse points and hard links are refused before anything is written. The
// repair is logged once. When the descriptor still is not exact but no
// untrusted principal can write the folder, the drift is accepted and logged
// once instead of failing the target. Anything else, and every finding in
// strict mode, returns the original error.
func healWindowsEnterpriseDeferredTargetDataDir(home, dataDir string, target *windows.SID, driftErr error) error {
	if managed.TrustStrictAncestors() {
		return driftErr
	}
	var repairErr error
	if identityErr := windowsEnterpriseMutationIdentityCheck(); identityErr == nil {
		repairErr = windowsEnterpriseGuardianDACLRepair(home, dataDir, target, true)
		if repairErr == nil {
			recheck := windowsDeferredTargetDataDirExactCheck(dataDir, target)
			if recheck == nil {
				windowsDeferredTargetAccepted.Delete(strings.ToLower(filepath.Clean(dataDir)))
				managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
					"sid":    target.String(),
					"path":   dataDir,
					"reason": "deferred target data directory: " + driftErr.Error(),
				})
				return nil
			}
			repairErr = fmt.Errorf("still not exact after repair: %w", recheck)
		}
	} else {
		repairErr = fmt.Errorf("repair needs the LocalSystem guardian: %w", identityErr)
	}
	if writerErr := windowsDeferredTargetDataDirWriterCheck(dataDir, target); writerErr != nil {
		return errors.Join(driftErr, writerErr)
	}
	reason := "deferred target data directory: " + driftErr.Error() + "; not repaired: " + repairErr.Error()
	key := strings.ToLower(filepath.Clean(dataDir))
	if previous, loaded := windowsDeferredTargetAccepted.Swap(key, reason); !loaded || previous != reason {
		managed.EmitResilienceEvent(managed.MarkerAccept, map[string]string{
			"sid":    target.String(),
			"path":   dataDir,
			"reason": reason,
		})
	}
	return nil
}
