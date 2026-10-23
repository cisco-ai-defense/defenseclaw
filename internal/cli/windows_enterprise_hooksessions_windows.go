// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The gateway's protected foreign-hook session records (GAP-0352) live in
// %ProgramData%\Cisco\DefenseClaw-HookSessions. This lifecycle step owns
// the folder and the records' key, the file
// %ProgramData%\Cisco\DefenseClaw-HookSessions.key-<random> next to it
// (enterprisepolicy.CreatePublishedSessionKey). The gateway service creates
// one folder per account in the record folder, with a protected DACL that
// lets only that account read it; a guarded connector's hook reads its own
// account's records during a gateway outage under fail mode open, and
// blocks when they are missing, untrusted, or were not written under the
// current key.
//
// The kill switch (1.0.4 guard loop): install, upgrade, repair, ensure and
// uninstall take the key lock and remove every key before they change
// anything (beginWindowsHookSessionKeyChange), and hold the lock to their
// end, so the hook guardian makes no key meanwhile. An install, upgrade,
// repair or ensure stops when the lock cannot be taken or a key cannot be
// shown dead. Those that finish without an error put the folder's owner and
// DACL back and only then give every account a new key; uninstall removes
// the folder and the key. No record
// written before the run proves anything after it, whatever an account
// that kept a handle on the folder (with WRITE_DAC, from a time it owned
// the folder) puts back in it: no handle on the folder reaches the key, and
// only SYSTEM or Administrators can make a file the hook accepts as one.
// Status and verify report a missing or untrusted folder or key.

var (
	windowsHookSessionDir = func() (string, error) {
		layout, err := managed.StandaloneWindowsLayout()
		return layout.HookSessionDir, err
	}
	// windowsHookSessionKeyLock is the key lock in the lifecycle folder
	// (enterprisepolicy.PublishedSessionKeysLockPath).
	windowsHookSessionKeyLock = func() (string, error) {
		layout, err := managed.StandaloneWindowsLayout()
		return enterprisepolicy.PublishedSessionKeysLockPath(layout.LifecycleDir), err
	}
	windowsHookSessionGatewayAccount = `NT SERVICE\` + managed.StandaloneWindowsGatewaySvc
)

// windowsHookSessionFolderName is the folder's last element, which
// uninstall checks before it removes anything.
const windowsHookSessionFolderName = managed.StandaloneWindowsHookSessionDirName

// windowsHookSessionDACL: LocalSystem and Administrators full control, the
// gateway service modify (it creates and replaces the per-account folders),
// standard users read and list of this folder only (they reach their own
// folder through its own DACL, and the hook checks the DACL of every folder
// above a record). No other access.
func windowsHookSessionDACL(gateway *windows.SID) string {
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)(A;OICI;0x1301bf;;;" + gateway.String() + ")"
}

func windowsHookSessionSDDL(gateway *windows.SID) string {
	return "O:BAG:SY" + windowsHookSessionDACL(gateway)
}

// windowsHookSessionTrust names the gateway service, which a key file lets
// remove the key and the hook accepts as a writer of the records.
func windowsHookSessionTrust() enterprisepolicy.PublishedSessionTrust {
	return enterprisepolicy.PublishedSessionTrust{ServiceAccount: windowsHookSessionGatewayAccount}
}

// windowsHookSessionLockKeys takes the key lock for an action,
// windowsHookSessionKillKeys removes every account's key of the records
// before the action changes anything, and windowsHookSessionRotateKeys
// gives every account a new one after it (replaceable in tests).
// windowsHookSessionKeyLockWait is the least an action waits for the key
// lock, which another action holds for its whole run (its --lock-wait, when
// longer, applies).
var (
	windowsHookSessionLockKeys    = enterprisepolicy.LockPublishedSessionKeysForLifecycle
	windowsHookSessionKillKeys    = enterprisepolicy.KillAllPublishedSessionKeys
	windowsHookSessionRotateKeys  = enterprisepolicy.RotateAllPublishedSessionKeys
	windowsHookSessionKeyLockWait = 30 * time.Second
)

// windowsHookSessionRootTrustProblem reports a record folder, or a folder
// above it, that the hook refuses (enterprisepolicy.ValidatePublishedSessionRoot);
// replaceable in tests.
var windowsHookSessionRootTrustProblem = func(root string) error {
	return enterprisepolicy.ValidatePublishedSessionRoot(root, windowsHookSessionTrust())
}

// windowsHookSessionKeyChange reports an action that changes the
// deployment, and so the trust of the record folders.
func windowsHookSessionKeyChange(action string) bool {
	switch action {
	case "install", "upgrade", "repair", "ensure", "uninstall":
		return true
	}
	return false
}

// beginWindowsHookSessionKeyChange takes the key lock of the protected
// session records for an elevated action that changes the deployment and
// removes every account's key (killWindowsHookSessionKey), before the
// action changes anything (GAP-0352): no hook guardian makes a key until
// the action released the lock at its end, after it made new ones, and no
// record written before the action proves anything once it started, not
// even one written under a key an action it waited for made at its end. An
// install, upgrade, repair or ensure stops with an error when the lock
// cannot be taken or a key cannot be shown dead: it would put the record
// folder's trust back while an earlier allow could still prove itself. An
// uninstall only removes the keys and goes on; it removes the folder and
// the keys at its end. The caller releases the lock once the action
// finished.
func beginWindowsHookSessionKeyChange(ctx context.Context, action string, opts *windowsEnterpriseLifecycleOptions) (release func(), err error) {
	release = func() {}
	if !windowsHookSessionKeyChange(action) || !windowsEnterpriseIsElevated() {
		return release, nil
	}
	if action == "uninstall" {
		// It removes the record folder and the keys at its end; a lock held
		// across it would only keep the installer from removing its state.
		_ = killWindowsHookSessionKey(action)
		return release, nil
	}
	lockPath, err := windowsHookSessionKeyLock()
	if err == nil {
		wait := windowsHookSessionKeyLockWait
		if opts != nil && opts.bundleLockWait > wait {
			wait = opts.bundleLockWait
		}
		lockCtx, cancel := context.WithTimeout(ctx, wait)
		var held func()
		held, err = windowsHookSessionLockKeys(lockCtx, lockPath)
		cancel()
		if err == nil {
			release = held
		} else if errors.Is(err, context.DeadlineExceeded) {
			err = fmt.Errorf("another DefenseClaw lifecycle action %s of the protected session record keys (waited %s): %w", windowsEnterpriseLifecycleBusyMarker, wait, err)
		}
	}
	if err != nil {
		return func() {}, fmt.Errorf("hook_session_records_unavailable: the protected foreign-hook session record key lock could not be taken, so nothing was changed: %w", err)
	}
	if err := killWindowsHookSessionKey(action); err != nil {
		release()
		return func() {}, err
	}
	return release, nil
}

// killWindowsHookSessionKey removes the key of the protected session
// records, of every account, before an elevated install, upgrade, repair,
// ensure or uninstall changes anything (GAP-0352): no record written before
// the action proves anything once it started. A key that could not be
// removed but is shadowed or marked revoked is enough. It returns an error
// when the record folder cannot be located or a key cannot be shown dead
// (enterprisepolicy.ErrPublishedSessionKeyAlive). The end of the action,
// and the hook guardian, make new keys.
func killWindowsHookSessionKey(action string) error {
	if !windowsHookSessionKeyChange(action) || !windowsEnterpriseIsElevated() {
		return nil
	}
	root, err := windowsHookSessionDir()
	if err == nil && strings.TrimSpace(root) == "" {
		err = errors.New("the standalone layout names no record folder")
	}
	if err != nil {
		return fmt.Errorf("hook_session_records_unavailable: the protected foreign-hook session record folder cannot be located, so its keys cannot be removed and nothing was changed: %w", err)
	}
	if err := windowsHookSessionKillKeys(root); errors.Is(err, enterprisepolicy.ErrPublishedSessionKeyAlive) {
		return fmt.Errorf("hook_session_records_unavailable: the protected foreign-hook session record keys could not be shown dead, so nothing was changed (a record written before this action could still allow a guarded call during a gateway outage): %w", err)
	}
	return nil
}

// ensureWindowsHookSessionRoot makes root a folder Administrators own with
// the protected DACL: a missing folder is created with it, and an existing
// one gets its owner and DACL back. A file, link or junction where the
// folder belongs is removed (never followed) first. An account that kept a
// handle on an existing folder can still change it, but nothing it puts
// there counts: the action made a new key, which the folder does not hold.
func ensureWindowsHookSessionRoot(root string, gateway *windows.SID) error {
	info, err := os.Lstat(root)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	case !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0:
		if err := os.Remove(root); err != nil {
			return fmt.Errorf("remove %s, which is not a folder: %w", root, err)
		}
	default:
		if err := winpath.RejectReparseChain(root); err != nil {
			return err
		}
		if err := applyWindowsSDDL(root, windowsHookSessionSDDL(gateway)); err != nil {
			return fmt.Errorf("protect %s: %w", root, err)
		}
		return nil
	}
	descriptor, err := windows.SecurityDescriptorFromString(windowsHookSessionDACL(gateway))
	if err != nil {
		return err
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	pointer, err := winpath.UTF16Ptr(root)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(pointer, attributes); err != nil {
		return fmt.Errorf("create %s: %w", root, err)
	}
	if err := applyWindowsSDDL(root, windowsHookSessionSDDL(gateway)); err != nil {
		return fmt.Errorf("protect %s: %w", root, err)
	}
	return nil
}

func removeWindowsHookSessionRoot() error {
	root, err := windowsHookSessionDir()
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Base(root), windowsHookSessionFolderName) {
		return fmt.Errorf("refusing to remove %s", root)
	}
	keyErr := enterprisepolicy.RemovePublishedSessionKeys(root)
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return keyErr
	}
	if err != nil {
		return errors.Join(keyErr, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(keyErr, fmt.Errorf("%s is not a real folder", root))
	}
	return errors.Join(keyErr, os.RemoveAll(root))
}

// windowsHookSessionRootProblem names a missing or untrusted folder or key,
// or "".
func windowsHookSessionRootProblem() string {
	root, err := windowsHookSessionDir()
	if err != nil || strings.TrimSpace(root) == "" {
		return ""
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return root + " is missing. It holds the gateway's protected foreign-hook session records; without it a guarded connector " +
			"(Copilot, OpenCode) blocks during a gateway outage even when the fail mode is open." +
			" Fix: run " + windowsEnterpriseAdminCommand("repair")
	}
	trusted, err := windowsPathOwnedByAdministrators(root)
	if err == nil && !trusted {
		err = errors.New("it is not owned by Administrators or SYSTEM")
	}
	if err == nil {
		// The hook's own rule (GAP-0352 review): the folder strict, and every
		// folder above it with fatal verdicts, the shared Cisco folder
		// included. The advisory ancestor verdicts of
		// ValidateTrustedServiceRuntimeDir would hide a drifted Cisco folder
		// that makes every hook refuse its record.
		err = windowsHookSessionRootTrustProblem(root)
	}
	if err != nil {
		return root + ": " + err.Error() + ". A guarded connector's hook refuses the session records there and blocks during a gateway outage." +
			" Fix: if a folder above it lets other accounts change it, put that folder's permissions back," +
			" then run " + windowsEnterpriseAdminCommand("repair")
	}
	return ""
}

// applyWindowsStandaloneHookSessionRecords runs the folder's lifecycle step
// at the end of a standalone action.
func applyWindowsStandaloneHookSessionRecords(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) {
	if result == nil || opts == nil || opts.runningDeploymentLabel {
		return
	}
	switch result.Action {
	case "install", "upgrade", "repair", "ensure":
		if len(result.Errors) != 0 {
			// The key stays removed: guarded connectors block during a
			// gateway outage until a run finishes or the hook guardian makes
			// a key.
			return
		}
		root, err := windowsHookSessionDir()
		if err == nil {
			var gateway *windows.SID
			if gateway, err = managed.WindowsServiceAccountSID(windowsHookSessionGatewayAccount); err == nil {
				err = ensureWindowsHookSessionRoot(root, gateway)
			}
		}
		if err == nil {
			err = windowsHookSessionRotateKeys(root, windowsHookSessionTrust())
		}
		if err != nil {
			result.AddWarning("hook_session_records_unavailable", "the protected foreign-hook session record folder could not be prepared ("+
				err.Error()+"); guarded connectors block during a gateway outage even when the fail mode is open")
		}
	case "uninstall":
		if len(result.Errors) != 0 {
			return
		}
		if err := removeWindowsHookSessionRoot(); err != nil {
			result.AddWarning("hook_session_records_left", "the protected foreign-hook session record folder could not be removed: "+err.Error())
		}
	case "status", "verify":
		if result.Installed && !windowsEnterpriseResultHasWarning(result, windowsEnterpriseHealthNotChecked) {
			if problem := windowsHookSessionRootProblem(); problem != "" {
				result.AddWarning("hook_session_records_untrusted", problem)
			}
		}
	}
}
