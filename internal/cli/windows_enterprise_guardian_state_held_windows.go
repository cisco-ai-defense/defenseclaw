// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"golang.org/x/sys/windows"
)

// A program that holds one of the hook guardian's state files open without
// delete sharing (an editor, a backup agent, a script that opened the file)
// keeps the guardian from publishing its authorization ledger, so no roster
// change can be proven or undone while it holds. Setup says so before it
// changes anything and, when the holder arrives mid-run, leaves the services
// running instead of stopping the gateway over a file it cannot judge
// (GAP-0967).

// windowsGuardianStateHold is one such file and the programs that hold it.
type windowsGuardianStateHold struct {
	Path    string
	Holders []string
}

// describe words the hold for an error message.
func (h *windowsGuardianStateHold) describe() string {
	holder := "another program"
	if len(h.Holders) > 0 {
		holder = strings.Join(h.Holders, ", ")
	}
	return "the hook guardian's state file " + h.Path + " is held open by " + holder + ", so the guardian cannot publish its state"
}

// The probe, the retry wait and the holder lookup are replaceable in tests.
var (
	windowsEnterpriseGuardianStateOpenForDelete = func(path string) error {
		pointer, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		handle, err := windows.CreateFile(pointer, windows.DELETE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
			windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return err
		}
		return windows.CloseHandle(handle)
	}
	windowsEnterpriseGuardianStateProbeWait = 200 * time.Millisecond
	windowsEnterpriseGuardianStateHolders   = processutil.FileHolders
)

// windowsEnterpriseGuardianCriticalFiles are the guardian state files whose
// hold breaks a lifecycle run, measured natively (GAP-0977): the ledger
// (protected_targets.json) and the activation receipt, the guardian state
// record, and the cleanup ledger, whose failed save aborts a guardian pass
// (RevokeUsers returns the error). A hold on any other file the guardian or
// its enumerator publishes (the removed-connectors record, the startup record,
// the notices and restores records, the OpenCode port warnings, the
// enumerator folder, the off-roster markers) did not stop a repair, so it is
// not gated: gating a file a standard account can open would let that account
// block every ensure and repair (N2).
var (
	windowsEnterpriseGuardianAuthorizationCriticalFiles = []string{managed.HookGuardianAuthorizationFile, hookGuardianActivationFile, managed.HookGuardianUserCleanupFile}
	windowsEnterpriseGuardianRuntimeCriticalFiles       = []string{hookGuardianStateFile}
)

// windowsEnterpriseGuardianStateUserOpenable reports whether any principal
// other than SYSTEM, Administrators and a service SID has an Allow entry with
// any access on path: a standard account (through Users, Authenticated Users,
// Everyone, Interactive or a user SID named directly) can then open it and hold
// it with read sharing, so it is not a file a lifecycle run may wait for. The
// gated set holds only files just SYSTEM, Administrators and the service SIDs
// can open. Deny entries grant nothing. Replaceable in tests.
var windowsEnterpriseGuardianStateUserOpenable = func(path string) bool {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return false
	}
	if acl == nil {
		return true // no access list: everyone
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if ace.Mask == 0 {
			continue
		}
		if !windowsEnterpriseGuardianStateSIDIsAdminOnly((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return true
		}
	}
	return false
}

// windowsEnterpriseGuardianStateSIDIsAdminOnly reports whether sid is SYSTEM,
// Administrators or a service SID (S-1-5-80-...): the principals that may open
// a gated guardian state file.
func windowsEnterpriseGuardianStateSIDIsAdminOnly(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		if known, err := windows.CreateWellKnownSid(kind); err == nil && windows.EqualSid(sid, known) {
			return true
		}
	}
	return strings.HasPrefix(sid.String(), "S-1-5-80-")
}

// windowsEnterpriseGuardianStateFiles lists the critical guardian state files
// that exist and that no standard account can open.
func windowsEnterpriseGuardianStateFiles(layout managed.StandaloneLayout) []string {
	var files []string
	add := func(dir string, names []string) {
		if dir == "" {
			return
		}
		for _, name := range names {
			path := filepath.Join(dir, name)
			if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
				continue
			}
			if windowsEnterpriseGuardianStateUserOpenable(path) {
				continue
			}
			files = append(files, path)
		}
	}
	add(layout.GuardianAuthDir, windowsEnterpriseGuardianAuthorizationCriticalFiles)
	add(layout.DataDir, windowsEnterpriseGuardianRuntimeCriticalFiles)
	return files
}

// windowsEnterpriseGuardianStateHeldNow is windowsEnterpriseGuardianStateHeld;
// tests replace it.
var windowsEnterpriseGuardianStateHeldNow = windowsEnterpriseGuardianStateHeld

// windowsEnterpriseGuardianStateHeld returns the first guardian state file a
// program holds in a way that stops the guardian from replacing it, or nil. A
// file only the guardian itself has open for a moment passes: the probe is
// repeated for a second before it counts.
func windowsEnterpriseGuardianStateHeld(layout managed.StandaloneLayout) *windowsGuardianStateHold {
	for _, path := range windowsEnterpriseGuardianStateFiles(layout) {
		held := false
		for attempt := 0; attempt < 5; attempt++ {
			err := windowsEnterpriseGuardianStateOpenForDelete(path)
			held = errors.Is(err, windows.ERROR_SHARING_VIOLATION)
			if !held {
				break
			}
			time.Sleep(windowsEnterpriseGuardianStateProbeWait)
		}
		if held {
			return &windowsGuardianStateHold{Path: path, Holders: windowsEnterpriseGuardianStateHolders(path)}
		}
	}
	return nil
}

// windowsEnterpriseGuardianStatePreflight refuses a lifecycle run that would
// change the deployment while a guardian state file is held: nothing is
// changed, the services keep running, and the error names the holder and the
// repair to run once it lets go. It exits 1618 like the other held-file
// refusals, so a deployment tool retries it.
func windowsEnterpriseGuardianStatePreflight() error {
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return nil
	}
	hold := windowsEnterpriseGuardianStateHeldNow(layout)
	if hold == nil {
		return nil
	}
	return fmt.Errorf("%s; nothing was changed and the services are still running. Next step: close that program, then run this again, or from an elevated PowerShell prompt run %s",
		hold.describe(), windowsEnterpriseAdminCommand("repair"))
}

// applyWindowsEnterpriseGuardianStateHold makes status and verify say what a
// held guardian state file means: the guardian cannot publish, so the
// enrollment it last published is not proven now. The accounts' connectors that
// read enrolled are shown pending, the host is not security-complete, and the
// warning names the file, the holder and the repair (GAP-0977).
func applyWindowsEnterpriseGuardianStateHold(result *enterprisestatus.Result) {
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return
	}
	hold := windowsEnterpriseGuardianStateHeldNow(layout)
	if hold == nil {
		return
	}
	result.SecurityComplete = false
	reason := "not proven: " + hold.describe() + ", so what it published before is not verified now"
	for i := range result.Enrollment.Accounts {
		account := &result.Enrollment.Accounts[i]
		changed := false
		for name, state := range account.Connectors {
			if state == "enrolled" {
				account.Connectors[name] = "pending"
				result.Enrollment.Pending++
				changed = true
			}
		}
		if changed && account.Reason == "" {
			account.Reason = reason
		}
	}
	result.AddWarning("guardian_state_held", hold.describe()+"; the enrollment above is what the guardian published before and is not proven now. Next step: close that program, then from an elevated PowerShell prompt run "+windowsEnterpriseAdminCommand("repair"))
}
