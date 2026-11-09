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

// windowsEnterpriseGuardianStateFiles lists every file the hook guardian and
// its enumerator publish and a lifecycle run waits for: the regular files of
// the authorization folder (the ledger protected_targets.json, activation.json,
// removed-connectors.json, user-cleanup.json, unprotected-agents.json and the
// others the guardian writes there), the guardian's records in its data
// folder (hook_guardian_state.json, hook_guardian_notices.json,
// hook_guardian_restores.json and the OpenCode port warnings), the files of the
// enumerator's folder (the manifest targets.yaml, its unprotected-agents record,
// the enrollment group cache, the inventory grants and the OpenCode service
// ports), and the off-roster markers of the machine hook runtime folder.
func windowsEnterpriseGuardianStateFiles(layout managed.StandaloneLayout) []string {
	var files []string
	add := func(dir, pattern string) {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return
		}
		for _, match := range matches {
			// A lock or a service's own state marker is held open on
			// purpose while a service runs.
			if strings.HasSuffix(match, ".lock") || strings.HasSuffix(match, ".state") {
				continue
			}
			if info, err := os.Lstat(match); err == nil && info.Mode().IsRegular() {
				files = append(files, match)
			}
		}
	}
	if layout.GuardianAuthDir != "" {
		add(layout.GuardianAuthDir, "*")
	}
	if layout.DataDir != "" {
		add(layout.DataDir, "hook_guardian_*.json")
		add(layout.DataDir, windowsOpenCodePortWarningsFile)
	}
	if layout.ManifestPath != "" {
		// The enumerator's folder: the manifest (targets.yaml), its
		// unprotected-agents record, its enrollment group cache and inventory
		// grants, and the OpenCode service ports.
		add(filepath.Dir(layout.ManifestPath), "*")
	}
	if layout.HookRuntimeDir != "" {
		add(layout.HookRuntimeDir, ".defenseclaw-connector-off-roster-*")
	}
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
