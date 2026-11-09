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

// windowsEnterpriseGuardianStateFiles lists the files the guardian publishes:
// those of its authorization folder and its state file.
func windowsEnterpriseGuardianStateFiles(layout managed.StandaloneLayout) []string {
	var files []string
	if entries, err := os.ReadDir(layout.GuardianAuthDir); err == nil {
		for _, entry := range entries {
			if entry.Type().IsRegular() {
				files = append(files, filepath.Join(layout.GuardianAuthDir, entry.Name()))
			}
		}
	}
	state := filepath.Join(layout.DataDir, hookGuardianStateFile)
	if info, err := os.Lstat(state); err == nil && info.Mode().IsRegular() {
		files = append(files, state)
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
