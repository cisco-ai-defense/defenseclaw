// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// A standard user can hold requirements.toml open (GAP-0650, a documented
// Windows platform limit). Codex reads the file with the token of each user,
// so every user may read it, and Windows lets any reader refuse delete and
// write sharing; nothing an administrator holds overrides that. While such a
// handle is open the file cannot be replaced or removed, so a reconcile,
// policy change, upgrade or removal of the Codex requirements is delayed for
// as long as the handle stays open. The requirements already in place stay
// in force: the transaction counter returns to even and the hook keeps
// reading the last committed pair. DefenseClaw names the holder where
// Windows can tell (Restart Manager), and writes the update as soon as the
// file is released.

// WindowsCodexRequirementsHeldError is a requirements.toml write that another
// process blocked by holding the file open.
type WindowsCodexRequirementsHeldError struct {
	Path    string
	Holders []string
	Err     error
}

func (e *WindowsCodexRequirementsHeldError) Error() string {
	return fmt.Sprintf(
		"%s is held open by %s, so DefenseClaw cannot write it (%v); the enforced Codex policy stays in place, "+
			"and DefenseClaw writes the update as soon as the file is released",
		e.Path, e.holder(), e.Err,
	)
}

func (e *WindowsCodexRequirementsHeldError) Unwrap() error { return e.Err }

func (e *WindowsCodexRequirementsHeldError) holder() string {
	if len(e.Holders) == 0 {
		return "another program"
	}
	return strings.Join(e.Holders, ", ")
}

// WindowsCodexRequirementsHold reports, for status, whether another handle
// holds the machine requirements.toml open so that DefenseClaw cannot
// replace it, and names the holders where Restart Manager can tell. It
// needs an elevated caller (the probe asks for delete access); for any other
// caller, and for a missing file, it reports no hold.
func WindowsCodexRequirementsHold() (path string, holders []string, held bool) {
	programData, err := windowsCodexMachineProgramData()
	if err != nil {
		return "", nil, false
	}
	path = programData + `\OpenAI\Codex\requirements.toml`
	if !windowsCodexRequirementsHeld(path) {
		return path, nil, false
	}
	return path, windowsCodexRequirementsHolders(path), true
}

// WindowsCodexRequirementsHoldLine is the status line for a held
// requirements.toml (GAP-0650, a documented Windows platform limit).
func WindowsCodexRequirementsHoldLine(path string, holders []string) string {
	holder := "another program"
	if len(holders) != 0 {
		holder = strings.Join(holders, ", ")
	}
	return fmt.Sprintf("%s is held open by %s; Codex policy updates wait until it is released, "+
		"the enforced Codex policy stays in place, and DefenseClaw writes the update as soon as the file is released",
		path, holder)
}

// windowsCodexRequirementsHeldBy is the holder a held error names, or "".
func windowsCodexRequirementsHeldBy(err error) string {
	var held *WindowsCodexRequirementsHeldError
	if !errors.As(err, &held) {
		return ""
	}
	return held.holder()
}

var (
	// windowsCodexRequirementsHeld reports whether another handle keeps
	// path from being replaced; tests replace it.
	windowsCodexRequirementsHeld = windowsCodexFileHeldAgainstDelete
	// windowsCodexRequirementsHolders names the holding processes; tests
	// replace it.
	windowsCodexRequirementsHolders = processutil.FileHolders

	// A held requirements.toml is written again as soon as it is released:
	// the call polls the file every windowsCodexHeldRetryPoll, without the
	// writer lock, for at most windowsCodexHeldRetryWait, and otherwise
	// returns the named failure for the next pass. Tests replace them.
	windowsCodexHeldRetryWait  = 30 * time.Second
	windowsCodexHeldRetryPoll  = 2 * time.Second
	windowsCodexHeldRetryNow   = time.Now
	windowsCodexHeldRetrySleep = time.Sleep
)

// windowsCodexFileHeldAgainstDelete opens path for delete access, sharing
// everything: the open fails with a sharing violation exactly while another
// handle refuses delete sharing, which is what keeps a replace from landing.
func windowsCodexFileHeldAgainstDelete(path string) bool {
	extended, err := winpath.Extended(path)
	if err != nil {
		return false
	}
	name, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(
		name,
		windows.DELETE|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
	}
	_ = windows.CloseHandle(handle)
	return false
}

// windowsCodexRequirementsHeldFailure turns a failed write of the
// requirements at path into a WindowsCodexRequirementsHeldError when another
// handle holds the file open. A newer file another writer saved is not a
// hold.
func windowsCodexRequirementsHeldFailure(path string, err error) error {
	if err == nil || errors.Is(err, errWindowsCodexMachineFileChanged) {
		return err
	}
	var held *WindowsCodexRequirementsHeldError
	if errors.As(err, &held) {
		return err
	}
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
		!errors.Is(err, windows.ERROR_LOCK_VIOLATION) &&
		!errors.Is(err, windows.ERROR_ACCESS_DENIED) &&
		!errors.Is(err, windows.Errno(1175)) && // ERROR_UNABLE_TO_REMOVE_REPLACED
		!errors.Is(err, windows.Errno(1176)) { // ERROR_UNABLE_TO_MOVE_REPLACEMENT
		return err
	}
	if !windowsCodexRequirementsHeld(path) {
		return err
	}
	return &WindowsCodexRequirementsHeldError{Path: path, Holders: windowsCodexRequirementsHolders(path), Err: err}
}

// withWindowsCodexRequirementsReleaseRetry runs run (one whole transaction)
// and, while it fails because requirements.toml is held open, logs the
// holder, waits for the file to be released and runs it again, for at most
// windowsCodexHeldRetryWait. The writer lock is not held while it waits.
func withWindowsCodexRequirementsReleaseRetry(path string, run func() error) error {
	deadline := windowsCodexHeldRetryNow().Add(windowsCodexHeldRetryWait)
	for {
		err := run()
		var held *WindowsCodexRequirementsHeldError
		if !errors.As(err, &held) {
			return err
		}
		emitManagedResilience(managed.MarkerDegraded, path, held.Error(), map[string]string{"held_by": held.holder()})
		for windowsCodexRequirementsHeld(path) {
			if !windowsCodexHeldRetryNow().Before(deadline) {
				return err
			}
			windowsCodexHeldRetrySleep(windowsCodexHeldRetryPoll)
		}
		if !windowsCodexHeldRetryNow().Before(deadline) {
			// Released only now: one more pass, then the named failure.
			if retryErr := run(); !errors.As(retryErr, &held) {
				return retryErr
			}
			return err
		}
	}
}
