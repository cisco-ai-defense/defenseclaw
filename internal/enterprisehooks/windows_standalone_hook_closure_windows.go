// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const windowsStandaloneHookClosureFile = ".defenseclaw-hot-config-undo-closed"

var windowsStandaloneHookClosureBody = []byte("hot-config-undo-unproven-v1\n")

var (
	windowsStandaloneHookClosureEnsure = ensureWindowsManagedPolicyDirectory
	windowsStandaloneHookClosureWrite  = writeWindowsManagedFile
)

// ErrWindowsStandaloneHooksClosed identifies the administrator's durable
// closure of standalone hooks while an unproven config undo is repaired.
var ErrWindowsStandaloneHooksClosed = errors.New("enterprise_hot_config_undo_unproven")

func windowsStandaloneHookClosurePath(layout managed.StandaloneLayout) string {
	return filepath.Join(layout.HookRuntimeDir, windowsStandaloneHookClosureFile)
}

func readWindowsStandaloneHookClosure(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	if !info.Mode().IsRegular() || info.Size() > int64(len(windowsStandaloneHookClosureBody)) {
		return true, fmt.Errorf("unsafe standalone hook closure at %s", path)
	}
	data, exists, err := readTrustedWindowsManagedPolicyFile(path)
	if err != nil {
		return true, err
	}
	if !exists || !bytes.Equal(data, windowsStandaloneHookClosureBody) {
		return true, fmt.Errorf("standalone hook closure changed at %s", path)
	}
	return true, nil
}

// WindowsStandaloneHooksHeldClosed is read by the installed standalone hook
// before it accepts an authenticated generation's explicit outage-open mode.
// A present, damaged or unreadable marker tightens delivery; Secure Client
// hooks do not call this function.
func WindowsStandaloneHooksHeldClosed() (bool, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return true, err
	}
	return windowsStandaloneHookClosureHeldClosed(layout)
}

func windowsStandaloneHookClosureHeldClosed(layout managed.StandaloneLayout) (bool, error) {
	// An absent marker is meaningful only when its directory is trusted: a
	// replaced directory could otherwise hide a published closure.
	if err := windowsManagedPolicyDirTrustCheck(layout.HookRuntimeDir); err != nil {
		return true, err
	}
	return readWindowsStandaloneHookClosure(windowsStandaloneHookClosurePath(layout))
}

// CloseWindowsStandaloneHooksForUnprovenUndo publishes the closure in the
// administrator-owned, user-readable machine runtime directory. The managed
// policy writer flushes its bytes before replacing the path, and this readback
// must pass before the caller may stop the gateway.
func CloseWindowsStandaloneHooksForUnprovenUndo(layout managed.StandaloneLayout) error {
	path := windowsStandaloneHookClosurePath(layout)
	if err := windowsStandaloneHookClosureEnsure(layout.HookRuntimeDir); err != nil {
		return err
	}
	if held, err := readWindowsStandaloneHookClosure(path); err != nil {
		return err
	} else if held {
		return nil
	}
	if err := windowsStandaloneHookClosureWrite(path, windowsStandaloneHookClosureBody, true); err != nil {
		return err
	}
	if held, err := readWindowsStandaloneHookClosure(path); err != nil {
		return fmt.Errorf("prove standalone hook closure: %w", err)
	} else if !held {
		return errors.New("standalone hook closure was not published")
	}
	return nil
}

// ReleaseWindowsStandaloneHookClosure runs only after ensure proves the
// installed config's policy on the live gateway. Failure keeps the closure.
func ReleaseWindowsStandaloneHookClosure(layout managed.StandaloneLayout) error {
	path := windowsStandaloneHookClosurePath(layout)
	held, err := windowsStandaloneHookClosureHeldClosed(layout)
	if err != nil || !held {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if held, err := windowsStandaloneHookClosureHeldClosed(layout); err != nil {
		return fmt.Errorf("prove standalone hook closure release: %w", err)
	} else if held {
		return errors.New("standalone hook closure survived removal")
	}
	return nil
}
