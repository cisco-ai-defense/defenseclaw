// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-1001: the writer lock failures that mean "a Codex writer holds it" are
// classified by Win32 code, wrapped without changing the text, and nothing
// else is.
func TestWindowsCodexWriterLockBusyIsClassifiedByWin32Code(t *testing.T) {
	for name, tc := range map[string]struct {
		err      error
		openBusy bool
		rngBusy  bool
	}{
		"sharing violation":  {windows.ERROR_SHARING_VIOLATION, true, false},
		"lock violation":     {windows.ERROR_LOCK_VIOLATION, true, true},
		"io pending":         {windows.ERROR_IO_PENDING, false, true},
		"wrapped io pending": {fmt.Errorf("lock: %w", windows.ERROR_IO_PENDING), false, true},
		"access denied":      {windows.ERROR_ACCESS_DENIED, false, false},
		"not found":          {windows.ERROR_FILE_NOT_FOUND, false, false},
	} {
		if got := windowsCodexLockOpenBusy(tc.err); got != tc.openBusy {
			t.Errorf("%s: open busy = %v, want %v", name, got, tc.openBusy)
		}
		if got := windowsCodexLockRangeBusy(tc.err); got != tc.rngBusy {
			t.Errorf("%s: range busy = %v, want %v", name, got, tc.rngBusy)
		}
	}
	cause := errors.New("timed out waiting 10s for Codex machine policy lock")
	wrapped := fmt.Errorf("open Codex machine policy lock: %w", windowsCodexWriterLockBusyError{cause})
	if !errors.Is(wrapped, ErrWindowsCodexWriterLockBusy) {
		t.Fatal("a busy lock failure does not match ErrWindowsCodexWriterLockBusy")
	}
	if wrapped.Error() != "open Codex machine policy lock: "+cause.Error() {
		t.Fatalf("the text changed: %q", wrapped.Error())
	}
	if errors.Is(fmt.Errorf("acquire Codex machine policy lock: %w", windows.ERROR_ACCESS_DENIED), ErrWindowsCodexWriterLockBusy) {
		t.Fatal("an access error was classified as a busy writer")
	}
}
