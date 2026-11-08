//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"strings"
	"testing"
)

func TestManagedWindowsOpenCodeInstallWritesPortInsideTargetCallback(t *testing.T) {
	previous := windowsOpenCodeServicePortWriter
	t.Cleanup(func() { windowsOpenCodeServicePortWriter = previous })
	calls := 0
	windowsOpenCodeServicePortWriter = func(home string, port int) (int, error) {
		calls++
		if home != `C:\Users\one` || port != 25001 {
			t.Fatalf("writer got %q, %d", home, port)
		}
		return port, nil
	}
	if err := ensureWindowsManagedOpenCodePort("opencode", `C:\Users\one`, "S-1-5-21-1-2-3-1001", 25001, true); err != nil || calls != 1 {
		t.Fatalf("OpenCode writer: calls=%d err=%v", calls, err)
	}
	if err := ensureWindowsManagedOpenCodePort("codex", `C:\Users\one`, "S-1-5-21-1-2-3-1001", 25001, true); err != nil || calls != 1 {
		t.Fatalf("ordinary connector invoked OpenCode writer: calls=%d err=%v", calls, err)
	}
	if err := ensureWindowsManagedOpenCodePort("opencode", `C:\Users\one`, "S-1-5-21-1-2-3-1001", 0, true); err == nil || calls != 1 {
		t.Fatalf("missing required port was accepted: calls=%d err=%v", calls, err)
	}
	if err := ensureWindowsManagedOpenCodePort("opencode", `C:\Users\one`, "S-1-5-21-1-2-3-1001", 0, false); err != nil || calls != 1 {
		t.Fatalf("ordinary install changed: calls=%d err=%v", calls, err)
	}
	windowsOpenCodeServicePortWriter = func(string, int) (int, error) { return 49374, nil }
	if err := ensureWindowsManagedOpenCodePort("opencode", `C:\Users\one`, "S-1-5-21-1-2-3-1001", 25001, true); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("mismatched user port was accepted: %v", err)
	}
	windowsOpenCodeServicePortWriter = func(string, int) (int, error) { return 0, errors.New("unavailable") }
	if err := ensureWindowsManagedOpenCodePort("opencode", `C:\Users\one`, "S-1-5-21-1-2-3-1001", 25001, true); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("writer failure was hidden: %v", err)
	}
}
