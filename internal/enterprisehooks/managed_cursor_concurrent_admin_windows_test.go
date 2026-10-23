// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// An administrator can save hooks.json after repair reads it. The repair must
// carry the new hook into the closed machine guard rather than publish its old
// merge over that save.
func TestWindowsCursorEmptyGuardRepairKeepsConcurrentAdminSave(t *testing.T) {
	const hook = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	paths := installWindowsCursorStandaloneGuardForTest(t, hook, false)
	damaged := []byte(`{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"operator-hook"}]}}`)
	saved := []byte(`{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"operator-hook"}],"adminEvent":[{"type":"command","command":"admin-concurrent"}]}}`)
	if err := windowsManagedPolicyWriter(paths.Hooks, damaged, true); err != nil {
		t.Fatal(err)
	}
	previousTrust := windowsManagedPolicyFileTrustCheck
	savedOnce := false
	windowsManagedPolicyFileTrustCheck = func(path string) error {
		if strings.EqualFold(path, paths.Hooks) && !savedOnce {
			savedOnce = true
			if err := os.WriteFile(path, saved, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return previousTrust(path)
	}
	t.Cleanup(func() { windowsManagedPolicyFileTrustCheck = previousTrust })
	restored, err := RestoreWindowsCursorManagedAdapter(hook)
	if err != nil || !restored {
		t.Fatalf("repair: restored=%t err=%v", restored, err)
	}
	if !savedOnce {
		t.Fatal("fixture did not make the concurrent administrator save")
	}
	hooks, err := os.ReadFile(paths.Hooks)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(hooks, []byte(`"admin-concurrent"`)) {
		t.Fatalf("repair lost the administrator's concurrent hook: %s", hooks)
	}
	if err := connector.VerifyWindowsCursorEnterpriseHooks(hooks, paths.Adapter, "closed"); err != nil {
		t.Fatalf("the repaired guard is not closed: %v", err)
	}
	if targets, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active || len(targets) != 0 {
		t.Fatalf("empty guard: active=%t targets=%v err=%v", active, targets, err)
	}
}
