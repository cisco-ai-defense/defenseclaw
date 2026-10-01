// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func claudeLockTestSetup() connector.SetupOpts {
	return connector.SetupOpts{
		APIAddr:           "127.0.0.1:18970",
		HookFailMode:      "closed",
		ManagedEnterprise: true,
		HookExecutable:    `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
	}
}

// A standalone process renders and verifies the machine-wide Claude
// Code drop-in with allowManagedHooksOnly: true unless the administrator
// chose managed_hooks_only: preserve; a Secure Client process never does.
func TestWindowsStandaloneClaudePolicyCarriesTheManagedHooksOnlyLock(t *testing.T) {
	t.Cleanup(func() { SetWindowsClaudeManagedHooksOnlyPolicy(nil) })
	provider := connector.NewClaudeCodeConnector()

	setStandaloneProfileForTest(t, true)
	SetWindowsClaudeManagedHooksOnlyPolicy(nil)
	locked := withWindowsClaudeManagedHooksOnly(claudeMachinePolicySetup(claudeLockTestSetup(), "", true))
	if !locked.ClaudeAllowManagedHooksOnly {
		t.Fatal("a standalone process with the default policy renders the Claude drop-in without the lock")
	}
	body, err := provider.ManagedHookPolicy(locked)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["allowManagedHooksOnly"] != true {
		t.Fatalf("standalone drop-in allowManagedHooksOnly = %v, want true:\n%s", doc["allowManagedHooksOnly"], body)
	}

	SetWindowsClaudeManagedHooksOnlyPolicy(func() bool { return false })
	if withWindowsClaudeManagedHooksOnly(claudeLockTestSetup()).ClaudeAllowManagedHooksOnly {
		t.Fatal("managed_hooks_only: preserve still renders the lock")
	}
	SetWindowsClaudeManagedHooksOnlyPolicy(func() bool { return true })

	setStandaloneProfileForTest(t, false)
	if withWindowsClaudeManagedHooksOnly(claudeLockTestSetup()).ClaudeAllowManagedHooksOnly {
		t.Fatal("a Secure Client process renders the lock")
	}
}

// A standalone verify of a drop-in without the lock (an
// earlier release's) names the missing lock, and a later administrator
// drop-in that sets allowManagedHooksOnly to false fails verify naming that
// file, although DefenseClaw's own drop-in is canonical.
func TestStandaloneClaudeVerifyNamesTheMissingLockAndALaterOverride(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	t.Cleanup(func() { SetWindowsClaudeManagedHooksOnlyPolicy(nil) })
	setStandaloneProfileForTest(t, true)
	opts := windowsManagedInstallOptions(fixture)

	// Publish the drop-in without the lock, then verify under enforce.
	SetWindowsClaudeManagedHooksOnlyPolicy(func() bool { return false })
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("Install under preserve: %v", err)
	}
	SetWindowsClaudeManagedHooksOnlyPolicy(nil)
	_, err := Verify(context.Background(), opts)
	if err == nil {
		t.Fatal("Verify under enforce accepted a drop-in without allowManagedHooksOnly")
	}
	if !strings.Contains(err.Error(), "does not set allowManagedHooksOnly: true") {
		t.Fatalf("Verify error %q does not name the missing lock", err)
	}

	// Repair publishes the lock; a later administrator drop-in turns it off.
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("Install under enforce: %v", err)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("Verify of the locked drop-in: %v", err)
	}
	later := filepath.Join(filepath.Dir(fixture.policyPath), "95-x.json")
	if err := os.WriteFile(later, []byte("{\"allowManagedHooksOnly\": false}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(context.Background(), opts)
	if err == nil {
		t.Fatal("Verify accepted a later drop-in that sets allowManagedHooksOnly to false")
	}
	if !strings.Contains(err.Error(), later) {
		t.Fatalf("Verify error %q does not name %s", err, later)
	}
}
