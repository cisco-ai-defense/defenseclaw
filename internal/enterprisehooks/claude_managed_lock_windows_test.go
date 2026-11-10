// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
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

// cowork-1-0-8 GAP-0064: a config-only Setup /ensure that changed
// managed_hooks_only while an enrolled account was signed out failed 1603.
// Only the target's own install rewrote the drop-in, and the guardian
// installs a target only in its account's Windows session. The guardian now
// writes the setting into the drop-in itself, so the signed-out account's
// target verifies with no install at all; a target whose own files are
// broken still fails, and a drop-in edited outside DefenseClaw is left
// alone.
func TestWindowsClaudeManagedHooksOnlyChangeNeedsNoAccountSession(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	t.Cleanup(func() { SetWindowsClaudeManagedHooksOnlyPolicy(nil) })
	setStandaloneProfileForTest(t, true)
	opts := windowsManagedInstallOptions(fixture)
	ctx := context.Background()
	if _, err := Install(ctx, opts); err != nil {
		t.Fatalf("Install under enforce: %v", err)
	}
	if written, err := ApplyWindowsClaudeManagedHooksOnlyLock(); err != nil || written {
		t.Fatalf("unchanged setting: written=%v err=%v, want nothing written", written, err)
	}

	for _, step := range []struct {
		name    string
		enforce bool
	}{{"preserve", false}, {"enforce", true}} {
		enforce := step.enforce
		SetWindowsClaudeManagedHooksOnlyPolicy(func() bool { return enforce })
		if _, err := Verify(ctx, opts); err == nil {
			t.Fatalf("%s: Verify accepted the drop-in rendered for the other setting", step.name)
		}
		written, err := ApplyWindowsClaudeManagedHooksOnlyLock()
		if err != nil || !written {
			t.Fatalf("%s: written=%v err=%v, want the drop-in rewritten", step.name, written, err)
		}
		// No Install: the signed-out account's target verifies as it is.
		if _, err := Verify(ctx, opts); err != nil {
			t.Fatalf("%s: Verify after the machine-only change: %v", step.name, err)
		}
		body, err := os.ReadFile(fixture.policyPath)
		if err != nil {
			t.Fatal(err)
		}
		if windowsClaudeManagedPolicyHasLock(body) != enforce {
			t.Fatalf("%s: drop-in lock = %v", step.name, !enforce)
		}
		if path, removed := WindowsClaudeManagedPolicyDrift(); path != "" || removed {
			t.Fatalf("%s: the ownership record does not describe the new drop-in: drift=%q removed=%v", step.name, path, removed)
		}
		if written, err := ApplyWindowsClaudeManagedHooksOnlyLock(); err != nil || written {
			t.Fatalf("%s: second pass written=%v err=%v, want nothing written", step.name, written, err)
		}
	}

	// A target whose own files are broken still fails after the change.
	hookcfg := filepath.Join(fixture.home, ".defenseclaw", "hooks", ".hookcfg.claudecode")
	if err := os.Rename(hookcfg, hookcfg+".moved"); err != nil {
		t.Fatal(err)
	}
	SetWindowsClaudeManagedHooksOnlyPolicy(func() bool { return false })
	if written, err := ApplyWindowsClaudeManagedHooksOnlyLock(); err != nil || !written {
		t.Fatalf("broken target: written=%v err=%v, want the drop-in rewritten", written, err)
	}
	if _, err := Verify(ctx, opts); err == nil {
		t.Fatal("Verify accepted a target whose own hook config is missing")
	}
	if err := os.Rename(hookcfg+".moved", hookcfg); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(ctx, opts); err != nil {
		t.Fatalf("repair in the account's session: %v", err)
	}

	// A Secure Client process never writes the lock, even with a real change
	// pending on DefenseClaw's own drop-in: only the standalone gate stops it.
	setStandaloneProfileForTest(t, false)
	SetWindowsClaudeManagedHooksOnlyPolicy(func() bool { return true })
	if written, err := ApplyWindowsClaudeManagedHooksOnlyLock(); err != nil || written {
		t.Fatalf("Secure Client: written=%v err=%v, want nothing written", written, err)
	}
	setStandaloneProfileForTest(t, true)

	// A drop-in edited outside DefenseClaw is not a setting change.
	original, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := append(append([]byte(nil), original...), ' ')
	if err := os.WriteFile(fixture.policyPath, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	SetWindowsClaudeManagedHooksOnlyPolicy(nil)
	if written, err := ApplyWindowsClaudeManagedHooksOnlyLock(); err != nil || written {
		t.Fatalf("edited drop-in: written=%v err=%v, want it left alone", written, err)
	}
	if got, err := os.ReadFile(fixture.policyPath); err != nil || !bytes.Equal(got, edited) {
		t.Fatalf("edited drop-in was changed (err=%v)", err)
	}
	if _, err := Verify(ctx, opts); err == nil {
		t.Fatal("Verify accepted a drop-in edited outside DefenseClaw")
	}

}
