//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

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

// The guard wrapper texts 1.0.9 Setup wrote and the ones 1.0.10 renders
// (rel-1-0-10 GAP-0119), as literals so this test reads the same words at a
// build that predates either form.
var (
	gap1495Missing109 = "DefenseClaw could not start its Claude Code hook guard defenseclaw-hook-guard.exe " +
		"because it is missing from the install folder. Run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair " +
		"as an administrator to restore it. Setup is not installed on this computer: use the copy in your MDM package or the release download."
	gap1495Start109  = "DefenseClaw could not start its Claude Code hook guard. Run the DefenseClaw installer again to repair it."
	gap1495Missing10 = "If defenseclaw-hook-guard.exe is missing from the install folder: DefenseClaw cannot check Claude Code " +
		"until an administrator runs DefenseClawSetup-Enterprise-Standalone-x64.exe /repair to restore it. " +
		"Setup is not installed on this computer: use the copy in your MDM package or the release download."
	gap1495Start10 = "If defenseclaw-hook-guard.exe is in the install folder but does not run: DefenseClaw cannot check Claude Code " +
		"until an administrator runs DefenseClawSetup-Enterprise-Standalone-x64.exe /repair."
)

// gap1495Args is text as the run of JSON strings a compact guard wrapper
// holds, one per word.
func gap1495Args(t *testing.T, text string) []byte {
	t.Helper()
	var out bytes.Buffer
	for i, word := range strings.Fields(text) {
		if i > 0 {
			out.WriteByte(',')
		}
		encoded, err := json.Marshal(word)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(encoded)
	}
	return out.Bytes()
}

// rel-1-0-10 GAP-1495: Setup /ensure from 1.0.9 to 1.0.10 ended 1603 on
// every Windows standalone host whose Claude Code drop-in 1.0.9 published.
// GAP-0119 changed the guard wrapper texts, and the guardian's ensure, which
// recognizes its own drop-in by rendering it again, refused the 1.0.9 one as
// "an unrecognized registered command", so the first reconcile of the new
// guardian published no state. The 1.0.9 drop-in is this deployment's: ensure
// replaces it with the current form, and again is a no-op.
func TestGAP1495StandaloneClaudeEnsureUpgrades109GuardPolicy(t *testing.T) {
	requireElevatedManagedWindows(t)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	setStandaloneProfileForTest(t, true)
	opts := windowsManagedInstallOptions(fixture)
	opts.AgentVersion = "2.1.230 (Claude Code)"
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	newMissing, newStart := gap1495Args(t, gap1495Missing10), gap1495Args(t, gap1495Start10)
	events := bytes.Count(current, newMissing)
	if events == 0 || bytes.Count(current, newStart) != events {
		t.Fatalf("fixture policy is not the guarded wrapper form: %d missing and %d start texts", events, bytes.Count(current, newStart))
	}
	published109 := bytes.ReplaceAll(current, newMissing, gap1495Args(t, gap1495Missing109))
	published109 = bytes.ReplaceAll(published109, newStart, gap1495Args(t, gap1495Start109))

	statePath := filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)
	stateBody, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var record windowsClaudeManagedPolicyState
	if err := decodeWindowsClaudeManagedPolicyState(stateBody, &record); err != nil {
		t.Fatal(err)
	}
	record.PolicySHA256 = windowsManagedPolicyDigest(published109)
	stateBody, err = json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := windowsManagedPolicyWriter(fixture.policyPath, published109, true); err != nil {
		t.Fatal(err)
	}
	if err := windowsManagedPolicyWriter(statePath, append(stateBody, '\n'), true); err != nil {
		t.Fatal(err)
	}

	ensure := connector.SetupOpts{APIAddr: opts.APIAddr, HookExecutable: fixture.hookExe}
	if err := EnsureWindowsStandaloneClaudeManagedPolicy(ensure); err != nil {
		t.Fatalf("ensure over the drop-in 1.0.9 published: %v", err)
	}
	got, err := os.ReadFile(fixture.policyPath)
	if err != nil || !bytes.Equal(got, current) {
		t.Fatalf("ensure left the 1.0.9 drop-in instead of the current form: err=%v", err)
	}
	if err := EnsureWindowsStandaloneClaudeManagedPolicy(ensure); err != nil {
		t.Fatalf("idempotent ensure: %v", err)
	}
	if again, err := os.ReadFile(fixture.policyPath); err != nil || !bytes.Equal(again, current) {
		t.Fatalf("current policy changed on repeated ensure: err=%v", err)
	}
}
