// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWindowsManagedHooksTeardownCommandIsHiddenAndBounded(t *testing.T) {
	command := newWindowsManagedHooksTeardownCommand()
	if !command.Hidden {
		t.Fatal("teardown-managed-hooks command must remain hidden")
	}
	if command.Use != "teardown-managed-hooks" {
		t.Fatalf("Use = %q", command.Use)
	}
	// Flags whose scope is limited to specific teardown actions. If any of
	// these were exposed on rollback/status by accident, the PowerShell
	// teardown module could pass a receipt-scoped argument during rollback
	// and silently apply cleanup semantics against a rolled-back journal.
	scopedFlags := map[string]map[string]bool{
		"purge-contract-locks":     {"finalize": true},
		"contract-cleanup-receipt": {"prepare": true, "finalize": true},
		"contract-cleanup-scope":   {"prepare": true, "finalize": true},
	}
	var actions []string
	for _, child := range command.Commands() {
		if !child.Hidden {
			t.Fatalf("%s action must remain hidden", child.Name())
		}
		if child.Flags().Lookup("json") == nil {
			t.Fatalf("%s action is missing --json", child.Name())
		}
		for flag, allowed := range scopedFlags {
			present := child.Flags().Lookup(flag) != nil
			if allowed[child.Name()] && !present {
				t.Fatalf("%s action is missing --%s", child.Name(), flag)
			}
			if !allowed[child.Name()] && present {
				t.Fatalf("%s action unexpectedly accepts --%s", child.Name(), flag)
			}
		}
		actions = append(actions, child.Name())
	}
	if !slices.Equal(actions, []string{"capabilities", "check", "finalize", "prepare", "purge-user-state", "restore-owner-rights", "rollback", "verify"}) {
		t.Fatalf("actions = %v", actions)
	}
}

func TestWindowsManagedHooksTeardownTargetsCanonicalExactSet(t *testing.T) {
	enabled := true
	disabled := false
	homeA := filepath.Clean(`C:\Users\alice`)
	homeB := filepath.Clean(`C:\Users\bob`)
	manifest := enterprisehooks.Manifest{
		Version: 1,
		Targets: []enterprisehooks.ManifestTarget{
			{
				UserHome:     homeB,
				SID:          "S-1-5-21-111-222-333-1002",
				Connector:    "Codex",
				AgentVersion: "0.131.0",
				Enabled:      &enabled,
			},
			{
				UserHome:     homeA,
				SID:          "S-1-5-21-111-222-333-1001",
				Connector:    "ClaudeCode",
				DataDir:      filepath.Join(homeA, ".defenseclaw"),
				AgentVersion: "2.1.152",
			},
			{
				UserHome:     homeB,
				SID:          "S-1-5-21-111-222-333-1002",
				Connector:    "Cursor",
				AgentVersion: "1.7.0",
				Deferred:     true,
			},
			{
				UserHome:     `C:\Users\disabled`,
				SID:          "S-1-5-21-111-222-333-1003",
				Connector:    "codex",
				AgentVersion: "0.131.0",
				Enabled:      &disabled,
			},
		},
	}
	targets, claude, codex, cursor, err := windowsManagedHooksTeardownTargets(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 || targets[0].Connector != "claudecode" ||
		targets[1].Connector != "codex" || targets[2].Connector != "cursor" {
		t.Fatalf("sorted targets = %+v", targets)
	}
	if !slices.Equal(claude, []string{"S-1-5-21-111-222-333-1001"}) {
		t.Fatalf("Claude targets = %v", claude)
	}
	if len(codex) != 1 ||
		codex[0].SID != "S-1-5-21-111-222-333-1002" ||
		!sameWindowsEnterprisePathCLI(
			codex[0].DataDir,
			filepath.Join(homeB, ".defenseclaw"),
		) {
		t.Fatalf("Codex targets = %+v", codex)
	}
	if len(cursor) != 1 || cursor[0].SID != "S-1-5-21-111-222-333-1002" ||
		!sameWindowsEnterprisePathCLI(cursor[0].DataDir, filepath.Join(homeB, ".defenseclaw")) {
		t.Fatalf("Cursor targets = %+v", cursor)
	}
	if !targets[2].Deferred {
		t.Fatal("deferred manifest authorization was not preserved in teardown identity")
	}
}

func TestWindowsManagedHooksTeardownTargetsAcceptEntraIDForAllConnectors(t *testing.T) {
	const entraSID = "S-1-12-1-1111111111-2222222222-3333333333-4000000000"
	home := filepath.Clean(`C:\Users\entra-user`)
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{SID: entraSID, UserHome: home, Connector: "claudecode", AgentVersion: "2.1.152"},
		{SID: entraSID, UserHome: home, Connector: "codex", AgentVersion: "0.131.0"},
		{SID: entraSID, UserHome: home, Connector: "cursor", AgentVersion: "1.7.0"},
	}}

	targets, claude, codex, cursor, err := windowsManagedHooksTeardownTargets(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 || len(claude) != 1 || claude[0] != entraSID ||
		len(codex) != 1 || codex[0].SID != entraSID ||
		len(cursor) != 1 || cursor[0].SID != entraSID {
		t.Fatalf(
			"Microsoft Entra ID teardown targets = all:%+v claude:%v codex:%+v cursor:%+v",
			targets, claude, codex, cursor,
		)
	}
	wantDataDir := filepath.Join(home, ".defenseclaw")
	if !sameWindowsEnterprisePathCLI(codex[0].DataDir, wantDataDir) ||
		!sameWindowsEnterprisePathCLI(cursor[0].DataDir, wantDataDir) {
		t.Fatalf("Microsoft Entra ID teardown data dirs = codex:%q cursor:%q, want %q", codex[0].DataDir, cursor[0].DataDir, wantDataDir)
	}
}

func TestWindowsManagedHooksTeardownPendingTargetsAreNarrow(t *testing.T) {
	active := windowsManagedHooksTeardownTarget{
		Connector: "codex",
		SID:       "S-1-5-21-111-222-333-1001",
		DataDir:   `C:\Users\alice\.defenseclaw`,
	}
	pending := windowsManagedHooksTeardownTarget{
		Connector: "cursor",
		SID:       "S-1-5-21-111-222-333-1002",
		DataDir:   `C:\Users\bob\.defenseclaw`,
		Deferred:  true,
	}
	targets := []windowsManagedHooksTeardownTarget{active, pending}
	if err := validateWindowsManagedHooksPendingTargetSubset(
		targets,
		[]windowsManagedHooksTeardownTarget{pending},
		windowsManagedHooksActivated,
	); err != nil {
		t.Fatal(err)
	}
	if windowsManagedHooksTeardownSelectorExpected(
		pending,
		[]windowsManagedHooksTeardownTarget{pending},
		windowsManagedHooksActivated,
	) {
		t.Fatal("pending target unexpectedly requires a runtime selector")
	}
	if !windowsManagedHooksTeardownSelectorExpected(
		active,
		[]windowsManagedHooksTeardownTarget{pending},
		windowsManagedHooksActivated,
	) {
		t.Fatal("active target did not retain its exact selector requirement")
	}

	unauthorized := pending
	unauthorized.Deferred = false
	if err := validateWindowsManagedHooksPendingTargetSubset(
		targets,
		[]windowsManagedHooksTeardownTarget{unauthorized},
		windowsManagedHooksActivated,
	); err == nil {
		t.Fatal("pending target without manifest deferred authorization was accepted")
	}
	if err := validateWindowsManagedHooksPendingTargetSubset(
		targets,
		[]windowsManagedHooksTeardownTarget{pending},
		windowsManagedHooksNeverActivated,
	); err == nil {
		t.Fatal("never-activated deployment accepted current pending evidence")
	}
}

func TestWindowsManagedHooksTeardownSchemaFiveCannotAuthorizeDeferredState(t *testing.T) {
	legacyTarget := windowsManagedHooksTeardownTarget{
		Connector: "codex",
		SID:       "S-1-5-21-111-222-333-1001",
		DataDir:   `C:\Users\alice\.defenseclaw`,
	}
	legacy := windowsManagedHooksTeardownJournal{
		SchemaVersion: 5,
		Targets:       []windowsManagedHooksTeardownTarget{legacyTarget},
	}
	current := legacy
	current.SchemaVersion = windowsManagedHooksTeardownJournalSchema
	if !validWindowsManagedHooksTeardownJournalSchema(legacy, current) {
		t.Fatal("exact schema-5 non-deferred recovery journal was rejected")
	}

	deferredTarget := legacyTarget
	deferredTarget.Deferred = true
	current.Targets = []windowsManagedHooksTeardownTarget{deferredTarget}
	current.PendingTargets = []windowsManagedHooksTeardownTarget{deferredTarget}
	if validWindowsManagedHooksTeardownJournalSchema(legacy, current) {
		t.Fatal("schema-5 journal was allowed to authorize deferred pending state")
	}
}

func TestValidateWindowsManagedHooksTeardownJournalAcceptsOnlyExactPendingAbsence(t *testing.T) {
	active := windowsManagedHooksTeardownTarget{
		Connector: "codex",
		SID:       "S-1-5-21-111-222-333-1001",
		DataDir:   `C:\Users\alice\.defenseclaw`,
	}
	pending := windowsManagedHooksTeardownTarget{
		Connector: "codex",
		SID:       "S-1-5-21-111-222-333-1002",
		DataDir:   `C:\Users\bob\.defenseclaw`,
		Deferred:  true,
	}
	targets := []windowsManagedHooksTeardownTarget{active, pending}
	fingerprint, err := windowsManagedHooksTeardownFingerprint(targets)
	if err != nil {
		t.Fatal(err)
	}
	targetBody := []byte(`{"generation_id":"0123456789abcdef0123456789abcdef"}`)
	targetDigestBytes := sha256.Sum256(targetBody)
	targetDigest := "sha256:" + hex.EncodeToString(targetDigestBytes[:])
	identity := windowsManagedHooksTeardownJournal{
		SchemaVersion:          windowsManagedHooksTeardownJournalSchema,
		Phase:                  "captured",
		ManifestPath:           `C:\ProgramData\DefenseClaw\hook-guardian\targets.yaml`,
		ManifestSHA256:         strings.Repeat("a", 64),
		ManifestFingerprint:    fingerprint,
		ActivationState:        windowsManagedHooksActivated,
		DeploymentGenerationID: strings.Repeat("b", 32),
		HookBinary:             `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:            "127.0.0.1:18970",
		GatewayServiceName:     "DefenseClawGateway",
		Targets:                targets,
		PendingTargets:         []windowsManagedHooksTeardownTarget{pending},
		CodexPolicyActive:      true,
		CodexTargets: []connector.WindowsCodexManagedRuntimeTarget{
			{SID: active.SID, DataDir: active.DataDir},
			{SID: pending.SID, DataDir: pending.DataDir},
		},
		SelectorTargets: []enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot{
			{
				SchemaVersion: 1,
				Connector:     active.Connector,
				TargetSID:     active.SID,
				Existed:       true,
				Target:        targetBody,
				TargetSHA256:  targetDigest,
				CAS: enterprisehooks.WindowsManagedRuntimeSelectorTargetCAS{
					Exists:       true,
					GenerationID: strings.Repeat("c", 32),
					BundleSHA256: "sha256:" + strings.Repeat("d", 64),
					TargetSHA256: targetDigest,
				},
			},
			{
				SchemaVersion: 1,
				Connector:     pending.Connector,
				TargetSID:     pending.SID,
			},
		},
	}
	if err := validateWindowsManagedHooksTeardownJournal(identity, identity); err != nil {
		t.Fatal(err)
	}

	tampered := identity
	tampered.SelectorTargets = append(
		[]enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot(nil),
		identity.SelectorTargets...,
	)
	tampered.SelectorTargets[1] = identity.SelectorTargets[0]
	tampered.SelectorTargets[1].TargetSID = pending.SID
	if err := validateWindowsManagedHooksTeardownJournal(tampered, identity); err == nil {
		t.Fatal("pending target with a selector enrollment was accepted")
	}
}

func TestWindowsManagedHooksTeardownTargetsRejectsExpansion(t *testing.T) {
	base := enterprisehooks.ManifestTarget{
		UserHome:     `C:\Users\alice`,
		SID:          "S-1-5-21-111-222-333-1001",
		Connector:    "codex",
		AgentVersion: "0.131.0",
	}
	tests := []struct {
		name   string
		mutate func(*enterprisehooks.ManifestTarget)
		match  string
	}{
		{
			name: "unknown connector",
			mutate: func(target *enterprisehooks.ManifestTarget) {
				target.Connector = "custom"
			},
			match: "does not support connector",
		},
		{
			name: "arbitrary data dir",
			mutate: func(target *enterprisehooks.ManifestTarget) {
				target.DataDir = `C:\ProgramData\attacker`
			},
			match: "does not equal canonical",
		},
		{
			name: "malformed SID",
			mutate: func(target *enterprisehooks.ManifestTarget) {
				target.SID = "not-a-sid"
			},
			match: "invalid managed-hook teardown SID",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := base
			test.mutate(&target)
			_, _, _, _, err := windowsManagedHooksTeardownTargets(
				enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{target}},
			)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("error = %v, want %q", err, test.match)
			}
		})
	}
}

func TestValidateWindowsManagedHooksTeardownActivationBindsManifest(t *testing.T) {
	manifestSHA256 := strings.Repeat("a", 64)
	valid := windowsManagedHooksActivationRecord{
		SchemaVersion:          1,
		DeploymentGenerationID: strings.Repeat("b", 32),
		State:                  "never_activated",
		ManifestSHA256:         manifestSHA256,
		TargetCount:            3,
	}
	if _, err := validateWindowsManagedHooksTeardownActivation(
		&valid,
		manifestSHA256,
		3,
	); err != nil {
		t.Fatal(err)
	}
	previousStandalone := windowsManagedHooksTeardownStandaloneProcess
	t.Cleanup(func() { windowsManagedHooksTeardownStandaloneProcess = previousStandalone })
	// Secure Client (26.8.4): the enumerator republishing the manifest after
	// the installer pinned it is logged and accepted, never a teardown
	// failure.
	windowsManagedHooksTeardownStandaloneProcess = func() bool { return false }
	events := captureResilienceEvents(t)
	if _, err := validateWindowsManagedHooksTeardownActivation(
		&valid,
		strings.Repeat("c", 64),
		4,
	); err != nil {
		t.Fatalf("republished manifest rejected: %v", err)
	}
	if len(*events) != 1 || !strings.Contains((*events)[0], `pinned_sha256="`+manifestSHA256+`"`) {
		t.Fatalf("events = %v", *events)
	}
	// rel-1-0-6:GAP-0583: standalone refuses the same drift with the
	// catch-up refusal the uninstall pre-commit check waits on
	// (Test-DefenseClawManifestCatchUpTeardownRefusal), so the tombstone never
	// commits over activation evidence the PowerShell journal and receipt
	// checks cannot authenticate. An exact binding still passes.
	windowsManagedHooksTeardownStandaloneProcess = func() bool { return true }
	for _, drift := range []struct {
		name   string
		digest string
		count  int
	}{
		{name: "republished manifest", digest: strings.Repeat("c", 64), count: 3},
		{name: "deleted account dropped a row", digest: strings.Repeat("c", 64), count: 2},
		{name: "count only", digest: manifestSHA256, count: 2},
	} {
		_, err := validateWindowsManagedHooksTeardownActivation(&valid, drift.digest, drift.count)
		if err == nil || err.Error() != "protected managed-hook activation evidence does not match the current manifest" {
			t.Fatalf("standalone %s: error = %v, want the catch-up refusal", drift.name, err)
		}
	}
	if _, err := validateWindowsManagedHooksTeardownActivation(&valid, manifestSHA256, 3); err != nil {
		t.Fatalf("standalone exact binding rejected: %v", err)
	}

	tests := []struct {
		name   string
		record *windowsManagedHooksActivationRecord
		digest string
		count  int
	}{
		{name: "missing record", digest: manifestSHA256, count: 3},
		{name: "wrong schema", record: func() *windowsManagedHooksActivationRecord {
			changed := valid
			changed.SchemaVersion = 2
			return &changed
		}(), digest: manifestSHA256, count: 3},
		{name: "invalid generation", record: func() *windowsManagedHooksActivationRecord {
			changed := valid
			changed.DeploymentGenerationID = strings.Repeat("B", 32)
			return &changed
		}(), digest: manifestSHA256, count: 3},
		{name: "unknown state", record: func() *windowsManagedHooksActivationRecord {
			changed := valid
			changed.State = "unknown"
			return &changed
		}(), digest: manifestSHA256, count: 3},
		{name: "target count exceeds bound", record: func() *windowsManagedHooksActivationRecord {
			changed := valid
			changed.TargetCount = windowsManagedHooksTeardownTargetMax + 1
			return &changed
		}(), digest: manifestSHA256, count: windowsManagedHooksTeardownTargetMax + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateWindowsManagedHooksTeardownActivation(
				test.record,
				test.digest,
				test.count,
			); err == nil {
				t.Fatal("invalid activation evidence was accepted")
			}
		})
	}
}

func TestValidateWindowsManagedHooksTeardownDeploymentBindsActionToCommitState(t *testing.T) {
	manifestSHA256 := strings.Repeat("a", 64)
	active := true
	inactive := false
	activation := &windowsManagedHooksActivationRecord{
		SchemaVersion:          1,
		DeploymentGenerationID: strings.Repeat("b", 32),
		State:                  windowsManagedHooksNeverActivated,
		ManifestSHA256:         manifestSHA256,
		TargetCount:            3,
	}

	for _, action := range []string{"prepare", "verify", "rollback"} {
		t.Run(action+" accepts active metadata", func(t *testing.T) {
			_, err := validateWindowsManagedHooksTeardownDeployment(
				windowsCodexDeploymentMetadata{
					Installed:              &active,
					ManagedHooksActivation: activation,
				},
				action,
				manifestSHA256,
				3,
			)
			if err != nil {
				t.Fatal(err)
			}
		})
		t.Run(action+" rejects inactive tombstone", func(t *testing.T) {
			_, err := validateWindowsManagedHooksTeardownDeployment(
				windowsCodexDeploymentMetadata{
					Installed:              &inactive,
					ManagedHooksActivation: activation,
				},
				action,
				manifestSHA256,
				3,
			)
			if err == nil || !strings.Contains(err.Error(), "active deployment metadata") {
				t.Fatalf("error = %v, want active deployment metadata rejection", err)
			}
		})
	}

	t.Run("finalize accepts authenticated inactive tombstone", func(t *testing.T) {
		_, err := validateWindowsManagedHooksTeardownDeployment(
			windowsCodexDeploymentMetadata{
				Installed:              &inactive,
				ManagedHooksActivation: activation,
			},
			"finalize",
			manifestSHA256,
			3,
		)
		if err != nil {
			t.Fatal(err)
		}
	})
	for _, test := range []struct {
		name       string
		installed  *bool
		activation *windowsManagedHooksActivationRecord
	}{
		{name: "active metadata", installed: &active, activation: activation},
		{name: "legacy omitted installed flag", activation: activation},
		{name: "missing activation", installed: &inactive},
	} {
		t.Run("finalize rejects "+test.name, func(t *testing.T) {
			_, err := validateWindowsManagedHooksTeardownDeployment(
				windowsCodexDeploymentMetadata{
					Installed:              test.installed,
					ManagedHooksActivation: test.activation,
				},
				"finalize",
				manifestSHA256,
				3,
			)
			if err == nil {
				t.Fatal("invalid finalize deployment metadata was accepted")
			}
		})
	}
}

func TestWindowsManagedHooksCommitBoundaryForStandaloneUninstall(t *testing.T) {
	pending := filepath.Join(t.TempDir(), "pending.json")
	active, inactive := true, false
	for _, action := range []string{"prepare", "verify"} {
		validation, committed, err := windowsManagedHooksTeardownValidationAction(
			windowsCodexDeploymentMetadata{Installed: &active}, action, true, pending)
		if err != nil || validation != action || committed {
			t.Fatalf("active %s: validation=%q committed=%t error=%v", action, validation, committed, err)
		}
		validation, committed, err = windowsManagedHooksTeardownValidationAction(
			windowsCodexDeploymentMetadata{Installed: &inactive}, action, true, pending)
		if err != nil || validation != "finalize" || !committed {
			t.Fatalf("committed %s: validation=%q committed=%t error=%v", action, validation, committed, err)
		}
		if _, _, err = windowsManagedHooksTeardownValidationAction(
			windowsCodexDeploymentMetadata{Installed: &inactive}, action, false, pending); err == nil {
			t.Fatalf("Secure Client %s accepted standalone committed teardown", action)
		}
	}
	if err := os.WriteFile(pending, []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := windowsManagedHooksTeardownValidationAction(
		windowsCodexDeploymentMetadata{Installed: &inactive}, "prepare", true, pending); err == nil ||
		!strings.Contains(err.Error(), "transaction retirement") {
		t.Fatalf("pending transaction authorized hook removal: %v", err)
	}
}

func TestValidateWindowsManagedHooksTeardownEnrollmentDistinguishesNoStart(t *testing.T) {
	claudeTargets := []string{"S-1-5-21-111-222-333-1001"}
	codexTargets := []connector.WindowsCodexManagedRuntimeTarget{{
		SID: "S-1-5-21-111-222-333-1001", DataDir: `C:\Users\alice\.defenseclaw`,
	}}
	cursorTargets := []enterprisehooks.WindowsCursorManagedRuntimeTarget{{
		SID: "S-1-5-21-111-222-333-1001", DataDir: `C:\Users\alice\.defenseclaw`,
	}}

	never := windowsManagedHooksTeardownJournal{ActivationState: "never_activated"}
	never.ClaudeTargetSIDs, never.CodexPolicyActive, never.CodexTargets, never.CursorTargets =
		windowsManagedHooksTeardownExpectedEnrollment(
			never.ActivationState,
			true,
			claudeTargets,
			codexTargets,
			cursorTargets,
		)
	if err := validateWindowsManagedHooksTeardownEnrollment(
		never,
		[]string{},
		false,
		connector.WindowsCodexManagedRuntimeRegistry{Active: true, Targets: []connector.WindowsCodexManagedRuntimeTarget{}},
		[]enterprisehooks.WindowsCursorManagedRuntimeTarget{},
		false,
	); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsManagedHooksTeardownEnrollment(
		never,
		[]string{},
		false,
		connector.WindowsCodexManagedRuntimeRegistry{},
		[]enterprisehooks.WindowsCursorManagedRuntimeTarget{},
		false,
	); err == nil {
		t.Fatal("never-activated Codex policy absence was accepted for an enabled Codex manifest")
	}
	if err := validateWindowsManagedHooksTeardownEnrollment(
		never,
		claudeTargets,
		true,
		connector.WindowsCodexManagedRuntimeRegistry{Active: true, Targets: []connector.WindowsCodexManagedRuntimeTarget{}},
		[]enterprisehooks.WindowsCursorManagedRuntimeTarget{},
		false,
	); err == nil {
		t.Fatal("never-activated Claude enrollment was accepted")
	}
	if err := validateWindowsManagedHooksTeardownEnrollment(
		never,
		[]string{},
		false,
		connector.WindowsCodexManagedRuntimeRegistry{Active: true, Targets: []connector.WindowsCodexManagedRuntimeTarget{}},
		cursorTargets,
		true,
	); err == nil {
		t.Fatal("never-activated Cursor enrollment was accepted")
	}

	activated := windowsManagedHooksTeardownJournal{ActivationState: "activated"}
	activated.ClaudeTargetSIDs,
		activated.CodexPolicyActive,
		activated.CodexTargets,
		activated.CursorTargets = windowsManagedHooksTeardownExpectedEnrollment(
		activated.ActivationState,
		true,
		claudeTargets,
		codexTargets,
		cursorTargets,
	)
	if err := validateWindowsManagedHooksTeardownEnrollment(
		activated,
		claudeTargets,
		true,
		connector.WindowsCodexManagedRuntimeRegistry{Active: true, Targets: codexTargets},
		cursorTargets,
		true,
	); err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsManagedHooksTeardownEnrollment(
		activated,
		claudeTargets,
		true,
		connector.WindowsCodexManagedRuntimeRegistry{Active: true, Targets: []connector.WindowsCodexManagedRuntimeTarget{}},
		cursorTargets,
		true,
	); err == nil {
		t.Fatal("activated deployment with an emptied Codex registry was accepted")
	}
}

func TestWindowsManagedHooksTeardownAcceptsActiveEmptyMachinePolicies(t *testing.T) {
	identity := windowsManagedHooksTeardownJournal{
		SchemaVersion:          windowsManagedHooksTeardownJournalSchema,
		Phase:                  "captured",
		ManifestPath:           `C:\ProgramData\DefenseClaw\hook-guardian\targets.yaml`,
		ManifestSHA256:         strings.Repeat("a", 64),
		ActivationState:        windowsManagedHooksActivated,
		DeploymentGenerationID: strings.Repeat("b", 32),
		HookBinary:             `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:            "127.0.0.1:18970",
		GatewayServiceName:     "DefenseClawGateway",
		CodexPolicyActive:      true,
		ClaudeTargetSIDs:       []string{},
		CodexTargets:           []connector.WindowsCodexManagedRuntimeTarget{},
		CursorTargets:          []enterprisehooks.WindowsCursorManagedRuntimeTarget{},
	}
	var err error
	identity.ManifestFingerprint, err = windowsManagedHooksTeardownFingerprint(identity.Targets)
	if err != nil {
		t.Fatal(err)
	}
	identity.Claude.PolicyExisted = true
	identity.Claude.StateExisted = true
	identity.Cursor.PolicyActive = true
	identity.Cursor.HooksExisted = true
	identity.Cursor.AdapterExisted = true
	identity.Cursor.StateExisted = true
	identity.Cursor.ReceiptExisted = true
	for _, ptr := range []*string{&identity.Cursor.HooksSecurityDescriptor, &identity.Cursor.AdapterSecurityDescriptor, &identity.Cursor.StateSecurityDescriptor, &identity.Cursor.ReceiptSecurityDescriptor} {
		*ptr = "protected"
	}
	identity.Cursor.HooksAttributes = 1
	identity.Cursor.AdapterAttributes = 1
	identity.Cursor.StateAttributes = 1
	identity.Cursor.ReceiptAttributes = 1
	if err := validateWindowsManagedHooksTeardownJournal(identity, identity); err != nil {
		t.Fatalf("active zero-target snapshot rejected during teardown: %v", err)
	}
	legacyCodex := identity
	legacyCodex.CodexPolicyActive = false
	if err := validateWindowsManagedHooksTeardownJournal(legacyCodex, identity); err != nil {
		t.Fatalf("authenticated inactive zero-target Codex preimage rejected: %v", err)
	}
	if err := validateWindowsManagedHooksTeardownEnrollment(legacyCodex, nil, true,
		connector.WindowsCodexManagedRuntimeRegistry{}, nil, true); err != nil {
		t.Fatalf("inactive zero-target Codex preimage rejected: %v", err)
	}
	if err := validateWindowsManagedHooksTeardownEnrollment(identity, nil, true,
		connector.WindowsCodexManagedRuntimeRegistry{Active: true}, nil, true); err != nil {
		t.Fatalf("active zero-target enrollment rejected during teardown: %v", err)
	}
	identity.Claude = enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot{}
	identity.Cursor = enterprisehooks.WindowsCursorManagedPolicyTeardownSnapshot{}
	if err := validateWindowsManagedHooksTeardownJournal(identity, identity); err != nil {
		t.Fatalf("legacy zero-target snapshot rejected during teardown: %v", err)
	}
}

func TestWindowsManagedHooksTeardownConfiguredCodexWithoutEnrollment(t *testing.T) {
	_, active, targets, _ := windowsManagedHooksTeardownExpectedEnrollment(
		windowsManagedHooksActivated, true, nil, nil, nil,
	)
	if !active || len(targets) != 0 {
		t.Fatalf("configured Codex policy = active %t targets %v, want active with no enrolled accounts", active, targets)
	}
}

// AVC's dry-run of the v11 kit failed uninstall with
// "managed-hook teardown journal is missing codex_targets" on a
// single-user test VM where the activated deployment had zero eligible
// codex users. Root cause was append([]T(nil), src...) returning nil
// when src is an empty non-nil slice, which then marshals as JSON
// `null` and used to trip the reader's presence check on retry. This
// test locks the writer fix in place: the enrollment helper must
// return empty-non-nil slices for every connector target list, so the
// journal always serializes as `[]` (never `null`) even for connectors
// with zero eligible users at install time.
func TestWindowsManagedHooksTeardownExpectedEnrollmentEmptyTargetsAreNonNil(t *testing.T) {
	for _, state := range []string{
		windowsManagedHooksNeverActivated,
		"activated",
	} {
		state := state
		t.Run(state, func(t *testing.T) {
			claude, codexActive, codex, cursor :=
				windowsManagedHooksTeardownExpectedEnrollment(
					state,
					false,
					[]string{},
					[]connector.WindowsCodexManagedRuntimeTarget{},
					[]enterprisehooks.WindowsCursorManagedRuntimeTarget{},
				)
			if claude == nil {
				t.Error("claude target SIDs slice is nil for empty input")
			}
			if codex == nil {
				t.Error("codex targets slice is nil for empty input")
			}
			if cursor == nil {
				t.Error("cursor targets slice is nil for empty input")
			}
			if codexActive {
				t.Error("codex policy active is true when zero codex targets")
			}
			// Round-trip through JSON to prove the wire representation
			// is `[]` and never `null`, so a peer reader that rejects
			// null on these fields continues to accept our output.
			body, err := json.Marshal(windowsManagedHooksTeardownJournal{
				ClaudeTargetSIDs: claude,
				CodexTargets:     codex,
				CursorTargets:    cursor,
			})
			if err != nil {
				t.Fatalf("marshal empty enrollment: %v", err)
			}
			for _, key := range []string{
				`"claude_target_sids":[]`,
				`"codex_targets":[]`,
				`"cursor_targets":[]`,
			} {
				if !strings.Contains(string(body), key) {
					t.Errorf("marshal(%s): expected %s in %s", state, key, string(body))
				}
			}
			for _, key := range []string{
				`"claude_target_sids":null`,
				`"codex_targets":null`,
				`"cursor_targets":null`,
			} {
				if strings.Contains(string(body), key) {
					t.Errorf("marshal(%s): unexpected null field %s", state, key)
				}
			}
		})
	}
}

// Backward-compat: a pre-fix journal on disk from an older Setup EXE
// may have "codex_targets": null (or cursor_targets/claude_target_sids
// null) because the buggy writer emitted null for empty target lists.
// parseWindowsManagedHooksTeardownJournalBody must accept those without
// throwing "managed-hook teardown journal is missing codex_targets" so
// AVC (and every downstream operator) can uninstall a box that was
// installed with the buggy writer. Trust-critical identity fields
// (manifest_sha256, activation_state, deployment_generation_id) stay
// presence-required; validateWindowsManagedHooksTeardownJournal below
// still binds every target list to the recomputed activation identity.
//
// Tested against the ACL-independent JSON layer so the CI runner's
// non-Admin user identity does not trip
// managed.ValidateTrustedFilePath's owner walk. The production entry
// point readWindowsManagedHooksTeardownJournal still validates the file
// (repairing owner and DACL drift, keeping structural checks fatal)
// before reaching this parse step.
func TestParseWindowsManagedHooksTeardownJournalBodyAcceptsNullConnectorArrays(t *testing.T) {
	body := []byte(`{
  "schema_version": 6,
  "phase": "prepared",
  "manifest_path": "C:\\ProgramData\\DefenseClaw\\hook-guardian\\targets.yaml",
  "manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "manifest_fingerprint": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "activation_state": "activated",
  "deployment_generation_id": "cccccccccccccccccccccccccccccccc",
  "hook_binary": "C:\\Program Files\\DefenseClaw\\bin\\defenseclaw-hook.exe",
  "gateway_addr": "127.0.0.1:18970",
  "gateway_service_name": "DefenseClawGateway",
  "targets": [],
  "claude_target_sids": null,
  "claude": {},
  "codex_policy_active": false,
  "codex_targets": null,
  "cursor_targets": null,
  "cursor": {},
  "selector_targets": null
}
`)
	journal, err := parseWindowsManagedHooksTeardownJournalBody(body)
	if err != nil {
		t.Fatalf("parse journal with null connector arrays: %v", err)
	}
	if len(journal.CodexTargets) != 0 || len(journal.CursorTargets) != 0 ||
		len(journal.ClaudeTargetSIDs) != 0 {
		t.Errorf("expected empty target lists, got %#v / %#v / %#v",
			journal.CodexTargets, journal.CursorTargets, journal.ClaudeTargetSIDs)
	}
	if journal.ManifestSHA256 != strings.Repeat("a", 64) ||
		journal.ActivationState != "activated" ||
		journal.DeploymentGenerationID != strings.Repeat("c", 32) {
		t.Errorf("trust-critical identity fields did not decode: %+v", journal)
	}
	// Missing trust-critical field still rejects.
	withoutManifestSHA := strings.Replace(
		string(body),
		`"manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",`,
		`"manifest_sha256": null,`,
		1,
	)
	if _, err := parseWindowsManagedHooksTeardownJournalBody(
		[]byte(withoutManifestSHA),
	); err == nil || !strings.Contains(err.Error(), "missing manifest_sha256") {
		t.Errorf("expected missing-manifest_sha256 rejection, got %v", err)
	}
	// Unknown property still fails closed (DisallowUnknownFields).
	withForeignKey := strings.Replace(
		string(body),
		`"selector_targets": null`,
		`"selector_targets": null,
  "attacker_planted_key": "evil"`,
		1,
	)
	if _, err := parseWindowsManagedHooksTeardownJournalBody(
		[]byte(withForeignKey),
	); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("expected unknown-field rejection, got %v", err)
	}
}

func TestValidateWindowsManagedHooksTeardownJournalAcceptsExactNoStartPreimage(t *testing.T) {
	targets := []windowsManagedHooksTeardownTarget{{
		Connector: "codex",
		SID:       "S-1-5-21-111-222-333-1001",
		DataDir:   `C:\Users\alice\.defenseclaw`,
	}}
	fingerprint, err := windowsManagedHooksTeardownFingerprint(targets)
	if err != nil {
		t.Fatal(err)
	}
	identity := windowsManagedHooksTeardownJournal{
		SchemaVersion:          windowsManagedHooksTeardownJournalSchema,
		Phase:                  "captured",
		ManifestPath:           `C:\ProgramData\DefenseClaw\hook-guardian\targets.yaml`,
		ManifestSHA256:         strings.Repeat("a", 64),
		ManifestFingerprint:    fingerprint,
		ActivationState:        "never_activated",
		DeploymentGenerationID: strings.Repeat("b", 32),
		HookBinary:             `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:            "127.0.0.1:18970",
		GatewayServiceName:     "DefenseClawGateway",
		Targets:                targets,
		ClaudeTargetSIDs:       []string{},
		CodexPolicyActive:      true,
		CodexTargets:           []connector.WindowsCodexManagedRuntimeTarget{},
		CursorTargets:          []enterprisehooks.WindowsCursorManagedRuntimeTarget{},
		SelectorTargets: []enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot{{
			SchemaVersion: 1,
			Connector:     "codex",
			TargetSID:     targets[0].SID,
		}},
	}
	if err := validateWindowsManagedHooksTeardownJournal(identity, identity); err != nil {
		t.Fatal(err)
	}
	tampered := identity
	tampered.SelectorTargets = append(
		[]enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot(nil),
		identity.SelectorTargets...,
	)
	tampered.SelectorTargets[0].Existed = true
	if err := validateWindowsManagedHooksTeardownJournal(tampered, identity); err == nil {
		t.Fatal("never-activated journal with a selector enrollment was accepted")
	}
}

func TestValidateWindowsManagedHooksTeardownJournalRejectsIdentityChanges(t *testing.T) {
	targets := []windowsManagedHooksTeardownTarget{{
		Connector:    "codex",
		SID:          "S-1-5-21-111-222-333-1001",
		DataDir:      `C:\Users\alice\.defenseclaw`,
		AgentVersion: "0.131.0",
	}}
	fingerprint, err := windowsManagedHooksTeardownFingerprint(targets)
	if err != nil {
		t.Fatal(err)
	}
	identity := windowsManagedHooksTeardownJournal{
		SchemaVersion:          windowsManagedHooksTeardownJournalSchema,
		Phase:                  "prepared",
		ManifestPath:           `C:\ProgramData\DefenseClaw\hook-guardian\targets.yaml`,
		ManifestSHA256:         strings.Repeat("a", 64),
		ManifestFingerprint:    fingerprint,
		ActivationState:        "activated",
		DeploymentGenerationID: strings.Repeat("b", 32),
		HookBinary:             `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:            "127.0.0.1:18970",
		GatewayServiceName:     "DefenseClawGateway",
		Targets:                targets,
		CodexPolicyActive:      true,
		CodexTargets: []connector.WindowsCodexManagedRuntimeTarget{{
			SID: targets[0].SID, DataDir: targets[0].DataDir,
		}},
	}
	selectorBody := []byte("canonical-secretless-selector-target\n")
	selectorDigestBytes := sha256.Sum256(selectorBody)
	selectorDigest := "sha256:" + hex.EncodeToString(selectorDigestBytes[:])
	identity.SelectorTargets = []enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot{{
		SchemaVersion: 1,
		Connector:     "codex",
		TargetSID:     targets[0].SID,
		Existed:       true,
		Target:        selectorBody,
		TargetSHA256:  selectorDigest,
		CAS: enterprisehooks.WindowsManagedRuntimeSelectorTargetCAS{
			Exists:       true,
			GenerationID: strings.Repeat("1", 32),
			BundleSHA256: "sha256:" + strings.Repeat("2", 64),
			TargetSHA256: selectorDigest,
		},
	}}
	if err := validateWindowsManagedHooksTeardownJournal(identity, identity); err != nil {
		t.Fatal(err)
	}
	tampered := identity
	tampered.GatewayServiceName = "OtherGateway"
	if err := validateWindowsManagedHooksTeardownJournal(tampered, identity); err == nil {
		t.Fatal("service-name journal tamper was accepted")
	}
	tampered = identity
	tampered.Targets = append([]windowsManagedHooksTeardownTarget(nil), identity.Targets...)
	tampered.Targets[0].SID = "S-1-5-21-111-222-333-1009"
	if err := validateWindowsManagedHooksTeardownJournal(tampered, identity); err == nil {
		t.Fatal("target-SID journal tamper was accepted")
	}
	tampered = identity
	tampered.Claude.PolicyExisted = true
	if err := validateWindowsManagedHooksTeardownJournal(tampered, identity); err == nil {
		t.Fatal("incomplete Claude snapshot was accepted")
	}
}

func TestWindowsManagedHooksTeardownReportJSONContract(t *testing.T) {
	report := windowsManagedHooksTeardownReport{
		SchemaVersion:                windowsManagedHooksTeardownSchema,
		Action:                       "prepare",
		OK:                           true,
		ManifestPath:                 `C:\ProgramData\DefenseClaw\hook-guardian\targets.yaml`,
		JournalPath:                  `C:\ProgramData\DefenseClaw\install\managed-hooks-teardown-journal.json`,
		TargetCount:                  1,
		EnrollmentTargetCount:        1,
		SucceededCount:               1,
		VerifiedCleanCount:           1,
		VerifiedInstalledCount:       0,
		FailedCount:                  0,
		SurvivingOwnedPathReferences: 0,
		RollbackReady:                true,
		SafeToRemoveBinary:           true,
		Results: []windowsManagedHooksTeardownResult{{
			Connector: "codex",
			SID:       "S-1-5-21-111-222-333-1001",
			OK:        true,
		}},
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, numeric := range []string{
		"target_count",
		"enrollment_target_count",
		"succeeded_count",
		"verified_clean_count",
		"verified_installed_count",
		"failed_count",
		"surviving_owned_path_references",
		"collected_generation_count",
	} {
		if _, ok := decoded[numeric].(float64); !ok {
			t.Fatalf("%s = %#v, want JSON number", numeric, decoded[numeric])
		}
	}
}

func TestCompleteWindowsManagedHooksTeardownRollbackIsIdempotent(t *testing.T) {
	for _, test := range []struct {
		name         string
		phase        string
		installed    bool
		wantRestores int
		wantVerifies int
		wantWrites   int
		wantErr      string
	}{
		{
			name: "captured partial teardown", phase: "captured",
			wantRestores: 1, wantVerifies: 2, wantWrites: 1,
		},
		{
			name: "prepared teardown", phase: "prepared",
			wantRestores: 1, wantVerifies: 2, wantWrites: 1,
		},
		{
			name: "captured after self rollback", phase: "captured", installed: true,
			wantRestores: 0, wantVerifies: 1, wantWrites: 1,
		},
		{
			name: "already rolled back", phase: "rolled_back", installed: true,
			wantRestores: 0, wantVerifies: 1, wantWrites: 0,
		},
		{
			// A rolled_back journal whose verify fails must NOT trigger a
			// restore — the fail-closed branch surfaces the verify error
			// directly so operators see the discrepancy instead of a silent
			// second-attempt restore.
			name: "rolled back with failed verify", phase: "rolled_back", installed: false,
			wantRestores: 0, wantVerifies: 1, wantWrites: 0,
			wantErr: "managed hooks are not installed",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			restores := 0
			verifies := 0
			writes := 0
			installed := test.installed
			err := completeWindowsManagedHooksTeardownRollback(
				windowsManagedHooksTeardownJournal{Phase: test.phase},
				func() error {
					restores++
					installed = true
					return nil
				},
				func() error {
					verifies++
					if !installed {
						return errors.New("managed hooks are not installed")
					}
					return nil
				},
				func(journal windowsManagedHooksTeardownJournal) error {
					writes++
					if journal.Phase != "rolled_back" {
						t.Fatalf("persisted phase = %q", journal.Phase)
					}
					return nil
				},
			)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("err = %v, want error containing %q", err, test.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if restores != test.wantRestores ||
				verifies != test.wantVerifies ||
				writes != test.wantWrites {
				t.Fatalf(
					"restores=%d verifies=%d writes=%d, want %d/%d/%d",
					restores,
					verifies,
					writes,
					test.wantRestores,
					test.wantVerifies,
					test.wantWrites,
				)
			}
		})
	}
}

func TestRestoreWindowsManagedHooksTeardownCompositeCompensatesInReverse(t *testing.T) {
	claudeErr := errors.New("Claude restore failed")
	cursorErr := errors.New("Cursor restore failed")
	codexErr := errors.New("Codex restore failed")
	claudeCompensationErr := errors.New("Claude compensation failed")
	cursorCompensationErr := errors.New("Cursor compensation failed")
	for name, test := range map[string]struct {
		claudeErr             error
		cursorErr             error
		codexErr              error
		claudeCompensationErr error
		cursorCompensationErr error
		wantSteps             []string
		wantErrors            []error
	}{
		"success": {
			wantSteps: []string{"restore-claude", "restore-cursor", "restore-codex"},
		},
		"Claude failure stops immediately": {
			claudeErr:  claudeErr,
			wantSteps:  []string{"restore-claude"},
			wantErrors: []error{claudeErr},
		},
		"Cursor failure compensates Claude": {
			cursorErr:  cursorErr,
			wantSteps:  []string{"restore-claude", "restore-cursor", "compensate-claude"},
			wantErrors: []error{cursorErr},
		},
		"Codex failure compensates Cursor then Claude": {
			codexErr:   codexErr,
			wantSteps:  []string{"restore-claude", "restore-cursor", "restore-codex", "compensate-cursor", "compensate-claude"},
			wantErrors: []error{codexErr},
		},
		"compensation failures are joined": {
			codexErr:              codexErr,
			claudeCompensationErr: claudeCompensationErr,
			cursorCompensationErr: cursorCompensationErr,
			wantSteps:             []string{"restore-claude", "restore-cursor", "restore-codex", "compensate-cursor", "compensate-claude"},
			wantErrors:            []error{codexErr, cursorCompensationErr, claudeCompensationErr},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var steps []string
			err := restoreWindowsManagedHooksTeardownComposite(
				func() error {
					steps = append(steps, "restore-claude")
					return test.claudeErr
				},
				func() error {
					steps = append(steps, "restore-cursor")
					return test.cursorErr
				},
				func() error {
					steps = append(steps, "restore-codex")
					return test.codexErr
				},
				func() error {
					steps = append(steps, "compensate-claude")
					return test.claudeCompensationErr
				},
				func() error {
					steps = append(steps, "compensate-cursor")
					return test.cursorCompensationErr
				},
			)
			if !slices.Equal(steps, test.wantSteps) {
				t.Fatalf("steps = %v, want %v", steps, test.wantSteps)
			}
			if len(test.wantErrors) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected composite restore failure")
			}
			for _, want := range test.wantErrors {
				if !errors.Is(err, want) {
					t.Fatalf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestWindowsManagedHooksClaudeSnapshotsEqualRequiresExactPreimage(t *testing.T) {
	base := enterprisehooks.WindowsClaudeManagedPolicyTeardownSnapshot{
		PolicyExisted: true,
		Policy:        []byte("policy"),
		StateExisted:  true,
		State:         []byte("state"),
	}
	identical := base
	identical.Policy = append([]byte(nil), base.Policy...)
	identical.State = append([]byte(nil), base.State...)
	if !windowsManagedHooksClaudeSnapshotsEqual(base, identical) {
		t.Fatal("byte-identical Claude snapshots must permit partial Cursor teardown recovery")
	}

	changed := identical
	changed.State = []byte("changed")
	if windowsManagedHooksClaudeSnapshotsEqual(base, changed) {
		t.Fatal("Claude preimage drift must prevent partial Cursor teardown recovery")
	}
}

func TestRecoverWindowsManagedHooksCursorTeardownCapture(t *testing.T) {
	captureErr := errors.New("strict capture failed")
	healErr := errors.New("journal heal failed")
	recaptureErr := errors.New("recapture failed")
	for name, test := range map[string]struct {
		initialErr error
		allowHeal  bool
		healErr    error
		recapture  error
		wantSteps  []string
		wantErrors []error
	}{
		"strict capture succeeds": {},
		"ambiguous state is not mutated": {
			initialErr: captureErr,
			wantErrors: []error{captureErr},
		},
		"heal failure is joined": {
			initialErr: captureErr,
			allowHeal:  true,
			healErr:    healErr,
			wantSteps:  []string{"heal"},
			wantErrors: []error{captureErr, healErr},
		},
		"recapture failure is joined": {
			initialErr: captureErr,
			allowHeal:  true,
			recapture:  recaptureErr,
			wantSteps:  []string{"heal", "recapture"},
			wantErrors: []error{captureErr, recaptureErr},
		},
		"authenticated partial state heals and recaptures": {
			initialErr: captureErr,
			allowHeal:  true,
			wantSteps:  []string{"heal", "recapture"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var steps []string
			err := recoverWindowsManagedHooksCursorTeardownCapture(
				test.initialErr,
				test.allowHeal,
				func() error {
					steps = append(steps, "heal")
					return test.healErr
				},
				func() error {
					steps = append(steps, "recapture")
					return test.recapture
				},
			)
			if !slices.Equal(steps, test.wantSteps) {
				t.Fatalf("steps = %v, want %v", steps, test.wantSteps)
			}
			if len(test.wantErrors) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected Cursor teardown capture recovery failure")
			}
			for _, want := range test.wantErrors {
				if !errors.Is(err, want) {
					t.Fatalf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

// An activated standalone deployment that enrolled no Codex user writes its
// teardown journal with codex_targets [], which the reader requires; a nil
// slice was written as null and the uninstall failed (GAP-0248).
func TestWindowsManagedHooksTeardownJournalWritesEmptyCodexTargets(t *testing.T) {
	journal := windowsManagedHooksTeardownJournal{ActivationState: "activated"}
	journal.ClaudeTargetSIDs, journal.CodexPolicyActive, journal.CodexTargets, journal.CursorTargets =
		windowsManagedHooksTeardownExpectedEnrollment(journal.ActivationState, false, []string{"S-1-5-21-111-222-333-1001"}, nil, nil)
	for _, c := range []struct{ profile, want string }{
		{managed.ProfileStandalone, `"codex_targets":[]`},
		// Secure Client: windowsManagedHooksTeardownExpectedEnrollment now
		// returns empty, non-nil slices, so it writes [] too; the reader
		// still accepts null from journals of earlier releases.
		{"", `"codex_targets":[]`},
	} {
		t.Setenv(managed.EnterpriseProfileEnv, c.profile)
		body, err := json.Marshal(windowsManagedHooksTeardownJournalForWrite(journal))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), c.want) {
			t.Fatalf("profile %q: journal %s does not contain %s", c.profile, body, c.want)
		}
	}
}

// Prepare journals the Codex policy bit it finds when no Codex account is
// enrolled. A 1.0.2 or 1.0.3 deployment with Codex configured and no enrolled
// account has no Codex requirements. Journaling the configured bit instead
// made prepare's installed-state check refuse that preimage and blocked
// teardown; a 1.0.4 empty guard must stay journaled active.
func TestWindowsManagedHooksTeardownPrepareCapturesZeroTargetCodexPolicy(t *testing.T) {
	previous := windowsManagedHooksTeardownCodexRegistryReader
	t.Cleanup(func() { windowsManagedHooksTeardownCodexRegistryReader = previous })
	const hook = `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`
	alice := connector.WindowsCodexManagedRuntimeTarget{
		SID: "S-1-5-21-111-222-333-1001", DataDir: `C:\Users\alice\.defenseclaw`,
	}
	expected := func(configured bool, targets []connector.WindowsCodexManagedRuntimeTarget) windowsManagedHooksTeardownJournal {
		claude, active, codex, cursor := windowsManagedHooksTeardownExpectedEnrollment(
			windowsManagedHooksActivated, configured, nil, targets, nil,
		)
		identity := windowsManagedHooksTeardownJournal{
			SchemaVersion:          windowsManagedHooksTeardownJournalSchema,
			Phase:                  "prepared",
			ManifestPath:           `C:\ProgramData\DefenseClaw\hook-guardian\targets.yaml`,
			ManifestSHA256:         strings.Repeat("a", 64),
			ActivationState:        windowsManagedHooksActivated,
			DeploymentGenerationID: strings.Repeat("b", 32),
			HookBinary:             hook,
			GatewayAddr:            "127.0.0.1:18970",
			GatewayServiceName:     "DefenseClawGateway",
			ClaudeTargetSIDs:       claude,
			CodexPolicyActive:      active,
			CodexTargets:           codex,
			CursorTargets:          cursor,
		}
		var err error
		identity.ManifestFingerprint, err = windowsManagedHooksTeardownFingerprint(identity.Targets)
		if err != nil {
			t.Fatal(err)
		}
		return identity
	}
	for _, test := range []struct {
		name     string
		registry connector.WindowsCodexManagedRuntimeRegistry
	}{
		{name: "1.0.2 or 1.0.3 zero-target state without requirements"},
		{name: "1.0.4 active empty guard", registry: connector.WindowsCodexManagedRuntimeRegistry{Active: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reads := 0
			windowsManagedHooksTeardownCodexRegistryReader = func(binary string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
				reads++
				if binary != hook {
					t.Fatalf("prepare read the Codex registry for %s", binary)
				}
				return test.registry, nil
			}
			configured := expected(true, nil)
			if !configured.CodexPolicyActive {
				t.Fatal("fixture: configured Codex must expect an active guard")
			}
			if !test.registry.Active {
				if err := validateWindowsManagedHooksTeardownEnrollment(configured, nil, false, test.registry, nil, false); err == nil {
					t.Fatal("fixture: the configured bit no longer refuses the legacy preimage")
				}
			}
			prepared := configured
			if err := captureWindowsManagedHooksTeardownCodexPolicy(&prepared); err != nil {
				t.Fatal(err)
			}
			if reads != 1 || prepared.CodexPolicyActive != test.registry.Active {
				t.Fatalf("prepare journaled Codex active=%t after %d reads, want %t", prepared.CodexPolicyActive, reads, test.registry.Active)
			}
			if err := validateWindowsManagedHooksTeardownEnrollment(prepared, nil, false, test.registry, nil, false); err != nil {
				t.Fatalf("prepare refused the installed zero-target Codex state: %v", err)
			}
			// Verify, rollback and finalize compare the journal with the
			// configuration-derived identity.
			if err := validateWindowsManagedHooksTeardownJournal(prepared, configured); err != nil {
				t.Fatalf("journal of the captured Codex state rejected: %v", err)
			}
		})
	}

	readErr := errors.New("Codex managed runtime state exists without machine requirements")
	for _, test := range []struct {
		name     string
		registry connector.WindowsCodexManagedRuntimeRegistry
		err      error
	}{
		{name: "unreadable registry", err: readErr},
		{name: "registry enrolls an account the manifest does not", registry: connector.WindowsCodexManagedRuntimeRegistry{
			Active: true, Targets: []connector.WindowsCodexManagedRuntimeTarget{alice},
		}},
	} {
		t.Run("refuses "+test.name, func(t *testing.T) {
			windowsManagedHooksTeardownCodexRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
				return test.registry, test.err
			}
			prepared := expected(true, nil)
			if err := captureWindowsManagedHooksTeardownCodexPolicy(&prepared); err == nil {
				t.Fatal("prepare journaled an unauthenticated Codex state")
			}
		})
	}

	windowsManagedHooksTeardownCodexRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
		t.Fatal("prepare read the Codex registry although the manifest decides the bit")
		return connector.WindowsCodexManagedRuntimeRegistry{}, nil
	}
	for name, identity := range map[string]windowsManagedHooksTeardownJournal{
		"enrolled Codex account":  expected(true, []connector.WindowsCodexManagedRuntimeTarget{alice}),
		"Codex is not configured": expected(false, nil),
	} {
		want := identity.CodexPolicyActive
		if err := captureWindowsManagedHooksTeardownCodexPolicy(&identity); err != nil || identity.CodexPolicyActive != want {
			t.Fatalf("%s: active=%t err=%v, want the manifest's bit %t", name, identity.CodexPolicyActive, err, want)
		}
	}
}

// GAP-1443/GAP-1447: Setup asks the installed helper whether it prepares the
// hook removal against a committed uninstall tombstone before it moves that
// removal after the commit. This helper says so in exactly one JSON report;
// the helpers of 1.0.0 to 1.0.3 have no such command, so Setup keeps the
// precommit order for them.
func TestWindowsManagedHooksTeardownReportsCommittedStandalonePrepare(t *testing.T) {
	command := newWindowsManagedHooksTeardownCommand()
	var out strings.Builder
	command.SetOut(&out)
	command.SetErr(&out)
	command.SetArgs([]string{"capabilities", "--json"})
	if err := command.Execute(); err != nil {
		t.Fatalf("capabilities: %v: %s", err, out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("capabilities wrote %d lines, want one JSON report: %q", len(lines), out.String())
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &report); err != nil {
		t.Fatalf("capabilities report: %v: %q", err, lines[0])
	}
	if report["schema_version"] != float64(windowsManagedHooksTeardownSchema) || report["action"] != "capabilities" ||
		report["ok"] != true || report["committed_standalone_prepare"] != true {
		t.Fatalf("capabilities report = %v", report)
	}
	// GAP-0571: the read-only check an uninstall asks before its commit.
	if report["precommit_check"] != true {
		t.Fatalf("capabilities report does not offer the precommit check: %v", report)
	}
	// GAP-0773: Setup passes --uninstall to "codex-requirements remove" only
	// when this report offers it, and the command it names has the flag.
	if report["codex_requirements_uninstall"] != true {
		t.Fatalf("capabilities report does not offer the Codex requirements uninstall removal: %v", report)
	}
	if remove, _, err := newWindowsCodexRequirementsCommand().Find([]string{"remove"}); err != nil ||
		remove == nil || remove.Flags().Lookup("uninstall") == nil {
		t.Fatalf("codex-requirements remove has no --uninstall flag: %v", err)
	}
	if child, _, err := command.Find([]string{"check"}); err != nil || child == nil || child.Name() != "check" {
		t.Fatalf("teardown-managed-hooks has no check action: %v", err)
	}
	// The committed preparation it reports is the one the validation admits.
	installed := false
	metadata := windowsCodexDeploymentMetadata{Installed: &installed}
	action, committed, err := windowsManagedHooksTeardownValidationAction(
		metadata, "prepare", true, filepath.Join(t.TempDir(), "pending.json"))
	if err != nil || action != "finalize" || !committed {
		t.Fatalf("committed standalone prepare = %q, %v, %v", action, committed, err)
	}
}

// rel-1-0-6:GAP-0303: the OWNER RIGHTS restore Setup runs with its own
// gateway acts only for a standalone deployment and reports per account.
func TestWindowsManagedHooksOwnerRightsRestoreRefusesOutsideStandalone(t *testing.T) {
	if enterprisehooks.WindowsStandaloneProcess() {
		t.Skip("the test process runs as a standalone deployment")
	}
	report, err := runWindowsManagedHooksOwnerRightsRestore()
	if err == nil || report.OK || report.Action != "restore-owner-rights" ||
		!strings.Contains(err.Error(), "standalone profile") {
		t.Fatalf("restore outside standalone: report=%+v err=%v", report, err)
	}
}

// The rollback of a teardown (restoreWindowsCodexManagedHooks) and its clean
// check (verifyWindowsManagedHooksCodexClean) read nothing behind a kept link:
// the verifier, reconciler and publisher are never called, and both succeed.
// Without the link they do call them (GAP-0773).
func TestWindowsManagedHooksTeardownRollbackAndCleanCheckSkipAKeptLink(t *testing.T) {
	savedKept, savedVerifier := windowsManagedHooksCodexFolderKept, windowsManagedHooksCodexVerifier
	savedReconciler, savedPublisher := windowsManagedHooksCodexReconciler, windowsManagedHooksCodexPublisher
	t.Cleanup(func() {
		windowsManagedHooksCodexFolderKept, windowsManagedHooksCodexVerifier = savedKept, savedVerifier
		windowsManagedHooksCodexReconciler, windowsManagedHooksCodexPublisher = savedReconciler, savedPublisher
	})
	var calls []string
	windowsManagedHooksCodexVerifier = func(connector.WindowsCodexMachineRequirementsOptions) (connector.WindowsCodexMachineRequirementsReport, error) {
		calls = append(calls, "verify")
		return connector.WindowsCodexMachineRequirementsReport{OK: true, SafeToRemoveBinary: true}, nil
	}
	windowsManagedHooksCodexReconciler = func(connector.WindowsCodexMachineRequirementsOptions) (connector.WindowsCodexMachineRequirementsReport, error) {
		calls = append(calls, "reconcile")
		return connector.WindowsCodexMachineRequirementsReport{OK: true}, nil
	}
	windowsManagedHooksCodexPublisher = func(connector.WindowsCodexMachineRequirementsOptions, []connector.WindowsCodexManagedRuntimeTarget) error {
		calls = append(calls, "publish")
		return nil
	}
	opts := connector.WindowsCodexMachineRequirementsOptions{}
	targets := []connector.WindowsCodexManagedRuntimeTarget{{SID: "S-1-5-21-111-222-333-1001", DataDir: `C:\Users\alice\.defenseclaw`}}

	windowsManagedHooksCodexFolderKept = func() (string, error) { return `C:\ProgramData\OpenAI\Codex`, nil }
	for _, active := range []bool{true, false} {
		if err := restoreWindowsCodexManagedHooks(opts, active, nil); err != nil {
			t.Fatalf("rollback over a kept link (policy active %t): %v", active, err)
		}
	}
	if surviving, err := verifyWindowsManagedHooksCodexClean(opts); err != nil || surviving != 0 {
		t.Fatalf("clean check over a kept link: %d, %v", surviving, err)
	}
	if len(calls) != 0 {
		t.Fatalf("a Codex read ran behind a kept link: %v", calls)
	}

	windowsManagedHooksCodexFolderKept = func() (string, error) { return "", nil }
	if err := restoreWindowsCodexManagedHooks(opts, true, targets); err != nil {
		t.Fatal(err)
	}
	if err := restoreWindowsCodexManagedHooks(opts, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyWindowsManagedHooksCodexClean(opts); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, ",") != "reconcile,publish,verify,verify,verify" {
		t.Fatalf("without a link the rollback and clean check ran %v", calls)
	}
}

// The Codex kept entry says what a kept link cannot promise, and the warning
// still names it once as kept (GAP-0773).
func TestWindowsCodexKeptLinkEntryNamesTheUnverifiedPolicy(t *testing.T) {
	if !strings.HasPrefix(windowsEnterpriseCodexKeptLinkReason, windowsEnterpriseKeptLinkReason) ||
		!strings.Contains(windowsEnterpriseCodexKeptLinkReason, "may still name the DefenseClaw hook binary") {
		t.Fatalf("Codex kept-link reason = %q", windowsEnterpriseCodexKeptLinkReason)
	}
}

// A link at the Codex machine-policy folder is kept and not read through
// (GAP-0773). The teardown registry read then reports it in Kept and nothing
// else; prepare keeps the expected policy bit, and the installed-state check
// has no Codex enrollment to compare, whether Codex is configured with no
// account, or has an enrolled account the manifest lists.
func TestWindowsManagedHooksTeardownKeepsALinkAtTheCodexFolder(t *testing.T) {
	previous := windowsManagedHooksTeardownCodexRegistryReader
	t.Cleanup(func() { windowsManagedHooksTeardownCodexRegistryReader = previous })
	const hook = `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`
	const link = `C:\ProgramData\OpenAI\Codex`
	alice := connector.WindowsCodexManagedRuntimeTarget{
		SID: "S-1-5-21-111-222-333-1001", DataDir: `C:\Users\alice\.defenseclaw`,
	}
	windowsManagedHooksTeardownCodexRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
		return connector.WindowsCodexManagedRuntimeRegistry{Kept: link}, nil
	}
	for name, targets := range map[string][]connector.WindowsCodexManagedRuntimeTarget{
		"configured, no account": nil,
		"enrolled account":       {alice},
	} {
		t.Run(name, func(t *testing.T) {
			claude, active, codex, cursor := windowsManagedHooksTeardownExpectedEnrollment(
				windowsManagedHooksActivated, true, nil, targets, nil,
			)
			identity := windowsManagedHooksTeardownJournal{
				HookBinary:        hook,
				ClaudeTargetSIDs:  claude,
				CodexPolicyActive: active,
				CodexTargets:      codex,
				CursorTargets:     cursor,
			}
			if !identity.CodexPolicyActive {
				t.Fatal("fixture: Codex must expect an active guard")
			}
			prepared := identity
			if err := captureWindowsManagedHooksTeardownCodexPolicy(&prepared); err != nil {
				t.Fatalf("prepare failed on a kept link: %v", err)
			}
			if prepared.CodexPolicyActive != identity.CodexPolicyActive || len(prepared.CodexTargets) != len(identity.CodexTargets) {
				t.Fatalf("prepare changed the expected Codex enrollment over a link: %+v", prepared)
			}
			kept := connector.WindowsCodexManagedRuntimeRegistry{Kept: link}
			if err := validateWindowsManagedHooksTeardownEnrollment(identity, nil, false, kept, nil, false); err != nil {
				t.Fatalf("the installed-state check failed on a kept link: %v", err)
			}
			// Without the link the same registry is a mismatch: the
			// exemption is the kept link, nothing else.
			if err := validateWindowsManagedHooksTeardownEnrollment(
				identity, nil, false, connector.WindowsCodexManagedRuntimeRegistry{}, nil, false,
			); err == nil {
				t.Fatal("an empty registry without a link matched an active Codex guard")
			}
		})
	}
}

// GAP-0773 and GAP-0829. The activation-binding checks compare what the
// manifest and the activation record say is enrolled with what the teardown
// reads in each connector's machine folder. Where a link keeps that folder
// nothing is read behind it, so that connector is left out of the comparison;
// a mismatch no kept link explains still refuses.

// keepConnectorFolders makes the named connectors' machine folders kept links.
func keepConnectorFolders(t *testing.T, names ...string) {
	t.Helper()
	previous := windowsManagedHooksConnectorFolderKept
	t.Cleanup(func() { windowsManagedHooksConnectorFolderKept = previous })
	windowsManagedHooksConnectorFolderKept = func(name string) (string, error) {
		if slices.Contains(names, name) {
			return `C:\ProgramData\link-to-` + name, nil
		}
		return "", nil
	}
}

const keptTestSID = "S-1-5-21-111-222-333-1001"

func keptTestTarget(connectorName string) windowsManagedHooksTeardownTarget {
	return windowsManagedHooksTeardownTarget{
		Connector: connectorName, SID: keptTestSID, DataDir: `C:\Users\alice\.defenseclaw`,
	}
}

// enrolledTeardownIdentity is an activated deployment with one enrolled account
// for each machine-enrolled connector.
func enrolledTeardownIdentity(t *testing.T) windowsManagedHooksTeardownJournal {
	t.Helper()
	targets := []windowsManagedHooksTeardownTarget{
		keptTestTarget("claudecode"), keptTestTarget("codex"), keptTestTarget("copilot"), keptTestTarget("cursor"),
	}
	codex := []connector.WindowsCodexManagedRuntimeTarget{{SID: keptTestSID, DataDir: `C:\Users\alice\.defenseclaw`}}
	cursor := []enterprisehooks.WindowsCursorManagedRuntimeTarget{{SID: keptTestSID, DataDir: `C:\Users\alice\.defenseclaw`}}
	identity := windowsManagedHooksTeardownJournal{
		SchemaVersion:          windowsManagedHooksTeardownJournalSchema,
		Phase:                  "captured",
		ManifestPath:           `C:\ProgramData\DefenseClaw\hook-guardian\targets.yaml`,
		ManifestSHA256:         strings.Repeat("a", 64),
		ActivationState:        windowsManagedHooksActivated,
		DeploymentGenerationID: strings.Repeat("b", 32),
		HookBinary:             `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:            "127.0.0.1:18970",
		GatewayServiceName:     "DefenseClawGateway",
		Targets:                targets,
	}
	var err error
	if identity.ManifestFingerprint, err = windowsManagedHooksTeardownFingerprint(targets); err != nil {
		t.Fatal(err)
	}
	identity.ClaudeTargetSIDs, identity.CodexPolicyActive, identity.CodexTargets, identity.CursorTargets =
		windowsManagedHooksTeardownExpectedEnrollment(
			windowsManagedHooksActivated, true, []string{keptTestSID}, codex, cursor,
		)
	return identity
}

func TestWindowsManagedHooksTeardownSelectorExpectationLeavesOutAKeptConnector(t *testing.T) {
	for _, name := range []string{"claudecode", "codex", "cursor", "copilot", "opencode", "devin", "antigravity", "hermes", "kiro"} {
		t.Run(name, func(t *testing.T) {
			target := keptTestTarget(name)
			keepConnectorFolders(t)
			expected, err := windowsManagedHooksTeardownSelectorExpectedLive(target, nil, windowsManagedHooksActivated)
			if err != nil || !expected {
				t.Fatalf("without a link an activated target expects its selector entry: %v, %v", expected, err)
			}
			keepConnectorFolders(t, name)
			expected, err = windowsManagedHooksTeardownSelectorExpectedLive(target, nil, windowsManagedHooksActivated)
			if err != nil || expected {
				t.Fatalf("behind a kept link no selector entry is expected: %v, %v", expected, err)
			}
			// A link at another connector's folder does not excuse this one.
			other := "cursor"
			if name == other {
				other = "codex"
			}
			keepConnectorFolders(t, other)
			expected, err = windowsManagedHooksTeardownSelectorExpectedLive(target, nil, windowsManagedHooksActivated)
			if err != nil || !expected {
				t.Fatalf("a link at %s excused %s: %v, %v", other, name, expected, err)
			}
		})
	}
	t.Run("a probe failure is reported, not treated as plain", func(t *testing.T) {
		previous := windowsManagedHooksConnectorFolderKept
		t.Cleanup(func() { windowsManagedHooksConnectorFolderKept = previous })
		windowsManagedHooksConnectorFolderKept = func(string) (string, error) { return "", errors.New("probe failed") }
		if _, err := windowsManagedHooksTeardownSelectorExpectedLive(keptTestTarget("cursor"), nil, windowsManagedHooksActivated); err == nil {
			t.Fatal("a failed probe was ignored")
		}
	})
}

func TestWindowsManagedHooksTeardownEnrollmentCheckExcludesAKeptConnector(t *testing.T) {
	identity := enrolledTeardownIdentity(t)
	// The reads behind a kept link come back empty, as the real ones do.
	emptyCodex := connector.WindowsCodexManagedRuntimeRegistry{Active: true}
	check := func(claude []string, claudeActive bool, codex connector.WindowsCodexManagedRuntimeRegistry, cursor []enterprisehooks.WindowsCursorManagedRuntimeTarget, cursorActive bool) error {
		return validateWindowsManagedHooksTeardownEnrollment(identity, claude, claudeActive, codex, cursor, cursorActive)
	}
	full := connector.WindowsCodexManagedRuntimeRegistry{Active: true, Targets: identity.CodexTargets}
	fullCursor := identity.CursorTargets

	keepConnectorFolders(t)
	if err := check([]string{keptTestSID}, true, full, fullCursor, true); err != nil {
		t.Fatalf("a matching deployment was refused: %v", err)
	}

	// Cursor (GAP-0829): enrolled and configured, the folder replaced by a link.
	keepConnectorFolders(t)
	if err := check([]string{keptTestSID}, true, full, nil, false); err == nil ||
		!strings.Contains(err.Error(), "Cursor machine enrollment does not match") {
		t.Fatalf("an emptied Cursor registry with no link was accepted: %v", err)
	}
	keepConnectorFolders(t, "cursor")
	if err := check([]string{keptTestSID}, true, full, nil, false); err != nil {
		t.Fatalf("an enrolled Cursor behind a kept link was refused: %v", err)
	}
	// The link at Cursor does not excuse a Claude Code mismatch.
	if err := check(nil, false, full, nil, false); err == nil ||
		!strings.Contains(err.Error(), "Claude machine enrollment does not match") {
		t.Fatalf("a link at Cursor excused a Claude Code mismatch: %v", err)
	}

	// Claude Code.
	keepConnectorFolders(t, "claudecode")
	if err := check(nil, false, full, fullCursor, true); err != nil {
		t.Fatalf("an enrolled Claude Code behind a kept link was refused: %v", err)
	}
	if err := check([]string{keptTestSID}, true, emptyCodex, fullCursor, true); err == nil ||
		!strings.Contains(err.Error(), "Codex machine enrollment does not match") {
		t.Fatalf("a link at Claude Code excused a Codex mismatch: %v", err)
	}
}

func TestWindowsManagedHooksTeardownPerUserEnrollmentCheckExcludesAKeptConnector(t *testing.T) {
	for _, name := range []string{"copilot", "opencode", "devin", "antigravity", "hermes", "kiro"} {
		t.Run(name, func(t *testing.T) {
			identity := windowsManagedHooksTeardownJournal{
				ActivationState: windowsManagedHooksActivated,
				Targets:         []windowsManagedHooksTeardownTarget{keptTestTarget(name)},
			}
			// Enrolled per the manifest, and nothing is enrolled on this computer.
			keepConnectorFolders(t)
			if err := validateWindowsManagedHooksStandalonePerUserEnrollment(identity); err == nil {
				t.Fatal("an enrolled connector with no machine enrollment was accepted")
			}
			keepConnectorFolders(t, name)
			if err := validateWindowsManagedHooksStandalonePerUserEnrollment(identity); err != nil {
				t.Fatalf("an enrolled %s behind a kept link was refused: %v", name, err)
			}
			keepConnectorFolders(t, "cursor")
			if err := validateWindowsManagedHooksStandalonePerUserEnrollment(identity); err == nil {
				t.Fatal("a link at Cursor excused a per-user connector")
			}
		})
	}
}

func TestWindowsManagedHooksTeardownJournalAcceptsTheEmptyReadsBehindKeptLinks(t *testing.T) {
	identity := enrolledTeardownIdentity(t)
	for _, target := range identity.Targets {
		identity.SelectorTargets = append(identity.SelectorTargets, enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot{
			SchemaVersion: 1, Connector: target.Connector, TargetSID: target.SID,
		})
	}
	all := []string{"claudecode", "codex", "copilot", "cursor"}
	keepConnectorFolders(t, all...)
	if err := validateWindowsManagedHooksTeardownJournal(identity, identity); err != nil {
		t.Fatalf("a journal captured behind kept links was refused: %v", err)
	}
	for _, left := range all {
		var some []string
		for _, name := range all {
			if name != left {
				some = append(some, name)
			}
		}
		keepConnectorFolders(t, some...)
		if err := validateWindowsManagedHooksTeardownJournal(identity, identity); err == nil {
			t.Fatalf("an empty snapshot for %s with no link on it was accepted", left)
		}
	}
	keepConnectorFolders(t)
	if err := validateWindowsManagedHooksTeardownJournal(identity, identity); err == nil {
		t.Fatal("empty snapshots with no link were accepted for an enrolled deployment")
	}
}

func TestWindowsManagedHooksKeptLinkIsNamedOnce(t *testing.T) {
	got := windowsManagedHooksNameKeptLinksOnce(
		[]string{`C:\ProgramData\OpenAI\Codex`},
		[]string{`c:\programdata\openai\codex`, `C:\ProgramData\Cursor`},
		[]string{`C:\ProgramData\Cursor`, `C:\ProgramData\GitHub\Copilot`},
	)
	want := []string{
		`C:\ProgramData\OpenAI\Codex: ` + windowsEnterpriseCodexKeptLinkReason,
		`C:\ProgramData\Cursor: ` + windowsEnterpriseKeptLinkReason,
		`C:\ProgramData\GitHub\Copilot: ` + windowsEnterpriseKeptLinkReason,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("kept links = %q, want %q", got, want)
	}
}

// After the uninstall committed, the clean check
// reads each per-user connector enrollment, and a rollback puts the enrollment
// back. Both go through the machine folder of the connector, and the read
// follows a link on that folder: an enrollment.json behind an administrator
// link made the purge exit 1603. The stand-in reader fails the way that read
// does when the decoy file is behind the link.
func stubPerUserEnrollmentIO(t *testing.T, decoyBehind ...string) (reads, restores *[]string) {
	t.Helper()
	previousReader, previousRestorer := windowsManagedHooksPerUserEnrollmentReader, windowsManagedHooksPerUserEnrollmentRestorer
	t.Cleanup(func() {
		windowsManagedHooksPerUserEnrollmentReader, windowsManagedHooksPerUserEnrollmentRestorer = previousReader, previousRestorer
	})
	reads, restores = new([]string), new([]string)
	windowsManagedHooksPerUserEnrollmentReader = func(name string) ([]enterprisehooks.WindowsPerUserManagedEnrollmentTarget, bool, error) {
		*reads = append(*reads, name)
		if slices.Contains(decoyBehind, name) {
			return nil, false, errors.New(name + " enrollment is untrusted: reparse point in path")
		}
		return nil, false, nil
	}
	windowsManagedHooksPerUserEnrollmentRestorer = func(name, _ string, _ []enterprisehooks.WindowsPerUserManagedEnrollmentTarget) error {
		*restores = append(*restores, name)
		if slices.Contains(decoyBehind, name) {
			return errors.New(name + " enrollment directory is a link")
		}
		return nil
	}
	return reads, restores
}

func TestWindowsManagedHooksTeardownCleanCheckDoesNotReadBehindAKeptPerUserLink(t *testing.T) {
	names := enterprisehooks.WindowsProfilePerUserConnectorNames()
	if len(names) == 0 {
		t.Skip("no per-user connector on this profile")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			reads, _ := stubPerUserEnrollmentIO(t, name)
			keepConnectorFolders(t, name)
			if err := verifyWindowsManagedHooksStandalonePerUserClean(); err != nil {
				t.Fatalf("the clean check read %s behind a kept link: %v", name, err)
			}
			if slices.Contains(*reads, name) {
				t.Fatalf("the clean check read the enrollment of %s behind a kept link", name)
			}
			// The same decoy with no link on the folder is a real read, and it still fails the check.
			keepConnectorFolders(t)
			if err := verifyWindowsManagedHooksStandalonePerUserClean(); err == nil {
				t.Fatalf("an unreadable %s enrollment with no link was accepted", name)
			}
			// A link at another connector excuses nothing here.
			keepConnectorFolders(t, "cursor", "claudecode", "codex")
			if err := verifyWindowsManagedHooksStandalonePerUserClean(); err == nil {
				t.Fatalf("a link at another connector excused %s", name)
			}
		})
	}
}

func TestWindowsManagedHooksTeardownCleanCheckStillFailsOnASurvivingPerUserEnrollment(t *testing.T) {
	names := enterprisehooks.WindowsProfilePerUserConnectorNames()
	if len(names) == 0 {
		t.Skip("no per-user connector on this profile")
	}
	previous := windowsManagedHooksPerUserEnrollmentReader
	t.Cleanup(func() { windowsManagedHooksPerUserEnrollmentReader = previous })
	windowsManagedHooksPerUserEnrollmentReader = func(string) ([]enterprisehooks.WindowsPerUserManagedEnrollmentTarget, bool, error) {
		return []enterprisehooks.WindowsPerUserManagedEnrollmentTarget{{SID: keptTestSID}}, true, nil
	}
	keepConnectorFolders(t)
	if err := verifyWindowsManagedHooksStandalonePerUserClean(); err == nil || !strings.Contains(err.Error(), "survived") {
		t.Fatalf("a surviving enrollment was accepted: %v", err)
	}
}

func TestWindowsManagedHooksTeardownRollbackDoesNotRestoreBehindAKeptPerUserLink(t *testing.T) {
	journal := windowsManagedHooksTeardownJournal{
		ActivationState: windowsManagedHooksActivated,
		HookBinary:      `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		Targets:         []windowsManagedHooksTeardownTarget{keptTestTarget("copilot")},
	}
	_, restores := stubPerUserEnrollmentIO(t, "copilot")
	keepConnectorFolders(t, "copilot")
	if err := restoreWindowsManagedHooksStandalonePerUserEnrollments(journal); err != nil {
		t.Fatalf("a rollback republished an enrollment behind a kept link: %v", err)
	}
	if len(*restores) != 0 {
		t.Fatalf("a rollback wrote the enrollment of %q behind a kept link", *restores)
	}
	keepConnectorFolders(t)
	if err := restoreWindowsManagedHooksStandalonePerUserEnrollments(journal); err == nil {
		t.Fatal("a rollback with no link did not republish the enrollment")
	}
	if !slices.Equal(*restores, []string{"copilot"}) {
		t.Fatalf("restores = %q, want copilot once", *restores)
	}
}

// GAP-0999: a managed-hook teardown whose Codex step meets a Codex writer that
// holds the lock reports the stable busy-writer code, so the rollback that
// called it defers instead of failing with the services stopped.
func TestWindowsManagedHooksTeardownReportsABusyCodexWriterByCode(t *testing.T) {
	busy := fmt.Errorf("restore Codex managed hooks: timed out waiting 10s for Codex machine policy lock: %w", connector.ErrWindowsCodexWriterLockBusy)
	for name, err := range map[string]error{
		"direct":      busy,
		"joined busy": errors.Join(busy, fmt.Errorf("again: %w", connector.ErrWindowsCodexWriterLockBusy)),
	} {
		if got := windowsManagedHooksTeardownErrorCode(err); got != "writer_lock_busy" {
			t.Fatalf("%s: code = %q, want writer_lock_busy", name, got)
		}
	}
	// A busy Codex writer next to another failure (a compensation that failed too) is not a
	// writer-only failure: no code, so the caller throws as before.
	for name, err := range map[string]error{
		"busy plus compensation":                          errors.Join(busy, errors.New("restore pre-rollback Claude policy after Codex failure: access denied")),
		"compensation first":                              errors.Join(errors.New("restore pre-rollback Cursor policy after Codex failure: access denied"), busy),
		"single wrapper around a join with a plain cause": fmt.Errorf("teardown rollback: %w", errors.Join(busy, errors.New("restore pre-rollback Claude policy after Codex failure: access denied"))),
	} {
		if got := windowsManagedHooksTeardownErrorCode(err); got != "" {
			t.Fatalf("%s: code = %q, want none", name, got)
		}
	}
	if got := windowsManagedHooksTeardownErrorCode(errors.New("Codex machine policy is not clean after teardown rollback")); got != "" {
		t.Fatalf("a plain failure got code %q", got)
	}
	if got := windowsManagedHooksTeardownErrorCode(nil); got != "" {
		t.Fatalf("nil error got code %q", got)
	}
}

// GAP-1062: a committed uninstall whose first attempt stopped after it took
// the Codex policy off leaves a captured journal. The rerun puts the preimage
// back and prepares again, so the zero-target Codex bit of the new identity
// must be the journal's: the one read from the half-removed machine made the
// verification of the restored state refuse it ("Codex machine enrollment does
// not match the authenticated activation state").
func TestWindowsManagedHooksTeardownRestoredIdentityTakesTheJournalsZeroTargetCodexBit(t *testing.T) {
	alice := connector.WindowsCodexManagedRuntimeTarget{
		SID: "S-1-5-21-111-222-333-1001", DataDir: `C:\Users\alice\.defenseclaw`,
	}
	journal := windowsManagedHooksTeardownJournal{Phase: "captured", CodexPolicyActive: true}
	identity := windowsManagedHooksTeardownJournal{Phase: "prepared", CodexPolicyActive: false, GatewayAddr: "127.0.0.1:18970"}
	got := windowsManagedHooksTeardownRestoredIdentity(identity, journal)
	if !got.CodexPolicyActive || got.Phase != "prepared" || got.GatewayAddr != identity.GatewayAddr {
		t.Fatalf("restored identity = %+v, want the journal's Codex bit and nothing else changed", got)
	}
	// The restored machine is the one the journal recorded: it passes the check
	// the stale bit failed.
	restoredRegistry := connector.WindowsCodexManagedRuntimeRegistry{Active: true}
	if err := validateWindowsManagedHooksTeardownEnrollment(identity, nil, false, restoredRegistry, nil, false); err == nil {
		t.Fatal("fixture: the stale bit no longer refuses the restored Codex policy")
	}
	if err := validateWindowsManagedHooksTeardownEnrollment(got, nil, false, restoredRegistry, nil, false); err != nil {
		t.Fatalf("the restored identity refused the restored Codex policy: %v", err)
	}
	// A legacy zero-target preimage (inactive) comes back inactive.
	inactive := windowsManagedHooksTeardownRestoredIdentity(
		windowsManagedHooksTeardownJournal{CodexPolicyActive: true},
		windowsManagedHooksTeardownJournal{CodexPolicyActive: false},
	)
	if inactive.CodexPolicyActive {
		t.Fatal("a journal of an inactive Codex policy was read as active")
	}
	// Enrolled Codex accounts come from the manifest: the identity keeps its value.
	enrolled := windowsManagedHooksTeardownRestoredIdentity(
		windowsManagedHooksTeardownJournal{CodexPolicyActive: true, CodexTargets: []connector.WindowsCodexManagedRuntimeTarget{alice}},
		windowsManagedHooksTeardownJournal{CodexPolicyActive: false, CodexTargets: []connector.WindowsCodexManagedRuntimeTarget{alice}},
	)
	if !enrolled.CodexPolicyActive {
		t.Fatal("an enrolled Codex account's bit was replaced by the journal's")
	}
}

// GAP-1062: a committed uninstall that meets a teardown journal of another
// deployment refuses, changes nothing and names the next step. No FORCE.
func TestWindowsManagedHooksTeardownForeignJournalNamesTheNextStep(t *testing.T) {
	const path = `C:\ProgramData\Cisco\DefenseClaw\install\managed-hooks-teardown-journal.json`
	if windowsManagedHooksTeardownForeignJournalNextStep(nil, path) != nil {
		t.Fatal("no error became an error")
	}
	other := errors.New("Codex machine enrollment does not match the authenticated activation state")
	if got := windowsManagedHooksTeardownForeignJournalNextStep(other, path); got != other {
		t.Fatalf("an unrelated refusal was rewritten: %v", got)
	}
	foreign := fmt.Errorf("%w: %s (phase captured)", errors.New("managed-hook teardown journal does not match the protected deployment"), path)
	got := windowsManagedHooksTeardownForeignJournalNextStep(foreign, path).Error()
	for _, want := range []string{"does not match the protected deployment", path, "changed nothing", "Next step:", "Setup /verify", "lifecycle log"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the foreign journal refusal lacks %q: %s", want, got)
		}
	}
	if strings.Contains(got, "FORCE") {
		t.Fatalf("the refusal names FORCE: %s", got)
	}
}
