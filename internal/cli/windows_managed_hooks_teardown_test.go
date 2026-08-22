// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func TestWindowsManagedHooksTeardownCommandIsHiddenAndBounded(t *testing.T) {
	command := newWindowsManagedHooksTeardownCommand()
	if !command.Hidden {
		t.Fatal("teardown-managed-hooks command must remain hidden")
	}
	if command.Use != "teardown-managed-hooks" {
		t.Fatalf("Use = %q", command.Use)
	}
	var actions []string
	for _, child := range command.Commands() {
		if !child.Hidden {
			t.Fatalf("%s action must remain hidden", child.Name())
		}
		if child.Flags().Lookup("json") == nil {
			t.Fatalf("%s action is missing --json", child.Name())
		}
		actions = append(actions, child.Name())
	}
	if !slices.Equal(actions, []string{"prepare", "rollback", "verify"}) {
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
		SchemaVersion:       windowsManagedHooksTeardownSchema,
		Phase:               "prepared",
		ManifestPath:        `C:\ProgramData\DefenseClaw\hook-guardian\targets.yaml`,
		ManifestFingerprint: fingerprint,
		HookBinary:          `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:         "127.0.0.1:18970",
		GatewayServiceName:  "DefenseClawGateway",
		Targets:             targets,
	}
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
		"failed_count",
		"surviving_owned_path_references",
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
