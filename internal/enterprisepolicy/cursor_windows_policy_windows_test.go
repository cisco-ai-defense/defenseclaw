//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A configured Windows machine hook must stay in force even with no enrolled
// users. Policy verify must treat its absence as a protection failure and
// give the administrator a recovery command for every affected connector.
func TestWindowsPolicyVerifyReportsMissingConfiguredMachineHooks(t *testing.T) {
	for _, test := range []struct {
		name      string
		connector string
	}{
		{name: "Claude Code", connector: ConnectorClaudeCode},
		{name: "Codex", connector: ConnectorCodex},
		{name: "Cursor", connector: ConnectorCursor},
	} {
		for _, ownership := range []string{"default", config.MachinePolicyOwnershipOff} {
			t.Run(test.name+"/"+ownership, func(t *testing.T) {
				root := t.TempDir()
				programFiles := filepath.Join(root, "ProgramFiles")
				programData := filepath.Join(root, "ProgramData")
				for _, path := range []string{programFiles, programData} {
					if err := createProtectedDir(path); err != nil {
						t.Fatal(err)
					}
				}
				testWindowsTrust(t, root)
				opts := Options{
					GOOS:                "windows",
					HookBinary:          `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
					WindowsProgramFiles: programFiles,
					WindowsProgramData:  programData,
					StateDir:            filepath.Join(root, "state", "machine-policy"),
				}
				if ownership == config.MachinePolicyOwnershipOff {
					opts = withPolicy(opts, test.connector, func(p *config.EnterpriseConnectorPolicy) {
						p.Ownership = config.MachinePolicyOwnershipOff
					})
				}
				result, err := VerifyAll(opts, []string{test.connector})
				if err != nil {
					t.Fatal(err)
				}
				if result.Complete() || len(result.States) != 1 {
					t.Fatalf("missing %s machine hook passed verify: %+v", test.name, result)
				}
				state := result.States[0]
				if state.Route != RouteMachinePolicy || state.Covered {
					t.Fatalf("missing %s machine hook is covered: %+v", test.name, state)
				}
				conflicts := strings.Join(state.Conflicts, " ")
				for _, want := range []string{
					test.name + "'s configured machine hook is missing",
					"protection failure even with zero enrolled users",
					"Stop " + test.name + " use until repaired",
					"enterprise windows reconcile --profile standalone",
					"enterprise windows repair --profile standalone",
				} {
					if !strings.Contains(conflicts, want) {
						t.Errorf("conflicts = %q, want %q", conflicts, want)
					}
				}
			})
		}
	}
}

// A hooks.json an earlier release published registers afterAgentThought. It
// still counts as DefenseClaw's registration (presence, no flap conflict) and
// the next reconcile rewrites it without that event; removal strips it too.
func TestWindowsCursorReconcileRepairsPreRetirementAfterAgentThought(t *testing.T) {
	opts := windowsTestOptions(t)
	if _, err := (cursorTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	hooksPath, adapterPath, err := windowsCursorPaths(opts)
	if err != nil {
		t.Fatal(err)
	}
	current, exists, err := readPolicyFile(opts, hooksPath)
	if err != nil || !exists {
		t.Fatalf("published hooks.json: exists=%v err=%v", exists, err)
	}
	if bytes.Contains(current, []byte("afterAgentThought")) {
		t.Fatalf("reconcile registered afterAgentThought:\n%s", current)
	}

	var doc map[string]any
	if err := json.Unmarshal(current, &doc); err != nil {
		t.Fatal(err)
	}
	hooks := doc["hooks"].(map[string]any)
	hooks["afterAgentThought"] = hooks["preToolUse"]
	legacy, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writePolicyFile(opts, hooksPath, legacy); err != nil {
		t.Fatal(err)
	}
	if present, err := MachinePolicyPresent(opts, ConnectorCursor); err != nil || !present {
		t.Fatalf("pre-retirement policy presence = %v, %v; want true", present, err)
	}
	if err := connector.VerifyWindowsCursorEnterpriseHooks(legacy, adapterPath, "closed"); err == nil {
		t.Fatal("strict verifier accepted the pre-retirement policy")
	}

	state, err := cursorTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if !state.Changed {
		t.Fatalf("reconcile left the pre-retirement policy in place: %+v", state)
	}
	repaired, _, err := readPolicyFile(opts, hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(repaired, []byte("afterAgentThought")) {
		t.Fatalf("reconcile kept afterAgentThought:\n%s", repaired)
	}
	if err := connector.VerifyWindowsCursorEnterpriseHooks(repaired, adapterPath, "closed"); err != nil {
		t.Fatalf("repaired policy: %v", err)
	}

	if _, err := writePolicyFile(opts, hooksPath, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := (cursorTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	left, exists, err := readPolicyFile(opts, hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(left, adapterPath)
		if err != nil || !connector.WindowsCursorEnterpriseHooksSemanticallyEqual(cleaned, left) {
			t.Fatalf("removal left DefenseClaw entries (err=%v):\n%s", err, left)
		}
	}
}
