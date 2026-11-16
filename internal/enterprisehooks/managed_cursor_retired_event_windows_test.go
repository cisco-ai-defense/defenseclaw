// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// withRetiredCursorThoughtEntry returns hooks as an earlier release wrote
// them: DefenseClaw's preToolUse entry also registered on afterAgentThought.
func withRetiredCursorThoughtEntry(t *testing.T, hooks []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(hooks, &doc); err != nil {
		t.Fatal(err)
	}
	events := doc["hooks"].(map[string]any)
	if _, exists := events["afterAgentThought"]; exists {
		t.Fatal("current merge still registers afterAgentThought")
	}
	owned := events["preToolUse"].([]any)
	events["afterAgentThought"] = []any{owned[len(owned)-1]}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(body, '\n')
}

// A protected policy published before afterAgentThought was retired stays
// active (hook processes keep resolving their target) until the next
// install/repair merge rewrites it.
func TestWindowsCursorPublicArtifactsAcceptPreRetirementAfterAgentThought(t *testing.T) {
	originalRoot := windowsCursorManagedRootResolver
	originalTrust := windowsManagedPolicyFileTrustCheck
	windowsCursorManagedRootResolver = func() (string, error) {
		return `C:\ProgramData\Cursor`, nil
	}
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		windowsCursorManagedRootResolver = originalRoot
		windowsManagedPolicyFileTrustCheck = originalTrust
	})

	hookExecutable := `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`
	adapter, err := connector.RenderWindowsCursorEnterpriseAdapter(hookExecutable, "closed")
	if err != nil {
		t.Fatal(err)
	}
	cursorPaths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	current, err := connector.MergeWindowsCursorEnterpriseHooks(nil, cursorPaths.Adapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	legacy := withRetiredCursorThoughtEntry(t, current)
	state, err := windowsCursorManagedStateBody(windowsCursorManagedPolicyState{
		SchemaVersion:      1,
		HookExecutable:     hookExecutable,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
		AdapterSHA256:      windowsManagedPolicyDigest(adapter),
		ReceiptSHA256:      windowsManagedPolicyDigest([]byte("private receipt")),
		Targets: []WindowsCursorManagedRuntimeTarget{{
			SID: "S-1-5-21-1000-1000-1000-1001", DataDir: `C:\Users\developer\.defenseclaw`,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	validated, err := validateWindowsCursorManagedPublicArtifacts(windowsCursorManagedArtifacts{
		hooks:   windowsManagedFileSnapshot{path: cursorPaths.Hooks, existed: true, data: legacy},
		adapter: windowsManagedFileSnapshot{path: cursorPaths.Adapter, existed: true, data: adapter},
		state:   windowsManagedFileSnapshot{path: cursorPaths.State, existed: true, data: state},
	})
	if err != nil || !validated.active {
		t.Fatalf("pre-retirement Cursor policy was refused: active=%t err=%v", validated.active, err)
	}
	repaired, err := connector.MergeWindowsCursorEnterpriseHooks(legacy, cursorPaths.Adapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	if !connector.WindowsCursorEnterpriseHooksSemanticallyEqual(repaired, current) {
		t.Fatalf("repair did not produce the current roster:\n%s", repaired)
	}
	if err := connector.VerifyWindowsCursorEnterpriseHooks(repaired, cursorPaths.Adapter, "closed"); err != nil {
		t.Fatalf("repaired policy: %v", err)
	}
}

// A teardown journal captured before the upgrade (afterAgentThought still
// registered) restores over a repaired hooks.json: only DefenseClaw-owned
// entries differ, so the remainders match.
func TestWindowsCursorRestoreAcceptsPreRetirementJournal(t *testing.T) {
	adapterPath := `C:\ProgramData\Cursor\defenseclaw-hook.ps1`
	original := []byte(`{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"operator-hook"}]}}`)
	repaired, err := connector.MergeWindowsCursorEnterpriseHooks(original, adapterPath, "closed")
	if err != nil {
		t.Fatal(err)
	}
	legacy := withRetiredCursorThoughtEntry(t, repaired)
	metadata := windowsCursorManagedFileMetadata{
		securityDescriptor: windowsCursorTestTrustedSDDL,
		attributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
	}
	snapshot := WindowsCursorManagedPolicyTeardownSnapshot{
		PolicyActive:            true,
		HooksExisted:            true,
		Hooks:                   legacy,
		HooksSecurityDescriptor: metadata.securityDescriptor,
		HooksAttributes:         metadata.attributes,
	}
	current := windowsCursorManagedArtifacts{
		hooks:         windowsManagedFileSnapshot{path: `C:\ProgramData\Cursor\hooks.json`, existed: true, data: repaired},
		hooksMetadata: metadata,
	}
	if err := windowsCursorRestoreHooksCompatible(current, snapshot, adapterPath, false); err != nil {
		t.Fatalf("pre-retirement journal was refused against a repaired config: %v", err)
	}
	if err := connector.VerifyWindowsCursorEnterpriseHooksForMigration(legacy, adapterPath, "closed"); err != nil {
		t.Fatalf("journaled pre-retirement hook contract was refused: %v", err)
	}
}
