// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func windowsCursorForeignHookStateFixture(t *testing.T, approved []string) (windowsCursorManagedArtifacts, []byte) {
	t.Helper()
	originalRoot := windowsCursorManagedRootResolver
	originalTrust := windowsManagedPolicyFileTrustCheck
	windowsCursorManagedRootResolver = func() (string, error) { return `C:\ProgramData\Cursor`, nil }
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
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	hooks, err := connector.MergeWindowsCursorEnterpriseHooks(nil, paths.Adapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
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
		ApprovedForeignHookSHA256: approved,
	})
	if err != nil {
		t.Fatal(err)
	}
	return windowsCursorManagedArtifacts{
		hooks:   windowsManagedFileSnapshot{path: paths.Hooks, existed: true, data: hooks},
		adapter: windowsManagedFileSnapshot{path: paths.Adapter, existed: true, data: adapter},
		state:   windowsManagedFileSnapshot{path: paths.State, existed: true, data: state},
	}, state
}

func TestWindowsCursorStateCarriesCanonicalApprovedForeignHooks(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	artifacts, _ := windowsCursorForeignHookStateFixture(t, []string{a, b})
	validated, err := validateWindowsCursorManagedPublicArtifacts(artifacts)
	if err != nil || !validated.active {
		t.Fatalf("state with canonical allowlist rejected: active=%t err=%v", validated.active, err)
	}
	if got := validated.parsed.ApprovedForeignHookSHA256; len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("parsed allowlist = %v", got)
	}

	unsorted, _ := windowsCursorForeignHookStateFixture(t, []string{b, a})
	if _, err := validateWindowsCursorManagedPublicArtifacts(unsorted); err == nil {
		t.Fatal("state with a non-canonical allowlist accepted")
	}
	malformed, _ := windowsCursorForeignHookStateFixture(t, []string{"not-a-digest"})
	if _, err := validateWindowsCursorManagedPublicArtifacts(malformed); err == nil {
		t.Fatal("state with a malformed allowlist entry accepted")
	}
}

func TestWindowsCursorStateWithoutAllowlistKeepsLegacyShape(t *testing.T) {
	_, state := windowsCursorForeignHookStateFixture(t, nil)
	if strings.Contains(string(state), "approved_foreign_hook_sha256") {
		t.Fatalf("default state gained an allowlist field: %s", state)
	}
}
