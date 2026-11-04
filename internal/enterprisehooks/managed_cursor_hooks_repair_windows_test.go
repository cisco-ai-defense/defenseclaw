// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

type windowsCursorHooksRepairFixture struct {
	artifacts windowsCursorManagedArtifacts
	foreign   []byte
	writes    int
}

// newWindowsCursorHooksRepairFixture builds an intact protected Cursor
// enrollment (state, adapter, private receipt) under a temporary Cursor root
// with hooks.json holding hooksBody, or no hooks.json when hooksBody is nil.
func newWindowsCursorHooksRepairFixture(t *testing.T, hooksBody func(foreign []byte, adapterPath string) []byte) *windowsCursorHooksRepairFixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "Cursor")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	originalRoot := windowsCursorManagedRootResolver
	originalTrust := windowsManagedPolicyFileTrustCheck
	originalWriter := windowsCursorManagedHooksRepairWriter
	fixture := &windowsCursorHooksRepairFixture{
		foreign: []byte(`{"version":1,"hooks":{"beforeShellExecution":[{"type":"command","command":"operator-shell-hook"}],"operatorEvent":[{"type":"command","command":"operator-hook"}]}}`),
	}
	windowsCursorManagedRootResolver = func() (string, error) { return root, nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	// The production writer stamps the protected machine descriptor, which a
	// non-elevated test cannot do on a temporary file.
	windowsCursorManagedHooksRepairWriter = func(
		snapshot windowsManagedFileSnapshot,
		_ windowsCursorManagedFileMetadata,
		data []byte,
	) error {
		fixture.writes++
		return os.WriteFile(snapshot.path, data, 0o600)
	}
	t.Cleanup(func() {
		windowsCursorManagedRootResolver = originalRoot
		windowsManagedPolicyFileTrustCheck = originalTrust
		windowsCursorManagedHooksRepairWriter = originalWriter
	})

	paths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	hookExecutable := `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`
	adapter, err := connector.RenderWindowsCursorEnterpriseAdapter(hookExecutable, "closed")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := windowsCursorManagedReceiptBody(windowsCursorManagedPolicyReceipt{
		SchemaVersion:                    1,
		ConfigPreexisting:                true,
		ConfigOriginal:                   fixture.foreign,
		ConfigOriginalSHA256:             windowsManagedPolicyDigest(fixture.foreign),
		ConfigOriginalSecurityDescriptor: windowsCursorTestTrustedSDDL,
		ConfigOriginalAttributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := windowsCursorManagedStateBody(windowsCursorManagedPolicyState{
		SchemaVersion:      1,
		HookExecutable:     hookExecutable,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
		AdapterSHA256:      windowsManagedPolicyDigest(adapter),
		ReceiptSHA256:      windowsManagedPolicyDigest(receipt),
		Targets: []WindowsCursorManagedRuntimeTarget{{
			SID: "S-1-5-21-1000-1000-1000-1001", DataDir: `C:\Users\developer\.defenseclaw`,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata := windowsCursorManagedFileMetadata{
		securityDescriptor: windowsCursorTestTrustedSDDL,
		attributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
	}
	fixture.artifacts = windowsCursorManagedArtifacts{
		root:            root,
		hooks:           windowsManagedFileSnapshot{path: paths.Hooks},
		adapter:         windowsManagedFileSnapshot{path: paths.Adapter, existed: true, data: adapter},
		adapterMetadata: metadata,
		state:           windowsManagedFileSnapshot{path: paths.State, existed: true, data: state},
		stateMetadata:   metadata,
		receipt:         windowsManagedFileSnapshot{path: paths.Receipt, existed: true, data: receipt},
		receiptMetadata: windowsCursorManagedFileMetadata{
			securityDescriptor: windowsCursorTestPrivateSDDL,
			attributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
		},
	}
	if body := hooksBody(fixture.foreign, paths.Adapter); body != nil {
		if err := os.WriteFile(paths.Hooks, body, 0o600); err != nil {
			t.Fatal(err)
		}
		fixture.artifacts.hooks.existed = true
		fixture.artifacts.hooks.data = body
		fixture.artifacts.hooksMetadata = metadata
	}
	return fixture
}

func assertWindowsCursorHooksRepaired(t *testing.T, fixture *windowsCursorHooksRepairFixture, repaired windowsCursorManagedArtifacts) {
	t.Helper()
	if !repaired.active {
		t.Fatal("repaired Cursor policy is not active")
	}
	if fixture.writes != 1 {
		t.Fatalf("hooks.json repair writes = %d, want 1", fixture.writes)
	}
	onDisk, err := os.ReadFile(fixture.artifacts.hooks.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, repaired.hooks.data) {
		t.Fatal("repaired artifacts do not carry the hooks.json image written to disk")
	}
	if err := connector.VerifyWindowsCursorEnterpriseHooks(onDisk, fixture.artifacts.adapter.path, "closed"); err != nil {
		t.Fatalf("re-merged hooks.json does not verify: %v", err)
	}
}

func TestWindowsCursorHooksRepairReMergesRemovedEntriesKeepingUserEntries(t *testing.T) {
	fixture := newWindowsCursorHooksRepairFixture(t, func(foreign []byte, _ string) []byte {
		// An operator or tool rewrote hooks.json with only its own entries.
		return append([]byte(nil), foreign...)
	})

	// Plain validation reports repairable drift and never writes.
	if _, err := validateWindowsCursorManagedArtifacts(fixture.artifacts); !windowsCursorManagedHooksDrifted(err) {
		t.Fatalf("validate drifted Cursor hooks = %v, want repairable drift", err)
	}
	if fixture.writes != 0 {
		t.Fatal("plain validation wrote hooks.json")
	}

	repaired, err := validateWindowsCursorManagedArtifactsRepairingHooks(fixture.artifacts)
	if err != nil {
		t.Fatalf("repair removed Cursor DefenseClaw entries: %v", err)
	}
	assertWindowsCursorHooksRepaired(t, fixture, repaired)
	for _, foreignCommand := range []string{"operator-shell-hook", "operator-hook"} {
		if !bytes.Contains(repaired.hooks.data, []byte(foreignCommand)) {
			t.Fatalf("re-merge dropped the user's %q entry: %s", foreignCommand, repaired.hooks.data)
		}
	}
	remainder, err := connector.RemoveWindowsCursorEnterpriseHooks(repaired.hooks.data, fixture.artifacts.adapter.path)
	if err != nil {
		t.Fatal(err)
	}
	if !connector.WindowsCursorEnterpriseHooksOwnedRemainderEqual(remainder, fixture.foreign) {
		t.Fatalf("re-merge changed the user's own hooks: %s", remainder)
	}
}

func TestWindowsCursorHooksRepairReplacesAlteredEntries(t *testing.T) {
	fixture := newWindowsCursorHooksRepairFixture(t, func(foreign []byte, adapterPath string) []byte {
		merged, err := connector.MergeWindowsCursorEnterpriseHooks(foreign, adapterPath, "closed")
		if err != nil {
			t.Fatal(err)
		}
		// Flip DefenseClaw's fail-closed flag so its entries no longer match.
		altered := bytes.ReplaceAll(merged, []byte(`"failClosed": true`), []byte(`"failClosed": false`))
		if bytes.Equal(altered, merged) {
			t.Fatalf("fixture could not alter the DefenseClaw entries: %s", merged)
		}
		return altered
	})
	repaired, err := validateWindowsCursorManagedArtifactsRepairingHooks(fixture.artifacts)
	if err != nil {
		t.Fatalf("repair altered Cursor DefenseClaw entries: %v", err)
	}
	assertWindowsCursorHooksRepaired(t, fixture, repaired)
	if !bytes.Contains(repaired.hooks.data, []byte("operator-hook")) {
		t.Fatalf("re-merge dropped the user's entry: %s", repaired.hooks.data)
	}
}

func TestWindowsCursorHooksRepairRecreatesDeletedHooksFile(t *testing.T) {
	fixture := newWindowsCursorHooksRepairFixture(t, func([]byte, string) []byte { return nil })
	repaired, err := validateWindowsCursorManagedArtifactsRepairingHooks(fixture.artifacts)
	if err != nil {
		t.Fatalf("recreate deleted Cursor hooks.json: %v", err)
	}
	assertWindowsCursorHooksRepaired(t, fixture, repaired)
	if !repaired.hooks.existed || repaired.hooksMetadata.securityDescriptor == "" {
		t.Fatalf("recreated hooks.json snapshot is incomplete: existed=%t", repaired.hooks.existed)
	}
}

// An edit made to hooks.json after the snapshot is never overwritten: the
// repair refuses and the next guardian tick retries from a fresh snapshot.
func TestWindowsCursorHooksRepairRefusesConcurrentEdit(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	for name, body := range map[string]func([]byte, string) []byte{
		"edited":  func(foreign []byte, _ string) []byte { return append([]byte(nil), foreign...) },
		"created": func([]byte, string) []byte { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newWindowsCursorHooksRepairFixture(t, body)
			concurrent := []byte(`{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"edited-after-snapshot"}]}}`)
			if err := os.WriteFile(fixture.artifacts.hooks.path, concurrent, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := validateWindowsCursorManagedArtifactsRepairingHooks(fixture.artifacts)
			if err == nil || !strings.Contains(err.Error(), "changed concurrently before repair") {
				t.Fatalf("repair over a concurrent edit = %v, want the concurrent-change refusal", err)
			}
			if fixture.writes != 0 {
				t.Fatal("repair overwrote a concurrent hooks.json edit")
			}
			onDisk, err := os.ReadFile(fixture.artifacts.hooks.path)
			if err != nil || !bytes.Equal(onDisk, concurrent) {
				t.Fatalf("hooks.json on disk = %q, %v; want the concurrent edit kept", onDisk, err)
			}
		})
	}
}

func TestWindowsCursorHooksRepairRefusedInStrictMode(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	for name, body := range map[string]func([]byte, string) []byte{
		"entries removed": func(foreign []byte, _ string) []byte { return append([]byte(nil), foreign...) },
		"file deleted":    func([]byte, string) []byte { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newWindowsCursorHooksRepairFixture(t, body)
			before, readErr := os.ReadFile(fixture.artifacts.hooks.path)
			_, err := validateWindowsCursorManagedArtifactsRepairingHooks(fixture.artifacts)
			if err == nil || !strings.Contains(err.Error(), "verify Cursor enterprise hooks") {
				t.Fatalf("strict-mode Cursor hooks drift = %v, want verification error", err)
			}
			if fixture.writes != 0 {
				t.Fatal("strict mode rewrote hooks.json")
			}
			after, afterErr := os.ReadFile(fixture.artifacts.hooks.path)
			if !bytes.Equal(before, after) || (readErr == nil) != (afterErr == nil) ||
				(readErr != nil && !errors.Is(afterErr, os.ErrNotExist)) {
				t.Fatal("strict mode changed hooks.json on disk")
			}
		})
	}
}

func TestWindowsCursorHooksRepairRequiresIntactReceipt(t *testing.T) {
	fixture := newWindowsCursorHooksRepairFixture(t, func(foreign []byte, _ string) []byte {
		return append([]byte(nil), foreign...)
	})
	fixture.artifacts.receipt.data = []byte(`{"schema_version":1}`)
	if _, err := validateWindowsCursorManagedArtifactsRepairingHooks(fixture.artifacts); err == nil ||
		windowsCursorManagedHooksDrifted(err) {
		t.Fatalf("drift over a changed rollback receipt = %v, want a non-repairable identity error", err)
	}
	if fixture.writes != 0 {
		t.Fatal("hooks.json was rewritten over a changed rollback receipt")
	}
}
