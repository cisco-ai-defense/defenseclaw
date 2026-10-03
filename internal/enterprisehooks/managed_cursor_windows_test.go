// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

func TestWindowsCursorTransactionLockRetiresOnlyWithoutManagedArtifacts(t *testing.T) {
	adapterPath := `C:\ProgramData\Cursor\defenseclaw-hook.ps1`
	foreignHooks := []byte(`{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"operator-hook"}]}}`)
	managedHooks, err := connector.MergeWindowsCursorEnterpriseHooks(
		foreignHooks,
		adapterPath,
		"closed",
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		artifacts  windowsCursorManagedArtifacts
		wantRetire bool
	}{
		"completely absent": {
			artifacts: windowsCursorManagedArtifacts{
				adapter: windowsManagedFileSnapshot{path: adapterPath},
			},
			wantRetire: true,
		},
		"foreign hooks only": {
			artifacts: windowsCursorManagedArtifacts{
				hooks:   windowsManagedFileSnapshot{existed: true, data: foreignHooks},
				adapter: windowsManagedFileSnapshot{path: adapterPath},
			},
			wantRetire: true,
		},
		"owned hook remains": {
			artifacts: windowsCursorManagedArtifacts{
				hooks:   windowsManagedFileSnapshot{existed: true, data: managedHooks},
				adapter: windowsManagedFileSnapshot{path: adapterPath},
			},
		},
		"adapter tombstone remains": {
			artifacts: windowsCursorManagedArtifacts{
				adapter: windowsManagedFileSnapshot{
					path: adapterPath, existed: true, data: windowsCursorManagedTombstone(),
				},
			},
		},
		"private receipt remains": {
			artifacts: windowsCursorManagedArtifacts{
				adapter: windowsManagedFileSnapshot{path: adapterPath},
				receipt: windowsManagedFileSnapshot{existed: true},
			},
		},
		"public state remains": {
			artifacts: windowsCursorManagedArtifacts{
				adapter: windowsManagedFileSnapshot{path: adapterPath},
				state:   windowsManagedFileSnapshot{existed: true},
			},
		},
		"malformed config is ambiguous": {
			artifacts: windowsCursorManagedArtifacts{
				hooks:   windowsManagedFileSnapshot{existed: true, data: []byte(`{"hooks":`)},
				adapter: windowsManagedFileSnapshot{path: adapterPath},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := windowsCursorManagedLockCanRetire(test.artifacts); got != test.wantRetire {
				t.Fatalf("windowsCursorManagedLockCanRetire = %t, want %t", got, test.wantRetire)
			}
		})
	}

	lockPath := filepath.Join(t.TempDir(), windowsCursorManagedLockFile)
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := retireWindowsCursorManagedLock(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := retireWindowsCursorManagedLock(lockPath); err != nil {
		t.Fatalf("idempotent Cursor lock retirement: %v", err)
	}
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired Cursor lock still exists: %v", err)
	}
}

const (
	windowsCursorTestTrustedSDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)"
	windowsCursorTestPrivateSDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

func TestWindowsCursorInactiveSnapshotPreservesForeignEnterpriseConfig(t *testing.T) {
	foreign := []byte(`{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"operator-hook"}]}}`)
	snapshot := WindowsCursorManagedPolicyTeardownSnapshot{
		HooksExisted:            true,
		Hooks:                   foreign,
		HooksSecurityDescriptor: windowsCursorTestTrustedSDDL,
		HooksAttributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
	}
	if err := validateWindowsCursorManagedTeardownSnapshot(
		WindowsCursorManagedPolicyTeardownOptions{},
		snapshot,
	); err != nil {
		t.Fatalf("inactive foreign Cursor config snapshot rejected: %v", err)
	}

	artifacts := windowsCursorManagedArtifacts{
		hooks: windowsManagedFileSnapshot{existed: true, data: foreign},
		hooksMetadata: windowsCursorManagedFileMetadata{
			securityDescriptor: windowsCursorTestTrustedSDDL,
			attributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
		},
	}
	captured := windowsCursorManagedTeardownSnapshot(artifacts)
	if captured.PolicyActive || !captured.HooksExisted ||
		!bytes.Equal(captured.Hooks, foreign) ||
		captured.HooksSecurityDescriptor != windowsCursorTestTrustedSDDL ||
		captured.HooksAttributes != windows.FILE_ATTRIBUTE_ARCHIVE {
		t.Fatalf("inactive Cursor snapshot lost foreign config or metadata: %+v", captured)
	}
}

func TestWindowsCursorSnapshotRejectsContradictoryOwnership(t *testing.T) {
	metadata := windowsCursorTestTrustedSDDL
	for name, snapshot := range map[string]WindowsCursorManagedPolicyTeardownSnapshot{
		"active without state": {
			PolicyActive:              true,
			HooksExisted:              true,
			HooksSecurityDescriptor:   metadata,
			HooksAttributes:           windows.FILE_ATTRIBUTE_ARCHIVE,
			AdapterExisted:            true,
			AdapterSecurityDescriptor: metadata,
			AdapterAttributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
		},
		"absent hooks with metadata": {
			HooksSecurityDescriptor: metadata,
			HooksAttributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
		},
		"inactive with state": {
			StateExisted:            true,
			State:                   []byte(`{}`),
			StateSecurityDescriptor: metadata,
			StateAttributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateWindowsCursorManagedTeardownSnapshot(
				WindowsCursorManagedPolicyTeardownOptions{},
				snapshot,
			); err == nil {
				t.Fatal("contradictory Cursor snapshot was accepted")
			}
		})
	}
}

func TestWindowsCursorPublicStateExcludesRollbackPreimage(t *testing.T) {
	secretMarker := []byte("administrator-only-foreign-hook")
	receiptBody, err := windowsCursorManagedReceiptBody(windowsCursorManagedPolicyReceipt{
		SchemaVersion:                    1,
		ConfigPreexisting:                true,
		ConfigOriginal:                   secretMarker,
		ConfigOriginalSHA256:             windowsManagedPolicyDigest(secretMarker),
		ConfigOriginalSecurityDescriptor: windowsCursorTestTrustedSDDL,
		ConfigOriginalAttributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
	})
	if err != nil {
		t.Fatal(err)
	}
	stateBody, err := windowsCursorManagedStateBody(windowsCursorManagedPolicyState{
		SchemaVersion:      1,
		HookExecutable:     `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
		AdapterSHA256:      strings.Repeat("a", 64),
		ReceiptSHA256:      windowsManagedPolicyDigest(receiptBody),
		Targets: []WindowsCursorManagedRuntimeTarget{{
			SID: "S-1-5-21-1000-1000-1000-1001", DataDir: `C:\Users\developer\.defenseclaw`,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	encodedMarker := []byte(base64.StdEncoding.EncodeToString(secretMarker))
	if bytes.Contains(stateBody, secretMarker) || bytes.Contains(stateBody, encodedMarker) ||
		!bytes.Contains(receiptBody, encodedMarker) {
		t.Fatal("Cursor rollback preimage crossed into the user-readable SID registry")
	}
}

func TestWindowsCursorPrivateReceiptMetadataRejectsUserReadAccess(t *testing.T) {
	if err := validateWindowsCursorPrivateReceiptMetadata(windowsCursorManagedFileMetadata{
		securityDescriptor: windowsCursorTestPrivateSDDL,
		attributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
	}); err != nil {
		t.Fatalf("private Cursor receipt ACL rejected: %v", err)
	}
	if err := validateWindowsCursorPrivateReceiptMetadata(windowsCursorManagedFileMetadata{
		securityDescriptor: windowsCursorTestTrustedSDDL,
		attributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
	}); err == nil {
		t.Fatal("user-readable Cursor receipt ACL was accepted")
	}
}

func TestWindowsCursorPublicArtifactsAcceptBoundReceiptDigest(t *testing.T) {
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
	hooksPath := cursorPaths.Hooks
	adapterPath := cursorPaths.Adapter
	statePath := cursorPaths.State
	hooks, err := connector.MergeWindowsCursorEnterpriseHooks(nil, adapterPath, "closed")
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
	})
	if err != nil {
		t.Fatal(err)
	}
	validated, err := validateWindowsCursorManagedPublicArtifacts(windowsCursorManagedArtifacts{
		hooks:   windowsManagedFileSnapshot{path: hooksPath, existed: true, data: hooks},
		adapter: windowsManagedFileSnapshot{path: adapterPath, existed: true, data: adapter},
		state:   windowsManagedFileSnapshot{path: statePath, existed: true, data: state},
	})
	if err != nil || !validated.active {
		t.Fatalf("public Cursor artifacts rejected a bound receipt digest: active=%t err=%v", validated.active, err)
	}
}

func TestWindowsCursorLifecycleRestoreAcceptsExactActivationPrefixes(t *testing.T) {
	originalTrust := windowsManagedPolicyFileTrustCheck
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	t.Cleanup(func() { windowsManagedPolicyFileTrustCheck = originalTrust })

	hooksPath := `C:\ProgramData\Cursor\hooks.json`
	adapterPath := `C:\ProgramData\Cursor\defenseclaw-hook.ps1`
	statePath := `C:\ProgramData\Cursor\.defenseclaw-managed-hooks.state`
	receiptPath := `C:\ProgramData\Cursor\.defenseclaw-managed-hooks.receipt`
	hookExecutable := `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`
	foreignHooks := []byte(`{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"operator-hook"}]}}`)
	metadata := windowsCursorManagedFileMetadata{
		securityDescriptor: windowsCursorTestTrustedSDDL,
		attributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
	}
	privateMetadata := windowsCursorManagedFileMetadata{
		securityDescriptor: windowsCursorTestPrivateSDDL,
		attributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
	}
	snapshot := WindowsCursorManagedPolicyTeardownSnapshot{
		HooksExisted:            true,
		Hooks:                   foreignHooks,
		HooksSecurityDescriptor: metadata.securityDescriptor,
		HooksAttributes:         metadata.attributes,
	}
	target := WindowsCursorManagedRuntimeTarget{
		SID:     "S-1-5-21-1000-1000-1000-1001",
		DataDir: `C:\Users\developer\.defenseclaw`,
	}
	allowed := WindowsCursorManagedPolicyTeardownOptions{
		HookExecutable:     hookExecutable,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
		Targets:            []WindowsCursorManagedRuntimeTarget{target},
	}
	adapter, err := connector.RenderWindowsCursorEnterpriseAdapter(hookExecutable, "closed")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := windowsCursorManagedReceiptBody(windowsCursorManagedPolicyReceipt{
		SchemaVersion:                    1,
		ConfigPreexisting:                true,
		ConfigOriginal:                   foreignHooks,
		ConfigOriginalSHA256:             windowsManagedPolicyDigest(foreignHooks),
		ConfigOriginalSecurityDescriptor: metadata.securityDescriptor,
		ConfigOriginalAttributes:         metadata.attributes,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := windowsCursorManagedStateBody(windowsCursorManagedPolicyState{
		SchemaVersion:      1,
		HookExecutable:     hookExecutable,
		GatewayAddr:        allowed.GatewayAddr,
		GatewayServiceName: allowed.GatewayServiceName,
		AdapterSHA256:      windowsManagedPolicyDigest(adapter),
		ReceiptSHA256:      windowsManagedPolicyDigest(receipt),
		Targets:            []WindowsCursorManagedRuntimeTarget{target},
	})
	if err != nil {
		t.Fatal(err)
	}
	activeHooks, err := connector.MergeWindowsCursorEnterpriseHooks(foreignHooks, adapterPath, "closed")
	if err != nil {
		t.Fatal(err)
	}
	base := windowsCursorManagedArtifacts{
		hooks:         windowsManagedFileSnapshot{path: hooksPath, existed: true, data: foreignHooks},
		hooksMetadata: metadata,
		adapter:       windowsManagedFileSnapshot{path: adapterPath},
		state:         windowsManagedFileSnapshot{path: statePath},
		receipt:       windowsManagedFileSnapshot{path: receiptPath},
	}
	for name, mutate := range map[string]func(*windowsCursorManagedArtifacts){
		"unchanged inactive preimage": func(*windowsCursorManagedArtifacts) {},
		"adapter": func(value *windowsCursorManagedArtifacts) {
			value.adapter.existed, value.adapter.data = true, adapter
		},
		"adapter and receipt": func(value *windowsCursorManagedArtifacts) {
			value.adapter.existed, value.adapter.data = true, adapter
			value.receipt.existed, value.receipt.data = true, receipt
			value.receiptMetadata = privateMetadata
		},
		"adapter receipt and state": func(value *windowsCursorManagedArtifacts) {
			value.adapter.existed, value.adapter.data = true, adapter
			value.receipt.existed, value.receipt.data = true, receipt
			value.receiptMetadata = privateMetadata
			value.state.existed, value.state.data = true, state
		},
		"fully active": func(value *windowsCursorManagedArtifacts) {
			value.hooks.data = activeHooks
			value.adapter.existed, value.adapter.data = true, adapter
			value.receipt.existed, value.receipt.data = true, receipt
			value.receiptMetadata = privateMetadata
			value.state.existed, value.state.data = true, state
		},
	} {
		t.Run(name, func(t *testing.T) {
			current := base
			mutate(&current)
			if err := validateWindowsCursorLifecycleRestoreSource(
				current,
				allowed,
				WindowsCursorManagedPolicyTeardownOptions{},
				snapshot,
			); err != nil {
				t.Fatalf("valid Cursor activation prefix rejected: %v", err)
			}
		})
	}

	badAdapter := base
	badAdapter.adapter.existed = true
	badAdapter.adapter.data = []byte("foreign adapter")
	if err := validateWindowsCursorLifecycleRestoreSource(
		badAdapter,
		allowed,
		WindowsCursorManagedPolicyTeardownOptions{},
		snapshot,
	); err == nil {
		t.Fatal("foreign partial Cursor adapter was accepted")
	}
	stateWithoutReceipt := base
	stateWithoutReceipt.adapter.existed, stateWithoutReceipt.adapter.data = true, adapter
	stateWithoutReceipt.state.existed, stateWithoutReceipt.state.data = true, state
	if err := validateWindowsCursorLifecycleRestoreSource(
		stateWithoutReceipt,
		allowed,
		WindowsCursorManagedPolicyTeardownOptions{},
		snapshot,
	); err == nil {
		t.Fatal("partial Cursor state without its private receipt was accepted")
	}
	changedInactive := base
	changedInactive.adapter.existed = true
	changedInactive.adapter.data = windowsCursorManagedTombstone()
	if err := validateWindowsCursorLifecycleRestoreSource(
		changedInactive,
		allowed,
		WindowsCursorManagedPolicyTeardownOptions{},
		snapshot,
	); err == nil {
		t.Fatal("inactive Cursor state outside the exact journaled preimage was accepted")
	}
}

func TestWindowsCursorTeardownRestoreAcceptsOnlyReceiptOriginalMetadata(t *testing.T) {
	adapterPath := `C:\ProgramData\Cursor\defenseclaw-hook.ps1`
	originalHooks := []byte(`{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"operator-hook"}]}}`)
	activeHooks, err := connector.MergeWindowsCursorEnterpriseHooks(originalHooks, adapterPath, "closed")
	if err != nil {
		t.Fatal(err)
	}
	originalMetadata := windowsCursorManagedFileMetadata{
		securityDescriptor: windowsCursorTestTrustedSDDL,
		attributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
	}
	receipt, err := windowsCursorManagedReceiptBody(windowsCursorManagedPolicyReceipt{
		SchemaVersion:                    1,
		ConfigPreexisting:                true,
		ConfigOriginal:                   originalHooks,
		ConfigOriginalSHA256:             windowsManagedPolicyDigest(originalHooks),
		ConfigOriginalSecurityDescriptor: originalMetadata.securityDescriptor,
		ConfigOriginalAttributes:         originalMetadata.attributes,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := WindowsCursorManagedPolicyTeardownSnapshot{
		PolicyActive:            true,
		HooksExisted:            true,
		Hooks:                   activeHooks,
		HooksSecurityDescriptor: "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)(A;;GR;;;AU)",
		HooksAttributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
		ReceiptExisted:          true,
		Receipt:                 receipt,
	}
	current := windowsCursorManagedArtifacts{
		hooks: windowsManagedFileSnapshot{
			path:    `C:\ProgramData\Cursor\hooks.json`,
			existed: true,
			data:    originalHooks,
		},
		hooksMetadata: originalMetadata,
	}
	if err := windowsCursorRestoreHooksCompatible(current, snapshot, adapterPath, true); err != nil {
		t.Fatalf("exact receipt-original Cursor ACL was rejected: %v", err)
	}
	if err := windowsCursorRestoreHooksCompatible(current, snapshot, adapterPath, false); err == nil {
		t.Fatal("lifecycle restore accepted a teardown-only ACL transition")
	}
	current.hooksMetadata.securityDescriptor = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if err := windowsCursorRestoreHooksCompatible(current, snapshot, adapterPath, true); err == nil {
		t.Fatal("foreign Cursor ACL was accepted as the receipt original")
	}
}

func TestWindowsCursorLifecycleRecognizesExactJournaledSnapshot(t *testing.T) {
	metadata := windowsCursorManagedFileMetadata{
		securityDescriptor: windowsCursorTestTrustedSDDL,
		attributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
	}
	artifacts := windowsCursorManagedArtifacts{
		hooks:           windowsManagedFileSnapshot{path: `C:\ProgramData\Cursor\hooks.json`, existed: true, data: []byte("hooks")},
		hooksMetadata:   metadata,
		adapter:         windowsManagedFileSnapshot{path: `C:\ProgramData\Cursor\defenseclaw-hook.ps1`, existed: true, data: []byte("adapter")},
		adapterMetadata: metadata,
		state:           windowsManagedFileSnapshot{path: `C:\ProgramData\Cursor\.defenseclaw-managed-hooks.state`, existed: true, data: []byte("state")},
		stateMetadata:   metadata,
		receipt:         windowsManagedFileSnapshot{path: `C:\ProgramData\Cursor\.defenseclaw-managed-hooks.receipt`, existed: true, data: []byte("receipt")},
		receiptMetadata: metadata,
		active:          true,
	}
	snapshot := windowsCursorManagedTeardownSnapshot(artifacts)
	if !windowsCursorManagedArtifactsMatchSnapshot(artifacts, snapshot) {
		t.Fatal("exact prior Cursor snapshot was not recognized")
	}
	artifacts.stateMetadata.securityDescriptor = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if windowsCursorManagedArtifactsMatchSnapshot(artifacts, snapshot) {
		t.Fatal("Cursor snapshot match ignored an ACL change")
	}
}

// An upgrade must snapshot and restore the Cursor adapter an earlier release
// installed: the adapter template changes between releases, so the recorded
// adapter no longer equals the current render (GAP-1068). A body that differs
// from the recorded digest, or that does not name the recorded hook
// executable, is still refused.
func TestWindowsCursorManagedStateAcceptsAnEarlierReleaseAdapter(t *testing.T) {
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
	current, err := connector.RenderWindowsCursorEnterpriseAdapter(hookExecutable, "closed")
	if err != nil {
		t.Fatal(err)
	}
	earlier := append([]byte("# adapter template of an earlier release\r\n"), current...)
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	artifactsFor := func(adapter []byte, recorded string) windowsCursorManagedArtifacts {
		t.Helper()
		state, err := windowsCursorManagedStateBody(windowsCursorManagedPolicyState{
			SchemaVersion:      1,
			HookExecutable:     hookExecutable,
			GatewayAddr:        "127.0.0.1:18970",
			GatewayServiceName: "DefenseClawGateway",
			AdapterSHA256:      recorded,
			ReceiptSHA256:      windowsManagedPolicyDigest([]byte("private receipt")),
			Targets: []WindowsCursorManagedRuntimeTarget{{
				SID: "S-1-5-21-1000-1000-1000-1001", DataDir: `C:\Users\developer\.defenseclaw`,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return windowsCursorManagedArtifacts{
			adapter: windowsManagedFileSnapshot{path: paths.Adapter, existed: true, data: adapter},
			state:   windowsManagedFileSnapshot{path: paths.State, existed: true, data: state},
		}
	}
	for name, adapter := range map[string][]byte{"current": current, "earlier release": earlier} {
		if _, err := validateWindowsCursorManagedStateIdentity(artifactsFor(adapter, windowsManagedPolicyDigest(adapter))); err != nil {
			t.Fatalf("%s adapter rejected: %v", name, err)
		}
	}
	if _, err := validateWindowsCursorManagedStateIdentity(artifactsFor(earlier, windowsManagedPolicyDigest(current))); err == nil {
		t.Fatal("an adapter that differs from the recorded digest was accepted")
	}
	other := bytes.ReplaceAll(current, []byte(hookExecutable), []byte(`C:\Users\Public\hook.exe`))
	if _, err := validateWindowsCursorManagedStateIdentity(artifactsFor(other, windowsManagedPolicyDigest(other))); err == nil {
		t.Fatal("an adapter that does not run the recorded hook executable was accepted")
	}
}

// GAP-2467: an upgrade rewrites an earlier release's adapter to this build's
// template and rebinds the state digest, so the pair stays valid; a current
// adapter, an inactive policy and another deployment's hook are left alone.
func TestWindowsCursorManagedAdapterRefreshRewritesAnEarlierReleaseAdapter(t *testing.T) {
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
	current, err := connector.RenderWindowsCursorEnterpriseAdapter(hookExecutable, "closed")
	if err != nil {
		t.Fatal(err)
	}
	earlier := append([]byte("# adapter template of an earlier release\r\n"), current...)
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	artifactsFor := func(adapter []byte) windowsCursorManagedArtifacts {
		t.Helper()
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
		artifacts, err := validateWindowsCursorManagedStateIdentity(windowsCursorManagedArtifacts{
			adapter: windowsManagedFileSnapshot{path: paths.Adapter, existed: true, data: adapter},
			state:   windowsManagedFileSnapshot{path: paths.State, existed: true, data: state},
		})
		if err != nil {
			t.Fatal(err)
		}
		artifacts.active = true
		return artifacts
	}

	stale := artifactsFor(earlier)
	adapter, state, ok, err := windowsCursorManagedAdapterRefresh(stale, hookExecutable)
	if err != nil || !ok {
		t.Fatalf("an earlier release's adapter was not refreshed: ok=%t err=%v", ok, err)
	}
	if !bytes.Equal(adapter, current) {
		t.Fatal("the refreshed adapter is not this build's render")
	}
	refreshed, err := validateWindowsCursorManagedStateIdentity(windowsCursorManagedArtifacts{
		adapter: windowsManagedFileSnapshot{path: paths.Adapter, existed: true, data: adapter},
		state:   windowsManagedFileSnapshot{path: paths.State, existed: true, data: state},
	})
	if err != nil {
		t.Fatalf("the refreshed adapter and state do not validate: %v", err)
	}
	if refreshed.parsed.ReceiptSHA256 != stale.parsed.ReceiptSHA256 ||
		len(refreshed.parsed.Targets) != 1 || refreshed.parsed.Targets[0] != stale.parsed.Targets[0] {
		t.Fatalf("the refresh changed more than the adapter digest: %+v", refreshed.parsed)
	}

	if _, _, ok, err := windowsCursorManagedAdapterRefresh(artifactsFor(current), hookExecutable); ok || err != nil {
		t.Fatalf("a current adapter was rewritten: ok=%t err=%v", ok, err)
	}
	inactive := stale
	inactive.active = false
	if _, _, ok, err := windowsCursorManagedAdapterRefresh(inactive, hookExecutable); ok || err != nil {
		t.Fatalf("an inactive policy was rewritten: ok=%t err=%v", ok, err)
	}
	if _, _, ok, err := windowsCursorManagedAdapterRefresh(stale, `C:\Other\defenseclaw-hook.exe`); ok || err != nil {
		t.Fatalf("another deployment's adapter was rewritten: ok=%t err=%v", ok, err)
	}
}

// GAP-2474: an adapter changed in place gets this build's render back, with
// the state digest rebound and nothing else changed; a state DefenseClaw did
// not write, or one for another hook executable, is refused.
func TestWindowsCursorManagedAdapterDriftCandidateRestoresAChangedAdapter(t *testing.T) {
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
	current, err := connector.RenderWindowsCursorEnterpriseAdapter(hookExecutable, "closed")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	policy := windowsCursorManagedPolicyState{
		SchemaVersion:      1,
		HookExecutable:     hookExecutable,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
		ReceiptSHA256:      windowsManagedPolicyDigest([]byte("private receipt")),
		Targets: []WindowsCursorManagedRuntimeTarget{{
			SID: "S-1-5-21-1000-1000-1000-1001", DataDir: `C:\Users\developer\.defenseclaw`,
		}},
	}
	changed := []byte("# an administrator's edit\r\n")
	artifactsFor := func(recorded []byte) windowsCursorManagedArtifacts {
		t.Helper()
		state := policy
		state.AdapterSHA256 = windowsManagedPolicyDigest(recorded)
		body, err := windowsCursorManagedStateBody(state)
		if err != nil {
			t.Fatal(err)
		}
		return windowsCursorManagedArtifacts{
			adapter: windowsManagedFileSnapshot{path: paths.Adapter, existed: true, data: changed},
			state:   windowsManagedFileSnapshot{path: paths.State, existed: true, data: body},
		}
	}

	earlier := append([]byte("# adapter template of an earlier release\r\n"), current...)
	for name, recorded := range map[string][]byte{"this release": current, "an earlier release": earlier} {
		drifted := artifactsFor(recorded)
		if _, err := validateWindowsCursorManagedStateIdentity(drifted); err == nil {
			t.Fatalf("%s: a changed adapter passed the strict identity check", name)
		}
		candidate, err := windowsCursorManagedAdapterDriftCandidate(drifted, hookExecutable)
		if err != nil {
			t.Fatalf("%s: a changed adapter was not restored: %v", name, err)
		}
		if !bytes.Equal(candidate.adapter.data, current) {
			t.Fatalf("%s: the restored adapter is not this build's render", name)
		}
		restored, err := validateWindowsCursorManagedStateIdentity(candidate)
		if err != nil {
			t.Fatalf("%s: the restored adapter and state do not validate: %v", name, err)
		}
		if restored.parsed.ReceiptSHA256 != policy.ReceiptSHA256 ||
			len(restored.parsed.Targets) != 1 || restored.parsed.Targets[0] != policy.Targets[0] {
			t.Fatalf("%s: the restore changed more than the adapter digest: %+v", name, restored.parsed)
		}
	}

	if _, err := windowsCursorManagedAdapterDriftCandidate(artifactsFor(current), `C:\Other\defenseclaw-hook.exe`); err == nil {
		t.Fatal("another deployment's adapter was restored")
	}
	reformatted := artifactsFor(current)
	reformatted.state.data = bytes.ReplaceAll(reformatted.state.data, []byte("\n  "), []byte("\n "))
	if _, err := windowsCursorManagedAdapterDriftCandidate(reformatted, hookExecutable); err == nil {
		t.Fatal("a state DefenseClaw did not write was accepted")
	}
	missing := artifactsFor(current)
	missing.adapter.existed = false
	if _, err := windowsCursorManagedAdapterDriftCandidate(missing, hookExecutable); err == nil {
		t.Fatal("a missing adapter was accepted")
	}
}

// GAP-1567: the purge removes the allow-only tombstone the default uninstall
// keeps in ProgramData\Cursor, and only that exact file.
func TestPurgeWindowsCursorManagedTombstoneRemovesOnlyTheTombstone(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Cursor")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	originalRoot := windowsCursorManagedRootResolver
	windowsCursorManagedRootResolver = func() (string, error) { return root, nil }
	t.Cleanup(func() { windowsCursorManagedRootResolver = originalRoot })
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, body []byte) {
		t.Helper()
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := purgeWindowsCursorManagedTombstoneUnlocked(); err != nil {
		t.Fatalf("purge with nothing there: %v", err)
	}
	write(paths.Adapter, windowsCursorManagedTombstone())
	if err := purgeWindowsCursorManagedTombstoneUnlocked(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(paths.Adapter); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the tombstone stayed: %v", err)
	}

	write(paths.Adapter, []byte("# an administrator's own Cursor hook\r\n"))
	if err := purgeWindowsCursorManagedTombstoneUnlocked(); err == nil {
		t.Fatal("a file that is not the tombstone was accepted")
	}
	if _, err := os.Stat(paths.Adapter); err != nil {
		t.Fatalf("a file that is not the tombstone was removed: %v", err)
	}

	write(paths.Adapter, windowsCursorManagedTombstone())
	write(paths.State, []byte("{}"))
	if err := purgeWindowsCursorManagedTombstoneUnlocked(); err == nil {
		t.Fatal("the tombstone was removed while managed ownership state remains")
	}
	if _, err := os.Stat(paths.Adapter); err != nil {
		t.Fatalf("the tombstone was removed while managed ownership state remains: %v", err)
	}
}
