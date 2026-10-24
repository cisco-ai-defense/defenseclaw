// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

func TestCanonicalWindowsCursorManagedTargetsAcceptsEntraID(t *testing.T) {
	const entraSID = "S-1-12-1-1111111111-2222222222-3333333333-4000000000"
	dataDir := filepath.Clean(`C:\Users\entra-user\.defenseclaw`)
	targets, err := canonicalWindowsCursorManagedTargets([]WindowsCursorManagedRuntimeTarget{{
		SID: entraSID, DataDir: dataDir,
	}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].SID != entraSID || targets[0].DataDir != dataDir {
		t.Fatalf("Cursor targets = %+v, want Microsoft Entra ID target", targets)
	}
}

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

func TestWindowsCursorActiveEmptySnapshotRestoresClosedGuard(t *testing.T) {
	previousRoot, previousOwner := windowsCursorManagedRootResolver, windowsManagedPolicyOwnerSID
	root := filepath.Join(t.TempDir(), "Cursor")
	windowsCursorManagedRootResolver = func() (string, error) { return root, nil }
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) {
		return windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	}
	t.Cleanup(func() {
		windowsCursorManagedRootResolver, windowsManagedPolicyOwnerSID = previousRoot, previousOwner
	})
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	opts := WindowsCursorManagedPolicyTeardownOptions{
		HookExecutable:     `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
	}
	adapter, err := connector.RenderWindowsCursorEnterpriseAdapter(opts.HookExecutable, "closed")
	if err != nil {
		t.Fatal(err)
	}
	hooks, err := connector.MergeWindowsCursorEnterpriseHooks([]byte("{}\n"), paths.Adapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := windowsCursorManagedReceiptBody(windowsCursorManagedPolicyReceipt{SchemaVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	state := windowsCursorManagedPolicyState{
		SchemaVersion:      1,
		HookExecutable:     opts.HookExecutable,
		GatewayAddr:        opts.GatewayAddr,
		GatewayServiceName: opts.GatewayServiceName,
		HookFailMode:       "closed",
		AdapterSHA256:      windowsManagedPolicyDigest(adapter),
		ReceiptSHA256:      windowsManagedPolicyDigest(receipt),
		Targets:            []WindowsCursorManagedRuntimeTarget{},
	}
	stateBody, err := windowsCursorManagedStateBody(state)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := WindowsCursorManagedPolicyTeardownSnapshot{
		PolicyActive:              true,
		HooksExisted:              true,
		Hooks:                     hooks,
		HooksSecurityDescriptor:   windowsCursorTestTrustedSDDL,
		HooksAttributes:           windows.FILE_ATTRIBUTE_ARCHIVE,
		AdapterExisted:            true,
		Adapter:                   adapter,
		AdapterSecurityDescriptor: windowsCursorTestTrustedSDDL,
		AdapterAttributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
		StateExisted:              true,
		State:                     stateBody,
		StateSecurityDescriptor:   windowsCursorTestTrustedSDDL,
		StateAttributes:           windows.FILE_ATTRIBUTE_ARCHIVE,
		ReceiptExisted:            true,
		Receipt:                   receipt,
		ReceiptSecurityDescriptor: windowsCursorTestPrivateSDDL,
		ReceiptAttributes:         windows.FILE_ATTRIBUTE_ARCHIVE,
	}
	if err := validateWindowsCursorManagedTeardownSnapshot(opts, snapshot); err != nil {
		t.Fatalf("closed zero-target Cursor snapshot rejected during upgrade or rollback: %v", err)
	}
	state.HookFailMode = "open"
	snapshot.State, err = windowsCursorManagedStateBody(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsCursorManagedTeardownSnapshot(opts, snapshot); err == nil {
		t.Fatal("open zero-target Cursor snapshot was accepted")
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
	mappedAdapter, err := connector.RenderWindowsCursorEnterpriseAdapterForTargets(hookExecutable, map[string]string{target.SID: "open"})
	if err != nil {
		t.Fatal(err)
	}
	mappedState, err := windowsCursorManagedStateBody(windowsCursorManagedPolicyState{
		SchemaVersion: 1, HookExecutable: hookExecutable, GatewayAddr: allowed.GatewayAddr,
		GatewayServiceName: allowed.GatewayServiceName, AdapterSHA256: windowsManagedPolicyDigest(mappedAdapter),
		ReceiptSHA256: windowsManagedPolicyDigest(receipt), Targets: []WindowsCursorManagedRuntimeTarget{target},
		HookFailMode: "open", TargetFailModes: map[string]string{target.SID: "open"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*windowsCursorManagedArtifacts){
		"mapped adapter": func(value *windowsCursorManagedArtifacts) {
			value.adapter.existed, value.adapter.data = true, mappedAdapter
		},
		"mapped adapter receipt and state": func(value *windowsCursorManagedArtifacts) {
			value.adapter.existed, value.adapter.data = true, mappedAdapter
			value.receipt.existed, value.receipt.data = true, receipt
			value.receiptMetadata = privateMetadata
			value.state.existed, value.state.data = true, mappedState
		},
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
	// GAP-2479: a deleted adapter gets this build's render back too.
	missing := artifactsFor(current)
	missing.adapter.existed = false
	missing.adapter.data = nil
	candidate, err := windowsCursorManagedAdapterDriftCandidate(missing, hookExecutable)
	if err != nil {
		t.Fatalf("a deleted adapter was not restored: %v", err)
	}
	if !candidate.adapter.existed || !bytes.Equal(candidate.adapter.data, current) {
		t.Fatal("the restored deleted adapter is not this build's render")
	}
	if _, err := validateWindowsCursorManagedStateIdentity(candidate); err != nil {
		t.Fatalf("the restored deleted adapter and state do not validate: %v", err)
	}
	noState := artifactsFor(current)
	noState.state.existed = false
	if _, err := windowsCursorManagedAdapterDriftCandidate(noState, hookExecutable); err == nil {
		t.Fatal("an adapter without ownership state was accepted")
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

// The public validator runs unlocked in every Cursor hook process and in
// lifecycle restore validation, so it must never rewrite hooks.json, even in
// the non-strict (bulldoze) posture. Orphan reclaim belongs to the locked
// install/repair paths (validateWindowsCursorManagedArtifactsReclaimingOrphans).
func TestWindowsCursorPublicValidatorDoesNotReclaimOrphanHookRefs(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	dir := t.TempDir()
	adapterPath := filepath.Join(dir, "defenseclaw-hook.ps1")
	hooksPath := filepath.Join(dir, "hooks.json")
	foreign := []byte(`{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"operator-hook"}]}}`)
	orphaned, err := connector.MergeWindowsCursorEnterpriseHooks(foreign, adapterPath, "open")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooksPath, orphaned, 0o600); err != nil {
		t.Fatal(err)
	}
	artifacts := windowsCursorManagedArtifacts{
		hooks:   windowsManagedFileSnapshot{path: hooksPath, existed: true, data: append([]byte(nil), orphaned...)},
		adapter: windowsManagedFileSnapshot{path: adapterPath},
	}
	validated, err := validateWindowsCursorManagedPublicArtifacts(artifacts)
	if !errors.Is(err, errWindowsCursorOrphanHookRefs) {
		t.Fatalf("orphan Cursor hook refs error = %v, want errWindowsCursorOrphanHookRefs", err)
	}
	if !bytes.Equal(validated.hooks.data, orphaned) {
		t.Fatal("public validator changed the in-memory hooks snapshot")
	}
	onDisk, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, orphaned) {
		t.Fatal("public validator rewrote hooks.json outside the locked install/repair path")
	}
}

// installWindowsCursorStandaloneGuardForTest installs a closed standalone
// Cursor guard under a temporary root. With enrolled, the protected state
// records Alice, as a per-target install leaves it.
func installWindowsCursorStandaloneGuardForTest(t *testing.T, hook string, enrolled bool) windowsCursorPaths {
	t.Helper()
	previousRoot, previousOwner := windowsCursorManagedRootResolver, windowsManagedPolicyOwnerSID
	previousStandalone, previousWriter := windowsEnterpriseStandaloneProcess, windowsManagedPolicyWriter
	previousIdentity, previousHookTrust := windowsEnterpriseMutationIdentityCheck, windowsEnterpriseHookTrustCheck
	previousAncestorTrust, previousDirTrust, previousFileTrust := windowsManagedPolicyAncestorTrustCheck, windowsManagedPolicyDirTrustCheck, windowsManagedPolicyFileTrustCheck
	root := filepath.Join(t.TempDir(), "Cursor")
	windowsCursorManagedRootResolver = func() (string, error) { return root, nil }
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) {
		return windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	}
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		windowsCursorManagedRootResolver, windowsManagedPolicyOwnerSID = previousRoot, previousOwner
		windowsEnterpriseStandaloneProcess, windowsManagedPolicyWriter = previousStandalone, previousWriter
		windowsEnterpriseMutationIdentityCheck, windowsEnterpriseHookTrustCheck = previousIdentity, previousHookTrust
		windowsManagedPolicyAncestorTrustCheck, windowsManagedPolicyDirTrustCheck, windowsManagedPolicyFileTrustCheck = previousAncestorTrust, previousDirTrust, previousFileTrust
	})
	t.Setenv(connector.WindowsGatewayServiceNameEnv, "DefenseClawGateway")
	if err := EnsureWindowsStandaloneCursorManagedPolicy(connector.SetupOpts{
		APIAddr: "127.0.0.1:18970", HookExecutable: hook,
	}); err != nil {
		t.Fatal(err)
	}
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	if enrolled {
		data, err := os.ReadFile(paths.State)
		if err != nil {
			t.Fatal(err)
		}
		var state windowsCursorManagedPolicyState
		if err := json.Unmarshal(data, &state); err != nil {
			t.Fatal(err)
		}
		alice := WindowsCursorManagedRuntimeTarget{SID: "S-1-5-21-1000-1000-1000-1001", DataDir: `C:\Users\alice\.defenseclaw`}
		state.Targets = []WindowsCursorManagedRuntimeTarget{alice}
		state.TargetFailModes = map[string]string{alice.SID: "closed"}
		state.HookFailMode = "closed"
		adapter, err := renderWindowsCursorManagedAdapter(state)
		if err != nil {
			t.Fatal(err)
		}
		state.AdapterSHA256 = windowsManagedPolicyDigest(adapter)
		body, err := windowsCursorManagedStateBody(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := windowsManagedPolicyWriter(paths.Adapter, adapter, true); err != nil {
			t.Fatal(err)
		}
		if err := windowsManagedPolicyWriter(paths.State, body, true); err != nil {
			t.Fatal(err)
		}
	}
	targets, active, err := ReadWindowsCursorManagedPolicyTargets()
	if err != nil || !active || (len(targets) == 1) != enrolled {
		t.Fatalf("fixture guard: active=%t targets=%v err=%v", active, targets, err)
	}
	return paths
}

// A standalone Cursor guard owns hooks.json's registration and the adapter.
// Repair rebuilds whichever of them is missing or changed, both together when
// both are damaged, from the machine-owned record, and validates the complete
// guard before it returns. Enrollment, the receipt and unrelated hooks stay.
func TestWindowsCursorMachineGuardRebuildsEveryOwnedArtifact(t *testing.T) {
	const hook = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	operatorHooks := []byte(`{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"operator-hook"}]}}`)
	hooksDamage := []struct {
		name  string
		apply func(t *testing.T, paths windowsCursorPaths)
	}{
		{name: "hooks.json intact"},
		{name: "hooks.json missing", apply: func(t *testing.T, paths windowsCursorPaths) {
			if err := os.Remove(paths.Hooks); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hooks.json replaced", apply: func(t *testing.T, paths windowsCursorPaths) {
			if err := windowsManagedPolicyWriter(paths.Hooks, operatorHooks, true); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "registration fails open", apply: func(t *testing.T, paths windowsCursorPaths) {
			data, err := os.ReadFile(paths.Hooks)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			events, _ := document["hooks"].(map[string]any)
			changed := 0
			for _, raw := range events {
				entries, _ := raw.([]any)
				for _, entry := range entries {
					if hookEntry, ok := entry.(map[string]any); ok && hookEntry["failClosed"] == true {
						hookEntry["failClosed"] = false
						changed++
					}
				}
			}
			events["operatorEvent"] = []any{map[string]any{"type": "command", "command": "operator-hook"}}
			edited, err := json.Marshal(document)
			if err != nil || changed == 0 {
				t.Fatalf("fixture: changed %d registrations: %v", changed, err)
			}
			if err := windowsManagedPolicyWriter(paths.Hooks, edited, true); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hooks.json not JSON", apply: func(t *testing.T, paths windowsCursorPaths) {
			if err := windowsManagedPolicyWriter(paths.Hooks, []byte("{ not json"), true); err != nil {
				t.Fatal(err)
			}
		}},
	}
	adapterDamage := []struct {
		name  string
		apply func(t *testing.T, paths windowsCursorPaths)
	}{
		{name: "adapter intact"},
		{name: "adapter missing", apply: func(t *testing.T, paths windowsCursorPaths) {
			if err := os.Remove(paths.Adapter); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "adapter changed", apply: func(t *testing.T, paths windowsCursorPaths) {
			if err := windowsManagedPolicyWriter(paths.Adapter, []byte("exit 0\r\n"), true); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, enrolled := range []bool{false, true} {
		for _, hooks := range hooksDamage {
			for _, adapter := range adapterDamage {
				if hooks.apply == nil && adapter.apply == nil {
					continue
				}
				name := map[bool]string{false: "empty", true: "Alice"}[enrolled] + "/" + hooks.name + "/" + adapter.name
				t.Run(name, func(t *testing.T) {
					paths := installWindowsCursorStandaloneGuardForTest(t, hook, enrolled)
					targetsBefore, _, err := ReadWindowsCursorManagedPolicyTargets()
					if err != nil {
						t.Fatal(err)
					}
					receiptBefore, err := os.ReadFile(paths.Receipt)
					if err != nil {
						t.Fatal(err)
					}
					for _, damage := range []func(*testing.T, windowsCursorPaths){hooks.apply, adapter.apply} {
						if damage != nil {
							damage(t, paths)
						}
					}
					if _, _, err := ReadWindowsCursorManagedPolicyTargets(); err == nil {
						t.Fatal("the damaged guard appeared healthy")
					}
					restored, err := RestoreWindowsCursorManagedAdapter(hook)
					if err != nil || !restored {
						t.Fatalf("rebuild: restored=%t err=%v", restored, err)
					}
					targets, active, err := ReadWindowsCursorManagedPolicyTargets()
					if err != nil || !active || !slices.Equal(targets, targetsBefore) {
						t.Fatalf("rebuilt guard: active=%t targets=%v (want %v) err=%v", active, targets, targetsBefore, err)
					}
					hooksAfter, err := os.ReadFile(paths.Hooks)
					if err != nil {
						t.Fatal(err)
					}
					if err := connector.VerifyWindowsCursorEnterpriseHooks(hooksAfter, paths.Adapter, "closed"); err != nil {
						t.Fatalf("rebuilt registration is not the closed guard: %v", err)
					}
					keepsOperatorHook := hooks.name == "hooks.json replaced" || hooks.name == "registration fails open"
					if keepsOperatorHook && !bytes.Contains(hooksAfter, []byte("operator-hook")) {
						t.Fatal("the rebuild removed an unrelated Cursor hook")
					}
					if receiptAfter, err := os.ReadFile(paths.Receipt); err != nil || !bytes.Equal(receiptAfter, receiptBefore) {
						t.Fatalf("the rebuild changed the rollback receipt: %v", err)
					}
					if again, err := RestoreWindowsCursorManagedAdapter(hook); err != nil || again {
						t.Fatalf("second repair of a healthy guard: restored=%t err=%v", again, err)
					}
				})
			}
		}
	}
}

// A rebuild writes nothing unless the record authenticates, and a failed
// rebuild puts back every file it wrote, so no repair leaves a half guard.
func TestWindowsCursorMachineGuardRebuildRefusesOrRollsBack(t *testing.T) {
	const hook = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	type files struct{ hooks, adapter, state, receipt []byte }
	read := func(t *testing.T, paths windowsCursorPaths) files {
		t.Helper()
		var result files
		for path, target := range map[string]*[]byte{paths.Hooks: &result.hooks, paths.Adapter: &result.adapter, paths.State: &result.state, paths.Receipt: &result.receipt} {
			data, err := os.ReadFile(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			*target = data
		}
		return result
	}
	removeBoth := func(t *testing.T, paths windowsCursorPaths) {
		for _, path := range []string{paths.Hooks, paths.Adapter} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, test := range []struct {
		name   string
		damage func(t *testing.T, paths windowsCursorPaths)
		hook   string
	}{
		{name: "receipt not bound by the state", damage: func(t *testing.T, paths windowsCursorPaths) {
			removeBoth(t, paths)
			if err := windowsManagedPolicyWriter(paths.Receipt, []byte("{}\n"), false); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "receipt missing", damage: func(t *testing.T, paths windowsCursorPaths) {
			removeBoth(t, paths)
			if err := os.Remove(paths.Receipt); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "state DefenseClaw did not write", damage: func(t *testing.T, paths windowsCursorPaths) {
			removeBoth(t, paths)
			data, err := os.ReadFile(paths.State)
			if err != nil {
				t.Fatal(err)
			}
			if err := windowsManagedPolicyWriter(paths.State, bytes.ReplaceAll(data, []byte("\n  "), []byte("\n ")), true); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "another hook executable", damage: removeBoth, hook: `C:\Other\bin\defenseclaw-hook.exe`},
		{name: "hooks.json of another version", damage: func(t *testing.T, paths windowsCursorPaths) {
			if err := os.Remove(paths.Adapter); err != nil {
				t.Fatal(err)
			}
			if err := windowsManagedPolicyWriter(paths.Hooks, []byte(`{"version":2,"hooks":{}}`), true); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "Secure Client", damage: func(t *testing.T, paths windowsCursorPaths) {
			removeBoth(t, paths)
			windowsEnterpriseStandaloneProcess = func() bool { return false }
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths := installWindowsCursorStandaloneGuardForTest(t, hook, true)
			test.damage(t, paths)
			before := read(t, paths)
			repairHook := hook
			if test.hook != "" {
				repairHook = test.hook
			}
			if restored, err := RestoreWindowsCursorManagedAdapter(repairHook); err == nil || restored {
				t.Fatalf("unauthenticated rebuild: restored=%t err=%v", restored, err)
			}
			if after := read(t, paths); !reflect.DeepEqual(after, before) {
				t.Fatal("a refused rebuild wrote a guard artifact")
			}
		})
	}

	t.Run("failed hooks.json write rolls back the adapter", func(t *testing.T) {
		paths := installWindowsCursorStandaloneGuardForTest(t, hook, true)
		removeBoth(t, paths)
		before := read(t, paths)
		swap := windowsCursorManagedFileSwap
		windowsCursorManagedFileSwap = func(request windowsCursorManagedSwap) (windowsCursorManagedSwapResult, error) {
			if strings.EqualFold(request.path, paths.Hooks) {
				return windowsCursorManagedSwapResult{}, errors.New("injected hooks.json write failure")
			}
			return swap(request)
		}
		t.Cleanup(func() { windowsCursorManagedFileSwap = swap })
		if restored, err := RestoreWindowsCursorManagedAdapter(hook); err == nil || restored {
			t.Fatalf("failed rebuild: restored=%t err=%v", restored, err)
		}
		if after := read(t, paths); !reflect.DeepEqual(after, before) {
			t.Fatal("a failed rebuild left a partly rebuilt guard")
		}
		windowsCursorManagedFileSwap = swap
		if restored, err := RestoreWindowsCursorManagedAdapter(hook); err != nil || !restored {
			t.Fatalf("rebuild after the failure: restored=%t err=%v", restored, err)
		}
	})
}
