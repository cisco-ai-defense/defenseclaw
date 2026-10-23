// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

func TestWindowsCursorTargetModesPreservePeersAndLegacyPolicy(t *testing.T) {
	first := WindowsCursorManagedRuntimeTarget{SID: "S-1-5-21-1000-1000-1000-1001", DataDir: `C:\Users\first\.defenseclaw`}
	second := WindowsCursorManagedRuntimeTarget{SID: "S-1-5-21-1000-1000-1000-1002", DataDir: `C:\Users\second\.defenseclaw`}
	for _, legacyMode := range []string{"", "closed", "open"} {
		state := windowsCursorManagedPolicyState{HookExecutable: `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`, HookFailMode: legacyMode, Targets: []WindowsCursorManagedRuntimeTarget{first}}
		legacy, err := renderWindowsCursorManagedAdapter(state)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := connector.RenderWindowsCursorEnterpriseAdapter(state.HookExecutable, cursorManagedPolicyFailMode(state))
		if err != nil || !bytes.Equal(legacy, expected) {
			t.Fatal("legacy renderer changed")
		}
		prior := state
		cursorManagedSetTargetFailMode(&state, second.SID, "open")
		state.Targets = append(state.Targets, second)
		if state.TargetFailModes[first.SID] != cursorManagedPolicyFailMode(prior) || state.TargetFailModes[second.SID] != "open" {
			t.Fatalf("peer modes changed: %v", state.TargetFailModes)
		}
		if _, err := renderWindowsCursorManagedAdapter(state); err != nil {
			t.Fatal(err)
		}
		// A refresh of either user must not change the other's policy or mutate
		// the authenticated preimage retained for transaction rollback.
		before := state
		cursorManagedSetTargetFailMode(&state, first.SID, "closed")
		if state.TargetFailModes[second.SID] != "open" || before.TargetFailModes[first.SID] != cursorManagedPolicyFailMode(prior) {
			t.Fatal("refresh overwrote peer/preimage policy")
		}
		remaining, err := cursorManagedNarrowState(state, []WindowsCursorManagedRuntimeTarget{second})
		if err != nil || remaining.HookFailMode != "open" || len(remaining.TargetFailModes) != 1 || state.TargetFailModes[first.SID] != "closed" {
			t.Fatalf("revocation=%+v err=%v", remaining, err)
		}
		if _, err := renderWindowsCursorManagedAdapter(remaining); err != nil {
			t.Fatal(err)
		}
		changed := second
		changed.DataDir = `C:\Users\other\.defenseclaw`
		if _, err := cursorManagedNarrowState(state, []WindowsCursorManagedRuntimeTarget{changed}); err == nil {
			t.Fatal("uninstalled replacement runtime accepted")
		}
	}
}

func TestWindowsCursorTargetModeVerificationRejectsMismatch(t *testing.T) {
	for _, pair := range [][2]string{{"open", "open"}, {"closed", "closed"}, {"", "closed"}} {
		if err := verifyWindowsCursorRuntimeDeliveryMode(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]string{{"open", "closed"}, {"closed", "open"}, {"open", ""}} {
		if err := verifyWindowsCursorRuntimeDeliveryMode(pair[0], pair[1]); err == nil {
			t.Fatal("mismatched authenticated generation accepted")
		}
	}
	sid, err := windows.StringToSid("S-1-5-21-1000-1000-1000-1001")
	if err != nil {
		t.Fatal(err)
	}
	target := windowsGenericManagedTarget{sid: sid, dataDir: `C:\Users\first\.defenseclaw`, setup: connector.SetupOpts{HookFailMode: "closed"}}
	state := windowsCursorManagedPolicyState{HookExecutable: `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`, HookFailMode: "closed", Targets: []WindowsCursorManagedRuntimeTarget{{SID: sid.String(), DataDir: target.dataDir}}, TargetFailModes: map[string]string{sid.String(): "closed"}}
	if err := verifyWindowsCursorMachineTargetState(state, target); err != nil {
		t.Fatal(err)
	}
	state.TargetFailModes[sid.String()] = "open"
	if err := verifyWindowsCursorMachineTargetState(state, target); err == nil {
		t.Fatal("adapter/runtime mode mismatch accepted")
	}
	if _, err := renderWindowsCursorManagedAdapter(state); err == nil {
		t.Fatal("aggregate mode mismatch accepted")
	}
	state.HookFailMode = "open"
	state.TargetFailModes["S-1-5-21-1000-1000-1000-1002"] = "open"
	if _, err := renderWindowsCursorManagedAdapter(state); err == nil {
		t.Fatal("unenrolled mode entry accepted")
	}
	delete(state.TargetFailModes, sid.String())
	if _, err := renderWindowsCursorManagedAdapter(state); err == nil {
		t.Fatal("missing enrolled mode accepted")
	}
}

func TestDeferredWindowsCursorModeUsesConfiguredPolicyAndVersionFallback(t *testing.T) {
	// The version fallback and the open default are Secure Client's (#1163).
	useWindowsSecureClientForTest(t)
	for _, tc := range []struct{ version, configured, want string }{
		{"3.21.16", "", "open"}, {"3.21.16", "open", "open"}, {"3.21.16", "closed", "closed"},
		{"", "closed", "open"}, {"not-a-version", "closed", "open"}, {"0.0.1", "closed", "open"},
		{"3.21.16", "typo", "closed"},
	} {
		if got := deferredWindowsCursorFailMode(tc.version, tc.configured); got != tc.want {
			t.Errorf("version=%q configured=%q got=%q want=%q", tc.version, tc.configured, got, tc.want)
		}
	}
}

func TestWindowsCursorMappedUpgradeRollbackAcceptsOnlyCanonicalPrefixes(t *testing.T) {
	originalTrust := windowsManagedPolicyFileTrustCheck
	originalRoot := windowsCursorManagedRootResolver
	root := filepath.Join(t.TempDir(), "Cursor")
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	windowsCursorManagedRootResolver = func() (string, error) { return root, nil }
	t.Cleanup(func() {
		windowsManagedPolicyFileTrustCheck = originalTrust
		windowsCursorManagedRootResolver = originalRoot
	})
	sid := currentWindowsTestSID(t)
	home := t.TempDir()
	if err := setWindowsUserPathProtection(home, sid, true); err != nil {
		t.Fatal(err)
	}
	target := WindowsCursorManagedRuntimeTarget{SID: sid.String(), DataDir: filepath.Join(home, ".defenseclaw")}
	state := windowsCursorManagedPolicyState{SchemaVersion: 1, HookExecutable: `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`, GatewayAddr: "127.0.0.1:18970", GatewayServiceName: "DefenseClawGateway", Targets: []WindowsCursorManagedRuntimeTarget{target}}
	paths, err := windowsCursorManagedPaths()
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := renderWindowsCursorManagedAdapter(state)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := windowsCursorManagedReceiptBody(windowsCursorManagedPolicyReceipt{SchemaVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	state.AdapterSHA256 = windowsManagedPolicyDigest(adapter)
	state.ReceiptSHA256 = windowsManagedPolicyDigest(receipt)
	body, err := windowsCursorManagedStateBody(state)
	if err != nil {
		t.Fatal(err)
	}
	hooks, err := connector.MergeWindowsCursorEnterpriseHooks(nil, paths.Adapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	metadata := windowsCursorManagedFileMetadata{securityDescriptor: windowsCursorTestTrustedSDDL, attributes: windows.FILE_ATTRIBUTE_ARCHIVE}
	private := windowsCursorManagedFileMetadata{securityDescriptor: windowsCursorTestPrivateSDDL, attributes: windows.FILE_ATTRIBUTE_ARCHIVE}
	prior := windowsCursorManagedArtifacts{
		active: true,
		hooks:  windowsManagedFileSnapshot{path: paths.Hooks, existed: true, data: hooks}, hooksMetadata: metadata,
		adapter: windowsManagedFileSnapshot{path: paths.Adapter, existed: true, data: adapter}, adapterMetadata: metadata,
		state: windowsManagedFileSnapshot{path: paths.State, existed: true, data: body}, stateMetadata: metadata,
		receipt: windowsManagedFileSnapshot{path: paths.Receipt, existed: true, data: receipt}, receiptMetadata: private,
	}
	opts := WindowsCursorManagedPolicyTeardownOptions{HookExecutable: state.HookExecutable, GatewayAddr: state.GatewayAddr, GatewayServiceName: state.GatewayServiceName, Targets: state.Targets}
	snapshot := windowsCursorManagedTeardownSnapshot(prior)
	cursorManagedSetTargetFailMode(&state, target.SID, "open")
	mapped, err := renderWindowsCursorManagedAdapter(state)
	if err != nil {
		t.Fatal(err)
	}
	state.AdapterSHA256 = windowsManagedPolicyDigest(mapped)
	newState, err := windowsCursorManagedStateBody(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"adapter", "state"} {
		t.Run(stage, func(t *testing.T) {
			current := prior
			current.adapter.data = mapped
			if stage == "state" {
				current.state.data = newState
			}
			if err := validateWindowsCursorLifecycleRestoreSource(current, opts, opts, snapshot); err != nil {
				t.Fatalf("upgrade prefix rejected: %v", err)
			}
			current.adapter.data = append(append([]byte(nil), mapped...), []byte("\n# unauthorized change")...)
			if err := validateWindowsCursorLifecycleRestoreSource(current, opts, opts, snapshot); err == nil {
				t.Fatal("changed adapter accepted for upgrade rollback")
			}
		})
	}
	current := prior
	current.adapter.data, err = connector.RenderWindowsCursorEnterpriseAdapterForTargets(state.HookExecutable, map[string]string{"S-1-5-21-9999-9999-9999-9999": "open"})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsCursorLifecycleRestoreSource(current, opts, opts, snapshot); err == nil {
		t.Fatal("unauthorized adapter SID accepted for upgrade rollback")
	}
}
