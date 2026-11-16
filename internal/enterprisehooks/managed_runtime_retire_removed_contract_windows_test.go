// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// 1.0.5 selected managed OpenCode bundles with the V1 hook contract
// ("opencode-hooks-v1"), which 1.0.6 removed. After the upgrade, revoking such
// a selection (the account is no longer an OpenCode target) failed in the
// bundle retire with "managed runtime bundle contains invalid authenticated
// fields" and left the bundle behind, and the reconcile logged an Error for
// an account still enrolled for other connectors (rel-1-0-6:GAP-0199). The
// selector entry pins the bundle's digest and the bundle's identity matches,
// so the retire deletes it; a bundle whose bytes the entry does not pin is
// still refused, naming the file.
func TestWindowsManagedRuntimeRetireDeletesBundleOfARemovedContract(t *testing.T) {
	fixture := newWindowsManagedRuntimeGenerationMissingHooksGCFixture(t)
	fixture.options.Connector = "opencode"
	home := filepath.Dir(fixture.options.DataDir)
	hookDir := filepath.Join(fixture.options.DataDir, "hooks")
	if _, err := ensureWindowsTargetOwnedDirectoryTree(home, hookDir, fixture.target); err != nil {
		t.Fatal(err)
	}
	if windowsManagedRuntimeValidContract("opencode", "opencode-hooks-v1") {
		t.Fatal("this build still registers the OpenCode V1 contract; the fixture no longer models a removed contract")
	}
	stamp := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	legacy := func(gatewayAddr string) (windowsManagedRuntimeSelectorTarget, string) {
		t.Helper()
		generationID, err := newWindowsManagedRuntimeGenerationID()
		if err != nil {
			t.Fatal(err)
		}
		desired := WindowsManagedRuntimeGenerationDesired{
			Connector:                  "opencode",
			TargetSID:                  fixture.options.TargetSID,
			DataDir:                    fixture.options.DataDir,
			HookExecutable:             fixture.options.HookExecutable,
			GatewayAddr:                gatewayAddr,
			GatewayServiceName:         "DefenseClawGateway",
			FailMode:                   "closed",
			ScopedToken:                "legacy-opencode-scoped-test-token",
			HookContractID:             "opencode-hooks-v1",
			HookContractLockUpdatedAt:  stamp,
			HookContractEntryUpdatedAt: stamp,
		}
		data, err := marshalWindowsManagedRuntimeBundle(windowsManagedRuntimeBundleFromDesired(desired, generationID))
		if err != nil {
			t.Fatal(err)
		}
		path, err := windowsManagedRuntimeBundlePath(fixture.options.DataDir, "opencode", generationID)
		if err != nil {
			t.Fatal(err)
		}
		if err := connector.PublishManagedTargetRuntimeFileNoReplace(path, data); err != nil {
			t.Fatalf("publish legacy OpenCode bundle: %v", err)
		}
		return windowsManagedRuntimeSelectorTargetFromDesired(desired, generationID, windowsManagedRuntimeSHA256(data)), path
	}
	revoke := func(entry windowsManagedRuntimeSelectorTarget) error {
		t.Helper()
		if err := publishWindowsManagedRuntimeSelector(windowsManagedRuntimeSelector{
			SchemaVersion: windowsManagedRuntimeGenerationSchema,
			Connector:     "opencode",
			Targets:       []windowsManagedRuntimeSelectorTarget{entry},
		}); err != nil {
			t.Fatalf("publish selector naming the legacy bundle: %v", err)
		}
		removal, err := RemoveWindowsManagedRuntimeGenerationEnrollment(WindowsManagedRuntimeGenerationRemovalOptions{
			Connector:                "opencode",
			TargetSID:                fixture.options.TargetSID,
			DataDir:                  fixture.options.DataDir,
			HookExecutable:           fixture.options.HookExecutable,
			PrimaryEnrollmentRemoved: true,
		})
		if err != nil || !removal.Changed() {
			t.Fatalf("remove legacy OpenCode selection: changed=%v err=%v", removal.Changed(), err)
		}
		return removal.Finalize()
	}

	entry, path := legacy("127.0.0.1:18970")
	if err := revoke(entry); err != nil {
		t.Fatalf("retire the bundle of a removed contract: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("the legacy OpenCode bundle survived its retire: %v", err)
	}

	// The selector pins other bytes: the retire refuses and names the file.
	forged, forgedPath := legacy("127.0.0.1:18971")
	forged.BundleSHA256 = "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000"
	err := revoke(forged)
	if err == nil {
		t.Fatal("a bundle whose digest the selector does not pin was retired")
	}
	if !strings.Contains(err.Error(), forgedPath) {
		t.Fatalf("the refused retire does not name the bundle file: %v", err)
	}
	if _, statErr := os.Lstat(forgedPath); statErr != nil {
		t.Fatalf("a refused retire deleted the bundle: %v", statErr)
	}
}
