// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMultiHomeOSSDoesNotClaimOtherUsersPlugin(t *testing.T) {
	withoutMachineIDEs(t)
	base := t.TempDir()
	alice, bob := filepath.Join(base, "alice"), filepath.Join(base, "bob")
	writeVSCodeExtensions(t, bob, "github.copilot")
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, DataDir: filepath.Join(base, "data"), HomeDir: alice,
		HomeDirs: []string{alice, bob}, ScanRoots: []string{filepath.Join(base, "none")},
	}, []AISignature{{ID: "copilot", Name: "Copilot", Category: SignalSupportedConnector, ExtensionIDs: []string{"github.copilot"}}})
	cleanupPreparedDiscoveryService(t, svc)
	svc.account = ideOwner{id: "1000", name: "gateway"}
	report, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sig := range report.Signals {
		if sig.Detector != "editor_extension" {
			continue
		}
		found = true
		if sig.UserID != "" || sig.UserName != "" {
			t.Fatalf("cross-home signal attributed to gateway: %+v", sig)
		}
	}
	if !found {
		t.Fatal("missing plugin signal")
	}
}
