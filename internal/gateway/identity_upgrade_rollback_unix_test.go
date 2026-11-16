// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// TestRunningGatewayReadsTheMigrationMapAgain is GAP-0709's gateway half: the
// guardian adds an account to the map after a rollback window, and the
// running gateway, which had read the first map, applies the account's
// agents entry without a restart.
func TestRunningGatewayReadsTheMigrationMapAgain(t *testing.T) {
	b := newUpgradeBridge(t, "alice")
	legacy := agentidentity.LegacyAgentID(b.inputs(70001, "alice"))
	b.migrate(70002, "carol")
	cfg := legacyConfig(legacy, upgradeProfiles)
	if got, _ := b.hook(cfg, 70001, profileSubject{UserID: "70001", UserName: "alice"}); got.Refused == "" {
		t.Fatalf("fixture: an account the map does not record = %+v; want refused", got)
	}
	owners, _, _, ok := enterprisehooks.ReadLegacyAgentOwners(b.dir, nil)
	if !ok {
		t.Fatal("no map")
	}
	b.peer(70001)
	owners[70001] = enterprisehooks.LegacyAgentOwner{User: "alice", Token: enterprisehooks.LegacyAgentOwnerToken("files", b.homes[70001])}
	if err := os.Remove(filepath.Join(b.dir, enterprisehooks.LegacyAgentOwnersFile)); err != nil {
		t.Fatal(err)
	}
	if written, err := enterprisehooks.WriteLegacyAgentOwners(b.dir, owners, time.Now(), nil); err != nil || !written {
		t.Fatalf("rewrite the map: %v %v", written, err)
	}
	// The next check is due; the cache is the one the gateway kept.
	legacyAgentOwners.mu.Lock()
	legacyAgentOwners.nextTry = time.Time{}
	legacyAgentOwners.mu.Unlock()
	got, mode := b.hook(cfg, 70001, profileSubject{UserID: "70001", UserName: "alice"})
	if got.Name != "relaxed" || got.Match != profileMatchAgent || mode != "observe" || got.Refused != "" {
		t.Fatalf("%+v, mode %q; want alice's agents entry from the updated map", got, mode)
	}
}
