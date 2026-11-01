// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// writeGuardianRecord writes the root guardian's identity record of uid for
// name, with the home proof token, dated at.
func writeGuardianRecord(t *testing.T, dir string, uid int, name, token string, at time.Time) {
	t.Helper()
	record, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
		Key: strconv.Itoa(uid), User: name, AccountIncarnation: "files", LegacyOwnerToken: token, UpdatedAt: at.UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(uid)+".json"), record, 0o640); err != nil {
		t.Fatal(err)
	}
}

func setLocalAccountsChangedAt(t *testing.T, at time.Time) {
	t.Helper()
	previous := localAccountsChangedAt
	t.Cleanup(func() { localAccountsChangedAt = previous })
	localAccountsChangedAt = func() time.Time { return at }
}

// GAP-0422, GAP-1876 (TST-33312, FC-BLK-167-ER on cap-erhel1): after
// `userdel -r` and `useradd -u` under the same name and home path, the
// guardian's identity record of the uid still carried the earlier holder's
// home proof until its next pass. The new account's real Codex turn was
// bound to the earlier holder's 1.0.3 agents entry (observe) and kept its
// agent identity. A record older than the last change of the local account
// database proves nothing about the account that holds the uid now: the
// entry is a candidate and the request is refused, naming the fact. A record
// newer than the change binds as before.
func TestRecordOlderThanTheAccountDatabaseDoesNotBindTheUIDsHolder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changed time.Duration // account database change, relative to the record
		bound   bool
	}{
		{"account database unchanged since the record", -time.Minute, true},
		{"account deleted and created again after the record", time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newUpgradeBridge(t, "alice")
			legacy := agentidentity.LegacyAgentID(b.inputs(70001, "alice"))
			b.migrate(70001, "alice")
			recordedAt := time.Now().Add(-30 * time.Second)
			writeGuardianRecord(t, b.dir, 70001, "alice", enterprisehooks.LegacyAgentOwnerToken("files", b.homes[70001]), recordedAt)
			setLocalAccountsChangedAt(t, recordedAt.Add(tc.changed))
			managedHookPeerHome = func(int) string { return "" } // ProtectHome
			got, mode := b.hook(legacyConfig(legacy, upgradeProfiles), 70001, profileSubject{UserID: "70001", UserName: "alice"})
			if tc.bound {
				if got.Name != "relaxed" || got.Match != profileMatchAgent || mode != "observe" || got.Refused != "" {
					t.Fatalf("%+v, mode %q; want the holder's agents assignment", got, mode)
				}
				return
			}
			if got.Name == "relaxed" && got.Refused == "" || mode == "observe" || !strings.Contains(got.Refused, "agent identity") {
				t.Fatalf("%+v, mode %q; want a refused candidate naming the agent identity", got, mode)
			}
		})
	}
}

// The same rule for the agent identity: a home proof from a record older
// than the account database change is no proof of the uid's holder.
func TestHomeProofOfARecordOlderThanTheAccountDatabaseIsNone(t *testing.T) {
	b := newUpgradeBridge(t, "alice")
	b.peer(70001)
	token := enterprisehooks.LegacyAgentOwnerToken("files", b.homes[70001])
	recordedAt := time.Now().Add(-30 * time.Second)
	writeGuardianRecord(t, b.dir, 70001, "alice", token, recordedAt)
	setLocalAccountsChangedAt(t, recordedAt.Add(-time.Minute))
	if got := managedHookPeerHomeProof(70001, "alice", "files"); got == "" || got != normalizeHomeProof(token) {
		t.Fatalf("proof %q before the change; want %q", got, normalizeHomeProof(token))
	}
	setLocalAccountsChangedAt(t, recordedAt.Add(time.Second))
	if got := managedHookPeerHomeProof(70001, "alice", "files"); got != "" {
		t.Fatalf("proof %q from a record older than the account database; want none", got)
	}
}
