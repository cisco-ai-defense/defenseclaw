// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-2024 (RV5-1): after 1.0.3 -> 1.0.4 -> 1.0.5, an account recreated
// during 1.0.4 that 1.0.4 never served kept the earlier holder's entry
// (legacy_holder, no first_seen) and another user's first hook moved the
// homes file's mtime past the new home's birth: the guardian counted the new
// account as the 1.0.3 holder, and the first map bound it to the earlier
// holder's agents entry. The uid's last hook in the agent ledger bounds the
// sighting in the guardian too (as in the gateway, GAP-1947). Control: a
// ledger hook after the home's birth keeps the 1.0.3 holder (GAP-1976).
func TestGuardianBoundsALegacyEntrysSightingByTheUIDsLastHook(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current account:", err)
	}
	uid, err := strconv.Atoi(me.Uid)
	if err != nil || uid <= 0 {
		t.Skip("not run as a non-root account")
	}
	birth, known := enterprisehooks.HomeBirth(me.HomeDir)
	if !known || time.Since(time.Unix(0, birth)) < 3*time.Hour {
		t.Skip("the file system keeps no creation time for the home here, or the home is too young")
	}
	head := `"` + me.Uid + `":{"home":"` + me.HomeDir + `","name":"` + me.Username + `"`
	for _, file := range []struct{ name, body string }{
		{"1.0.4 file, legacy holder 1.0.4 never served", `{"format":{"format":1},` + head + `,"legacy_holder":true}}`},
		{"1.0.3 file", `{` + head + `}}`},
	} {
		for _, tc := range []struct {
			name     string
			lastHook int64
			pre      bool
		}{
			{"last hook before the home was created", birth - int64(time.Hour), false},
			{"last hook after the home was created", time.Now().Add(-time.Minute).UnixNano(), true},
			{"no ledger", 0, true},
		} {
			t.Run(file.name+": "+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "managed_peer_homes.json")
				if err := os.WriteFile(path, []byte(file.body), 0o600); err != nil {
					t.Fatal(err)
				}
				previous := enterpriseHookAgentLastHooks
				t.Cleanup(func() { enterpriseHookAgentLastHooks = previous })
				enterpriseHookAgentLastHooks = func(dataDir string) map[int]int64 {
					if dataDir != dir {
						t.Errorf("ledger read from %q; want the homes file's data dir %q", dataDir, dir)
					}
					if tc.lastHook == 0 {
						return nil
					}
					return map[int]int64{uid: tc.lastHook}
				}
				peer, ok := enterpriseHookResolveGatewayPeers(path, nil)[uid]
				if !ok {
					t.Skip("the account database gives the current account no non-SID incarnation here")
				}
				if peer.PreToken != tc.pre {
					t.Fatalf("PreToken %v, want %v", peer.PreToken, tc.pre)
				}
			})
		}
	}
}

// GAP-2026 (RV5-3): the identity spool's fingerprint includes the local
// account database's stamp, so the records are rewritten at the next tick
// after useradd or userdel, not at the 15-minute interval.
func TestIdentitySpoolFingerprintFollowsTheAccountDatabase(t *testing.T) {
	previous := enterpriseHookLocalAccountsStamp
	t.Cleanup(func() { enterpriseHookLocalAccountsStamp = previous })
	stamp := "1/100/7"
	enterpriseHookLocalAccountsStamp = func() string { return stamp }
	keys := []string{"1001:alice:12", "1002:bob:13"}
	before := enterpriseHookIdentitySpoolFingerprint(keys)
	if again := enterpriseHookIdentitySpoolFingerprint(keys); again != before {
		t.Fatalf("fingerprint %q then %q with nothing changed", before, again)
	}
	stamp = "2/100/8"
	if after := enterpriseHookIdentitySpoolFingerprint(keys); after == before {
		t.Fatalf("fingerprint %q did not change with the account database", after)
	}
}
