// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// GAP-1976: 1.0.3 -> 1.0.4 -> 1.0.5. 1.0.4 rewrote the homes file as format
// 1 when bob's first hook adopted a token; alice, whom 1.0.4 never served,
// stayed a legacy holder without a base token. Each such entry gets its own
// pre_token_holder mark, which this release keeps after it adopts a token;
// bob's gets none. A file 1.0.3 wrote marks every entry.
func TestHomesFileMarksEachUIDNo104GatewayServed(t *testing.T) {
	const alice = `"52100":{"home":"/home/alice","name":"alice","legacy_holder":true}`
	const bob = `"52101":{"home":"/home/bob","name":"bob","base_incarnation":"files","incarnation":"files"}`
	for _, tc := range []struct {
		name, body string
		want       map[string]bool
	}{
		{"written by 1.0.3", `{"52100":{"home":"/home/alice","name":"alice"},"52101":{"home":"/home/bob","name":"bob"}}`,
			map[string]bool{"52100": true, "52101": true}},
		{"written by 1.0.4", `{"format":{"format":1},` + alice + `,` + bob + `}`, map[string]bool{"52100": true, "52101": false}},
		{"rewritten by this release after alice's first hook",
			`{"format":{"format":1},"52100":{"home":"/home/alice","name":"alice","base_incarnation":"files","pre_token_holder":true},` + bob + `}`,
			map[string]bool{"52100": true, "52101": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := filepath.Join(t.TempDir(), "managed_peer_homes.json")
			if err := os.WriteFile(store, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			c := &managedHookPeerHomeCache{now: time.Now}
			c.setStore(store)
			c.mu.Lock()
			c.loadHomesLocked()
			c.saveHomesLocked()
			c.mu.Unlock()
			data, err := os.ReadFile(store)
			if err != nil {
				t.Fatal(err)
			}
			var stored map[string]managedHookPeerLast
			if err := json.Unmarshal(data, &stored); err != nil {
				t.Fatal(err)
			}
			if stored[managedHookPeerHomesFormatKey].Format != 1 {
				t.Fatalf("format entry %+v; want format 1", stored[managedHookPeerHomesFormatKey])
			}
			for uid, want := range tc.want {
				if stored[uid].PreTokenHolder != want {
					t.Fatalf("uid %s: pre_token_holder %v after the rewrite, want %v: %s", uid, stored[uid].PreTokenHolder, want, data)
				}
			}
		})
	}
}

// GAP-1977: an account created under a 1.0.3 holder's uid and name after
// this gateway took the homes file over is no 1.0.3 holder. When the first
// proof read for the uid names a home created after its last sighting, or a
// home other than the first one proven, the uid loses its pre_token_holder
// mark, so the guardian does not bind the new account to the 1.0.3 agent
// identities.
func TestNewHolderOfAPreTokenUIDLosesTheMark(t *testing.T) {
	seen := time.Now().Add(-time.Hour).UnixNano()
	for _, tc := range []struct {
		name  string
		first string // first proof read, "" for none
		birth int64
		mark  bool
	}{
		{"home created before the sighting", "", seen - int64(time.Hour), true},
		{"home created after the sighting", "", seen + int64(time.Minute), false},
		{"another home than the first one proven", "home:4:" + strconv.FormatInt(seen-int64(2*time.Hour), 10), seen - int64(time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := "home:5:" + strconv.FormatInt(tc.birth, 10)
			previous := managedHookPeerHomeProof
			t.Cleanup(func() { managedHookPeerHomeProof = previous })
			managedHookPeerHomeProof = func(int, string, string) string { return proof }
			c := &managedHookPeerHomeCache{now: time.Now}
			c.setStore(filepath.Join(t.TempDir(), "managed_peer_homes.json"))
			c.mu.Lock()
			c.loadHomesLocked()
			c.preToken = map[int]bool{1001: true}
			c.firstSeen = map[int]int64{1001: seen}
			if tc.first != "" {
				c.homeProofs = map[int]string{1001: tc.first}
			}
			c.mu.Unlock()
			_ = c.holderToken(1001, "alice", "files")
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.preToken[1001] != tc.mark {
				t.Fatalf("pre_token_holder %v, want %v", c.preToken[1001], tc.mark)
			}
		})
	}
}
