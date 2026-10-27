// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// GAP-1947 (RV4-2): 1.0.4 saves the homes file whenever any uid's home or
// name changes, so its mtime can come after an account was deleted and
// created again (another user's first hook). The uid's last hook in the
// agent ledger bounds the sighting too: the recreated account's home is
// younger than that hook and gets a token of its own.
func TestLegacyEntrySightingIsBoundedByTheUIDsLastHook(t *testing.T) {
	now := time.Now()
	lastHook := now.Add(-2 * time.Hour).UnixNano()
	store := filepath.Join(t.TempDir(), "managed_peer_homes.json")
	body := `{"format":{"format":1},"1006":{"home":"/home/r4a","name":"r4a","base_incarnation":"files","incarnation":"files"}}`
	if err := os.WriteFile(store, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(store, now, now); err != nil {
		t.Fatal(err)
	}
	previousHooks, previousProof := managedHookPeerLastHooks, managedHookPeerHomeProof
	t.Cleanup(func() { managedHookPeerLastHooks, managedHookPeerHomeProof = previousHooks, previousProof })
	managedHookPeerLastHooks = func() map[int]int64 { return map[int]int64{1006: lastHook} }
	recreated := "home:9:" + strconv.FormatInt(lastHook+int64(time.Hour), 10)
	managedHookPeerHomeProof = func(int, string, string) string { return recreated }
	c := &managedHookPeerHomeCache{now: time.Now}
	c.setStore(store)
	if got := c.holderToken(1006, "r4a", "files"); got != "files|"+recreated {
		t.Fatalf("token %q; want the recreated account's own token", got)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.firstSeen[1006] != lastHook {
		t.Fatalf("first_seen %d; want the last hook %d", c.firstSeen[1006], lastHook)
	}
}

// GAP-2069: the agent ledger prunes the rows of a uid that runs no hook in
// its row window (7 days), so an earlier holder who stopped using the host
// leaves no row and the homes file's mtime alone (moved by another
// account's first hook) bounded the sighting. A readable ledger with no row
// of the uid bounds it by the window's start: a home created after then is
// another account's.
func TestLegacyEntrySightingIsBoundedByTheLedgerWindowWhenTheUIDsRowsWerePruned(t *testing.T) {
	now := time.Now()
	previousHooks, previousWindow := managedHookPeerLastHooks, inventory.AgentLedgerRowWindow
	t.Cleanup(func() { managedHookPeerLastHooks, inventory.AgentLedgerRowWindow = previousHooks, previousWindow })
	inventory.AgentLedgerRowWindow = 7 * 24 * time.Hour
	for _, tc := range []struct {
		name   string
		hooks  map[int]int64
		pruned bool
	}{
		{"rows pruned", map[int]int64{1007: now.UnixNano()}, true},
		{"ledger unreadable", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := filepath.Join(t.TempDir(), "managed_peer_homes.json")
			body := `{"format":{"format":1},"1006":{"home":"/home/r4a","name":"r4a","legacy_holder":true}}`
			if err := os.WriteFile(store, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(store, now, now); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(store)
			if err != nil {
				t.Fatal(err)
			}
			want := info.ModTime().UnixNano()
			if tc.pruned {
				want = now.Add(-7 * 24 * time.Hour).UnixNano()
			}
			managedHookPeerLastHooks = func() map[int]int64 { return tc.hooks }
			c := &managedHookPeerHomeCache{now: func() time.Time { return now }}
			c.setStore(store)
			c.mu.Lock()
			c.loadHomesLocked()
			got := c.firstSeen[1006]
			c.mu.Unlock()
			if got != want {
				t.Fatalf("first_seen %d; want %d", got, want)
			}
		})
	}
}
