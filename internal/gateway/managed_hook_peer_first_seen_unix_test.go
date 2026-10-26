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
