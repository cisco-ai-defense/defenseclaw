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

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-2025 (RV5-2): the GAP-0422 rule compared wall-clock times. With
// /etc/passwd dated in the future (a useradd while the clock was ahead, then
// an NTP step back) every record the guardian wrote was older than the
// change, so every bound account stayed refused until the clock passed it.
// A record carries the stamp the guardian read before its pass: it is
// current while that stamp is, whatever the clock says, and stale as soon as
// the database changes.
func TestHomeProofWithTheGuardiansStampFollowsTheStampNotTheClock(t *testing.T) {
	b := newUpgradeBridge(t, "alice")
	b.peer(70001)
	token := enterprisehooks.LegacyAgentOwnerToken("files", b.homes[70001])
	recordedAt := time.Now().Add(-30 * time.Second)
	record, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
		Key: "70001", User: "alice", AccountIncarnation: "files", LegacyOwnerToken: token, AccountsStamp: "1/100/7", UpdatedAt: recordedAt.UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.dir, "70001.json"), record, 0o640); err != nil {
		t.Fatal(err)
	}
	setLocalAccountsChangedAt(t, time.Now().Add(2*time.Hour)) // dated in the future
	previous := localAccountsStamp
	t.Cleanup(func() { localAccountsStamp = previous })
	stamp := "1/100/7"
	localAccountsStamp = func() string { return stamp }
	if got := managedHookPeerHomeProof(70001, "alice", "files"); got != normalizeHomeProof(token) {
		t.Fatalf("proof %q with the guardian's stamp current; want %q", got, normalizeHomeProof(token))
	}
	if got := legacyAgentOwnerTokenNow(70001, "alice"); got != token {
		t.Fatalf("owner token %q with the guardian's stamp current; want %q", got, token)
	}
	stamp = "2/100/8"
	if got := managedHookPeerHomeProof(70001, "alice", "files"); got != "" {
		t.Fatalf("proof %q after the account database changed; want none", got)
	}
}

// GAP-2024 (RV5-1), gateway half: the gateway writes the sightings it
// bounded by the ledger into the homes file when it loads it, before its
// own hooks reach the ledger, so the guardian reads them as first_seen.
func TestLoadedLegacySightingsAreWrittenBoundedByTheLedger(t *testing.T) {
	now := time.Now()
	lastHook := now.Add(-2 * time.Hour).UnixNano()
	store := filepath.Join(t.TempDir(), "managed_peer_homes.json")
	body := `{"format":{"format":1},"1006":{"home":"/home/r4a","name":"r4a","legacy_holder":true}}`
	if err := os.WriteFile(store, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(store, now, now); err != nil {
		t.Fatal(err)
	}
	previous := managedHookPeerLastHooks
	t.Cleanup(func() { managedHookPeerLastHooks = previous })
	managedHookPeerLastHooks = func() map[int]int64 { return map[int]int64{1006: lastHook} }
	c := &managedHookPeerHomeCache{now: time.Now}
	c.setStore(store)
	c.mu.Lock()
	c.loadHomesLocked()
	c.mu.Unlock()
	data, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]managedHookPeerLast
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if got := stored[strconv.Itoa(1006)]; got.FirstSeen != lastHook || !got.PreTokenHolder {
		t.Fatalf("stored entry %+v; want first_seen %d (the last hook) and the 1.0.3-holder mark", got, lastHook)
	}
}
