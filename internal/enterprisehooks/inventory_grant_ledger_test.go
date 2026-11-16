// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// memoryGrantLedger is a ledger file that outlives the enumerator process.
type memoryGrantLedger struct{ data []byte }

func (m *memoryGrantLedger) ledger() InventoryGrantLedger {
	return InventoryGrantLedger{
		Load: func() ([]ManifestTarget, error) {
			if m.data == nil {
				return nil, fmt.Errorf("open ledger: %w", os.ErrNotExist)
			}
			return ParseInventoryGrantLedger(m.data)
		},
		Save: func(targets []ManifestTarget) error {
			data, err := MarshalInventoryGrantLedger(targets)
			m.data = data
			return err
		},
	}
}

func revokeRecorder(fail *bool, calls *[]string) func(Manifest) error {
	return func(m Manifest) error {
		var homes []string
		for _, target := range m.Targets {
			homes = append(homes, target.UserHome)
		}
		*calls = append(*calls, strings.Join(homes, ","))
		if *fail {
			return errors.New("access is denied")
		}
		return nil
	}
}

// A profile that keeps only disabled rows loses the inventory read access
// an earlier cycle granted it, though it is still in the manifest.
func TestInventoryGrantsAreRevokedWhenAProfileKeepsOnlyDisabledRows(t *testing.T) {
	off := false
	store := &memoryGrantLedger{}
	fail := false
	var calls []string
	enabled := Manifest{Targets: []ManifestTarget{{SID: "S-1-5-21-1-2-3-1001", UserHome: `C:\Users\alice`, Connector: "codex"}}}
	ReconcileInventoryGrants(store.ledger(), nil, enabled, revokeRecorder(&fail, &calls))
	disabled := Manifest{Targets: []ManifestTarget{{SID: "S-1-5-21-1-2-3-1001", UserHome: `C:\Users\alice`, Connector: "codex", Enabled: &off}}}
	got := ReconcileInventoryGrants(store.ledger(), &enabled, disabled, revokeRecorder(&fail, &calls))
	if strings.Join(calls, ";") != `C:\Users\alice` || len(got.Revoked) != 1 {
		t.Fatalf("revokes = %q (%+v), want alice's once her only row is disabled", calls, got)
	}
	ReconcileInventoryGrants(store.ledger(), &disabled, disabled, revokeRecorder(&fail, &calls))
	if len(calls) != 1 {
		t.Fatalf("revokes = %q, want none once the access is gone", calls)
	}
}

// A revoke that failed for a dropped profile is retried by the next
// enumerator process, which never saw the profile in a manifest; one that
// is enrolled again is not revoked.
func TestInventoryGrantRevokeIsRetriedAfterARestart(t *testing.T) {
	store := &memoryGrantLedger{}
	fail := false
	var calls []string
	alice := ManifestTarget{SID: "S-1-5-21-1-2-3-1001", UserHome: `C:\Users\alice`, Connector: "codex"}
	bob := ManifestTarget{SID: "S-1-5-21-1-2-3-1002", UserHome: `C:\Users\bob`, Connector: "codex"}
	carol := ManifestTarget{SID: "S-1-5-21-1-2-3-1003", UserHome: `C:\Users\carol`, Connector: "codex"}
	all := Manifest{Targets: []ManifestTarget{alice, bob, carol}}
	ReconcileInventoryGrants(store.ledger(), nil, all, revokeRecorder(&fail, &calls))
	fail = true
	onlyAlice := Manifest{Targets: []ManifestTarget{alice}}
	if got := ReconcileInventoryGrants(store.ledger(), &all, onlyAlice, revokeRecorder(&fail, &calls)); len(got.Pending) != 2 {
		t.Fatalf("failed revoke = %+v, want bob and carol pending", got)
	}
	// A restart: nothing but the ledger is left of that cycle, and the
	// previous manifest no longer lists bob or carol.
	fail = false
	aliceAndCarol := Manifest{Targets: []ManifestTarget{alice, carol}}
	ReconcileInventoryGrants(store.ledger(), &onlyAlice, aliceAndCarol, revokeRecorder(&fail, &calls))
	ReconcileInventoryGrants(store.ledger(), &aliceAndCarol, aliceAndCarol, revokeRecorder(&fail, &calls))
	if got := strings.Join(calls, ";"); got != `C:\Users\bob,C:\Users\carol;C:\Users\bob` {
		t.Fatalf("revokes = %q, want the failed pair, then bob's retry alone, then none", got)
	}
}

// With no ledger yet (an upgrade), every profile of the last manifest may
// hold access, disabled rows included: those builds granted them too.
func TestInventoryGrantLedgerStartsFromEveryRowOfThePreviousManifest(t *testing.T) {
	off := false
	store := &memoryGrantLedger{}
	fail := false
	var calls []string
	previous := Manifest{Targets: []ManifestTarget{
		{SID: "S-1-5-21-1-2-3-1001", UserHome: `C:\Users\alice`, Connector: "codex"},
		{SID: "S-1-5-21-1-2-3-1002", UserHome: `C:\Users\bob`, Connector: "codex", Enabled: &off},
	}}
	ReconcileInventoryGrants(store.ledger(), &previous, previous, revokeRecorder(&fail, &calls))
	if strings.Join(calls, ";") != `C:\Users\bob` {
		t.Fatalf("revokes = %q, want bob's disabled-only profile", calls)
	}
	targets, err := ParseInventoryGrantLedger(store.data)
	if err != nil || len(targets) != 1 || targets[0].UserHome != `C:\Users\alice` {
		t.Fatalf("ledger = %+v, %v; want alice only", targets, err)
	}
}
