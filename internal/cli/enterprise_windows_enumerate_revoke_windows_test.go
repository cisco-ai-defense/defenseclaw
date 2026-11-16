// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// A revoke that fails for a profile the cycle stopped enrolling is retried
// by a later enumerator process, from the grant ledger alone, and a profile
// whose rows are all disabled loses its access too (GAP-1269, GAP-1193).
func TestEnterpriseWindowsInventoryGrantRevokeSurvivesARestart(t *testing.T) {
	previousRevoker, previousLoader, previousSaver := enterpriseWindowsInventoryReadRevoker, enterpriseWindowsInventoryGrantLedgerLoader, enterpriseWindowsInventoryGrantLedgerSaver
	t.Cleanup(func() {
		enterpriseWindowsInventoryReadRevoker = previousRevoker
		enterpriseWindowsInventoryGrantLedgerLoader, enterpriseWindowsInventoryGrantLedgerSaver = previousLoader, previousSaver
	})
	var ledger []byte
	enterpriseWindowsInventoryGrantLedgerLoader = func(string) ([]enterprisehooks.ManifestTarget, error) {
		if ledger == nil {
			return nil, fmt.Errorf("ledger: %w", os.ErrNotExist)
		}
		return enterprisehooks.ParseInventoryGrantLedger(ledger)
	}
	enterpriseWindowsInventoryGrantLedgerSaver = func(_ string, targets []enterprisehooks.ManifestTarget) error {
		data, err := enterprisehooks.MarshalInventoryGrantLedger(targets)
		ledger = data
		return err
	}
	off := false
	alice := enterprisehooks.ManifestTarget{SID: "S-1-5-21-1-2-3-1001", User: "alice", UserHome: `C:\Users\alice`, Connector: "codex"}
	bob := enterprisehooks.ManifestTarget{SID: "S-1-5-21-1-2-3-1002", User: "bob", UserHome: `C:\Users\bob`, Connector: "codex"}
	fail := true
	var calls []string
	enterpriseWindowsInventoryReadRevoker = func(dropped enterprisehooks.Manifest) error {
		var homes []string
		for _, target := range dropped.Targets {
			homes = append(homes, target.UserHome)
		}
		calls = append(calls, strings.Join(homes, ","))
		if fail {
			return errors.New("access is denied")
		}
		return nil
	}
	both := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{alice, bob}}
	reconcileEnterpriseWindowsInventoryGrants(io.Discard, `C:\ProgramData\DefenseClaw\targets.yaml`, nil, both)
	onlyAlice := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{alice}}
	reconcileEnterpriseWindowsInventoryGrants(io.Discard, `C:\ProgramData\DefenseClaw\targets.yaml`, &both, onlyAlice)
	// A new enumerator process: only the ledger remembers bob.
	fail = false
	aliceDisabled := alice
	aliceDisabled.Enabled = &off
	reconcileEnterpriseWindowsInventoryGrants(io.Discard, `C:\ProgramData\DefenseClaw\targets.yaml`, &onlyAlice, enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{aliceDisabled}})
	if got := strings.Join(calls, ";"); got != `C:\Users\bob;C:\Users\alice,C:\Users\bob` {
		t.Fatalf("revokes = %q, want bob's failed revoke, then alice's (disabled only) with bob's retry", got)
	}
}
