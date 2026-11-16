// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// InventoryGrantLedgerFileName is the standalone Windows enumerator's record,
// beside the manifest, of the profiles the gateway service may hold
// inventory read access to. A profile leaves it only once a revoke took the
// access away, so a failed revoke is retried at a later cycle, also after a
// restart (GAP-1269).
const InventoryGrantLedgerFileName = ".inventory-grants.json"

const inventoryGrantLedgerMaxBytes = 4 << 20

// InventoryGrantLedgerPath is the grant ledger for manifestPath.
func InventoryGrantLedgerPath(manifestPath string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(manifestPath)), InventoryGrantLedgerFileName)
}

type inventoryGrantLedgerFile struct {
	Version  int                     `json:"version"`
	Profiles []inventoryGrantProfile `json:"profiles"`
}

type inventoryGrantProfile struct {
	SID      string `json:"sid,omitempty"`
	UserHome string `json:"user_home"`
}

func inventoryGrantKey(home string) string {
	home = strings.TrimSpace(home)
	if home == "" {
		return ""
	}
	if home = filepath.Clean(home); home == "." {
		return ""
	}
	return strings.ToLower(home)
}

// MarshalInventoryGrantLedger serializes the profiles of targets, one per
// home, in a stable order.
func MarshalInventoryGrantLedger(targets []ManifestTarget) ([]byte, error) {
	out := inventoryGrantLedgerFile{Version: 1, Profiles: []inventoryGrantProfile{}}
	seen := map[string]bool{}
	for _, target := range targets {
		key := inventoryGrantKey(target.UserHome)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out.Profiles = append(out.Profiles, inventoryGrantProfile{SID: strings.TrimSpace(target.SID), UserHome: filepath.Clean(strings.TrimSpace(target.UserHome))})
	}
	sort.Slice(out.Profiles, func(i, j int) bool {
		return inventoryGrantKey(out.Profiles[i].UserHome) < inventoryGrantKey(out.Profiles[j].UserHome)
	})
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ParseInventoryGrantLedger decodes a grant ledger.
func ParseInventoryGrantLedger(data []byte) ([]ManifestTarget, error) {
	if len(data) > inventoryGrantLedgerMaxBytes {
		return nil, errors.New("enterprise hooks: inventory grant ledger is too large")
	}
	var ledger inventoryGrantLedgerFile
	if err := json.Unmarshal(data, &ledger); err != nil {
		return nil, fmt.Errorf("enterprise hooks: parse inventory grant ledger: %w", err)
	}
	if ledger.Version != 1 {
		return nil, fmt.Errorf("enterprise hooks: inventory grant ledger version %d is not supported", ledger.Version)
	}
	out := make([]ManifestTarget, 0, len(ledger.Profiles))
	for _, profile := range ledger.Profiles {
		if inventoryGrantKey(profile.UserHome) != "" {
			out = append(out, ManifestTarget{SID: profile.SID, UserHome: profile.UserHome})
		}
	}
	return out, nil
}

// InventoryGrantLedger is where ReconcileInventoryGrants keeps its record.
type InventoryGrantLedger struct {
	// Load returns the recorded profiles, or an error that wraps
	// os.ErrNotExist when there is no record yet.
	Load func() ([]ManifestTarget, error)
	Save func([]ManifestTarget) error
}

// InventoryGrantReconcile is what one ReconcileInventoryGrants did.
type InventoryGrantReconcile struct {
	// Revoked are the profiles whose access was taken away; Pending those
	// whose revoke failed, kept for the next cycle.
	Revoked, Pending []ManifestTarget
	// LoadErr is an unreadable record (the cycle went on from the
	// previous manifest), RevokeErr the failed revoke, SaveErr a record
	// that could not be written.
	LoadErr, RevokeErr, SaveErr error
}

// ReconcileInventoryGrants revokes the gateway's inventory read access on
// every profile the ledger holds that current gives no grant to, the
// profiles the grant pass skips (inventoryDACLGrantTargets): one current no
// longer lists, and one it lists with disabled rows only (GAP-1193). It
// then records current's grant targets, with any profile whose revoke
// failed. previous, the manifest of the last cycle (nil when there is none),
// is added to the record: with no readable record (the first cycle, an
// upgrade from a build that kept none) every profile it lists, since those
// builds granted disabled rows too.
func ReconcileInventoryGrants(ledger InventoryGrantLedger, previous *Manifest, current Manifest, revoke func(Manifest) error) InventoryGrantReconcile {
	var out InventoryGrantReconcile
	recorded, err := ledger.Load()
	if err != nil {
		recorded = nil
		if !errors.Is(err, os.ErrNotExist) {
			out.LoadErr = err
		}
	}
	if previous != nil {
		if err != nil {
			recorded = append(recorded, previous.Targets...)
		} else {
			recorded = append(recorded, inventoryDACLGrantTargets(*previous)...)
		}
	}
	granted := inventoryDACLGrantTargets(current)
	seen := map[string]bool{}
	for _, target := range granted {
		seen[inventoryGrantKey(target.UserHome)] = true
	}
	var stale []ManifestTarget
	for _, target := range recorded {
		key := inventoryGrantKey(target.UserHome)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		stale = append(stale, ManifestTarget{SID: target.SID, User: target.User, UserHome: target.UserHome})
	}
	next := append([]ManifestTarget(nil), granted...)
	if len(stale) > 0 {
		if out.RevokeErr = revoke(Manifest{Targets: stale}); out.RevokeErr != nil {
			out.Pending = stale
			next = append(next, stale...)
		} else {
			out.Revoked = stale
		}
	}
	out.SaveErr = ledger.Save(next)
	return out
}
