// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianstate

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// CoverageTarget projects the identity and current disposition of a Guardian
// row. Key is the caller's canonical connector+principal key. A retained row
// describes the last successful enrollment, not current verification.
type CoverageTarget struct {
	Key       string
	Home      string
	OK        bool
	Pending   bool
	Error     string
	HasResult bool
}

// ValidateCoverage validates a protected enrollment ledger against the exact
// current reconcile. Returned keys are previously enrolled targets currently
// awaiting repair. Newly enrolled pending targets have no retained row.
// Callers authenticate the files, freshness, manifest and reconcile identity
// before using this structural proof.
func ValidateCoverage(current, retained []CoverageTarget, successes, pending int) (map[string]bool, error) {
	rows := make(map[string]CoverageTarget, len(current))
	observedOK, observedPending := 0, 0
	for _, row := range current {
		if row.Key == "" || rows[row.Key].Key != "" {
			return nil, fmt.Errorf("Guardian reconcile contains an incomplete or duplicate target")
		}
		if row.OK == row.Pending || row.Error != "" || (row.Pending && row.HasResult) {
			return nil, fmt.Errorf("Guardian reconcile contains an invalid target disposition")
		}
		rows[row.Key] = row
		if row.OK {
			observedOK++
		} else {
			observedPending++
		}
	}
	if successes != observedOK || pending != observedPending {
		return nil, fmt.Errorf("Guardian coverage counts differ from current target dispositions")
	}
	seen := make(map[string]bool, len(retained))
	repairPending := make(map[string]bool)
	for _, previous := range retained {
		if previous.Key == "" || seen[previous.Key] || !previous.OK || previous.Pending || previous.Error != "" {
			return nil, fmt.Errorf("Guardian enrollment history contains an invalid or duplicate target")
		}
		row, exists := rows[previous.Key]
		if !exists {
			return nil, fmt.Errorf("Guardian enrollment history contains extra or stale target %s", previous.Key)
		}
		if row.Pending && (row.Home == "" || previous.Home == "") {
			return nil, fmt.Errorf("Guardian repair history has no bound profile for %s", previous.Key)
		}
		if row.Home != "" && previous.Home != "" {
			a, b := filepath.Clean(row.Home), filepath.Clean(previous.Home)
			match := a == b
			if runtime.GOOS == "windows" {
				match = strings.EqualFold(a, b)
			}
			if !match {
				return nil, fmt.Errorf("Guardian enrollment history has a different profile for %s", previous.Key)
			}
		}
		seen[previous.Key] = true
		if row.Pending {
			repairPending[previous.Key] = true
		}
	}
	for key, row := range rows {
		if row.OK && !seen[key] {
			return nil, fmt.Errorf("Guardian enrollment history does not cover verified target %s", key)
		}
	}
	return repairPending, nil
}
