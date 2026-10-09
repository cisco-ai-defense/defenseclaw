// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianstate

import (
	"path/filepath"
	"testing"
)

func TestCoverageSeparatesVerificationFromRepairHistory(t *testing.T) {
	home := filepath.Join(t.TempDir(), "user")
	current := []CoverageTarget{{Key: "codex:active", Home: home, OK: true}, {Key: "codex:offline", Home: home, Pending: true}}
	retained := []CoverageTarget{current[0], {Key: current[1].Key, Home: home, OK: true}}
	repairs, err := ValidateCoverage(current, retained, 1, 1)
	if err != nil || len(repairs) != 1 || !repairs[current[1].Key] {
		t.Fatalf("repairs=%v err=%v", repairs, err)
	}
	repairs, err = ValidateCoverage(current, retained[:1], 1, 1)
	if err != nil || len(repairs) != 0 {
		t.Fatalf("new enrollment: repairs=%v err=%v", repairs, err)
	}
}

func TestCoverageRejectsInvalidHistory(t *testing.T) {
	for _, name := range []string{"extra", "duplicate", "wrong-profile", "missing-profile", "pending-result", "pending-error", "missing-verified", "counts"} {
		t.Run(name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "user")
			current := []CoverageTarget{{Key: "active", Home: home, OK: true}, {Key: "offline", Home: home, Pending: true}}
			retained := []CoverageTarget{current[0], {Key: "offline", Home: home, OK: true}}
			successes := 1
			switch name {
			case "extra":
				retained[1].Key = "removed"
			case "duplicate":
				retained = append(retained, retained[1])
			case "wrong-profile":
				retained[1].Home = home + "-other"
			case "missing-profile":
				retained[1].Home = ""
			case "pending-result":
				current[1].HasResult = true
			case "pending-error":
				current[1].Error = "machine policy failed"
			case "missing-verified":
				retained = retained[1:]
			case "counts":
				successes = 2
			}
			if _, err := ValidateCoverage(current, retained, successes, 1); err == nil {
				t.Fatal("invalid coverage accepted")
			}
		})
	}
}
