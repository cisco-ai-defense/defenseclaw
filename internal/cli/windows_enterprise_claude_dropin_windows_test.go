//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-2336: with the guardian stopped, verify said only not_ready about a
// hook entry an administrator removed from DefenseClaw's Claude Code drop-in,
// and the repair it advised failed 1603. Status and verify now fail with
// machine_policy_incomplete naming the drop-in, and an elevated repair puts
// it back before its lifecycle runs and says so.
func TestWindowsEnterpriseClaudeDropInDriftFailsVerifyAndRepairPutsItBack(t *testing.T) {
	const dropIn = `C:\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json`
	previousDrift, previousRestore := windowsEnterpriseClaudeDropInDrift, windowsEnterpriseClaudeDropInRestore
	t.Cleanup(func() {
		windowsEnterpriseClaudeDropInDrift, windowsEnterpriseClaudeDropInRestore = previousDrift, previousRestore
	})
	drifted, removed, restoreCalls := true, false, 0
	windowsEnterpriseClaudeDropInDrift = func() (string, bool) {
		if !drifted {
			return "", false
		}
		return dropIn, removed
	}
	restoreErr := error(nil)
	windowsEnterpriseClaudeDropInRestore = func() (bool, error) {
		restoreCalls++
		if restoreErr != nil {
			return false, restoreErr
		}
		drifted = false
		return true, nil
	}
	for _, gone := range []bool{false, true} {
		drifted, removed = true, gone
		for _, action := range []string{"status", "verify"} {
			result := enterprisestatus.New(action, "standalone", "windows", "test")
			applyWindowsEnterpriseClaudeDropInDrift(result)
			want := "was changed outside DefenseClaw"
			if gone {
				want = "was removed outside DefenseClaw"
			}
			if len(result.Errors) != 1 || result.Errors[0].Code != "machine_policy_incomplete" ||
				!strings.Contains(result.Errors[0].Message, dropIn) ||
				!strings.Contains(result.Errors[0].Message, want) ||
				!strings.Contains(result.Errors[0].Message, "repair") {
				t.Fatalf("%s with the drop-in drifted (removed=%v): errors = %+v", action, gone, result.Errors)
			}
		}
		if change := repairWindowsEnterpriseClaudeDropIn(); !strings.Contains(change, "put back DefenseClaw's Claude Code machine policy drop-in "+dropIn) {
			t.Fatalf("repair change = %q", change)
		}
		result := enterprisestatus.New("verify", "standalone", "windows", "test")
		applyWindowsEnterpriseClaudeDropInDrift(result)
		if len(result.Errors) != 0 {
			t.Fatalf("verify after the repair put it back: errors = %+v", result.Errors)
		}
	}
	calls := restoreCalls
	if change := repairWindowsEnterpriseClaudeDropIn(); change != "" || restoreCalls != calls {
		t.Fatalf("untouched drop-in: change=%q restore calls %d -> %d, want nothing", change, calls, restoreCalls)
	}
	drifted, restoreErr = true, errors.New("no rendering has the recorded digest")
	if change := repairWindowsEnterpriseClaudeDropIn(); change != "" {
		t.Fatalf("restore that failed: change=%q, want none (the lifecycle names the refusal)", change)
	}
}
