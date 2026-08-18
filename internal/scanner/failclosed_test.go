// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestScanners_FailClosedOnNonZeroExitWithParseableStdout is the
// regression for finding "Non-zero {mcp,plugin,skill} scanner
// exits can be treated as successful scans".
//
// Before the fix, a scanner subprocess that wrote `{"findings":[]}`
// to stdout AND exited non-zero was treated as a clean scan: the
// wrapper recorded ExitCode/ScanError on ScanResult but returned
// `(result, nil)`, so the watcher admission path -- which branches
// only on `err != nil` -- treated it as a successful empty scan.
//
// The fix returns `(result, error)` for any non-zero exit. The
// returned result is preserved (so callers can observe the partial
// findings + ExitCode + ScanError for diagnostics) but the non-nil
// Go error guarantees admission fails closed.
func TestScanners_FailClosedOnNonZeroExitWithParseableStdout(t *testing.T) {
	// Fake scanner that emits a valid empty findings array on stdout
	// and then exits 7. Pre-fix this would have been parsed as a
	// clean scan; post-fix it must surface as a Go error.
	bin := buildScannerFixture(t, `{"findings":[]}`+"\n", 7)

	tcs := []struct {
		name    string
		scanner Scanner
	}{
		{
			name:    "skill",
			scanner: NewSkillScanner(config.SkillScannerConfig{Binary: bin}, config.InspectLLMConfig{}, config.CiscoAIDefenseConfig{}),
		},
		{
			name:    "mcp",
			scanner: NewMCPScanner(config.MCPScannerConfig{Binary: bin}, config.InspectLLMConfig{}, config.CiscoAIDefenseConfig{}),
		},
		{
			name:    "plugin",
			scanner: NewPluginScanner(bin),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.scanner.Scan(context.Background(), t.TempDir())
			if err == nil {
				t.Fatalf("scanner %s: expected non-nil error on non-zero exit; got nil (result=%+v)", tc.name, result)
			}
			if result == nil {
				t.Fatalf("scanner %s: expected partial result preserved alongside error: %v", tc.name, err)
			}
			if result.ExitCode != 7 {
				t.Errorf("scanner %s: ExitCode = %d, want 7", tc.name, result.ExitCode)
			}
			// Sanity: error message references the exit code so
			// operators can debug.
			if !strings.Contains(err.Error(), "exited 7") {
				t.Errorf("scanner %s: error %q does not mention exit code", tc.name, err.Error())
			}
		})
	}
}

// TestScanners_PartialResultPreservedOnFailure pins the contract
// that the returned ScanResult on failure is never nil so callers
// can surface ExitCode / ScanError / partial findings in diagnostics.
func TestScanners_PartialResultPreservedOnFailure(t *testing.T) {
	bin := buildScannerFixture(t, `{"findings":[]}`+"\n", 1)
	ss := NewPluginScanner(bin)
	result, err := ss.Scan(context.Background(), t.TempDir())
	if err == nil {
		t.Fatal("expected error")
	}
	if result == nil {
		t.Fatal("partial ScanResult must not be nil on failure")
	}
	if result.ExitCode == 0 {
		t.Errorf("ExitCode should be set on failure, got 0")
	}
}
