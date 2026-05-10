// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package policy

import "testing"

// TestEvaluateAdmissionFallback_RejectsScanError is the policy-side
// defence-in-depth for finding "Non-zero scanner exits can be
// treated as successful scans". Even if a future caller forgets to
// check the Scan() Go error and feeds a ScanResultInput whose
// ExitCode != 0 or ScanError is set into the admission policy, the
// fallback evaluator must reject and quarantine instead of treating
// the empty findings list as a clean scan.
func TestEvaluateAdmissionFallback_RejectsScanError(t *testing.T) {
	cases := []struct {
		name  string
		input ScanResultInput
	}{
		{
			name: "exit_code_only",
			input: ScanResultInput{
				MaxSeverity:   "INFO",
				TotalFindings: 0,
				ExitCode:      7,
			},
		},
		{
			name: "scan_error_only",
			input: ScanResultInput{
				MaxSeverity:   "INFO",
				TotalFindings: 0,
				ScanError:     "scanner crashed",
			},
		},
		{
			name: "both_set",
			input: ScanResultInput{
				MaxSeverity:   "INFO",
				TotalFindings: 0,
				ExitCode:      2,
				ScanError:     "boom",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := EvaluateAdmissionFallback(AdmissionInput{
				TargetType: "plugin",
				TargetName: "failed-scan-target",
				Path:       "/tmp/plugins/failed-scan-target",
				ScanResult: &tc.input,
			}, nil)
			if out == nil {
				t.Fatal("nil AdmissionOutput")
			}
			if out.Verdict != "rejected" {
				t.Errorf("Verdict = %q, want rejected", out.Verdict)
			}
			if out.FileAction != "quarantine" {
				t.Errorf("FileAction = %q, want quarantine", out.FileAction)
			}
			if out.InstallAction != "block" {
				t.Errorf("InstallAction = %q, want block", out.InstallAction)
			}
			if out.RuntimeAction != "block" {
				t.Errorf("RuntimeAction = %q, want block", out.RuntimeAction)
			}
		})
	}
}

// TestEvaluateAdmissionFallback_CleanScanStillPasses ensures the new
// scan-error gate does not regress the happy path: a scan that exits
// 0 with no findings must still be admitted as clean.
func TestEvaluateAdmissionFallback_CleanScanStillPasses(t *testing.T) {
	out := EvaluateAdmissionFallback(AdmissionInput{
		TargetType: "plugin",
		TargetName: "ok-target",
		Path:       "/tmp/plugins/ok-target",
		ScanResult: &ScanResultInput{
			MaxSeverity:   "INFO",
			TotalFindings: 0,
			ExitCode:      0,
		},
	}, nil)
	if out == nil {
		t.Fatal("nil AdmissionOutput")
	}
	if out.Verdict != "clean" {
		t.Errorf("clean scan should remain clean, got %q", out.Verdict)
	}
}
