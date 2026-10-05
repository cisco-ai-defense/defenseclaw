// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestPreparedGuardrailReadsInputThresholds evaluates the shipped
// guardrail.rego through queries prepared once: the block level comes from
// input.thresholds, not data.json.
func TestPreparedGuardrailReadsInputThresholds(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "..", "..", "policies", "rego")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("policies/rego not found: %v", err)
	}
	prepared, err := Prepare(context.Background(), dir)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	input := GuardrailInput{
		Direction:   "prompt",
		Mode:        "action",
		LocalResult: &GuardrailScanResult{Action: "alert", Severity: "MEDIUM"},
	}
	for _, tc := range []struct {
		thresholds *ThresholdsInput
		want       string
	}{
		{nil, "alert"},
		{&ThresholdsInput{Block: 2, Alert: 1, CiscoTrustLevel: "full"}, "block"},
	} {
		input.Thresholds = tc.thresholds
		out, err := prepared.EvaluateGuardrail(context.Background(), input)
		if err != nil || out.Action != tc.want {
			t.Fatalf("thresholds %+v: action = %v, %v; want %s", tc.thresholds, out, err, tc.want)
		}
	}
}
