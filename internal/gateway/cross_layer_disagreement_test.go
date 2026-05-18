// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

func TestCrossLayerDisagreement_DetectsTwoRankGap(t *testing.T) {
	regex := &ScanVerdict{Severity: "CRITICAL"}
	judge := &ScanVerdict{Severity: "MEDIUM"}

	got := crossLayerDisagreement(regex, judge)
	if got == "" {
		t.Fatal("expected disagreement annotation for CRITICAL vs MEDIUM, got empty")
	}
	if !strings.Contains(got, "CRITICAL") || !strings.Contains(got, "MEDIUM") || !strings.Contains(got, "gap=2") {
		t.Errorf("annotation missing expected fields: %q", got)
	}
}

func TestCrossLayerDisagreement_IgnoresOneRankGap(t *testing.T) {
	regex := &ScanVerdict{Severity: "HIGH"}
	judge := &ScanVerdict{Severity: "MEDIUM"}

	got := crossLayerDisagreement(regex, judge)
	if got != "" {
		t.Errorf("expected no annotation for HIGH vs MEDIUM (one-rank gap), got %q", got)
	}
}

func TestCrossLayerDisagreement_Symmetric(t *testing.T) {
	// Judge overrating regex by 2 ranks should also fire — direction
	// of the gap is not the signal; the magnitude is.
	regex := &ScanVerdict{Severity: "LOW"}
	judge := &ScanVerdict{Severity: "CRITICAL"}

	got := crossLayerDisagreement(regex, judge)
	if got == "" {
		t.Fatal("expected annotation for LOW vs CRITICAL, got empty")
	}
	if !strings.Contains(got, "gap=3") {
		t.Errorf("expected gap=3 for LOW vs CRITICAL, got %q", got)
	}
}

func TestCrossLayerDisagreement_NilVerdicts(t *testing.T) {
	if got := crossLayerDisagreement(nil, &ScanVerdict{Severity: "CRITICAL"}); got != "" {
		t.Errorf("nil regex should return empty, got %q", got)
	}
	if got := crossLayerDisagreement(&ScanVerdict{Severity: "CRITICAL"}, nil); got != "" {
		t.Errorf("nil judge should return empty, got %q", got)
	}
}

func TestMergeWithJudge_IncrementsDisagreementCounter(t *testing.T) {
	before := CrossLayerDisagreementCount()

	regex := &ScanVerdict{Severity: "CRITICAL", Action: "block", Reason: "regex matched /etc/shadow"}
	judge := &ScanVerdict{Severity: "MEDIUM", Action: "alert", Reason: "judge thinks documentation"}

	merged := mergeWithJudge(regex, judge)
	after := CrossLayerDisagreementCount()

	if after != before+1 {
		t.Errorf("counter = %d, want %d (before=%d)", after, before+1, before)
	}
	if !strings.Contains(merged.Reason, "cross-layer-disagreement") {
		t.Errorf("merged verdict reason missing disagreement annotation: %q", merged.Reason)
	}
}

func TestMergeWithJudge_NoCounterBumpWhenAligned(t *testing.T) {
	before := CrossLayerDisagreementCount()

	regex := &ScanVerdict{Severity: "HIGH", Action: "alert"}
	judge := &ScanVerdict{Severity: "HIGH", Action: "alert"}

	_ = mergeWithJudge(regex, judge)
	after := CrossLayerDisagreementCount()

	if after != before {
		t.Errorf("counter bumped unexpectedly: before=%d after=%d", before, after)
	}
}
