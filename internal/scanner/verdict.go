// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import "strings"

// InferVerdict derives clean | warn | block from findings and errors.
func InferVerdict(r *ScanResult) string {
	if r == nil {
		return "clean"
	}
	if strings.TrimSpace(r.ScanError) != "" && len(r.Findings) == 0 {
		return "block"
	}
	if len(r.Findings) == 0 {
		return "clean"
	}
	switch r.MaxSeverity() {
	case SeverityCritical, SeverityHigh:
		return "block"
	case SeverityMedium, SeverityLow:
		return "warn"
	default:
		return "clean"
	}
}

// VerdictForResult returns explicit Verdict when set, else InferVerdict.
func VerdictForResult(r *ScanResult) string {
	if r == nil {
		return "clean"
	}
	if strings.TrimSpace(r.Verdict) != "" {
		return r.Verdict
	}
	return InferVerdict(r)
}
