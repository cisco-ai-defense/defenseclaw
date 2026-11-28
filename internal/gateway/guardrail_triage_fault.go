// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
)

// Triage faults (rel-1-0-10:GAP-1953). The triage readers of regex_judge and
// judge_first must not panic; when one does, the inspection could not read
// the text, and fewer signals is not an answer for it. A panic in triage is
// contained here, counted and logged as an evaluator fault, and answered with
// the triage-fault finding at CRITICAL, as a tool call the evaluation failed
// on is (evaluationFaultFindings): finalize then maps it like any CRITICAL
// verdict (a block in action mode, observe mode reports it), never an allow
// because the signals were lost. Before this, judge_first sent nil signals
// from its recovered goroutine (the judge alone decided, GAP-1933's allow)
// and regex_judge had no recovery at all (the inspection panicked).

// triageFaultHook is a test-only seam: when non-nil it runs at the start of
// every guarded triage scan, inside its recovery, so a test can make triage
// fail. Production never sets it.
var triageFaultHook func(direction string)

// triageFaultFinding is the finding of an inspection whose triage panicked.
const triageFaultFinding = "TRIAGE-EVALUATION-FAULT:The text could not be checked safely (internal triage error)"

// guardedTriagePatterns is triagePatternsFor with the triage-fault recovery:
// a panic marks the inspection degraded, reaches the panic recorder and the
// evaluator-fault log, and reports faulted with no signals.
func (g *GuardrailInspector) guardedTriagePatterns(ctx context.Context, direction, content string) (signals []TriageSignal, faulted bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			g.recordRecoveredPanic(ctx)
			logEvaluatorFault("guardrail triage direction="+direction, recovered)
			signals, faulted = nil, true
		}
	}()
	if triageFaultHook != nil {
		triageFaultHook(direction)
	}
	return triagePatternsFor(ctx, direction, content), false
}

// withTriageFault returns verdict raised to the triage-fault answer: the
// fault finding first, CRITICAL with the action the default thresholds give
// it unless verdict is already as severe. verdict is not modified.
func withTriageFault(verdict *ScanVerdict) *ScanVerdict {
	const severity = "CRITICAL"
	if verdict == nil || verdict.Severity == "" || verdict.Severity == "NONE" {
		return &ScanVerdict{
			Action:         guardrailFallbackActionForSeverity(severity),
			Severity:       severity,
			Reason:         "triage: " + triageFaultFinding,
			Findings:       []string{triageFaultFinding},
			Scanner:        "local-triage",
			ScannerSources: []string{"local-triage"},
		}
	}
	out := *verdict
	if severityRank[severity] > severityRank[out.Severity] {
		out.Action, out.Severity = guardrailFallbackActionForSeverity(severity), severity
	}
	out.Reason = "triage: " + triageFaultFinding + "; " + out.Reason
	out.Findings = append([]string{triageFaultFinding}, out.Findings...)
	if !slices.Contains(out.ScannerSources, "local-triage") {
		out.ScannerSources = append(slices.Clone(out.ScannerSources), "local-triage")
	}
	return &out
}
