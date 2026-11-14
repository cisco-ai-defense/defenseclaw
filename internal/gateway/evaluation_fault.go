// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"slices"
	"sync/atomic"
)

// Evaluator faults (rel-1-0-10:GAP-0437, GAP-0486). The readers and the
// shell parser they call must not panic: a parser fault is contained where it
// happens (shellparse.ParseRecovering), and the recoveries here are the
// defense in depth behind that rule. Either way the call is one the gateway
// could not read, and the answer is the one the hook recovery gave on 1.0.10
// before the containment: a block in every pack and mode, with its own
// reason (evaluationFaultFindings). The process keeps running; a recovered
// panic is logged with its stack as a bug.

// evaluatorFaults counts the faults recovered here, for tests and the log.
var evaluatorFaults atomic.Int64

// trustedActionFaultHook is a test-only seam: when non-nil it runs at the
// start of every dispatchTrustedAction, so a route test can make the
// evaluation fail. Production never sets it.
var trustedActionFaultHook func(trustedActionRequest)

// acpEvaluateFaultHook is a test-only seam: when non-nil it runs at the start
// of every ACP frame evaluation (handleACPEvaluate), inside its recovery, so
// a route test can make it fail. Production never sets it.
var acpEvaluateFaultHook func()

// parserFaultTitle is the reason of a call the shell parser failed on.
const parserFaultTitle = "The command could not be parsed safely"

// evaluatorFaultTitle is the reason of a call a reader failed on (a
// recovered panic).
const evaluatorFaultTitle = "The command could not be checked safely (internal evaluator error)"

// evaluationFaultFindings is the verdict of a call the evaluation failed
// on: the reader-failure finding, marked evaluationFault, which blocks in
// every pack (profileClassFloor) and, on the hook routes, in observe mode
// too (hookActionMustEnforce).
func evaluationFaultFindings(title string, enforcementCapable bool) []RuleFinding {
	finding := RuleFinding{
		RuleID: parseFailureRuleID, Title: title, Severity: "CRITICAL", Confidence: 1,
		enforcement: findingEnforcementAllowed, evaluationFault: true,
	}.withTrustedActionProof(newEvaluationFailureFindingProof(parseFailureRuleID))
	return applyTrustedActionProofBoundary([]RuleFinding{finding}, enforcementCapable)
}

// withParserFaultFinding puts the parser-fault finding first in findings
// (its title is the call's reason) and keeps every other reader's finding.
func withParserFaultFinding(findings []RuleFinding, enforcementCapable bool) []RuleFinding {
	if slices.ContainsFunc(findings, func(finding RuleFinding) bool { return finding.evaluationFault }) {
		return findings
	}
	return append(evaluationFaultFindings(parserFaultTitle, enforcementCapable), findings...)
}

// hasEvaluationFault reports an enforceable evaluation-fault finding.
func hasEvaluationFault(findings []RuleFinding) bool {
	return slices.ContainsFunc(findings, func(finding RuleFinding) bool {
		return finding.evaluationFault && finding.contributesToEnforcement()
	})
}

// evaluationFaultMustEnforce reports a blocked verdict that rests on an
// evaluation fault, which a hook route enforces in observe mode, as the hook
// recovery's failed-check answer did. The Secure Client integration keeps
// its own mapping. /inspect/tool and ACP report it as would_block in observe
// mode, as any block. The asymmetry is deliberate (rel parity on the hook
// routes, which blocked it on rel); see hookActionMustEnforce before changing
// either side.
func (a *APIServer) evaluationFaultMustEnforce(ctx context.Context, verdict *ToolInspectVerdict) bool {
	if verdict == nil || normalizeCodexAction(verdict.Action) != "block" || !hasEvaluationFault(verdict.DetailedFindings) {
		return false
	}
	cfg := a.decisionConfig(ctx)
	return cfg == nil || !cfg.SecureClientIntegration()
}

// recoverTrustedActionFault is deferred by dispatchTrustedAction, the one
// evaluation entry of every route that reads a tool call (the hook routes,
// /api/v1/inspect/tool, the OpenClaw approval and tool_call events, the
// proxy's tool-call checks, sandbox shell calls). A panic in the evaluation
// becomes the evaluation-fault finding: a block in every pack.
func recoverTrustedActionFault(request trustedActionRequest, findings *[]RuleFinding) {
	recovered := recover()
	if recovered == nil {
		return
	}
	logEvaluatorFault("trusted action evaluation connector="+request.Connector, recovered)
	*findings = evaluationFaultFindings(evaluatorFaultTitle, request.EnforcementCapable)
}

// recoverGatewayGoroutine is deferred at the top of a gateway goroutine that
// no handler recovery covers. It logs the fault and runs answer (when not
// nil) to give the caller a failed-check answer instead of none.
func recoverGatewayGoroutine(where string, answer func()) {
	recovered := recover()
	if recovered == nil {
		return
	}
	logEvaluatorFault(where, recovered)
	if answer != nil {
		func() {
			defer func() {
				if again := recover(); again != nil {
					logEvaluatorFault(where+" (answer)", again)
				}
			}()
			answer()
		}()
	}
}

func logEvaluatorFault(where string, recovered any) {
	evaluatorFaults.Add(1)
	fmt.Fprintf(os.Stderr, "[gateway] PANIC recovered in %s (a DefenseClaw bug: please report it): %v\n%s\n",
		where, recovered, debug.Stack())
}

// toolCheckFaultVerdict is the answer of a route whose check failed outside
// the evaluation (/api/v1/inspect/tool's worker, an ACP evaluation): a block
// in every pack, mapped by the route's mode (observe reports would_block).
func toolCheckFaultVerdict() *ToolInspectVerdict {
	return &ToolInspectVerdict{
		Action:           "block",
		Severity:         "CRITICAL",
		Confidence:       1,
		Reason:           "DefenseClaw could not complete its tool check because of an internal error",
		Findings:         []string{"INSPECT-INTERNAL-ERROR"},
		DetailedFindings: evaluationFaultFindings(evaluatorFaultTitle, true),
	}
}
