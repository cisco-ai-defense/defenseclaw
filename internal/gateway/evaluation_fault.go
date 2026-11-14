// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"runtime/debug"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// Evaluator faults (rel-1-0-10:GAP-0437). The readers and the shell parser
// they call must not panic: a parser fault is contained where it happens
// (shellparse.ParseRecovering) and read as a bounded reading. These
// recoveries are the defense in depth behind that rule. They log the fault
// with its stack as a bug and keep the gateway process running; they are
// never the way a verdict is reached.

// evaluatorFaults counts the faults recovered here, for tests and the log.
var evaluatorFaults atomic.Int64

// trustedActionFaultHook is a test-only seam: when non-nil it runs at the
// start of every dispatchTrustedAction, so a route test can make the
// evaluation fail. Production never sets it.
var trustedActionFaultHook func(trustedActionRequest)

// recoverTrustedActionFault is deferred by dispatchTrustedAction, the one
// evaluation entry of every route that reads a tool call (the hook routes,
// /api/v1/inspect/tool, the OpenClaw approval and tool_call events, the
// proxy's tool-call checks, sandbox shell calls). A panic in the evaluation
// becomes the evaluation-limit finding with the bounded reason (cap=nodes:
// the reading stopped in the parse), which each route's profile maps to the
// pack's unknown tier: an alert in the default and permissive packs (a
// managed install's included), a block in the strict pack, as for any
// truncated input (boundedTruncatedFinding).
func recoverTrustedActionFault(request trustedActionRequest, findings *[]RuleFinding) {
	recovered := recover()
	if recovered == nil {
		return
	}
	logEvaluatorFault("trusted action evaluation connector="+request.Connector, recovered)
	*findings = []RuleFinding{boundedTruncatedFinding(bounded.Of(bounded.Nodes), request.EnforcementCapable)}
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

// toolCheckFaultVerdict is the /api/v1/inspect/tool answer when the check
// itself failed outside the evaluation: a block, like a hook check that
// could not complete. The route's mode still applies (observe reports it as
// would_block).
func toolCheckFaultVerdict() *ToolInspectVerdict {
	return &ToolInspectVerdict{
		Action:     "block",
		Severity:   "HIGH",
		Confidence: 1,
		Reason:     "DefenseClaw could not complete its tool check because of an internal error",
		Findings:   []string{"INSPECT-INTERNAL-ERROR"},
	}
}
