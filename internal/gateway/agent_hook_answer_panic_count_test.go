// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

type panickingHookOutputValue struct{}

func (panickingHookOutputValue) MarshalJSON() ([]byte, error) {
	panic("synthetic hook output encoding panic")
}

// GAP-1114: a recovered answer-encoding panic counts once in the panic
// counter and leaves the finalized answer and audit row alone.
func TestHandleAgentHookAnswerEncodingPanicCountsOnce(t *testing.T) {
	useHookRuntimeForTest(t, "antigravity", func() agentHookResponse {
		return agentHookResponse{
			Action: "confirm", RawAction: "confirm", Mode: "action", Reason: "review this command",
			HookOutput: map[string]interface{}{"decision": "force_ask", "bad": panickingHookOutputValue{}},
		}
	})
	runtime, _ := newProxyGeneratedTraceRuntime(t)
	capture := &managedAIDFailOpenCapture{lifecycleV8Runtime: runtime}
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	api.bindObservabilityV8Runtimes(capture, nil, nil, capture)
	answer, row := postAntigravityConfirmForTest(t, api, "encoding-panic")
	if answer.Action != "confirm" || answer.Output.Decision != "force_ask" {
		t.Fatalf("answer=%+v, want the finalized confirmation", answer)
	}
	if row.Structured["action"] != "confirm" || row.Enforced {
		t.Fatalf("audit row=%+v, want the native confirmation", row.Structured)
	}
	if got := countGeneratedMetricRecordsByName(capture.metricRecords, observability.TelemetryInstrumentDefenseClawPanicsTotal); got != 1 {
		t.Fatalf("answer encoding panic count=%d, want one", got)
	}
}
