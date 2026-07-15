// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// TestHandleGuardrailEvent_GeneratedTokenMetricsRemainBounded_PerConnector
// proves that installing connector-specific shared identity cannot leak that
// identity into the exported token series. Exact connector and agent identity
// remains available on canonical logs/traces and in the correlation ledger.
func TestHandleGuardrailEvent_GeneratedTokenMetricsRemainBounded_PerConnector(t *testing.T) {
	for _, connectorName := range []string{"openclaw", "zeptoclaw", "claudecode", "codex"} {
		t.Run(connectorName, func(t *testing.T) {
			// InstallSharedAgentRegistry is *merge-once*: the first
			// non-empty configuredAgentName sticks for the lifetime of
			// the process, which is the right semantics in production
			// (config doesn't hot-swap) but wrong for a parametrized
			// per-connector parity test. Reset the package-global so
			// each subtest gets a fresh tag association. We're in the
			// gateway package so we can reach `sharedReg` directly.
			sharedRegMu.Lock()
			sharedReg = nil
			sharedRegMu.Unlock()
			InstallSharedAgentRegistry("agent-e1-"+connectorName, connectorName)
			t.Cleanup(func() {
				sharedRegMu.Lock()
				sharedReg = nil
				sharedRegMu.Unlock()
			})

			api, capture := newGuardrailEventV8TestAPI(t)

			tokIn := int64(64)
			tokOut := int64(32)
			body, _ := json.Marshal(guardrailEventRequest{
				EvaluationID: "eval-agent-" + connectorName,
				Direction:    "prompt",
				Model:        "gpt-4",
				Action:       "allow",
				Severity:     "INFO",
				Reason:       "ok",
				Findings:     []string{},
				ElapsedMs:    1.0,
				TokensIn:     &tokIn,
				TokensOut:    &tokOut,
			})

			req := httptest.NewRequest(http.MethodPost, "/v1/guardrail/event", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			api.handleGuardrailEvent(rec, req)

			if rec.Result().StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d; body: %s",
					rec.Result().StatusCode, http.StatusOK, rec.Body.String())
			}

			tokens := generatedMetricByName(capture.metricSnapshot(), observability.TelemetryInstrumentGenAIClientTokenUsage)
			if len(tokens) != 2 {
				t.Fatalf("generated token metrics=%d, want 2", len(tokens))
			}
			for _, metric := range tokens {
				attributes := metric.Attributes()
				if attributes["gen_ai.provider.name"] != "defenseclaw" ||
					attributes["gen_ai.operation.name"] != "chat" ||
					attributes["gen_ai.request.model"] != "gpt-4" {
					t.Fatalf("connector=%s: generated token attributes=%v", connectorName, metric.Attributes())
				}
				for _, key := range []string{"gen_ai.agent.id", "gen_ai.agent.name", "gen_ai.conversation.id"} {
					if _, leaked := attributes[key]; leaked {
						t.Fatalf("connector=%s: high-cardinality %q leaked into token attributes=%v", connectorName, key, attributes)
					}
				}
			}
		})
	}
}
