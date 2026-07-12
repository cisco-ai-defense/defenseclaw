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

// TestHandleGuardrailEvent_GeneratedAgentName_PerConnector parametrizes
// the connector-attribution check over the generated v8 path
// over the full connector matrix. For every connector, the
// SharedAgentRegistry-tagged “gen_ai.agent.name“ attribute on the
// gen_ai.client.token.usage histogram MUST equal the connector
// name. Without per-connector parity, Splunk cost attribution only
// covers OpenClaw; switching to claudecode/codex/zeptoclaw at runtime
// would silently strip the tag and merge spend with the OpenClaw
// bucket. Plan E1 / item 3.
func TestHandleGuardrailEvent_GeneratedAgentName_PerConnector(t *testing.T) {
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
				if metric.Attributes()["gen_ai.agent.name"] != connectorName {
					t.Fatalf("connector=%s: generated token attributes=%v", connectorName, metric.Attributes())
				}
			}
		})
	}
}
