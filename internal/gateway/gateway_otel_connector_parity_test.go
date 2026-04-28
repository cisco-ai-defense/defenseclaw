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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestHandleGuardrailEvent_OTelAgentName_PerConnector parametrizes
// the v7 review finding H3 check (TestHandleGuardrailEvent_OTelMetricsRecorded)
// over the full connector matrix. For every connector, the
// SharedAgentRegistry-tagged “gen_ai.agent.name“ attribute on the
// gen_ai.client.token.usage histogram MUST equal the connector
// name. Without per-connector parity, Splunk cost attribution only
// covers OpenClaw; switching to claudecode/codex/zeptoclaw at runtime
// would silently strip the tag and merge spend with the OpenClaw
// bucket. Plan E1 / item 3.
func TestHandleGuardrailEvent_OTelAgentName_PerConnector(t *testing.T) {
	for _, connectorName := range []string{"openclaw", "zeptoclaw", "claudecode", "codex"} {
		t.Run(connectorName, func(t *testing.T) {
			store, logger := testStoreAndLogger(t)
			reader := sdkmetric.NewManualReader()
			otelProvider, err := telemetry.NewProviderForTest(reader)
			if err != nil {
				t.Fatalf("NewProviderForTest: %v", err)
			}
			defer otelProvider.Shutdown(context.Background())

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

			api := &APIServer{health: NewSidecarHealth(), logger: logger, store: store}
			api.SetOTelProvider(otelProvider)

			tokIn := int64(64)
			tokOut := int64(32)
			body, _ := json.Marshal(guardrailEventRequest{
				Direction: "prompt",
				Model:     "gpt-4",
				Action:    "allow",
				Severity:  "INFO",
				Reason:    "ok",
				Findings:  []string{},
				ElapsedMs: 1.0,
				TokensIn:  &tokIn,
				TokensOut: &tokOut,
			})

			req := httptest.NewRequest(http.MethodPost, "/v1/guardrail/event", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			api.handleGuardrailEvent(rec, req)

			if rec.Result().StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d; body: %s",
					rec.Result().StatusCode, http.StatusOK, rec.Body.String())
			}

			var rm metricdata.ResourceMetrics
			if err := reader.Collect(context.Background(), &rm); err != nil {
				t.Fatalf("Collect: %v", err)
			}
			tokenMetric := findMetric(rm, "gen_ai.client.token.usage")
			if tokenMetric == nil {
				t.Fatal("expected gen_ai.client.token.usage metric")
			}
			tokenHist, ok := tokenMetric.Data.(metricdata.Histogram[float64])
			if !ok {
				t.Fatalf("expected Histogram[float64], got %T", tokenMetric.Data)
			}

			// We just reset sharedReg above and re-installed it with
			// our connector name, so the registry-merged tag MUST be
			// our own. If a future refactor adds a different code
			// path that swallows the reset, this loop catches it.
			var sawAgentName bool
			for _, dp := range tokenHist.DataPoints {
				for _, attr := range dp.Attributes.ToSlice() {
					if string(attr.Key) == "gen_ai.agent.name" &&
						attr.Value.AsString() == connectorName {
						sawAgentName = true
					}
				}
			}
			if !sawAgentName {
				t.Errorf("connector=%s: expected gen_ai.agent.name=%q on gen_ai.client.token.usage; found none",
					connectorName, connectorName)
			}
		})
	}
}
