// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managedaid

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
)

type testProvider struct {
	mu          sync.Mutex
	token       string
	tokenErr    error
	fresh       string
	tokenCalls  int
	invalidates int
}

func (provider *testProvider) Token(context.Context) (string, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.tokenCalls++
	return provider.token, provider.tokenErr
}
func (*testProvider) Refresh(context.Context) error { return nil }
func (provider *testProvider) Invalidate() {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.invalidates++
	provider.token = provider.fresh
}
func (provider *testProvider) snapshot() (int, int) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.tokenCalls, provider.invalidates
}

type testResolver struct {
	provider cloudreg.Provider
	err      error
	calls    atomic.Int64
}

type panickingNetworkResolver struct{}

type testNetworkError struct{}

func (testNetworkError) Error() string   { return "temporary network failure" }
func (testNetworkError) Timeout() bool   { return true }
func (testNetworkError) Temporary() bool { return true }

func (panickingNetworkResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	panic("resolver implementation panic")
}

func (resolver *testResolver) ResolveCMIDProvider(context.Context) (cloudreg.Provider, error) {
	resolver.calls.Add(1)
	return resolver.provider, resolver.err
}

func testConfig(endpoint string) Config {
	return Config{
		Destination: config.ObservabilityV8ManagedAIDDestinationName,
		Endpoint:    endpoint,
		LoggerName:  "defenseclaw",
		ContentHash: strings.Repeat("a", 64),
		Timeout:     time.Second,
		Resource: otlp.LogResourceSnapshot{
			SchemaURL: "https://opentelemetry.io/schemas/1.42.0",
			Values: map[string]string{
				"service.name": "defenseclaw", "service.instance.id": "managed-generation",
				"defenseclaw.device.public_key_fingerprint": "sha256:managed-device",
				"host.name": "managed-host",
			},
		},
	}
}

func TestMain(main *testing.M) {
	gatewaylog.SetTelemetryHMACSeed([]byte("managed-aid-test-hmac-seed-32-bytes"))
	os.Exit(main.Run())
}

func testPayload(t *testing.T) delivery.Payload {
	t.Helper()
	projected := `{"record_id":"record-managed-1","timestamp":"2026-07-13T12:00:00Z","severity":"INFO","body":{"message":"[REDACTED]"},"correlation":{"trace_id":"1234567890abcdef1234567890abcdef","span_id":"1234567890abcdef"}}`
	payload, err := delivery.NewPayload([]byte(projected), delivery.RoutingIdentity{
		RecordID: "record-managed-1", Bucket: "diagnostic", Signal: "logs", EventName: "diagnostic.message",
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func testDispatcher(t *testing.T, adapter delivery.Adapter) *delivery.Dispatcher {
	return testDispatcherAttempts(t, adapter, 1)
}

func testDispatcherAttempts(t *testing.T, adapter delivery.Adapter, attempts int) *delivery.Dispatcher {
	t.Helper()
	dispatcher, err := delivery.NewDispatcher(delivery.Config{
		Destination: config.ObservabilityV8ManagedAIDDestinationName,
		Generation:  7, Signal: "logs", Enabled: true,
		MaxQueueItems: 8, MaxQueueBytes: 8 * 1024 * 1024,
		MaxBatchItems: 8, MaxBatchBytes: 8 * 1024 * 1024,
		ScheduledDelay: 0, AttemptTimeout: 2 * time.Second,
		Retry: delivery.RetryPolicy{MaxAttempts: attempts},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	return dispatcher
}

func flushAndClose(t *testing.T, dispatcher *delivery.Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := dispatcher.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterWrapsCanonicalOTLPJSONAndRemintsOnce(t *testing.T) {
	provider := &testProvider{token: "stale-token", fresh: "fresh-token"}
	var requests atomic.Int64
	var body []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != config.ObservabilityV8ManagedAIDIngestPath || request.Method != http.MethodPost {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		attempt := requests.Add(1)
		if attempt == 1 {
			if request.Header.Get("Authorization") != "Bearer stale-token" {
				t.Errorf("first authorization = %q", request.Header.Get("Authorization"))
			}
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if request.Header.Get("Authorization") != "Bearer fresh-token" {
			t.Errorf("retry authorization = %q", request.Header.Get("Authorization"))
		}
		body, _ = io.ReadAll(request.Body)
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	resolver := &testResolver{provider: provider}
	source := testConfig(server.URL + config.ObservabilityV8ManagedAIDIngestPath)
	source.Network.AllowPrivateNetworks = true
	adapter, err := New(t.Context(), source, resolver)
	if err != nil {
		t.Fatal(err)
	}
	adapter.client = server.Client()
	if resolver.calls.Load() != 0 {
		t.Fatal("CMID provider was resolved during generation preparation")
	}
	dispatcher := testDispatcher(t, adapter)
	if result := dispatcher.Enqueue(testPayload(t)); !result.Accepted() {
		t.Fatalf("enqueue = %+v", result)
	}
	flushAndClose(t, dispatcher)

	if requests.Load() != 2 || resolver.calls.Load() != 1 {
		t.Fatalf("requests=%d resolver calls=%d", requests.Load(), resolver.calls.Load())
	}
	if tokenCalls, invalidates := provider.snapshot(); tokenCalls != 2 || invalidates != 1 {
		t.Fatalf("token calls=%d invalidates=%d", tokenCalls, invalidates)
	}
	var envelope struct {
		Payload struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []struct {
						Body    map[string]any `json:"body"`
						TraceID string         `json:"traceId"`
						SpanID  string         `json:"spanId"`
					} `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode request: %v: %s", err, body)
	}
	record := envelope.Payload.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	projected, _ := record.Body["stringValue"].(string)
	if !strings.Contains(projected, `"message":"[REDACTED]"`) || strings.Contains(projected, "stale-token") {
		t.Fatalf("canonical projection was not preserved safely: %q", projected)
	}
	if record.TraceID != "1234567890abcdef1234567890abcdef" || record.SpanID != "1234567890abcdef" {
		t.Fatalf("OTLP/JSON ids = %q/%q", record.TraceID, record.SpanID)
	}
}

func TestAdapterManagedCompatibilityGoldenWire(t *testing.T) {
	provider := &testProvider{token: "managed-token"}
	var (
		requestsMu sync.Mutex
		requests   [][]byte
	)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		requestsMu.Lock()
		requests = append(requests, body)
		requestsMu.Unlock()
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	source := testConfig(server.URL + config.ObservabilityV8ManagedAIDIngestPath)
	source.Network.AllowPrivateNetworks = true
	adapter, err := New(t.Context(), source, &testResolver{provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	adapter.client = server.Client()
	dispatcher := testDispatcher(t, adapter)
	// Under Vineet's v8-only contract, redaction runs BEFORE the
	// adapter's compat layer — every raw path / token / private
	// field has already been stripped by the time these payloads
	// reach here. The golden payloads represent that
	// already-redacted state: no raw_path, no command_path, no url
	// with a token, no raw_binary_path, no operator-authorization
	// leakage. The verdict record retains the redacted-reason
	// marker and no operator-authorization field.
	payloads := []delivery.Payload{
		managedGoldenPayload(t, "verdict-record", "guardrail.evaluation", "guardrail.evaluation.completed", "guardrail-verdict", map[string]any{
			"defenseclaw.evaluation.id":              "evaluation-1",
			"defenseclaw.guardrail.stage":            "final",
			"defenseclaw.guardrail.direction":        "prompt",
			"defenseclaw.guardrail.effective_action": "block",
			"defenseclaw.guardrail.reason":           "[REDACTED]",
			"defenseclaw.guardrail.latency_ms":       42,
			"defenseclaw.guardrail.rule_ids":         []string{"rule-1"},
			"gen_ai.request.model":                   "gpt-test",
		}),
		managedGoldenPayload(t, "connector-record", "ai.discovery", "ai.discovery.completed", string(config.ObservabilityV8ManagedConnectorInventoryAction), map[string]any{
			"defenseclaw.ai.discovery.source":         "endpoint_connector_inventory",
			"defenseclaw.ai.discovery.result":         "completed",
			"defenseclaw.ai.discovery.signals_total":  1,
			"defenseclaw.ai.discovery.active_signals": 1,
			"defenseclaw.ai.discovery.errors":         0,
			"defenseclaw.inventory.connector.identifiers": []any{
				map[string]any{"name": "codex"},
			},
			"defenseclaw.inventory.connector.metadata": []any{
				map[string]any{"source": "built-in", "tool_inspection_mode": "both", "subprocess_policy": "sandbox"},
			},
			"defenseclaw.inventory.connector.content": []any{
				map[string]any{"description": "Codex connector"},
			},
		}),
		managedGoldenPayload(t, "mcp-record", "ai.discovery", "ai.discovery.completed", string(config.ObservabilityV8ManagedMCPInventoryAction), map[string]any{
			"defenseclaw.ai.discovery.source":         "endpoint_mcp_inventory",
			"defenseclaw.ai.discovery.result":         "completed",
			"defenseclaw.ai.discovery.signals_total":  1,
			"defenseclaw.ai.discovery.active_signals": 1,
			"defenseclaw.ai.discovery.errors":         0,
			"defenseclaw.inventory.mcp.identifiers": []any{
				map[string]any{"name": "safe-server", "url_host": "mcp.example.test:8443"},
			},
			"defenseclaw.inventory.mcp.metadata": []any{
				map[string]any{"transport": "stdio", "command_basename": "mcp-server", "auth_provider_type": "oauth", "disabled": false},
			},
		}),
		managedGoldenPayload(t, "agent-record", "ai.discovery", "ai.discovery.completed", string(config.ObservabilityV8ManagedAgentInventoryAction), map[string]any{
			"defenseclaw.ai.discovery.source":         "agent_discovery_api",
			"defenseclaw.ai.discovery.result":         "completed",
			"defenseclaw.ai.discovery.signals_total":  1,
			"defenseclaw.ai.discovery.active_signals": 1,
			"defenseclaw.ai.discovery.errors":         0,
			"defenseclaw.agent.discovery.scanned_at":  "2026-07-13T12:00:00Z",
			"defenseclaw.inventory.agent.identifiers": []any{
				map[string]any{"name": "claudecode", "config_path_hash": "sha256:" + strings.Repeat("a", 64), "binary_path_hash": "sha256:" + strings.Repeat("b", 64)},
			},
			"defenseclaw.inventory.agent.metadata": []any{
				map[string]any{"installed": true, "has_config": true, "config_basename": "settings.json", "has_binary": true, "binary_basename": "claude", "version": "1.2.3", "probe_status": "ok"},
			},
		}),
	}
	for _, payload := range payloads {
		if result := dispatcher.Enqueue(payload); !result.Accepted() {
			t.Fatalf("enqueue = %+v", result)
		}
	}
	flushAndClose(t, dispatcher)

	type wireRecord struct {
		Body       map[string]any `json:"body"`
		Attributes []struct {
			Key   string         `json:"key"`
			Value map[string]any `json:"value"`
		} `json:"attributes"`
		TraceID string `json:"traceId"`
		SpanID  string `json:"spanId"`
	}
	type wireResource struct {
		Attributes []struct {
			Key   string         `json:"key"`
			Value map[string]any `json:"value"`
		} `json:"attributes"`
	}
	var records []wireRecord
	requestsMu.Lock()
	captured := append([][]byte(nil), requests...)
	requestsMu.Unlock()
	if len(captured) == 0 {
		t.Fatal("managed endpoint received no requests")
	}
	for _, requestBody := range captured {
		var envelope struct {
			Payload struct {
				ResourceLogs []struct {
					Resource  wireResource `json:"resource"`
					ScopeLogs []struct {
						LogRecords []wireRecord `json:"logRecords"`
					} `json:"scopeLogs"`
				} `json:"resourceLogs"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(requestBody, &envelope); err != nil {
			t.Fatalf("decode managed wrapper: %v", err)
		}
		if len(envelope.Payload.ResourceLogs) != 1 {
			t.Fatalf("resourceLogs=%d", len(envelope.Payload.ResourceLogs))
		}
		resource := managedGoldenAttributeValues(envelope.Payload.ResourceLogs[0].Resource.Attributes)
		if resource["defenseclaw.device.public_key_fingerprint"] != "sha256:managed-device" ||
			resource["defenseclaw.device.id"] != "sha256:managed-device" ||
			resource["host.name"] != "managed-host" {
			t.Fatalf("managed resource anchor = %#v", resource)
		}
		for _, scope := range envelope.Payload.ResourceLogs[0].ScopeLogs {
			records = append(records, scope.LogRecords...)
		}
	}
	if len(records) != 4 {
		t.Fatalf("records=%d want 4", len(records))
	}

	// v8-only contract (Vineet's [P1] on managedaid/compatibility.go):
	// only the guardrail verdict retains the legacy schema-v7
	// gatewaylog.Event wrap; every ai.discovery inventory record now
	// flows through as its original canonical v8 OTLP log body with
	// the ai.discovery attributes preserved.
	var verdictSeen bool
	var inventoryRecords []wireRecord
	for _, record := range records {
		attributes := managedGoldenAttributeValues(record.Attributes)
		if record.TraceID != "1234567890abcdef1234567890abcdef" || record.SpanID != "1234567890abcdef" {
			t.Fatalf("topology=%s/%s", record.TraceID, record.SpanID)
		}
		body, _ := record.Body["stringValue"].(string)
		if body == "" || strings.Contains(body, "/private/") || strings.Contains(body, "token=secret") ||
			strings.Contains(body, "must-not-cross-managed-projection") {
			t.Fatalf("unsafe or empty managed body: %q", body)
		}
		if _, hasEventType := attributes["defenseclaw.gateway.event_type"]; hasEventType {
			// v7-projected verdict — flat contract still applies.
			eventType, _ := attributes["defenseclaw.gateway.event_type"].(string)
			if eventType != managedEventVerdict {
				t.Fatalf("unexpected v7 projection for eventType=%q — inventory should pass through as v8", eventType)
			}
			if verdictSeen {
				t.Fatal("more than one v7-projected verdict record")
			}
			verdictSeen = true
			if attributes["event.name"] != "defenseclaw.gateway."+eventType ||
				attributes["event.domain"] != "defenseclaw.gateway" ||
				attributes["defenseclaw.device.id"] != "sha256:managed-device" ||
				attributes["host.name"] != "managed-host" {
				t.Fatalf("verdict flat contract = %#v", attributes)
			}
			var event gatewaylog.Event
			if err := json.Unmarshal([]byte(body), &event); err != nil {
				t.Fatalf("decode verdict compatibility body: %v", err)
			}
			if event.ContentHash != strings.Repeat("a", 64) || event.PayloadHMAC == "" {
				t.Fatalf("verdict provenance/hash = %+v", event)
			}
			if gatewaylog.VerifyPayloadHMAC(event.Verdict, event.PayloadHMAC) != nil {
				t.Fatal("verdict payload HMAC did not verify")
			}
			if event.Verdict == nil || event.Verdict.Action != "block" ||
				event.Verdict.Stage != gatewaylog.Stage("final") ||
				event.Verdict.Reason != "[REDACTED]" || event.Verdict.LatencyMs != 42 ||
				event.RequestID != "request-verdict" || event.SessionID != "session-verdict" {
				t.Fatalf("verdict body = %+v", event)
			}
			continue
		}
		// v8 passthrough — the record.Body carries the exact canonical
		// v8 wire JSON, and the OTLP attributes carry the ai.discovery
		// identity fields.
		if attributes["defenseclaw.bucket"] != "ai.discovery" ||
			attributes["defenseclaw.event.name"] != "ai.discovery.completed" ||
			attributes["defenseclaw.signal"] != "logs" {
			t.Fatalf("v8 passthrough identity attributes = %#v", attributes)
		}
		if attributes["defenseclaw.connector.instance.id"] != "connector-instance-1" {
			t.Fatalf("v8 passthrough correlation missing: %#v", attributes)
		}
		inventoryRecords = append(inventoryRecords, record)
	}
	if !verdictSeen {
		t.Fatal("verdict record missing from managed egress")
	}
	if len(inventoryRecords) != 3 {
		t.Fatalf("v8 inventory passthrough count = %d, want 3 (connector + mcp + agent)", len(inventoryRecords))
	}

	// Assert the v8 wire body preserves per-inventory identifiers.
	// The body is the canonical JSON (bucket/action/body/correlation/
	// provenance) — decode it and verify the caller-supplied inventory
	// arrays appear intact.
	byAction := make(map[string]map[string]any, len(inventoryRecords))
	for _, record := range inventoryRecords {
		body, _ := record.Body["stringValue"].(string)
		var wire struct {
			Action     string         `json:"action"`
			Body       map[string]any `json:"body"`
			Provenance map[string]any `json:"provenance"`
		}
		if err := json.Unmarshal([]byte(body), &wire); err != nil {
			t.Fatalf("decode v8 passthrough body: %v", err)
		}
		if wire.Action == "" || wire.Body == nil {
			t.Fatalf("v8 passthrough body missing action/body: %s", body)
		}
		if _, alreadySeen := byAction[wire.Action]; alreadySeen {
			t.Fatalf("duplicate v8 passthrough record for action=%q", wire.Action)
		}
		byAction[wire.Action] = wire.Body
		// Provenance quartet stays in the payload for downstream
		// consumers — v8-only doesn't strip it.
		if wire.Provenance["config_digest"] != strings.Repeat("c", 64) {
			t.Fatalf("v8 passthrough provenance = %#v", wire.Provenance)
		}
	}
	// Connector inventory: identifiers preserved.
	connectorBody, ok := byAction[string(config.ObservabilityV8ManagedConnectorInventoryAction)]
	if !ok {
		t.Fatalf("managed_connector_inventory action not in passthrough set: %v", keysOf(byAction))
	}
	connectorIDs, _ := connectorBody["defenseclaw.inventory.connector.identifiers"].([]any)
	if len(connectorIDs) != 1 {
		t.Fatalf("connector identifiers count = %d", len(connectorIDs))
	}
	if got, _ := connectorIDs[0].(map[string]any)["name"].(string); got != "codex" {
		t.Fatalf("connector identifier name = %q", got)
	}
	// MCP inventory: identifiers preserved.
	mcpBody, ok := byAction[string(config.ObservabilityV8ManagedMCPInventoryAction)]
	if !ok {
		t.Fatalf("managed_mcp_inventory action not in passthrough set: %v", keysOf(byAction))
	}
	mcpIDs, _ := mcpBody["defenseclaw.inventory.mcp.identifiers"].([]any)
	if len(mcpIDs) != 1 {
		t.Fatalf("mcp identifiers count = %d", len(mcpIDs))
	}
	if got, _ := mcpIDs[0].(map[string]any)["name"].(string); got != "safe-server" {
		t.Fatalf("mcp identifier name = %q", got)
	}
	// Agent inventory: identifiers preserved.
	agentBody, ok := byAction[string(config.ObservabilityV8ManagedAgentInventoryAction)]
	if !ok {
		t.Fatalf("managed_agent_inventory action not in passthrough set: %v", keysOf(byAction))
	}
	agentIDs, _ := agentBody["defenseclaw.inventory.agent.identifiers"].([]any)
	if len(agentIDs) != 1 {
		t.Fatalf("agent identifiers count = %d", len(agentIDs))
	}
	if got, _ := agentIDs[0].(map[string]any)["name"].(string); got != "claudecode" {
		t.Fatalf("agent identifier name = %q", got)
	}
}

// keysOf returns the map keys as a sorted slice for stable failure
// messages when a v8 passthrough action is missing from the set.
func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestManagedCompatibilityInventoryIsV8Passthrough replaces the old
// "atomic + fail-closed" contract (which enforced v7 carrier validity
// at the compat layer). Under Vineet's v8-only mandate, every
// ai.discovery inventory action is passthrough: projectManagedCompatibility
// returns useProjection=false, valid=true regardless of the carrier's
// shape, so the record flows through as the original canonical v8
// OTLP log. Atomicity / integrity checks on the v8 records move to
// redaction and the OTLP canonical projector — this test only asserts
// the compat-layer contract.
func TestManagedCompatibilityInventoryIsV8Passthrough(t *testing.T) {
	sampleBodies := map[string]map[string]any{
		"connector-inventory-well-formed":  managedConnectorCarrierBody(),
		"connector-inventory-empty-arrays": connectorBodyWithArrays(0),
		"connector-inventory-large":        connectorBodyWithArrays(129),
		"connector-inventory-mismatch":     connectorBodyWithMismatch(),
		"connector-inventory-partial-flag": connectorBodyPartial(),
		"mcp-inventory-item-shape":         {"defenseclaw.inventory.item.name": "webex", "defenseclaw.inventory.mcp.disabled": false},
		"agent-inventory-item-shape":       {"defenseclaw.inventory.item.name": "claudecode"},
		"skill-inventory-item-shape":       {"defenseclaw.inventory.item.name": "code-review"},
		"plugin-inventory-item-shape":      {"defenseclaw.inventory.item.name": "cache"},
		"ai-discovery-scan-summary":        {"defenseclaw.ai.discovery.result": "ok"},
	}
	// Every one of these action / body combinations is v8-passthrough
	// under the new contract. Compat-layer projection never runs; the
	// caller must return useProjection=false, valid=true.
	cases := []struct {
		name   string
		action string
		event  string
	}{
		{"connector inventory summary",
			string(config.ObservabilityV8ManagedConnectorInventoryAction), "ai.discovery.completed"},
		{"mcp inventory item",
			string(config.ObservabilityV8ManagedMCPInventoryAction), "ai_component.observed"},
		{"agent inventory item",
			string(config.ObservabilityV8ManagedAgentInventoryAction), "ai_component.observed"},
		{"skill inventory item",
			string(config.ObservabilityV8ManagedSkillInventoryAction), "ai_component.observed"},
		{"plugin inventory item",
			string(config.ObservabilityV8ManagedPluginInventoryAction), "ai_component.observed"},
		{"ai discovery scan summary",
			"ai_discovery", "ai.discovery.completed"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for name, body := range sampleBodies {
				_, useProjection, valid := projectManagedCompatibility(
					managedGoldenPayload(t, "record", "ai.discovery", tc.event, tc.action, body),
					"sha256:managed-device", "managed-host", strings.Repeat("a", 64),
				)
				if !valid || useProjection {
					t.Fatalf("%s + body %q: valid/use=%t/%t (want v8 passthrough: valid=true, use=false)",
						tc.name, name, valid, useProjection)
				}
			}
		})
	}

	// Diagnostic action MUST remain fail-closed at the compat layer:
	// local_inventory_diagnostic is never eligible for managed egress
	// and the route in reserveObservabilityV8ManagedInventory drops it
	// upstream. If the compat layer accidentally passthrough'd it, a
	// misrouted diagnostic could leak.
	localSummary := managedGoldenPayload(t, "local-record", "ai.discovery", "ai.discovery.completed",
		string(config.ObservabilityV8LocalInventoryDiagnosticAction), managedConnectorCarrierBody())
	if _, useProjection, valid := projectManagedCompatibility(
		localSummary, "sha256:managed-device", "managed-host", strings.Repeat("a", 64),
	); valid || useProjection {
		t.Fatalf("local diagnostic action must be fail-closed at compat: valid/use=%t/%t", valid, useProjection)
	}
}

func connectorBodyWithArrays(n int) map[string]any {
	body := managedConnectorCarrierBody()
	body["defenseclaw.ai.discovery.signals_total"] = n
	body["defenseclaw.ai.discovery.active_signals"] = n
	body["defenseclaw.inventory.connector.identifiers"] = []any{}
	body["defenseclaw.inventory.connector.metadata"] = []any{}
	body["defenseclaw.inventory.connector.content"] = []any{}
	return body
}

func connectorBodyWithMismatch() map[string]any {
	body := managedConnectorCarrierBody()
	body["defenseclaw.inventory.connector.metadata"] = []any{}
	return body
}

func connectorBodyPartial() map[string]any {
	body := managedConnectorCarrierBody()
	body["defenseclaw.ai.discovery.result"] = "partial"
	return body
}

// TestAdapterV8InventoryPassthroughReachesNetwork replaces the old
// "reject invalid managed carrier at compat" test. Under Vineet's
// v8-only mandate, the compat layer no longer validates inventory
// carrier shape — those checks moved to redaction and the OTLP
// canonical projector, which run BEFORE the batch reaches this
// adapter. Any well-formed v8 inventory record (including ones that
// would have been rejected by the old carrier validator) now
// passes through to network egress, which is what "canonical v8
// wire body" means in Vineet's ask. This test guards the new
// contract: a mismatched connector carrier now DOES cross to the
// endpoint because compat-layer validation is gone.
func TestAdapterV8InventoryPassthroughReachesNetwork(t *testing.T) {
	var requests atomic.Int64
	var capturedMu sync.Mutex
	var captured [][]byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(request.Body)
		capturedMu.Lock()
		captured = append(captured, body)
		capturedMu.Unlock()
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	resolver := &testResolver{provider: &testProvider{token: "passthrough-token"}}
	source := testConfig(server.URL + config.ObservabilityV8ManagedAIDIngestPath)
	source.Network.AllowPrivateNetworks = true
	adapter, err := New(t.Context(), source, resolver)
	if err != nil {
		t.Fatal(err)
	}
	adapter.client = server.Client()
	dispatcher := testDispatcher(t, adapter)
	// Mismatched-parallel-arrays body — the exact shape the old
	// v7-projection-layer used to reject with fail-closed semantics.
	body := managedConnectorCarrierBody()
	body["defenseclaw.inventory.connector.metadata"] = []any{}
	if result := dispatcher.Enqueue(managedGoldenPayload(
		t, "passthrough-record", "ai.discovery", "ai.discovery.completed",
		string(config.ObservabilityV8ManagedConnectorInventoryAction), body,
	)); !result.Accepted() {
		t.Fatalf("enqueue=%+v", result)
	}
	flushAndClose(t, dispatcher)
	if requests.Load() != 1 {
		t.Fatalf("v8 passthrough must reach network; got requests=%d", requests.Load())
	}
	if resolver.calls.Load() == 0 {
		t.Fatal("v8 passthrough must invoke the credential resolver before POST")
	}
	counters := dispatcher.Counters()
	if counters.Delivered != 1 || counters.Rejected != 0 || counters.Failed != 0 {
		t.Fatalf("v8 passthrough counters = %+v (want delivered=1)", counters)
	}
	// Body sanity: the request MUST contain the canonical v8 wire body,
	// not a legacy gatewaylog.Event flat envelope. Verify by decoding
	// the OTLP wrapper and asserting the log body includes the
	// ai.discovery bucket + action attributes.
	capturedMu.Lock()
	first := append([]byte(nil), captured[0]...)
	capturedMu.Unlock()
	if !strings.Contains(string(first), "\"ai.discovery\"") ||
		!strings.Contains(string(first), string(config.ObservabilityV8ManagedConnectorInventoryAction)) {
		t.Fatalf("v8 wire body missing expected ai.discovery / connector-inventory identity: %s", string(first))
	}
}

func TestAdapterMissingExactSourceHashIsDropOnly(t *testing.T) {
	resolver := &testResolver{provider: &testProvider{token: "must-not-be-used"}}
	source := testConfig("https://8.8.8.8" + config.ObservabilityV8ManagedAIDIngestPath)
	source.ContentHash = ""
	adapter, err := New(t.Context(), source, resolver)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := testDispatcher(t, adapter)
	if result := dispatcher.Enqueue(testPayload(t)); !result.Accepted() {
		t.Fatalf("enqueue=%+v", result)
	}
	flushAndClose(t, dispatcher)
	if resolver.calls.Load() != 0 {
		t.Fatalf("missing source hash resolved credentials %d time(s)", resolver.calls.Load())
	}
}

func managedConnectorCarrierBody() map[string]any {
	return map[string]any{
		"defenseclaw.ai.discovery.source":         "endpoint_connector_inventory",
		"defenseclaw.ai.discovery.result":         "completed",
		"defenseclaw.ai.discovery.signals_total":  1,
		"defenseclaw.ai.discovery.active_signals": 1,
		"defenseclaw.ai.discovery.errors":         0,
		"defenseclaw.inventory.connector.identifiers": []any{
			map[string]any{"name": "codex"},
		},
		"defenseclaw.inventory.connector.metadata": []any{
			map[string]any{"source": "built-in", "tool_inspection_mode": "both", "subprocess_policy": "sandbox"},
		},
		"defenseclaw.inventory.connector.content": []any{
			map[string]any{"description": "Codex connector"},
		},
	}
}

func managedGoldenPayload(
	t *testing.T,
	recordID string,
	bucket string,
	eventName string,
	action string,
	body map[string]any,
) delivery.Payload {
	t.Helper()
	prefix := strings.TrimSuffix(recordID, "-record")
	wire := map[string]any{
		"schema_version": 1, "bucket_catalog_version": 1,
		"record_id": recordID, "timestamp": "2026-07-13T12:00:00Z",
		"bucket": bucket, "signal": "logs", "event_name": eventName,
		"source": "gateway", "connector": "codex", "action": action,
		"phase": "finalize", "outcome": "completed", "severity": "HIGH", "log_level": "ERROR",
		"mandatory": false, "body": body, "field_classes": map[string]any{},
		"correlation": map[string]any{
			"semantic_event_id":     "semantic-" + prefix,
			"logical_event_id":      "logical-" + prefix,
			"connector_instance_id": "connector-instance-1",
			"request_id":            "request-" + prefix, "session_id": "session-" + prefix,
			"trace_id": "1234567890abcdef1234567890abcdef", "span_id": "1234567890abcdef",
		},
		"provenance": map[string]any{
			"producer": "managed-test", "binary_version": "0.8.5",
			"registry_schema_version": 8, "config_generation": 7,
			"config_digest": strings.Repeat("c", 64),
		},
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := delivery.NewPayload(encoded, delivery.RoutingIdentity{
		RecordID: recordID, Bucket: bucket, Signal: "logs", EventName: eventName,
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func managedGoldenAttributeValues[T interface {
	~struct {
		Key   string         `json:"key"`
		Value map[string]any `json:"value"`
	}
}](attributes []T) map[string]any {
	result := make(map[string]any, len(attributes))
	for _, attribute := range attributes {
		encoded, _ := json.Marshal(attribute)
		var decoded struct {
			Key   string         `json:"key"`
			Value map[string]any `json:"value"`
		}
		_ = json.Unmarshal(encoded, &decoded)
		for _, value := range decoded.Value {
			result[decoded.Key] = value
			break
		}
	}
	return result
}

func TestAdapterUnavailableProviderFailsClosedWithDispatcherHealth(t *testing.T) {
	resolver := &testResolver{err: errors.New("not enrolled")}
	adapter, err := New(t.Context(), testConfig("https://8.8.8.8"+config.ObservabilityV8ManagedAIDIngestPath), resolver)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := testDispatcher(t, adapter)
	if result := dispatcher.Enqueue(testPayload(t)); !result.Accepted() {
		t.Fatalf("enqueue = %+v", result)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := dispatcher.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	health := dispatcher.DeliveryHealthSnapshot()
	if health.State != delivery.HealthFailing || health.Counters.Delivered != 0 ||
		health.Counters.Rejected != 1 || health.Counters.Failed != 1 {
		t.Fatalf("unavailable managed sink health = %+v", health)
	}
	if resolver.calls.Load() != 1 {
		t.Fatalf("resolver calls = %d", resolver.calls.Load())
	}
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterInvalidManagedEndpointIsDropOnlyWithoutNetwork(t *testing.T) {
	resolver := &testResolver{provider: &testProvider{token: "must-not-be-used"}}
	adapter, err := New(t.Context(), testConfig("https://aid.example.test/operator-controlled-path"), resolver)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := testDispatcher(t, adapter)
	if result := dispatcher.Enqueue(testPayload(t)); !result.Accepted() {
		t.Fatalf("enqueue = %+v", result)
	}
	flushAndClose(t, dispatcher)
	if resolver.calls.Load() != 0 {
		t.Fatalf("invalid endpoint resolved credentials %d time(s)", resolver.calls.Load())
	}
}

func TestManagedEndpointRequiresHTTPSExactIngestPath(t *testing.T) {
	accepted := "https://aid.example.test:8443" + config.ObservabilityV8ManagedAIDIngestPath
	if got, ok := validEndpoint(accepted); !ok || got != accepted {
		t.Fatalf("validEndpoint(%q) = %q, %v", accepted, got, ok)
	}
	for _, endpoint := range []string{
		"http://aid.example.test" + config.ObservabilityV8ManagedAIDIngestPath,
		"https://aid.example.test",
		"https://aid.example.test" + config.ObservabilityV8ManagedAIDIngestPath + "/",
		"https://aid.example.test/api/v1/defenseclaw/events/%69ngest",
		"https://aid.example.test" + config.ObservabilityV8ManagedAIDIngestPath + "?tenant=operator",
		"https://aid.example.test" + config.ObservabilityV8ManagedAIDIngestPath + "?",
		"https://aid.example.test" + config.ObservabilityV8ManagedAIDIngestPath + "#fragment",
		"https://user@aid.example.test" + config.ObservabilityV8ManagedAIDIngestPath,
		" https://aid.example.test" + config.ObservabilityV8ManagedAIDIngestPath,
		"https://aid.example.test:70000" + config.ObservabilityV8ManagedAIDIngestPath,
		"https://[invalid" + config.ObservabilityV8ManagedAIDIngestPath,
	} {
		t.Run(endpoint, func(t *testing.T) {
			if got, ok := validEndpoint(endpoint); ok || got != "" {
				t.Fatalf("validEndpoint(%q) = %q, %v, want rejection", endpoint, got, ok)
			}
		})
	}
}

func TestAdapterRetriesCredentialFetchErrors(t *testing.T) {
	errorsToRetry := map[string]error{
		"canceled":    context.Canceled,
		"deadline":    context.DeadlineExceeded,
		"network":     testNetworkError{},
		"operational": errors.New("credential service unavailable"),
	}
	for name, fetchErr := range errorsToRetry {
		for _, surface := range []string{"resolver", "token"} {
			t.Run(surface+"/"+name, func(t *testing.T) {
				provider := &testProvider{token: "token"}
				resolver := &testResolver{provider: provider}
				if surface == "resolver" {
					resolver.err = fetchErr
				} else {
					provider.tokenErr = fetchErr
				}
				adapter, err := New(t.Context(), testConfig(
					"https://8.8.8.8"+config.ObservabilityV8ManagedAIDIngestPath,
				), resolver)
				if err != nil {
					t.Fatal(err)
				}
				dispatcher := testDispatcherAttempts(t, adapter, 2)
				if result := dispatcher.Enqueue(testPayload(t)); !result.Accepted() {
					t.Fatalf("enqueue = %+v", result)
				}
				flushAndClose(t, dispatcher)
				counters := dispatcher.Counters()
				if counters.Retried != 1 || counters.Rejected != 1 || counters.Failed != 2 {
					t.Fatalf("credential fetch counters = %+v, want one retry", counters)
				}
				if resolver.calls.Load() != 2 {
					t.Fatalf("resolver calls = %d, want 2", resolver.calls.Load())
				}
				tokenCalls, _ := provider.snapshot()
				if surface == "token" && tokenCalls != 2 {
					t.Fatalf("token calls = %d, want 2", tokenCalls)
				}
			})
		}
	}
}

func TestAdapterDoesNotRetryMissingOrInvalidToken(t *testing.T) {
	for name, resolver := range map[string]*testResolver{
		"provider not compiled": {err: cloudreg.ErrNoProviderRegistered},
		"missing provider":      {provider: nil},
		"missing token":         {provider: &testProvider{}},
		"invalid token":         {provider: &testProvider{token: " token"}},
	} {
		t.Run(name, func(t *testing.T) {
			adapter, err := New(t.Context(), testConfig(
				"https://8.8.8.8"+config.ObservabilityV8ManagedAIDIngestPath,
			), resolver)
			if err != nil {
				t.Fatal(err)
			}
			dispatcher := testDispatcherAttempts(t, adapter, 2)
			if result := dispatcher.Enqueue(testPayload(t)); !result.Accepted() {
				t.Fatalf("enqueue = %+v", result)
			}
			flushAndClose(t, dispatcher)
			counters := dispatcher.Counters()
			if counters.Retried != 0 || counters.Rejected != 1 || counters.Failed != 1 {
				t.Fatalf("invalid credential counters = %+v, want terminal authentication failure", counters)
			}
			if resolver.calls.Load() != 1 {
				t.Fatalf("resolver calls = %d, want 1", resolver.calls.Load())
			}
		})
	}
}

func TestAdapterPanickingActivationResolverIsDropOnly(t *testing.T) {
	resolver := &testResolver{provider: &testProvider{token: "must-not-be-used"}}
	source := testConfig("https://aid.example.test" + config.ObservabilityV8ManagedAIDIngestPath)
	source.Network.Resolver = panickingNetworkResolver{}
	adapter, err := New(t.Context(), source, resolver)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := testDispatcher(t, adapter)
	if result := dispatcher.Enqueue(testPayload(t)); !result.Accepted() {
		t.Fatalf("enqueue = %+v", result)
	}
	flushAndClose(t, dispatcher)
	if resolver.calls.Load() != 0 {
		t.Fatalf("unsafe prepared adapter resolved credentials %d time(s)", resolver.calls.Load())
	}
}

func TestAdapterRejectsOversizedAcknowledgement(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, strings.Repeat("x", maxResponseBytes+1))
	}))
	defer server.Close()
	provider := &testProvider{token: "token"}
	resolver := &testResolver{provider: provider}
	source := testConfig(server.URL + config.ObservabilityV8ManagedAIDIngestPath)
	source.Network.AllowPrivateNetworks = true
	adapter, err := New(t.Context(), source, resolver)
	if err != nil {
		t.Fatal(err)
	}
	adapter.client = server.Client()
	dispatcher := testDispatcher(t, adapter)
	if result := dispatcher.Enqueue(testPayload(t)); !result.Accepted() {
		t.Fatalf("enqueue = %+v", result)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := dispatcher.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	health := dispatcher.DeliveryHealthSnapshot()
	if health.Counters.Delivered != 0 || health.Counters.Rejected != 1 || health.Counters.Failed != 1 {
		t.Fatalf("oversized acknowledgement health = %+v", health)
	}
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
