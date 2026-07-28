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
			"raw_path":                               "/private/home/operator",
			"authorization":                          "must-not-cross-managed-projection",
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
			"raw_path": "/private/connector",
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
			"command_path": "/opt/private/mcp-server",
			"url":          "https://mcp.example.test/private?token=secret",
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
			"raw_binary_path": "/usr/local/private/claude",
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

	byType := make(map[string]gatewaylog.Event, len(records))
	for _, record := range records {
		attributes := managedGoldenAttributeValues(record.Attributes)
		eventType, _ := attributes["defenseclaw.gateway.event_type"].(string)
		if attributes["event.name"] != "defenseclaw.gateway."+eventType ||
			attributes["event.domain"] != "defenseclaw.gateway" ||
			attributes["defenseclaw.device.id"] != "sha256:managed-device" ||
			attributes["host.name"] != "managed-host" {
			t.Fatalf("managed flat contract (%s) = %#v", eventType, attributes)
		}
		for key, want := range map[string]string{
			"defenseclaw.semantic_event.id":     "semantic-" + strings.TrimSuffix(attributes["defenseclaw.record.id"].(string), "-record"),
			"defenseclaw.logical_event.id":      "logical-" + strings.TrimSuffix(attributes["defenseclaw.record.id"].(string), "-record"),
			"defenseclaw.connector.instance.id": "connector-instance-1",
		} {
			if attributes[key] != want {
				t.Fatalf("%s=%v want %s", key, attributes[key], want)
			}
		}
		if record.TraceID != "1234567890abcdef1234567890abcdef" || record.SpanID != "1234567890abcdef" {
			t.Fatalf("topology=%s/%s", record.TraceID, record.SpanID)
		}
		body, _ := record.Body["stringValue"].(string)
		if body == "" || strings.Contains(body, "/private/") || strings.Contains(body, "token=secret") ||
			strings.Contains(body, "must-not-cross-managed-projection") {
			t.Fatalf("unsafe or empty managed body: %q", body)
		}
		var event gatewaylog.Event
		if err := json.Unmarshal([]byte(body), &event); err != nil {
			t.Fatalf("decode compatibility body: %v", err)
		}
		byType[eventType] = event
		if event.ContentHash != strings.Repeat("a", 64) || event.ContentHash == strings.Repeat("c", 64) ||
			event.PayloadHMAC == "" {
			t.Fatalf("managed provenance/hash = %+v", event)
		}
		var signedPayload any
		switch eventType {
		case managedEventVerdict:
			signedPayload = event.Verdict
		case managedEventConnectorInventory:
			signedPayload = event.ConnectorInventory
		case managedEventMCPInventory:
			signedPayload = event.MCPInventory
		case managedEventAgentInventory:
			signedPayload = event.AgentInventory
		}
		if signedPayload == nil || gatewaylog.VerifyPayloadHMAC(signedPayload, event.PayloadHMAC) != nil {
			t.Fatalf("managed payload HMAC did not verify for %s", eventType)
		}
	}

	verdict := byType[managedEventVerdict]
	if verdict.Verdict == nil || verdict.Verdict.Action != "block" || verdict.Verdict.Stage != gatewaylog.Stage("final") ||
		verdict.Verdict.Reason != "[REDACTED]" || verdict.Verdict.LatencyMs != 42 ||
		verdict.RequestID != "request-verdict" || verdict.SessionID != "session-verdict" {
		t.Fatalf("verdict body = %+v", verdict)
	}
	connector := byType[managedEventConnectorInventory]
	if connector.ConnectorInventory == nil || connector.ConnectorInventory.Count != 1 ||
		len(connector.ConnectorInventory.Connectors) != 1 || connector.ConnectorInventory.Connectors[0].Name != "codex" {
		t.Fatalf("connector body = %+v", connector)
	}
	mcp := byType[managedEventMCPInventory]
	if mcp.MCPInventory == nil || len(mcp.MCPInventory.Servers) != 1 ||
		mcp.MCPInventory.Servers[0].Command != "mcp-server" ||
		mcp.MCPInventory.Servers[0].URLHost != "mcp.example.test:8443" {
		t.Fatalf("mcp body = %+v", mcp)
	}
	agent := byType[managedEventAgentInventory]
	if agent.AgentInventory == nil || agent.AgentInventory.Count != 1 || agent.AgentInventory.Installed != 1 ||
		len(agent.AgentInventory.Agents) != 1 || agent.AgentInventory.Agents[0].BinaryBasename != "claude" ||
		agent.AgentInventory.Agents[0].ConfigPathHash != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("agent body = %+v", agent)
	}
}

func TestManagedCompatibilityInventoryIsAtomicAndFailClosed(t *testing.T) {
	validEmpty := managedConnectorCarrierBody()
	validEmpty["defenseclaw.ai.discovery.signals_total"] = 0
	validEmpty["defenseclaw.ai.discovery.active_signals"] = 0
	validEmpty["defenseclaw.inventory.connector.identifiers"] = []any{}
	validEmpty["defenseclaw.inventory.connector.metadata"] = []any{}
	validEmpty["defenseclaw.inventory.connector.content"] = []any{}
	projection, useProjection, valid := projectManagedCompatibility(
		managedGoldenPayload(t, "empty-record", "ai.discovery", "ai.discovery.completed",
			string(config.ObservabilityV8ManagedConnectorInventoryAction), validEmpty),
		"sha256:managed-device", "managed-host", strings.Repeat("a", 64),
	)
	if !valid || !useProjection {
		t.Fatalf("complete empty carrier projection valid/use=%t/%t", valid, useProjection)
	}
	var emptyEvent gatewaylog.Event
	if err := json.Unmarshal([]byte(projection.body), &emptyEvent); err != nil ||
		emptyEvent.ConnectorInventory == nil || emptyEvent.ConnectorInventory.Count != 0 ||
		len(emptyEvent.ConnectorInventory.Connectors) != 0 {
		t.Fatalf("complete empty legacy inventory=%+v err=%v", emptyEvent.ConnectorInventory, err)
	}

	invalid := map[string]map[string]any{
		"mismatched parallel arrays": func() map[string]any {
			body := managedConnectorCarrierBody()
			body["defenseclaw.inventory.connector.metadata"] = []any{}
			return body
		}(),
		"partial collection": func() map[string]any {
			body := managedConnectorCarrierBody()
			body["defenseclaw.ai.discovery.result"] = "partial"
			return body
		}(),
		"reported error": func() map[string]any {
			body := managedConnectorCarrierBody()
			body["defenseclaw.ai.discovery.errors"] = 1
			return body
		}(),
		"overflow": func() map[string]any {
			body := managedConnectorCarrierBody()
			body["defenseclaw.ai.discovery.signals_total"] = 129
			body["defenseclaw.ai.discovery.active_signals"] = 129
			return body
		}(),
		"unknown carrier field": func() map[string]any {
			body := managedConnectorCarrierBody()
			body["defenseclaw.inventory.connector.metadata"] = []any{
				map[string]any{"source": "built-in", "tool_inspection_mode": "both", "subprocess_policy": "sandbox", "private_path": "/tmp/secret"},
			}
			return body
		}(),
		"content length mismatch": func() map[string]any {
			body := managedConnectorCarrierBody()
			body["defenseclaw.inventory.connector.content"] = []any{}
			return body
		}(),
	}
	for name, body := range invalid {
		t.Run(name, func(t *testing.T) {
			_, useProjection, valid := projectManagedCompatibility(
				managedGoldenPayload(t, "invalid-record", "ai.discovery", "ai.discovery.completed",
					string(config.ObservabilityV8ManagedConnectorInventoryAction), body),
				"sha256:managed-device", "managed-host", strings.Repeat("a", 64),
			)
			if valid || useProjection {
				t.Fatalf("invalid atomic carrier valid/use=%t/%t", valid, useProjection)
			}
		})
	}

	component := managedGoldenPayload(t, "component-record", "ai.discovery", "ai_component.observed",
		string(config.ObservabilityV8ManagedConnectorInventoryAction), map[string]any{"private_path": "/tmp/private"})
	if _, useProjection, valid := projectManagedCompatibility(
		component, "sha256:managed-device", "managed-host", strings.Repeat("a", 64),
	); !valid || useProjection {
		t.Fatalf("non-summary component valid/use=%t/%t", valid, useProjection)
	}
	localSummary := managedGoldenPayload(t, "local-record", "ai.discovery", "ai.discovery.completed",
		string(config.ObservabilityV8LocalInventoryDiagnosticAction), managedConnectorCarrierBody())
	if _, useProjection, valid := projectManagedCompatibility(
		localSummary, "sha256:managed-device", "managed-host", strings.Repeat("a", 64),
	); valid || useProjection {
		t.Fatalf("unexpected summary action valid/use=%t/%t", valid, useProjection)
	}
}

func TestAdapterRejectsInvalidManagedCarrierBeforeCredentialsOrNetwork(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	resolver := &testResolver{provider: &testProvider{token: "must-not-be-used"}}
	source := testConfig(server.URL + config.ObservabilityV8ManagedAIDIngestPath)
	source.Network.AllowPrivateNetworks = true
	adapter, err := New(t.Context(), source, resolver)
	if err != nil {
		t.Fatal(err)
	}
	adapter.client = server.Client()
	dispatcher := testDispatcher(t, adapter)
	body := managedConnectorCarrierBody()
	body["defenseclaw.inventory.connector.metadata"] = []any{}
	if result := dispatcher.Enqueue(managedGoldenPayload(
		t, "invalid-record", "ai.discovery", "ai.discovery.completed",
		string(config.ObservabilityV8ManagedConnectorInventoryAction), body,
	)); !result.Accepted() {
		t.Fatalf("enqueue=%+v", result)
	}
	flushAndClose(t, dispatcher)
	if requests.Load() != 0 || resolver.calls.Load() != 0 {
		t.Fatalf("invalid carrier crossed credentials/network requests=%d resolver=%d", requests.Load(), resolver.calls.Load())
	}
	counters := dispatcher.Counters()
	if counters.Delivered != 0 || counters.Rejected != 1 || counters.Failed != 1 {
		t.Fatalf("invalid carrier counters=%+v", counters)
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
