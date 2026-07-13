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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
		Timeout:     time.Second,
		Resource: otlp.LogResourceSnapshot{
			SchemaURL: "https://opentelemetry.io/schemas/1.42.0",
			Values: map[string]string{
				"service.name": "defenseclaw", "service.instance.id": "managed-generation",
			},
		},
	}
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
