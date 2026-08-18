// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package destinations

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/local"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/localobservability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/push"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	collectorlogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

type secretResolver struct {
	mu     sync.Mutex
	values map[string]string
	calls  map[string]int
}

func (resolver *secretResolver) ResolveObservabilitySecret(name string) (string, bool) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.calls[name]++
	value, ok := resolver.values[name]
	return value, ok
}

func (resolver *secretResolver) set(name, value string) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.values[name] = value
}

func (resolver *secretResolver) callCount(name string) int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.calls[name]
}

type warningCollector struct {
	mu       sync.Mutex
	warnings []push.Warning
}

func (collector *warningCollector) ObservePushWarning(warning push.Warning) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.warnings = append(collector.warnings, warning)
}

func (collector *warningCollector) count(code push.WarningCode) int {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	count := 0
	for _, warning := range collector.warnings {
		if warning.Code == code {
			count++
		}
	}
	return count
}

type caLoader struct {
	mu      sync.Mutex
	bundles map[string][]byte
	errors  map[string]error
	calls   map[string]int
}

func absoluteDestinationTestPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

func (loader *caLoader) LoadObservabilityCA(_ context.Context, path string) ([]byte, error) {
	loader.mu.Lock()
	defer loader.mu.Unlock()
	loader.calls[path]++
	if err := loader.errors[path]; err != nil {
		return nil, err
	}
	return append([]byte(nil), loader.bundles[path]...), nil
}

func (loader *caLoader) callCount(path string) int {
	loader.mu.Lock()
	defer loader.mu.Unlock()
	return loader.calls[path]
}

type trackingDialer struct {
	base   net.Dialer
	closed atomic.Int64
}

func (dialer *trackingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	connection, err := dialer.base.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &trackingConnection{Conn: connection, closed: &dialer.closed}, nil
}

type trackingConnection struct {
	net.Conn
	closed *atomic.Int64
	once   sync.Once
}

type factoryGRPCLogCapture struct {
	collectorlogpb.UnimplementedLogsServiceServer
	requests chan *collectorlogpb.ExportLogsServiceRequest
	headers  chan metadata.MD
}

func (capture *factoryGRPCLogCapture) Export(ctx context.Context, request *collectorlogpb.ExportLogsServiceRequest) (*collectorlogpb.ExportLogsServiceResponse, error) {
	headers, _ := metadata.FromIncomingContext(ctx)
	capture.headers <- headers
	capture.requests <- request
	return &collectorlogpb.ExportLogsServiceResponse{}, nil
}

func protoAttribute(attributes []*commonpb.KeyValue, key string) string {
	for _, attribute := range attributes {
		if attribute != nil && attribute.Key == key && attribute.Value != nil {
			return attribute.Value.GetStringValue()
		}
	}
	return ""
}

type panickingResolver struct{}

func (panickingResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	panic("sensitive resolver panic")
}

func (connection *trackingConnection) Close() error {
	connection.once.Do(func() { connection.closed.Add(1) })
	return connection.Conn.Close()
}

func newTestFactory(
	t *testing.T,
	console io.Writer,
	secrets *secretResolver,
	loader *caLoader,
	dialer net.Dialer,
	warnings *warningCollector,
) *Factory {
	t.Helper()
	if secrets == nil {
		secrets = &secretResolver{values: map[string]string{}, calls: map[string]int{}}
	}
	if loader == nil {
		loader = &caLoader{bundles: map[string][]byte{}, errors: map[string]error{}, calls: map[string]int{}}
	}
	if warnings == nil {
		warnings = &warningCollector{}
	}
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewFactory(Options{
		ConsoleStream: ConsoleStderr, Stdout: io.Discard, Stderr: console,
		Secrets: secrets, CALoader: loader, Resolver: net.DefaultResolver,
		Dialer: &dialer, Warnings: warnings,
		RedactionEngine:       engine,
		DeliveryObserver:      delivery.ObserverFunc(func(delivery.HealthTransition) {}),
		OTLPCanonicalObserver: otlp.CanonicalObserverFunc(func(otlp.CanonicalFailure) {}),
		GalileoObserver:       galileo.CanonicalObserverFunc(func(galileo.CanonicalFailure) {}),
		LocalObserver:         localobservability.ObserverFunc(func(localobservability.Failure) {}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

func compileDestination(
	t *testing.T,
	destination config.ObservabilityV8DestinationSource,
) config.ObservabilityV8EffectiveDestination {
	t.Helper()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Destinations: []config.ObservabilityV8DestinationSource{destination},
	})
	if err != nil {
		t.Fatalf("compile destination: %v", err)
	}
	compiled, ok := plan.RuntimeDestination(destination.Name)
	if !ok {
		t.Fatal("runtime destination missing")
	}
	return compiled
}

func testResourceContext(t *testing.T) telemetry.V8ResourceContext {
	return testResourceContextWith(t, nil, true)
}

func testResourceContextWith(
	t *testing.T,
	attributes map[string]string,
	compatibilityAliases bool,
) telemetry.V8ResourceContext {
	t.Helper()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Resource: config.ObservabilityV8ResourceSource{Attributes: attributes},
		TracePolicy: config.ObservabilityV8TracePolicySource{
			CompatibilityAliases: &compatibilityAliases,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	context, err := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "factory-test", Environment: "test", ServiceInstanceID: "factory-test-instance",
		DefenseClawInstanceID: "factory-test-defenseclaw",
	}).ResourceContext(plan)
	if err != nil {
		t.Fatal(err)
	}
	return context
}

func TestFactoryManagedAIDIsGeneratedOnlyAndAuthUnavailabilityDoesNotRejectGeneration(t *testing.T) {
	base, err := config.CompileObservabilityV8(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := config.WithObservabilityV8ManagedAIDDestination(base, config.ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://8.8.8.8",
		SourceContentHash: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	destination, ok := plan.RuntimeDestination(config.ObservabilityV8ManagedAIDDestinationName)
	if !ok {
		t.Fatal("generated managed destination missing")
	}
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	adapter, cleanup, err := factory.PrepareDestination(t.Context(), destination, testResourceContext(t))
	if err != nil || adapter == nil || cleanup == nil {
		t.Fatalf("managed preparation adapter=%T cleanup=%v err=%v", adapter, cleanup != nil, err)
	}
	if err := cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}

	tampered := destination
	tampered.Transport.Headers = map[string]config.ObservabilityV8HeaderValue{
		"Authorization": config.ObservabilityV8StaticHeader("user-controlled"),
	}
	adapter, cleanup, err = factory.PrepareDestination(t.Context(), tampered, testResourceContext(t))
	if adapter != nil || cleanup == nil || !IsError(err, ErrorInvalidDestination) {
		t.Fatalf("tampered managed destination adapter=%T cleanup=%v err=%v", adapter, cleanup != nil, err)
	}
}

func protoResourceValues(attributes []*commonpb.KeyValue) map[string]string {
	result := make(map[string]string, len(attributes))
	for _, attribute := range attributes {
		if attribute != nil && attribute.Value != nil {
			result[attribute.Key] = attribute.Value.GetStringValue()
		}
	}
	return result
}

func deliverOne(t *testing.T, name string, adapter delivery.Adapter, projection string) delivery.Counters {
	return deliverOneWithAttempts(t, name, adapter, projection, 1)
}

func deliverOneWithAttempts(t *testing.T, name string, adapter delivery.Adapter, projection string, attempts int) delivery.Counters {
	t.Helper()
	dispatcher, err := delivery.NewDispatcher(delivery.Config{
		Destination: name, Enabled: true,
		MaxQueueItems: 4, MaxQueueBytes: 8 * 1024 * 1024,
		MaxBatchItems: 1, MaxBatchBytes: 8 * 1024 * 1024,
		AttemptTimeout: 2 * time.Second,
		Retry: delivery.RetryPolicy{
			MaxAttempts: attempts, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond,
			Jitter: func(delay time.Duration, _ int) time.Duration { return delay },
		},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	payload, err := delivery.NewPayload([]byte(projection), delivery.RoutingIdentity{
		RecordID: "record", Bucket: "diagnostic", Signal: "logs", EventName: "diagnostic.message",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result := dispatcher.Enqueue(payload); !result.Accepted() {
		t.Fatalf("enqueue=%+v", result)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dispatcher.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	counters := dispatcher.Counters()
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatal(err)
	}
	return counters
}

func TestFactoryPreparesLocalAndPushAdaptersWithoutStartingDelivery(t *testing.T) {
	var console bytes.Buffer
	secrets := &secretResolver{
		values: map[string]string{
			"ARCHIVE_BEARER": "archive-token", "ARCHIVE_TENANT": "tenant-a", "SPLUNK_TOKEN": "hec-token",
		},
		calls: map[string]int{},
	}
	loader := &caLoader{bundles: map[string][]byte{}, errors: map[string]error{}, calls: map[string]int{}}
	warnings := &warningCollector{}
	factory := newTestFactory(t, &console, secrets, loader, net.Dialer{}, warnings)

	type request struct {
		path, authorization, tenant, body string
	}
	var requestMu sync.Mutex
	var requests []request
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		body, _ := io.ReadAll(incoming.Body)
		requestMu.Lock()
		requests = append(requests, request{
			path: incoming.URL.Path, authorization: incoming.Header.Get("Authorization"),
			tenant: incoming.Header.Get("X-Tenant"), body: string(body),
		})
		requestMu.Unlock()
		if incoming.URL.Path == "/splunk" {
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, `{"code":0}`)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	jsonlPath := t.TempDir() + "/events.jsonl"
	destinations := []config.ObservabilityV8EffectiveDestination{
		compileDestination(t, config.ObservabilityV8DestinationSource{
			Name: "file", Kind: config.ObservabilityV8DestinationJSONL, Path: jsonlPath,
		}),
		compileDestination(t, config.ObservabilityV8DestinationSource{
			Name: "terminal", Kind: config.ObservabilityV8DestinationConsole,
		}),
		compileDestination(t, config.ObservabilityV8DestinationSource{
			Name: "archive", Kind: config.ObservabilityV8DestinationHTTPJSONL,
			Endpoint: server.URL + "/archive", BearerEnv: "ARCHIVE_BEARER",
			Headers: map[string]config.ObservabilityV8HeaderValue{
				"X-Tenant": config.ObservabilityV8EnvironmentHeader("ARCHIVE_TENANT"),
				"X-Static": config.ObservabilityV8StaticHeader("static"),
			},
			NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
		}),
		compileDestination(t, config.ObservabilityV8DestinationSource{
			Name: "splunk", Kind: config.ObservabilityV8DestinationSplunkHEC,
			Endpoint: server.URL + "/splunk", TokenEnv: "SPLUNK_TOKEN",
			SourceTypeOverrides: map[observability.ProducerKey]string{
				"config-update": "defenseclaw:config",
			},
			NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
		}),
	}

	adapters := make([]delivery.Adapter, 0, len(destinations))
	cleanups := make([]observabilityruntime.DestinationAdapterCleanup, 0, len(destinations))
	for _, destination := range destinations {
		adapter, cleanup, err := factory.PrepareDestination(context.Background(), destination, testResourceContext(t))
		if err != nil || adapter == nil || cleanup == nil {
			t.Fatalf("prepare %s: adapter=%T cleanup=%v error=%v", destination.Name, adapter, cleanup != nil, err)
		}
		adapters = append(adapters, adapter)
		cleanups = append(cleanups, cleanup)
	}
	requestMu.Lock()
	if len(requests) != 0 {
		t.Fatalf("PrepareDestination sent %d network requests", len(requests))
	}
	requestMu.Unlock()
	if console.Len() != 0 {
		t.Fatal("console wrote during preparation")
	}

	projection := `{"record_id":"record","bucket":"diagnostic","event_name":"diagnostic.message","body":{"message":"safe"}}`
	for index, adapter := range adapters {
		if counters := deliverOne(t, destinations[index].Name, adapter, projection); counters.Delivered != 1 {
			t.Fatalf("deliver %s counters=%+v", destinations[index].Name, counters)
		}
	}
	fileBytes, err := os.ReadFile(jsonlPath)
	if err != nil || string(fileBytes) != projection+"\n" {
		t.Fatalf("JSONL bytes=%q error=%v", fileBytes, err)
	}
	if got := console.String(); got != projection+"\n" {
		t.Fatalf("console=%q", got)
	}
	requestMu.Lock()
	if len(requests) != 2 {
		t.Fatalf("push requests=%+v", requests)
	}
	if requests[0].path != "/archive" || requests[0].authorization != "Bearer archive-token" ||
		requests[0].tenant != "tenant-a" || requests[0].body != projection+"\n" {
		t.Fatalf("HTTP request=%+v", requests[0])
	}
	if requests[1].path != "/splunk" || requests[1].authorization != "Splunk hec-token" ||
		!strings.Contains(requests[1].body, `"record":`+projection) {
		t.Fatalf("Splunk request metadata or projection mismatch")
	}
	requestMu.Unlock()
	for _, reference := range []string{"ARCHIVE_BEARER", "ARCHIVE_TENANT", "SPLUNK_TOKEN"} {
		if calls := secrets.callCount(reference); calls != 1 {
			t.Fatalf("secret %s resolved %d times", reference, calls)
		}
	}
	if warnings.count(push.WarningPrivateNetworksAllowed) != 2 {
		t.Fatalf("private-network warnings=%d", warnings.count(push.WarningPrivateNetworksAllowed))
	}
	if warnings.count(push.WarningPlaintextCredentials) != 2 {
		t.Fatalf("plaintext-credential warnings=%d", warnings.count(push.WarningPlaintextCredentials))
	}
	for index := len(cleanups) - 1; index >= 0; index-- {
		if err := cleanups[index](context.Background()); err != nil {
			t.Fatalf("cleanup %d: %v", index, err)
		}
		if err := cleanups[index](context.Background()); err != nil {
			t.Fatalf("idempotent cleanup %d: %v", index, err)
		}
	}
	for index := 0; index < 2; index++ {
		counters := deliverOne(t, "closed-"+destinations[index].Name, adapters[index], projection)
		if counters.Rejected != 1 || counters.Delivered != 0 {
			t.Fatalf("closed %s counters=%+v", destinations[index].Name, counters)
		}
	}
	if _, ok := adapters[0].(*local.JSONL); !ok {
		t.Fatalf("file adapter=%T", adapters[0])
	}
	if _, ok := adapters[1].(*local.Console); !ok {
		t.Fatalf("console adapter=%T", adapters[1])
	}
}

func cloneDestination(t *testing.T, source config.ObservabilityV8EffectiveDestination) config.ObservabilityV8EffectiveDestination {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var result config.ObservabilityV8EffectiveDestination
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestFactoryErrorsAreContentFreeAndAlwaysReturnCleanup(t *testing.T) {
	caPath := absoluteDestinationTestPath(t, "tenant-ca.pem")
	secrets := &secretResolver{values: map[string]string{}, calls: map[string]int{}}
	loader := &caLoader{
		bundles: map[string][]byte{},
		errors:  map[string]error{caPath: fmt.Errorf("read %s: tenant-secret", caPath)},
		calls:   map[string]int{},
	}
	factory := newTestFactory(t, io.Discard, secrets, loader, net.Dialer{}, nil)

	missingSecret := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "leaky-destination", Kind: config.ObservabilityV8DestinationHTTPJSONL,
		Endpoint: "https://collector.example.test/events?api_key=query-secret", BearerEnv: "LEAKY_SECRET_REF",
	})
	before := cloneDestination(t, missingSecret)
	adapter, cleanup, err := factory.PrepareDestination(context.Background(), missingSecret, telemetry.V8ResourceContext{})
	if adapter != nil || cleanup == nil || !IsError(err, ErrorSecretUnavailable) {
		t.Fatalf("missing secret adapter=%T cleanup=%v error=%v", adapter, cleanup != nil, err)
	}
	for _, forbidden := range []string{"leaky-destination", "collector.example.test", "query-secret", "LEAKY_SECRET_REF"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error disclosed %q: %v", forbidden, err)
		}
	}
	if !reflect.DeepEqual(missingSecret, before) {
		t.Fatal("factory mutated destination while resolving a missing secret")
	}
	if secrets.callCount("LEAKY_SECRET_REF") != 1 {
		t.Fatalf("missing secret calls=%d", secrets.callCount("LEAKY_SECRET_REF"))
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}

	caFailure := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "archive", Kind: config.ObservabilityV8DestinationHTTPJSONL,
		Endpoint: "https://collector.example.test/events?credential=hidden",
		TLS:      config.ObservabilityV8TLSSource{CACert: caPath},
	})
	adapter, cleanup, err = factory.PrepareDestination(context.Background(), caFailure, telemetry.V8ResourceContext{})
	if adapter != nil || cleanup == nil || !IsError(err, ErrorCALoadFailed) {
		t.Fatalf("CA failure adapter=%T cleanup=%v error=%v", adapter, cleanup != nil, err)
	}
	for _, forbidden := range []string{caPath, "tenant-secret", "credential=hidden"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("CA error disclosed %q: %v", forbidden, err)
		}
	}
	if loader.callCount(caPath) != 1 {
		t.Fatalf("CA load calls=%d", loader.callCount(caPath))
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}

	invalidPath := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "file", Kind: config.ObservabilityV8DestinationJSONL, Path: t.TempDir() + "/events.jsonl",
	})
	invalidPath.Transport.Path = "relative/private/events.jsonl"
	adapter, cleanup, err = factory.PrepareDestination(context.Background(), invalidPath, telemetry.V8ResourceContext{})
	if adapter != nil || cleanup == nil || !IsError(err, ErrorInvalidDestination) ||
		strings.Contains(err.Error(), "relative/private") {
		t.Fatalf("path failure adapter=%T cleanup=%v error=%v", adapter, cleanup != nil, err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestFactoryObservesSecretRotationOnlyAtPrepareBoundary(t *testing.T) {
	secrets := &secretResolver{
		values: map[string]string{"ARCHIVE_TOKEN": "first-token"}, calls: map[string]int{},
	}
	factory := newTestFactory(t, io.Discard, secrets, nil, net.Dialer{}, nil)
	var mu sync.Mutex
	var authorizations []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		mu.Lock()
		authorizations = append(authorizations, request.Header.Get("Authorization"))
		mu.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	destination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "archive", Kind: config.ObservabilityV8DestinationHTTPJSONL,
		Endpoint: server.URL, BearerEnv: "ARCHIVE_TOKEN",
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
	})
	before := cloneDestination(t, destination)
	first, firstCleanup, err := factory.PrepareDestination(context.Background(), destination, telemetry.V8ResourceContext{})
	if err != nil {
		t.Fatal(err)
	}
	secrets.set("ARCHIVE_TOKEN", "second-token")
	second, secondCleanup, err := factory.PrepareDestination(context.Background(), destination, telemetry.V8ResourceContext{})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(authorizations) != 0 {
		t.Fatal("secret rotation preparation sent a request")
	}
	mu.Unlock()
	projection := `{"record_id":"record"}`
	if counters := deliverOne(t, "first", first, projection); counters.Delivered != 1 {
		t.Fatalf("first counters=%+v", counters)
	}
	if counters := deliverOne(t, "second", second, projection); counters.Delivered != 1 {
		t.Fatalf("second counters=%+v", counters)
	}
	mu.Lock()
	got := append([]string(nil), authorizations...)
	mu.Unlock()
	if !reflect.DeepEqual(got, []string{"Bearer first-token", "Bearer second-token"}) {
		t.Fatalf("authorization rotation=%v", got)
	}
	if calls := secrets.callCount("ARCHIVE_TOKEN"); calls != 2 {
		t.Fatalf("secret resolved %d times across two preparations", calls)
	}
	if !reflect.DeepEqual(destination, before) {
		t.Fatal("factory mutated destination across secret rotation")
	}
	for _, cleanup := range []observabilityruntime.DestinationAdapterCleanup{secondCleanup, firstCleanup} {
		if err := cleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFactoryLoadsCABundleOnceAndDoesNotRequestDuringPrepare(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, request.Body)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caPath := absoluteDestinationTestPath(t, "collector-ca.pem")
	loader := &caLoader{
		bundles: map[string][]byte{caPath: certificate},
		errors:  map[string]error{}, calls: map[string]int{},
	}
	factory := newTestFactory(t, io.Discard, nil, loader, net.Dialer{}, nil)
	destination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "archive", Kind: config.ObservabilityV8DestinationHTTPJSONL,
		Endpoint: server.URL, TLS: config.ObservabilityV8TLSSource{CACert: caPath},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
	})
	adapter, cleanup, err := factory.PrepareDestination(context.Background(), destination, telemetry.V8ResourceContext{})
	if err != nil {
		t.Fatal(err)
	}
	if loader.callCount(caPath) != 1 || requests.Load() != 0 {
		t.Fatalf("CA calls=%d prepare requests=%d", loader.callCount(caPath), requests.Load())
	}
	if counters := deliverOne(t, "archive", adapter, `{"record_id":"record"}`); counters.Delivered != 1 {
		t.Fatalf("TLS counters=%+v", counters)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests=%d", requests.Load())
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestFactoryPreparesHTTPOTLPLogsWithDetachedSecretsCAOverridesAndExactRetry(t *testing.T) {
	type captured struct {
		path, authorization string
		body                []byte
	}
	var mu sync.Mutex
	var requests []captured
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mu.Lock()
		requests = append(requests, captured{
			path: request.URL.Path, authorization: request.Header.Get("Authorization"),
			body: append([]byte(nil), body...),
		})
		attempt := len(requests)
		mu.Unlock()
		if attempt == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/x-protobuf")
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caPath := absoluteDestinationTestPath(t, "otlp-ca.pem")
	secrets := &secretResolver{values: map[string]string{"OTLP_AUTH": "Bearer resolved-once"}, calls: map[string]int{}}
	loader := &caLoader{bundles: map[string][]byte{caPath: certificate}, errors: map[string]error{}, calls: map[string]int{}}
	warnings := &warningCollector{}
	factory := newTestFactory(t, io.Discard, secrets, loader, net.Dialer{}, warnings)
	destination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "otel-logs", Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: server.URL,
		Send: &config.ObservabilityV8SendSource{
			Signals: []observability.Signal{observability.SignalLogs}, Buckets: []observability.Bucket{"*"},
		},
		Headers: map[string]config.ObservabilityV8HeaderValue{
			"Authorization": config.ObservabilityV8EnvironmentHeader("OTLP_AUTH"),
		},
		LoggerName: "defenseclaw.factory", TLS: config.ObservabilityV8TLSSource{CACert: caPath},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
		Batch:         config.ObservabilityV8BatchSource{ScheduledDelayMS: 1},
	})
	before := cloneDestination(t, destination)
	resourceContext := testResourceContextWith(t, map[string]string{
		"team.name": "security-platform",
	}, true)
	adapter, cleanup, err := factory.PrepareDestination(context.Background(), destination, resourceContext)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := adapter.(*otlp.LogAdapter); !ok {
		t.Fatalf("adapter = %T", adapter)
	}
	mu.Lock()
	preparedRequests := len(requests)
	mu.Unlock()
	if preparedRequests != 0 || secrets.callCount("OTLP_AUTH") != 1 || loader.callCount(caPath) != 1 {
		t.Fatalf("prepare requests=%d secret calls=%d CA calls=%d", preparedRequests, secrets.callCount("OTLP_AUTH"), loader.callCount(caPath))
	}
	if !reflect.DeepEqual(destination, before) {
		t.Fatal("factory mutated compiled OTLP destination")
	}
	projection := `{"record_id":"otlp-record","body":{"message":"projected-only"}}`
	if counters := deliverOneWithAttempts(t, "otel-logs", adapter, projection, 3); counters.Delivered != 1 || counters.Retried != 1 {
		t.Fatalf("delivery counters = %+v", counters)
	}
	mu.Lock()
	got := append([]captured(nil), requests...)
	mu.Unlock()
	if len(got) != 2 || got[0].path != "/v1/logs" || got[1].path != "/v1/logs" ||
		got[0].authorization != "Bearer resolved-once" || !bytes.Equal(got[0].body, got[1].body) {
		t.Fatalf("OTLP requests = %+v", got)
	}
	var decoded collectorlogpb.ExportLogsServiceRequest
	if err := proto.Unmarshal(got[0].body, &decoded); err != nil {
		t.Fatal(err)
	}
	record := decoded.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	resourceLogs := decoded.ResourceLogs[0]
	if resourceLogs.SchemaUrl != resourceContext.SchemaURL() || resourceLogs.Resource == nil ||
		resourceLogs.Resource.DroppedAttributesCount != resourceContext.ResourceDroppedAttributesCount() ||
		!reflect.DeepEqual(protoResourceValues(resourceLogs.Resource.Attributes), resourceContext.Values()) {
		t.Fatalf("OTLP HTTP resource mismatch: got=%+v want=%+v", resourceLogs, resourceContext.Values())
	}
	if got := protoResourceValues(resourceLogs.Resource.Attributes); got["team.name"] != "security-platform" ||
		got["deployment.environment"] != got["deployment.environment.name"] {
		t.Fatalf("OTLP HTTP custom/alias resource mismatch: %+v", got)
	}
	if record.Body.GetStringValue() != projection || decoded.ResourceLogs[0].ScopeLogs[0].Scope.Name != "defenseclaw.factory" ||
		protoAttribute(record.Attributes, "defenseclaw.record.id") != "record" ||
		protoAttribute(record.Attributes, "defenseclaw.bucket") != "diagnostic" ||
		protoAttribute(record.Attributes, "defenseclaw.event.name") != "diagnostic.message" {
		t.Fatalf("OTLP record identity/body mismatch: %+v", record)
	}
	if warnings.count(push.WarningPrivateNetworksAllowed) != 1 || warnings.count(push.WarningPlaintextCredentials) != 0 {
		t.Fatalf("warnings = %+v", warnings.warnings)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("idempotent cleanup: %v", err)
	}
}

func TestFactoryRejectsOTLPLogsWithoutSharedProviderResource(t *testing.T) {
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	destination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "otel-missing-resource", Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: "https://8.8.8.8:4318",
		Send: &config.ObservabilityV8SendSource{
			Signals: []observability.Signal{observability.SignalLogs}, Buckets: []observability.Bucket{"*"},
		},
	})
	adapter, cleanup, err := factory.PrepareDestination(
		context.Background(), destination, telemetry.V8ResourceContext{},
	)
	if adapter != nil || cleanup == nil || !IsError(err, ErrorInvalidDependencies) {
		t.Fatalf("adapter=%T cleanup=%t error=%v", adapter, cleanup != nil, err)
	}
}

func TestFactoryHTTPOTLPLogOverrideAndUnsafeWarnings(t *testing.T) {
	paths := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		paths <- request.URL.Path
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	warnings := &warningCollector{}
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, warnings)
	destination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "otel-override", Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: server.URL,
		Send:          &config.ObservabilityV8SendSource{Signals: []observability.Signal{observability.SignalLogs}, Buckets: []observability.Bucket{"*"}},
		Headers:       map[string]config.ObservabilityV8HeaderValue{"X-API-Key": config.ObservabilityV8StaticHeader("credential")},
		TLS:           config.ObservabilityV8TLSSource{Insecure: true},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true, AllowCGNAT: true},
		SignalOverrides: map[observability.Signal]config.ObservabilityV8SignalOverrideSource{
			observability.SignalLogs: {Path: "/tenant/logs"},
		},
	})
	resourceContext := testResourceContextWith(t, map[string]string{
		"team.name": "runtime-security",
	}, false)
	adapter, cleanup, err := factory.PrepareDestination(context.Background(), destination, resourceContext)
	if err != nil {
		t.Fatal(err)
	}
	if counters := deliverOne(t, "otel-override", adapter, `{"record_id":"record"}`); counters.Delivered != 1 {
		t.Fatalf("counters = %+v", counters)
	}
	select {
	case path := <-paths:
		if path != "/tenant/logs" {
			t.Fatalf("path = %q", path)
		}
	case <-time.After(time.Second):
		t.Fatal("OTLP request not received")
	}
	for _, code := range []push.WarningCode{
		push.WarningTLSVerificationDisabled, push.WarningPrivateNetworksAllowed,
		push.WarningCGNATAllowed, push.WarningPlaintextCredentials,
	} {
		if warnings.count(code) != 1 {
			t.Fatalf("warning %s count = %d", code, warnings.count(code))
		}
	}
	_ = cleanup(context.Background())
}

func TestFactoryOTLPDefaultAllSignalsBuildsOnlyItsLogAdapter(t *testing.T) {
	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		requests <- struct{}{}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	destination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "otel-default-all", Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: server.URL,
		TLS:           config.ObservabilityV8TLSSource{Insecure: true},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
	})
	if !destination.Capabilities.Supports(observability.SignalLogs) ||
		!destination.Capabilities.Supports(observability.SignalTraces) ||
		!destination.Capabilities.Supports(observability.SignalMetrics) ||
		len(destination.SelectedSignals) != 3 {
		t.Fatalf("default OTLP signals = %v", destination.SelectedSignals)
	}
	resourceContext := testResourceContextWith(t, map[string]string{
		"team.name": "runtime-security",
	}, false)
	adapter, cleanup, err := factory.PrepareDestination(context.Background(), destination, resourceContext)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := adapter.(*otlp.LogAdapter); !ok {
		t.Fatalf("adapter = %T", adapter)
	}
	if counters := deliverOne(t, destination.Name, adapter, `{"record_id":"default-all"}`); counters.Delivered != 1 {
		t.Fatalf("counters = %+v", counters)
	}
	select {
	case <-requests:
	case <-time.After(time.Second):
		t.Fatal("default-all OTLP log request not received")
	}
	_ = cleanup(context.Background())
}

func TestFactoryRejectsInvalidOTLPCABundleAfterSingleResolution(t *testing.T) {
	caPath := absoluteDestinationTestPath(t, "invalid-otlp-ca.pem")
	loader := &caLoader{bundles: map[string][]byte{caPath: []byte("invalid certificate")}, errors: map[string]error{}, calls: map[string]int{}}
	factory := newTestFactory(t, io.Discard, nil, loader, net.Dialer{}, nil)
	destination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "otel-invalid-ca", Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: "https://8.8.8.8:4318",
		Send: &config.ObservabilityV8SendSource{Signals: []observability.Signal{observability.SignalLogs}, Buckets: []observability.Bucket{"*"}},
		TLS:  config.ObservabilityV8TLSSource{CACert: caPath},
	})
	adapter, cleanup, err := factory.PrepareDestination(context.Background(), destination, testResourceContext(t))
	if adapter != nil || cleanup == nil || !IsError(err, ErrorAdapterPrepare) || loader.callCount(caPath) != 1 {
		t.Fatalf("adapter=%T cleanup=%t error=%v CA calls=%d", adapter, cleanup != nil, err, loader.callCount(caPath))
	}
}

func TestFactoryPreparesGRPCOTLPLogsAndCleanupClosesGenerationConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	capture := &factoryGRPCLogCapture{requests: make(chan *collectorlogpb.ExportLogsServiceRequest, 1), headers: make(chan metadata.MD, 1)}
	collectorlogpb.RegisterLogsServiceServer(server, capture)
	go server.Serve(listener)
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	dialer := &trackingDialer{}
	secrets := &secretResolver{values: map[string]string{"GRPC_AUTH": "Bearer grpc-exact"}, calls: map[string]int{}}
	warnings := &warningCollector{}
	factory, err := NewFactory(Options{
		ConsoleStream: ConsoleStderr, Stdout: io.Discard, Stderr: io.Discard,
		Secrets:  secrets,
		CALoader: &caLoader{bundles: map[string][]byte{}, errors: map[string]error{}, calls: map[string]int{}},
		Resolver: net.DefaultResolver, Dialer: dialer, Warnings: warnings,
	})
	if err != nil {
		t.Fatal(err)
	}
	destination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "otel-grpc", Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "grpc", Endpoint: listener.Addr().String(),
		Send:       &config.ObservabilityV8SendSource{Signals: []observability.Signal{observability.SignalLogs}, Buckets: []observability.Bucket{"*"}},
		Headers:    map[string]config.ObservabilityV8HeaderValue{"Authorization": config.ObservabilityV8EnvironmentHeader("GRPC_AUTH")},
		LoggerName: "defenseclaw.grpc.factory", TLS: config.ObservabilityV8TLSSource{Insecure: true},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
	})
	resourceContext := testResourceContextWith(t, map[string]string{
		"team.name": "runtime-security",
	}, false)
	adapter, cleanup, err := factory.PrepareDestination(context.Background(), destination, resourceContext)
	if err != nil {
		t.Fatal(err)
	}
	projection := `{"record_id":"grpc-record","body":{"message":"grpc-projected"}}`
	if counters := deliverOne(t, "otel-grpc", adapter, projection); counters.Delivered != 1 {
		t.Fatalf("counters = %+v", counters)
	}
	select {
	case request := <-capture.requests:
		resourceLogs := request.ResourceLogs[0]
		if resourceLogs.SchemaUrl != resourceContext.SchemaURL() || resourceLogs.Resource == nil ||
			resourceLogs.Resource.DroppedAttributesCount != resourceContext.ResourceDroppedAttributesCount() ||
			!reflect.DeepEqual(protoResourceValues(resourceLogs.Resource.Attributes), resourceContext.Values()) {
			t.Fatalf("OTLP gRPC resource mismatch: got=%+v want=%+v", resourceLogs, resourceContext.Values())
		}
		if got := protoResourceValues(resourceLogs.Resource.Attributes); got["team.name"] != "runtime-security" ||
			got["deployment.environment"] != "" || got["deployment.mode"] != "" || got["defenseclaw.device.id"] != "" {
			t.Fatalf("OTLP gRPC alias-disabled resource mismatch: %+v", got)
		}
		record := request.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
		if request.ResourceLogs[0].ScopeLogs[0].Scope.Name != "defenseclaw.grpc.factory" ||
			record.Body.GetStringValue() != projection || protoAttribute(record.Attributes, "defenseclaw.record.id") != "record" {
			t.Fatalf("gRPC request mismatch: %+v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("gRPC OTLP request not received")
	}
	select {
	case headers := <-capture.headers:
		if got := headers.Get("authorization"); len(got) != 1 || got[0] != "Bearer grpc-exact" {
			t.Fatalf("authorization = %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("gRPC metadata not received")
	}
	if secrets.callCount("GRPC_AUTH") != 1 || warnings.count(push.WarningPlaintextCredentials) != 1 {
		t.Fatalf("secret calls=%d plaintext warnings=%d", secrets.callCount("GRPC_AUTH"), warnings.count(push.WarningPlaintextCredentials))
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for dialer.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dialer.closed.Load() != 1 {
		t.Fatalf("closed connections = %d", dialer.closed.Load())
	}
	if err := cleanup(context.Background()); err != nil || dialer.closed.Load() != 1 {
		t.Fatalf("idempotent cleanup error=%v closes=%d", err, dialer.closed.Load())
	}
}

func TestFactoryPushCleanupClosesIdleConnectionAndIsIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	dialer := &trackingDialer{}
	secrets := &secretResolver{values: map[string]string{}, calls: map[string]int{}}
	loader := &caLoader{bundles: map[string][]byte{}, errors: map[string]error{}, calls: map[string]int{}}
	warnings := &warningCollector{}
	factory, err := NewFactory(Options{
		ConsoleStream: ConsoleStderr, Stdout: io.Discard, Stderr: io.Discard,
		Secrets: secrets, CALoader: loader, Resolver: net.DefaultResolver,
		Dialer: dialer, Warnings: warnings,
	})
	if err != nil {
		t.Fatal(err)
	}
	destination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "archive", Kind: config.ObservabilityV8DestinationHTTPJSONL, Endpoint: server.URL,
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
	})
	adapter, cleanup, err := factory.PrepareDestination(context.Background(), destination, testResourceContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if counters := deliverOne(t, "archive", adapter, `{"record_id":"record"}`); counters.Delivered != 1 {
		t.Fatalf("counters=%+v", counters)
	}
	if dialer.closed.Load() != 0 {
		t.Fatalf("connection closed before cleanup: %d", dialer.closed.Load())
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for dialer.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dialer.closed.Load() != 1 {
		t.Fatalf("idle connection closes=%d", dialer.closed.Load())
	}
	if err := cleanup(context.Background()); err != nil || dialer.closed.Load() != 1 {
		t.Fatalf("second cleanup error=%v closes=%d", err, dialer.closed.Load())
	}
}

func TestFactoryRejectsUnownedKindsAndInvalidCompiledDestinations(t *testing.T) {
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	prometheus := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "metrics", Kind: config.ObservabilityV8DestinationPrometheus,
		Listen: "127.0.0.1:9464", Path: "/metrics",
	})
	otlp := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "otlp", Kind: config.ObservabilityV8DestinationOTLP,
		Endpoint: "https://collector.example.test",
		Send: &config.ObservabilityV8SendSource{
			Signals: []observability.Signal{observability.SignalTraces}, Buckets: []observability.Bucket{"*"},
		},
	})
	unknown := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "archive", Kind: config.ObservabilityV8DestinationHTTPJSONL,
		Endpoint: "https://collector.example.test",
	})
	unknown.Kind = config.ObservabilityV8DestinationKind("future_logs")
	for _, destination := range []config.ObservabilityV8EffectiveDestination{prometheus, otlp, unknown} {
		adapter, cleanup, err := factory.PrepareDestination(context.Background(), destination, testResourceContext(t))
		if adapter != nil || cleanup == nil || !IsError(err, ErrorUnsupportedKind) {
			t.Fatalf("kind %s adapter=%T cleanup=%v error=%v", destination.Kind, adapter, cleanup != nil, err)
		}
		if err := cleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	invalid := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "archive", Kind: config.ObservabilityV8DestinationHTTPJSONL,
		Endpoint: "https://collector.example.test",
	})
	invalidCases := []config.ObservabilityV8EffectiveDestination{
		func() config.ObservabilityV8EffectiveDestination {
			value := invalid
			value.Enabled = false
			return value
		}(),
		func() config.ObservabilityV8EffectiveDestination {
			value := cloneDestination(t, invalid)
			value.SelectedSignals = []observability.Signal{observability.SignalMetrics}
			return value
		}(),
		func() config.ObservabilityV8EffectiveDestination {
			value := cloneDestination(t, invalid)
			value.Transport.Batch = nil
			return value
		}(),
		func() config.ObservabilityV8EffectiveDestination {
			value := cloneDestination(t, invalid)
			value.Transport.TLS.Insecure = true
			return value
		}(),
	}
	for index, destination := range invalidCases {
		adapter, cleanup, err := factory.PrepareDestination(context.Background(), destination, testResourceContext(t))
		if adapter != nil || cleanup == nil || !IsError(err, ErrorInvalidDestination) {
			t.Fatalf("invalid %d adapter=%T cleanup=%v error=%v", index, adapter, cleanup != nil, err)
		}
	}
}

func TestFactoryStrictSecretValidationAndDeterministicHeaderResolution(t *testing.T) {
	secrets := &secretResolver{
		values: map[string]string{"A_SECRET": "alpha", "Z_SECRET": "zulu", "BAD_TOKEN": "bad token"},
		calls:  map[string]int{},
	}
	factory := newTestFactory(t, io.Discard, secrets, nil, net.Dialer{}, nil)
	destination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "archive", Kind: config.ObservabilityV8DestinationHTTPJSONL,
		Endpoint: "https://collector.example.test", BearerEnv: "BAD_TOKEN",
		Headers: map[string]config.ObservabilityV8HeaderValue{
			"Z-Last":  config.ObservabilityV8EnvironmentHeader("Z_SECRET"),
			"A-First": config.ObservabilityV8EnvironmentHeader("A_SECRET"),
		},
	})
	adapter, cleanup, err := factory.PrepareDestination(context.Background(), destination, testResourceContext(t))
	if adapter != nil || cleanup == nil || !IsError(err, ErrorSecretUnavailable) {
		t.Fatalf("adapter=%T cleanup=%v error=%v", adapter, cleanup != nil, err)
	}
	for _, reference := range []string{"A_SECRET", "Z_SECRET", "BAD_TOKEN"} {
		if calls := secrets.callCount(reference); calls != 1 {
			t.Fatalf("reference %s resolved %d times", reference, calls)
		}
	}

	malformed := cloneDestination(t, destination)
	static := "one"
	malformed.Transport.Headers["A-First"] = config.ObservabilityV8HeaderValue{
		Static: &static, Secret: &config.ObservabilityV8SecretRef{Env: "A_SECRET"},
	}
	adapter, cleanup, err = factory.PrepareDestination(context.Background(), malformed, testResourceContext(t))
	if adapter != nil || cleanup == nil || !IsError(err, ErrorInvalidDestination) {
		t.Fatalf("malformed union adapter=%T cleanup=%v error=%v", adapter, cleanup != nil, err)
	}
}

func TestFactoryDependencyAndCleanupContracts(t *testing.T) {
	secrets := &secretResolver{values: map[string]string{}, calls: map[string]int{}}
	loader := &caLoader{bundles: map[string][]byte{}, errors: map[string]error{}, calls: map[string]int{}}
	warnings := &warningCollector{}
	base := Options{
		ConsoleStream: ConsoleStderr, Stdout: io.Discard, Stderr: io.Discard,
		Secrets: secrets, CALoader: loader, Resolver: net.DefaultResolver,
		Dialer: &net.Dialer{}, Warnings: warnings,
	}
	invalid := []Options{
		func() Options { value := base; value.ConsoleStream = "unknown"; return value }(),
		func() Options { value := base; value.Stderr = nil; return value }(),
		func() Options { value := base; value.Secrets = nil; return value }(),
		func() Options { value := base; value.CALoader = nil; return value }(),
		func() Options { value := base; value.Resolver = nil; return value }(),
		func() Options { value := base; value.Dialer = nil; return value }(),
		func() Options { value := base; value.Warnings = nil; return value }(),
	}
	for index, options := range invalid {
		if factory, err := NewFactory(options); factory != nil || !IsError(err, ErrorInvalidDependencies) {
			t.Fatalf("dependency case %d factory=%v error=%v", index, factory != nil, err)
		}
	}

	calls := 0
	cleanup := retryableCleanup(func(context.Context) error {
		calls++
		if calls == 1 {
			return errors.New("temporary cleanup failure")
		}
		return nil
	})
	if err := cleanup(context.Background()); err == nil || calls != 1 {
		t.Fatalf("first cleanup error=%v calls=%d", err, calls)
	}
	if err := cleanup(context.Background()); err != nil || calls != 2 {
		t.Fatalf("retry cleanup error=%v calls=%d", err, calls)
	}
	const goroutines = 16
	var wait sync.WaitGroup
	wait.Add(goroutines)
	for range goroutines {
		go func() {
			defer wait.Done()
			if err := cleanup(context.Background()); err != nil {
				t.Errorf("concurrent cleanup: %v", err)
			}
		}()
	}
	wait.Wait()
	if calls != 2 {
		t.Fatalf("successful cleanup repeated: %d", calls)
	}

	var nilFactory *Factory
	adapter, nilCleanup, err := nilFactory.PrepareDestination(context.Background(), config.ObservabilityV8EffectiveDestination{}, telemetry.V8ResourceContext{})
	if adapter != nil || nilCleanup == nil || !IsError(err, ErrorInvalidDependencies) {
		t.Fatalf("nil factory adapter=%T cleanup=%v error=%v", adapter, nilCleanup != nil, err)
	}
}

func TestFactoryConsoleStreamChoiceAndPanickingCALoader(t *testing.T) {
	var stdout, stderr bytes.Buffer
	secrets := &secretResolver{values: map[string]string{}, calls: map[string]int{}}
	warnings := &warningCollector{}
	factory, err := NewFactory(Options{
		ConsoleStream: ConsoleStdout, Stdout: &stdout, Stderr: &stderr,
		Secrets: secrets,
		CALoader: CAFileLoaderFunc(func(context.Context, string) ([]byte, error) {
			panic("sensitive CA loader panic")
		}),
		Resolver: net.DefaultResolver, Dialer: &net.Dialer{}, Warnings: warnings,
	})
	if err != nil {
		t.Fatal(err)
	}
	console := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "terminal", Kind: config.ObservabilityV8DestinationConsole,
	})
	adapter, cleanup, err := factory.PrepareDestination(context.Background(), console, telemetry.V8ResourceContext{})
	if err != nil {
		t.Fatal(err)
	}
	projection := `{"record_id":"record"}`
	if counters := deliverOne(t, "terminal", adapter, projection); counters.Delivered != 1 {
		t.Fatalf("counters=%+v", counters)
	}
	if stdout.String() != projection+"\n" || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}

	caPath := absoluteDestinationTestPath(t, "panicking-ca.pem")
	caDestination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "archive", Kind: config.ObservabilityV8DestinationHTTPJSONL,
		Endpoint: "https://collector.example.test",
		TLS:      config.ObservabilityV8TLSSource{CACert: caPath},
	})
	adapter, cleanup, err = factory.PrepareDestination(context.Background(), caDestination, telemetry.V8ResourceContext{})
	if adapter != nil || cleanup == nil || !IsError(err, ErrorCALoadFailed) ||
		strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), caPath) {
		t.Fatalf("panic masking adapter=%T cleanup=%v error=%v", adapter, cleanup != nil, err)
	}

	resolverFactory, err := NewFactory(Options{
		ConsoleStream: ConsoleStderr, Stdout: io.Discard, Stderr: io.Discard,
		Secrets: secrets, CALoader: CAFileLoaderFunc(func(context.Context, string) ([]byte, error) { return nil, nil }),
		Resolver: panickingResolver{}, Dialer: &net.Dialer{}, Warnings: warnings,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolverDestination := compileDestination(t, config.ObservabilityV8DestinationSource{
		Name: "archive", Kind: config.ObservabilityV8DestinationHTTPJSONL,
		Endpoint: "https://collector.example.test",
	})
	adapter, cleanup, err = resolverFactory.PrepareDestination(context.Background(), resolverDestination, telemetry.V8ResourceContext{})
	if adapter != nil || cleanup == nil || !IsError(err, ErrorAdapterPrepare) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("resolver panic adapter=%T cleanup=%v error=%v", adapter, cleanup != nil, err)
	}
}
