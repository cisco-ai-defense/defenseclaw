// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package push

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

type capturedRequest struct {
	method  string
	header  http.Header
	payload []byte
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type closeTrackingBody struct {
	reader *strings.Reader
	closed atomic.Bool
}

func newCloseTrackingBody(value string) *closeTrackingBody {
	return &closeTrackingBody{reader: strings.NewReader(value)}
}

func (body *closeTrackingBody) Read(buffer []byte) (int, error) { return body.reader.Read(buffer) }
func (body *closeTrackingBody) Close() error {
	body.closed.Store(true)
	return nil
}

type requestCapture struct {
	mu       sync.Mutex
	requests []capturedRequest
	status   int
	body     string
}

func (capture *requestCapture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	payload, _ := io.ReadAll(request.Body)
	capture.mu.Lock()
	capture.requests = append(capture.requests, capturedRequest{
		method: request.Method, header: request.Header.Clone(), payload: payload,
	})
	status, body := capture.status, capture.body
	capture.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, body)
}

func (capture *requestCapture) snapshot() []capturedRequest {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	result := make([]capturedRequest, len(capture.requests))
	copy(result, capture.requests)
	return result
}

func projectedPayload(t *testing.T, recordID, projected string) delivery.Payload {
	t.Helper()
	payload, err := delivery.NewPayload([]byte(projected), delivery.RoutingIdentity{
		RecordID: recordID, Bucket: "diagnostic", Signal: "logs", EventName: "diagnostic.message",
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func deliverBatch(t *testing.T, name string, adapter delivery.Adapter, projected ...string) delivery.Counters {
	t.Helper()
	dispatcher, err := delivery.NewDispatcher(delivery.Config{
		Destination: name, Enabled: true,
		MaxQueueItems: 32, MaxQueueBytes: 16 * 1024 * 1024,
		MaxBatchItems: 32, MaxBatchBytes: 16 * 1024 * 1024,
		ScheduledDelay: time.Hour, AttemptTimeout: 2 * time.Second,
		Retry: delivery.RetryPolicy{MaxAttempts: 1},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	for index, encoded := range projected {
		result := dispatcher.Enqueue(projectedPayload(t, string(rune('a'+index)), encoded))
		if !result.Accepted() {
			t.Fatalf("enqueue %d: %+v", index, result)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dispatcher.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	counters := dispatcher.Counters()
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	return counters
}

func TestHTTPJSONLExactWireAndResolvedAuthorization(t *testing.T) {
	capture := &requestCapture{status: http.StatusNoContent}
	server := httptest.NewServer(capture)
	defer server.Close()
	adapter, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{
		Destination: "archive", Endpoint: server.URL, Method: http.MethodPatch,
		Headers: map[string]string{"X-Tenant": "acme"}, BearerToken: "resolved-token",
		Network: NetworkOptions{AllowPrivateNetworks: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	first := `{"record_id":"one","body":{"message":"safe"}}`
	second := `{"record_id":"two","body":{"message":"also-safe"}}`
	counters := deliverBatch(t, "archive", adapter, first, second)
	if counters.Delivered != 2 || counters.Rejected != 0 {
		t.Fatalf("counters=%+v", counters)
	}
	requests := capture.snapshot()
	if len(requests) != 1 {
		t.Fatalf("requests=%d", len(requests))
	}
	request := requests[0]
	if request.method != http.MethodPatch || request.header.Get("Content-Type") != "application/x-ndjson" ||
		request.header.Get("X-Tenant") != "acme" || request.header.Get("Authorization") != "Bearer resolved-token" {
		t.Fatalf("unexpected request metadata")
	}
	if got, want := string(request.payload), first+"\n"+second+"\n"; got != want {
		t.Fatalf("payload=%q want=%q", got, want)
	}
	if size, ok := adapter.EncodedSize([]int{len(first), len(second)}); !ok || size != len(request.payload) {
		t.Fatalf("encoded size=(%d,%t) wire=%d", size, ok, len(request.payload))
	}
}

func TestHTTPJSONLRejectsNonNDJSONProjectionBeforeRequest(t *testing.T) {
	capture := &requestCapture{status: http.StatusNoContent}
	server := httptest.NewServer(capture)
	defer server.Close()
	adapter, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{
		Destination: "archive", Endpoint: server.URL,
		Network: NetworkOptions{AllowPrivateNetworks: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, projected := range []string{`not-json`, "{\n\"record_id\":\"one\"}"} {
		counters := deliverBatch(t, "invalid-ndjson-"+string(rune('a'+index)), adapter, projected)
		if counters.Rejected != 1 {
			t.Fatalf("projection %d counters=%+v", index, counters)
		}
	}
	if requests := capture.snapshot(); len(requests) != 0 {
		t.Fatalf("invalid projection produced %d requests", len(requests))
	}
}

func TestAdaptersRejectInvalidUTF8Projection(t *testing.T) {
	invalid := []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	if validNDJSONProjection(invalid) {
		t.Fatal("HTTP JSONL accepted invalid UTF-8 projection")
	}
	if _, _, ok := projectedAliases(invalid); ok {
		t.Fatal("Splunk HEC accepted invalid UTF-8 projection")
	}
}

func TestProjectedAliasesPreserveCanonicalOccurrenceCorrelation(t *testing.T) {
	projected := []byte(`{"record_id":"r1","correlation":{"semantic_event_id":"semantic-1","logical_event_id":"logical-1","connector_instance_id":"connector-instance-1"},"body":{"message":"safe"}}`)
	alias, _, ok := projectedAliases(projected)
	if !ok {
		t.Fatal("canonical projection was rejected")
	}
	if alias.SemanticEventID != "semantic-1" || alias.LogicalEventID != "logical-1" ||
		alias.ConnectorInstanceID != "connector-instance-1" {
		t.Fatalf("correlation aliases = %#v", alias)
	}
}

func TestSplunkHECExactProjectionOnlyWrapperAndOverride(t *testing.T) {
	capture := &requestCapture{status: http.StatusOK, body: `{"text":"Success","code":0,"ackId":7}`}
	server := httptest.NewServer(capture)
	defer server.Close()
	adapter, err := NewSplunkHEC(context.Background(), SplunkHECConfig{
		Destination: "splunk", Endpoint: server.URL, Token: "resolved-hec-token",
		Index: "main", Source: "defenseclaw", SourceType: "defenseclaw:event",
		SourceTypeOverrides: map[string]string{"config-update": "defenseclaw:config"},
		Network:             NetworkOptions{AllowPrivateNetworks: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	projected := `{"record_id":"r1","timestamp":"2026-07-03T01:02:03Z","bucket":"diagnostic","event_name":"diagnostic.message","severity":"INFO","source":"gateway","action":"config-update","correlation":{"semantic_event_id":"semantic-1","logical_event_id":"logical-1","connector_instance_id":"connector-instance-1","run_id":"run-1"},"body":{"message":"safe","verbatim":"<>&","removed":false}}`
	counters := deliverBatch(t, "splunk", adapter, projected)
	if counters.Delivered != 1 || counters.Rejected != 0 {
		t.Fatalf("counters=%+v", counters)
	}
	requests := capture.snapshot()
	if len(requests) != 1 {
		t.Fatalf("requests=%d", len(requests))
	}
	request := requests[0]
	if request.method != http.MethodPost || request.header.Get("Authorization") != "Splunk resolved-hec-token" ||
		request.header.Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected request metadata")
	}
	want := `{"index":"main","source":"defenseclaw","sourcetype":"defenseclaw:config","event":{"record":` + projected + `,"id":"r1","record_id":"r1","timestamp":"2026-07-03T01:02:03Z","bucket":"diagnostic","event_name":"diagnostic.message","severity":"INFO","source":"gateway","action":"config-update","semantic_event_id":"semantic-1","logical_event_id":"logical-1","connector_instance_id":"connector-instance-1","run_id":"run-1","details":"safe"}}` + "\n"
	if got := string(request.payload); got != want {
		t.Fatalf("wire mismatch\n got: %s\nwant: %s", got, want)
	}
	var envelope struct {
		Event map[string]json.RawMessage `json:"event"`
	}
	if err := json.Unmarshal(request.payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if string(envelope.Event["record"]) != projected || string(envelope.Event["details"]) != `"safe"` {
		t.Fatalf("projection or aliases changed")
	}
	if _, found := envelope.Event["removed"]; found {
		t.Fatal("non-compatibility projected value became an alias")
	}
	if size, ok := adapter.EncodedSize([]int{len(projected)}); !ok || len(request.payload) > size {
		t.Fatalf("encoded size=(%d,%t) wire=%d", size, ok, len(request.payload))
	}
}

func TestSplunkWrapperCannotRecoverRemovedCanaryOrOpaqueEvents(t *testing.T) {
	capture := &requestCapture{status: http.StatusOK, body: `{"code":0}`}
	server := httptest.NewServer(capture)
	defer server.Close()
	adapter, err := NewSplunkHEC(context.Background(), SplunkHECConfig{
		Destination: "splunk", Endpoint: server.URL, Token: "token",
		Network: NetworkOptions{AllowPrivateNetworks: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	strictProjection := `{"record_id":"safe-id","bucket":"diagnostic","event_name":"diagnostic.message","body":{"message":"[REDACTED]"}}`
	counters := deliverBatch(t, "splunk", adapter, strictProjection)
	if counters.Delivered != 1 {
		t.Fatalf("strict counters=%+v", counters)
	}
	wire := capture.snapshot()[0].payload
	for _, absent := range []string{"raw-canary-998877", "secret@example.test"} {
		if strings.Contains(string(wire), absent) {
			t.Fatalf("removed canary %q appeared in complete wrapper", absent)
		}
	}

	opaque := `{"record_id":"unsafe","bucket":"diagnostic","event_name":"diagnostic.message","body":{"_splunk_hec_events":[{"event":"raw-canary-998877"}]}}`
	counters = deliverBatch(t, "splunk-opaque", adapter, opaque)
	if counters.Rejected != 1 || len(capture.snapshot()) != 1 {
		t.Fatalf("opaque counters=%+v requests=%d", counters, len(capture.snapshot()))
	}
}

func TestSplunkHECMultiRecordWireStaysWithinConservativeEstimate(t *testing.T) {
	capture := &requestCapture{status: http.StatusOK, body: `{"code":0}`}
	server := httptest.NewServer(capture)
	defer server.Close()
	adapter, err := NewSplunkHEC(context.Background(), SplunkHECConfig{
		Destination: "splunk", Endpoint: server.URL, Token: "token",
		Network: NetworkOptions{AllowPrivateNetworks: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	first := `{"record_id":"one","bucket":"diagnostic","event_name":"diagnostic.message"}`
	second := `{"record_id":"two","bucket":"diagnostic","event_name":"diagnostic.message"}`
	if counters := deliverBatch(t, "splunk", adapter, first, second); counters.Delivered != 2 {
		t.Fatalf("counters=%+v", counters)
	}
	request := capture.snapshot()[0]
	lines := strings.Split(strings.TrimSuffix(string(request.payload), "\n"), "\n")
	if len(lines) != 2 || !json.Valid([]byte(lines[0])) || !json.Valid([]byte(lines[1])) {
		t.Fatalf("HEC batch is not two JSON lines: %q", request.payload)
	}
	estimate, ok := adapter.EncodedSize([]int{len(first), len(second)})
	if !ok || len(request.payload) > estimate {
		t.Fatalf("wire=%d estimate=(%d,%t)", len(request.payload), estimate, ok)
	}
}

func TestStatusAndHECAcknowledgementClassifications(t *testing.T) {
	statusTests := map[int]delivery.DeliveryOutcome{
		200: delivery.OutcomeDelivered, 204: delivery.OutcomeDelivered,
		400: delivery.OutcomePermanentPayload, 401: delivery.OutcomeAuthentication,
		403: delivery.OutcomeAuthentication, 408: delivery.OutcomeTransient,
		425: delivery.OutcomeTransient, 429: delivery.OutcomeTransient,
		500: delivery.OutcomeTransient, 599: delivery.OutcomeTransient,
		600: delivery.OutcomePermanentPayload,
	}
	for status, want := range statusTests {
		if got := classifyHTTPStatus(status); got != want {
			t.Errorf("status %d=%s want=%s", status, got, want)
		}
	}
	ackTests := []struct {
		body string
		want delivery.DeliveryOutcome
	}{
		{`{"code":0}`, delivery.OutcomeDelivered},
		{`{"code":0,"text":"Success","ackId":9}`, delivery.OutcomeDelivered},
		{`{"code":4}`, delivery.OutcomeAuthentication},
		{`{"code":8}`, delivery.OutcomeTransient},
		{`{"code":12}`, delivery.OutcomePermanentPayload},
		{`{}`, delivery.OutcomeAmbiguous},
		{`not-json`, delivery.OutcomeAmbiguous},
		{"", delivery.OutcomeAmbiguous},
		{strings.Repeat("x", maxHECResponseBytes+1), delivery.OutcomeAmbiguous},
	}
	for _, test := range ackTests {
		if got := classifyHECAcknowledgement(strings.NewReader(test.body)); got != test.want {
			t.Errorf("ack len=%d got=%s want=%s", len(test.body), got, test.want)
		}
	}
}

func TestAdaptersCloseResponseBodiesOnSuccessAndFailure(t *testing.T) {
	activationServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer activationServer.Close()
	httpAdapter, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{
		Destination: "archive", Endpoint: activationServer.URL,
		Network: NetworkOptions{AllowPrivateNetworks: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	hecAdapter, err := NewSplunkHEC(context.Background(), SplunkHECConfig{
		Destination: "splunk", Endpoint: activationServer.URL, Token: "token",
		Network: NetworkOptions{AllowPrivateNetworks: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		adapter   delivery.Adapter
		setClient func(*http.Client)
		status    int
		body      string
		delivered uint64
		rejected  uint64
	}{
		{"http success", httpAdapter, func(client *http.Client) { httpAdapter.client = client }, 204, "ignored", 1, 0},
		{"http failure", httpAdapter, func(client *http.Client) { httpAdapter.client = client }, 500, "secret failure body", 0, 1},
		{"hec success", hecAdapter, func(client *http.Client) { hecAdapter.client = client }, 200, `{"code":0}`, 1, 0},
		{"hec failure", hecAdapter, func(client *http.Client) { hecAdapter.client = client }, 500, "secret failure body", 0, 1},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			responseBody := newCloseTrackingBody(test.body)
			test.setClient(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				_, _ = io.Copy(io.Discard, request.Body)
				return &http.Response{
					StatusCode: test.status, Header: make(http.Header), Body: responseBody, Request: request,
				}, nil
			})})
			counters := deliverBatch(t, "body-close-"+string(rune('a'+index)), test.adapter, `{"record_id":"one"}`)
			if counters.Delivered != test.delivered || counters.Rejected != test.rejected {
				t.Fatalf("counters=%+v", counters)
			}
			if !responseBody.closed.Load() {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func TestConstructorsRejectUnsafeOrSecretLeakingConfiguration(t *testing.T) {
	secret := "do-not-echo-token"
	tests := []struct {
		name string
		make func() error
	}{
		{"unsafe default loopback", func() error {
			_, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{Destination: "http", Endpoint: "http://127.0.0.1:4318"})
			return err
		}},
		{"inline credentials", func() error {
			_, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{Destination: "http", Endpoint: "https://user:" + secret + "@collector.example.test"})
			return err
		}},
		{"invalid method", func() error {
			_, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{Destination: "http", Endpoint: "https://collector.example.test", Method: http.MethodDelete})
			return err
		}},
		{"header injection", func() error {
			_, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{Destination: "http", Endpoint: "https://collector.example.test", Headers: map[string]string{"X-Test": "ok\r\n" + secret}})
			return err
		}},
		{"conflicting auth", func() error {
			_, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{Destination: "http", Endpoint: "https://collector.example.test", Headers: map[string]string{"Authorization": "one"}, BearerToken: secret})
			return err
		}},
		{"duplicate canonical header", func() error {
			_, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{Destination: "http", Endpoint: "https://collector.example.test", Headers: map[string]string{"X-Tenant": "one", "x-tenant": "two"}})
			return err
		}},
		{"invalid HEC token", func() error {
			_, err := NewSplunkHEC(context.Background(), SplunkHECConfig{Destination: "splunk", Endpoint: "https://collector.example.test", Token: secret + "\n"})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.make()
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "collector.example.test") {
				t.Fatalf("error disclosed configuration: %v", err)
			}
		})
	}
}

type resolverStep struct {
	addresses []net.IPAddr
	err       error
}

type sequenceResolver struct {
	mu    sync.Mutex
	steps []resolverStep
	calls int
}

func (resolver *sequenceResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	index := resolver.calls
	resolver.calls++
	if index >= len(resolver.steps) {
		index = len(resolver.steps) - 1
	}
	if index < 0 {
		return nil, errors.New("temporary resolver failure")
	}
	step := resolver.steps[index]
	return append([]net.IPAddr(nil), step.addresses...), step.err
}

type mappingDialer struct {
	target string
	calls  atomic.Int64
}

func (dialer *mappingDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	dialer.calls.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, dialer.target)
}

func ips(values ...string) []net.IPAddr {
	result := make([]net.IPAddr, 0, len(values))
	for _, value := range values {
		result = append(result, net.IPAddr{IP: net.ParseIP(value)})
	}
	return result
}

func TestActivationDNSDegradedThenGuardedRetrySucceeds(t *testing.T) {
	capture := &requestCapture{status: http.StatusNoContent}
	server := httptest.NewServer(capture)
	defer server.Close()
	target := strings.TrimPrefix(server.URL, "http://")
	resolver := &sequenceResolver{steps: []resolverStep{
		{err: errors.New("temporary resolver failure")},
		{addresses: ips("8.8.8.8")},
	}}
	dialer := &mappingDialer{target: target}
	var warnings []Warning
	adapter, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{
		Destination: "archive", Endpoint: "http://collector.example.test:4318",
		Network:  NetworkOptions{Resolver: resolver, Dialer: dialer},
		Observer: WarningObserverFunc(func(warning Warning) { warnings = append(warnings, warning) }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.ActivationState() != ActivationDegraded || len(warnings) != 1 || warnings[0].Code != WarningActivationDNSDegraded {
		t.Fatalf("activation=%s warnings=%+v", adapter.ActivationState(), warnings)
	}
	counters := deliverBatch(t, "archive", adapter, `{"record_id":"one"}`)
	if counters.Delivered != 1 || dialer.calls.Load() != 1 {
		t.Fatalf("counters=%+v dials=%d", counters, dialer.calls.Load())
	}
}

func TestDNSRebindingAndMixedAnswersNeverReachDialer(t *testing.T) {
	resolver := &sequenceResolver{steps: []resolverStep{
		{addresses: ips("8.8.8.8")},
		{addresses: ips("127.0.0.1")},
	}}
	dialer := &mappingDialer{target: "127.0.0.1:1"}
	adapter, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{
		Destination: "archive", Endpoint: "http://collector.example.test:4318",
		Network: NetworkOptions{Resolver: resolver, Dialer: dialer},
	})
	if err != nil {
		t.Fatal(err)
	}
	counters := deliverBatch(t, "archive", adapter, `{"record_id":"one"}`)
	if counters.Rejected != 1 || dialer.calls.Load() != 0 {
		t.Fatalf("rebind counters=%+v dials=%d", counters, dialer.calls.Load())
	}

	mixed := &sequenceResolver{steps: []resolverStep{{addresses: ips("8.8.8.8", "127.0.0.1")}}}
	_, err = NewHTTPJSONL(context.Background(), HTTPJSONLConfig{
		Destination: "archive", Endpoint: "http://collector.example.test:4318",
		Network: NetworkOptions{Resolver: mixed, Dialer: dialer},
	})
	if !errors.Is(err, ErrUnsafeEndpoint) {
		t.Fatalf("mixed error=%v", err)
	}
}

func TestRedirectIsUnsafeAndNotFollowed(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		http.Redirect(writer, request, "/second-hop", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	adapter, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{
		Destination: "archive", Endpoint: server.URL,
		Network: NetworkOptions{AllowPrivateNetworks: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	counters := deliverBatch(t, "archive", adapter, `{"record_id":"one"}`)
	if counters.Rejected != 1 || requests.Load() != 1 {
		t.Fatalf("counters=%+v requests=%d", counters, requests.Load())
	}
}

func TestTLSCABundleAndSafeWarnings(t *testing.T) {
	capture := &requestCapture{status: http.StatusNoContent}
	server := httptest.NewTLSServer(capture)
	defer server.Close()
	certificate := server.Certificate()
	if _, err := x509.ParseCertificate(certificate.Raw); err != nil {
		t.Fatal(err)
	}
	caBundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	adapter, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{
		Destination: "archive", Endpoint: server.URL,
		TLS:     TLSOptions{CABundle: caBundle},
		Network: NetworkOptions{AllowPrivateNetworks: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	secureTransport := adapter.client.Transport.(*http.Transport)
	if secureTransport.TLSClientConfig.InsecureSkipVerify || secureTransport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("TLS transport is not secure by default")
	}
	if counters := deliverBatch(t, "archive", adapter, `{"record_id":"one"}`); counters.Delivered != 1 {
		t.Fatalf("CA delivery=%+v", counters)
	}

	var warnings []Warning
	insecureAdapter, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{
		Destination: "archive", Endpoint: server.URL,
		TLS:      TLSOptions{InsecureSkipVerify: true},
		Network:  NetworkOptions{AllowPrivateNetworks: true, AllowCGNAT: true},
		Observer: WarningObserverFunc(func(warning Warning) { warnings = append(warnings, warning) }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !insecureAdapter.client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("explicit insecure TLS opt-in was not applied")
	}
	wantCodes := []WarningCode{WarningTLSVerificationDisabled, WarningPrivateNetworksAllowed, WarningCGNATAllowed}
	if len(warnings) != len(wantCodes) {
		t.Fatalf("warnings=%+v", warnings)
	}
	for index, warning := range warnings {
		if warning.Destination != "archive" || warning.Code != wantCodes[index] {
			t.Fatalf("warning[%d]=%+v", index, warning)
		}
	}
	_, err = NewHTTPJSONL(context.Background(), HTTPJSONLConfig{
		Destination: "archive", Endpoint: server.URL,
		TLS:     TLSOptions{CABundle: []byte("not a certificate")},
		Network: NetworkOptions{AllowPrivateNetworks: true},
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid CA error=%v", err)
	}
}

func TestPlaintextCredentialWarningsAreBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	var warnings []Warning
	observer := WarningObserverFunc(func(warning Warning) { warnings = append(warnings, warning) })
	base := HTTPJSONLConfig{
		Destination: "archive", Endpoint: server.URL,
		Network: NetworkOptions{AllowPrivateNetworks: true}, Observer: observer,
	}
	if _, err := NewHTTPJSONL(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	if countWarning(warnings, WarningPlaintextCredentials) != 0 {
		t.Fatalf("unauthenticated HTTP warnings=%+v", warnings)
	}

	warnings = nil
	base.BearerToken = "bounded-token"
	if _, err := NewHTTPJSONL(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	if countWarning(warnings, WarningPlaintextCredentials) != 1 {
		t.Fatalf("bearer HTTP warnings=%+v", warnings)
	}
	for _, warning := range warnings {
		if warning.Destination != "archive" {
			t.Fatalf("warning identity drifted: %+v", warning)
		}
	}

	warnings = nil
	base.BearerToken = ""
	base.Headers = map[string]string{"X-Tenant": "tenant-a"}
	base.SecretHeaders = true
	if _, err := NewHTTPJSONL(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	if countWarning(warnings, WarningPlaintextCredentials) != 1 {
		t.Fatalf("secret-header HTTP warnings=%+v", warnings)
	}

	warnings = nil
	if _, err := NewSplunkHEC(context.Background(), SplunkHECConfig{
		Destination: "splunk", Endpoint: server.URL, Token: "hec-token",
		Network: NetworkOptions{AllowPrivateNetworks: true}, Observer: observer,
	}); err != nil {
		t.Fatal(err)
	}
	if countWarning(warnings, WarningPlaintextCredentials) != 1 {
		t.Fatalf("Splunk HTTP warnings=%+v", warnings)
	}
}

func countWarning(warnings []Warning, code WarningCode) int {
	count := 0
	for _, warning := range warnings {
		if warning.Code == code {
			count++
		}
	}
	return count
}

func TestTimeoutAfterServerReceivesBodyTerminatesAmbiguousAttempt(t *testing.T) {
	received := make(chan string, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		received <- string(body)
		select {
		case <-request.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	adapter, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{
		Destination: "archive", Endpoint: server.URL,
		Network: NetworkOptions{AllowPrivateNetworks: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := delivery.NewDispatcher(delivery.Config{
		Destination: "archive", Enabled: true,
		MaxQueueItems: 1, MaxQueueBytes: 1024,
		MaxBatchItems: 1, MaxBatchBytes: 1024,
		AttemptTimeout: 50 * time.Millisecond,
		Retry:          delivery.RetryPolicy{MaxAttempts: 1},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	if !dispatcher.Enqueue(projectedPayload(t, "one", `{"record_id":"one"}`)).Accepted() {
		t.Fatal("enqueue failed")
	}
	select {
	case body := <-received:
		if body != `{"record_id":"one"}`+"\n" {
			t.Fatalf("server body=%q", body)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive request body")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := dispatcher.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if counters := dispatcher.Counters(); counters.Rejected != 1 {
		t.Fatalf("counters=%+v", counters)
	}
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestEncodedSizeBoundariesAndOverflow(t *testing.T) {
	httpAdapter := &HTTPJSONL{}
	if got, ok := httpAdapter.EncodedSize([]int{1, 2, 3}); !ok || got != 9 {
		t.Fatalf("HTTP size=(%d,%t)", got, ok)
	}
	if _, ok := httpAdapter.EncodedSize([]int{-1}); ok {
		t.Fatal("HTTP accepted negative size")
	}
	hecAdapter := &SplunkHEC{}
	if got, ok := hecAdapter.EncodedSize([]int{1, 2}); !ok || got != 3+2*maxHECWrapperBytes {
		t.Fatalf("HEC size=(%d,%t)", got, ok)
	}
	if _, ok := hecAdapter.EncodedSize([]int{int(^uint(0) >> 1)}); ok {
		t.Fatal("HEC accepted overflow")
	}
}

func TestWorstCaseHECCompatibilityWrapperFitsAllowance(t *testing.T) {
	aliasValue := strings.Repeat("<", maxAliasValueBytes)
	aliases := compatibilityAlias{
		ID: aliasValue, RecordID: aliasValue, Timestamp: aliasValue,
		Bucket: aliasValue, EventName: aliasValue, Severity: aliasValue,
		Source: aliasValue, Connector: aliasValue, Action: aliasValue, Outcome: aliasValue,
		RunID: aliasValue, RequestID: aliasValue, SessionID: aliasValue,
		TurnID: aliasValue, TraceID: aliasValue, AgentID: aliasValue,
		AgentInstanceID: aliasValue, SidecarInstanceID: aliasValue, PolicyID: aliasValue,
		ModelRequestID: aliasValue, ModelResponseID: aliasValue,
		ToolInvocationID: aliasValue, ConnectorID: aliasValue, Actor: aliasValue,
		Target: aliasValue, Details: aliasValue, ToolName: aliasValue,
		ToolID: aliasValue, DestinationApp: aliasValue, AgentName: aliasValue,
	}
	staticValue := strings.Repeat("<", 512)
	projection := json.RawMessage(`{"record_id":"one"}`)
	encoded, err := encodeHECEnvelope(hecEnvelope{
		Index: staticValue, Source: staticValue, SourceType: staticValue,
		Event: hecEvent{Record: projection, Aliases: aliases},
	})
	if err != nil {
		t.Fatal(err)
	}
	if overhead := len(encoded) - len(projection); overhead > maxHECWrapperBytes {
		t.Fatalf("worst-case wrapper overhead=%d max=%d", overhead, maxHECWrapperBytes)
	}
}

func TestTransportClassificationIsBounded(t *testing.T) {
	for _, test := range []struct {
		err  error
		want delivery.DeliveryOutcome
	}{
		{netguard.ErrV8AddressProhibited, delivery.OutcomeUnsafeEndpoint},
		{netguard.ErrV8RedirectBlocked, delivery.OutcomeUnsafeEndpoint},
		{netguard.ErrV8ResolutionFailed, delivery.OutcomeTransient},
		{netguard.ErrV8ConnectionFailed, delivery.OutcomeTransient},
		{context.DeadlineExceeded, delivery.OutcomeTransient},
		{errors.New("acknowledgement lost"), delivery.OutcomeAmbiguous},
	} {
		if got := classifyTransportError(test.err, false); got != test.want {
			t.Errorf("error=%v got=%s want=%s", test.err, got, test.want)
		}
	}
	if got := classifyTransportError(context.DeadlineExceeded, true); got != delivery.OutcomeAmbiguous {
		t.Fatalf("post-write deadline=%s want=%s", got, delivery.OutcomeAmbiguous)
	}
	if got := classifyTransportError(netguard.ErrV8AddressProhibited, true); got != delivery.OutcomeUnsafeEndpoint {
		t.Fatalf("post-write unsafe=%s want=%s", got, delivery.OutcomeUnsafeEndpoint)
	}
}
