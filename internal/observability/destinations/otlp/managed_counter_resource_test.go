// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	collectormetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/proto"
)

// A direct OTLP metric destination gets the managed sandbox counters with a
// resource that keeps only the service, the environment and the OS, and
// every other metric with the full resource. Before, the counters carried
// host.name, tenant.id, workspace.id and the device key fingerprint, which
// a collector that turns resource attributes into labels exposes.
func TestDirectOTLPSendsManagedSandboxCountersWithoutHostOrAccountResource(t *testing.T) {
	requests := make(chan *collectormetricpb.ExportMetricsServiceRequest, 8)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		var decoded collectormetricpb.ExportMetricsServiceRequest
		if err := proto.Unmarshal(body, &decoded); err != nil {
			t.Error(err)
		}
		requests <- &decoded
		encoded, _ := proto.Marshal(&collectormetricpb.ExportMetricsServiceResponse{})
		writer.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = writer.Write(encoded)
	}))
	defer server.Close()
	factory := prepareTestFactory(t, Config{
		Destination: "direct-otlp", Protocol: ProtocolHTTP, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalMetrics}, Timeout: time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	reader, err := factory.NewPeriodicMetricReader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	full, _ := testCompleteSignalResource()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithResource(full), sdkmetric.WithReader(reader.SDKReader()))
	defer func() { _ = provider.Shutdown(context.Background()) }()
	meter := provider.Meter("defenseclaw.telemetry")
	managed, err := meter.Int64Counter(observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals)
	if err != nil {
		t.Fatal(err)
	}
	other, err := meter.Int64Counter("defenseclaw.sandbox.transitions")
	if err != nil {
		t.Fatal(err)
	}
	managed.Add(context.Background(), 1)
	other.Add(context.Background(), 1)
	if err := reader.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	resources := map[string][]string{}
	for len(resources) < 2 {
		select {
		case request := <-requests:
			for _, rm := range request.ResourceMetrics {
				var keys []string
				for _, kv := range rm.Resource.Attributes {
					keys = append(keys, kv.Key)
				}
				sort.Strings(keys)
				if rm.SchemaUrl != testCompleteSignalResourceSchemaURL {
					t.Fatalf("schema URL = %q", rm.SchemaUrl)
				}
				for _, scope := range rm.ScopeMetrics {
					for _, metric := range scope.Metrics {
						resources[metric.Name] = keys
					}
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("metric requests not received, have %v", resources)
		}
	}
	want := []string{"deployment.environment.name", "os.type", "service.instance.id", "service.name", "service.namespace", "service.version"}
	got := resources[observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals]
	if len(got) != len(want) {
		t.Fatalf("managed counter resource = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("managed counter resource = %v, want %v", got, want)
		}
	}
	if keys := resources["defenseclaw.sandbox.transitions"]; len(keys) != len(testCompleteSignalResourceValues()) {
		t.Fatalf("other metric resource = %v, want the full resource", keys)
	}
}
