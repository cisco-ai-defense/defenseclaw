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
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/netguard/netguardtest"
)

// namedPushResolver maps destination names to one address each.
type namedPushResolver map[string]string

func (resolver namedPushResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	address, ok := resolver[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
}

// The standalone gateway hands the push destinations a dialer that connects
// through the enterprise.network proxy below their destination check. HTTP
// JSONL and Splunk HEC must deliver to a named endpoint through that proxy
// (the name resolves only in the check, so a direct connection could not
// reach it).
func TestPushDestinationsDeliverThroughTheEnterpriseEgressRoute(t *testing.T) {
	jsonl := &requestCapture{status: http.StatusNoContent}
	jsonlServer := httptest.NewServer(jsonl)
	t.Cleanup(jsonlServer.Close)
	hec := &requestCapture{status: http.StatusOK, body: `{"text":"Success","code":0}`}
	hecServer := httptest.NewServer(hec)
	t.Cleanup(hecServer.Close)
	_, jsonlPort, _ := net.SplitHostPort(jsonlServer.Listener.Addr().String())
	_, hecPort, _ := net.SplitHostPort(hecServer.Listener.Addr().String())

	proxy := netguardtest.NewRecordingProxy(t, map[string]string{
		"archive.example.test:" + jsonlPort: jsonlServer.Listener.Addr().String(),
		"hec.example.test:" + hecPort:       hecServer.Listener.Addr().String(),
	})
	route, err := (netguard.EgressProxy{HTTPSProxy: proxy.URL}).Route()
	if err != nil {
		t.Fatal(err)
	}
	network := NetworkOptions{
		AllowPrivateNetworks: true,
		Resolver:             namedPushResolver{"archive.example.test": "127.0.0.1", "hec.example.test": "127.0.0.1"},
		Dialer:               route.Dialer(&net.Dialer{Timeout: 5 * time.Second}),
	}

	archive, err := NewHTTPJSONL(context.Background(), HTTPJSONLConfig{
		Destination: "archive", Endpoint: "http://archive.example.test:" + jsonlPort + "/ingest", Network: network,
	})
	if err != nil {
		t.Fatal(err)
	}
	if counters := deliverBatch(t, "archive", archive, `{"record_id":"one"}`); counters.Delivered != 1 {
		t.Fatalf("HTTP JSONL through the proxy: counters=%+v", counters)
	}
	splunk, err := NewSplunkHEC(context.Background(), SplunkHECConfig{
		Destination: "splunk", Endpoint: "http://hec.example.test:" + hecPort + "/services/collector/event",
		Token: "resolved-hec-token", Network: network,
	})
	if err != nil {
		t.Fatal(err)
	}
	projected := `{"record_id":"r1","timestamp":"2026-07-03T01:02:03Z","bucket":"diagnostic","event_name":"diagnostic.message","severity":"INFO","source":"gateway","body":{"message":"safe"}}`
	if counters := deliverBatch(t, "splunk", splunk, projected); counters.Delivered != 1 {
		t.Fatalf("Splunk HEC through the proxy: counters=%+v", counters)
	}
	if len(jsonl.snapshot()) != 1 || len(hec.snapshot()) != 1 {
		t.Fatalf("deliveries: jsonl=%d hec=%d", len(jsonl.snapshot()), len(hec.snapshot()))
	}
	want := []string{"archive.example.test:" + jsonlPort, "hec.example.test:" + hecPort}
	if got := proxy.Targets(); !reflect.DeepEqual(got, want) {
		t.Fatalf("proxy CONNECT targets = %v, want %v", got, want)
	}
}
