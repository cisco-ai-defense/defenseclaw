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
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	collectorlogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/netguard/netguardtest"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// The standalone gateway hands the exporters a dialer that connects through
// the enterprise.network proxy below their destination check. The HTTP and
// gRPC log exporters must reach a named collector through that proxy (the
// collector name resolves only in the check, so a direct connection could
// not reach it).
func TestLogExportsReachTheCollectorThroughTheEnterpriseEgressRoute(t *testing.T) {
	httpReceived := make(chan struct{}, 4)
	httpCollector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		httpReceived <- struct{}{}
		writer.Header().Set("Content-Type", "application/x-protobuf")
		encoded, _ := proto.Marshal(&collectorlogpb.ExportLogsServiceResponse{})
		_, _ = writer.Write(encoded)
	}))
	t.Cleanup(httpCollector.Close)
	_, httpPort, _ := net.SplitHostPort(httpCollector.Listener.Addr().String())

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	capture := &grpcLogCapture{requests: make(chan *collectorlogpb.ExportLogsServiceRequest, 1), headers: make(chan metadata.MD, 1)}
	collectorlogpb.RegisterLogsServiceServer(grpcServer, capture)
	go grpcServer.Serve(listener)
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})
	_, grpcPort, _ := net.SplitHostPort(listener.Addr().String())

	proxy := netguardtest.NewRecordingProxy(t, map[string]string{
		"logs.example.test:" + httpPort: httpCollector.Listener.Addr().String(),
		"grpc.example.test:" + grpcPort: listener.Addr().String(),
	})
	route, err := (netguard.EgressProxy{HTTPSProxy: proxy.URL}).Route()
	if err != nil {
		t.Fatal(err)
	}
	dependencies := Dependencies{
		Resolver: namedTestResolver{"logs.example.test": "127.0.0.1", "grpc.example.test": "127.0.0.1"},
		Dialer:   route.Dialer(&net.Dialer{Timeout: 5 * time.Second}),
	}

	for _, tc := range []struct {
		name     string
		protocol string
		endpoint string
		received func() bool
	}{
		{
			name: "http", protocol: ProtocolHTTPProtobuf, endpoint: "http://logs.example.test:" + httpPort,
			received: func() bool {
				select {
				case <-httpReceived:
					return true
				case <-time.After(2 * time.Second):
					return false
				}
			},
		},
		{
			name: "grpc", protocol: ProtocolGRPCProtobuf, endpoint: "grpc.example.test:" + grpcPort,
			received: func() bool {
				select {
				case <-capture.requests:
					return true
				case <-time.After(2 * time.Second):
					return false
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factory := prepareTestFactory(t, Config{
				Destination: tc.name + "-logs", Protocol: tc.protocol, Endpoint: tc.endpoint,
				Selected: []observability.Signal{observability.SignalLogs},
				Timeout:  2 * time.Second, TLS: TLSConfig{Insecure: true},
				NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
			}, dependencies)
			adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
			if err != nil {
				t.Fatal(err)
			}
			dispatcher := newOTLPDispatcher(t, tc.name+"-logs", adapter)
			enqueueOTLP(t, dispatcher, "record-"+tc.name, `{"message":"through the enterprise proxy"}`)
			drainOTLP(t, dispatcher)
			if err := adapter.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !tc.received() {
				t.Fatalf("%s export did not reach the collector through the proxy", tc.name)
			}
		})
	}
	seen := map[string]bool{}
	for _, target := range proxy.Targets() {
		seen[target] = true
	}
	want := map[string]bool{"logs.example.test:" + httpPort: true, "grpc.example.test:" + grpcPort: true}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("proxy CONNECT targets = %v, want %v", proxy.Targets(), want)
	}
}

// namedTestResolver maps destination names to one address each.
type namedTestResolver map[string]string

func (resolver namedTestResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	address, ok := resolver[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
}
