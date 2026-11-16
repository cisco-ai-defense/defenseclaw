// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	collectorlogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// GAP-1087: when the bundled stack is stopped another account can bind its
// collector port. The bundled destination writes nothing to a loopback
// listener whose account is not proven (hookexec.VerifyLocalPeer); this
// account's own collector still gets every record, and other destinations
// (an operator's local agent may run as its own service account) dial as
// before.
func TestBundledStackSendsNothingToAnUnprovenCollector(t *testing.T) {
	for _, tc := range []struct {
		name, destination string
		foreign           bool
		wantSent          bool
	}{
		{"bundled stack, foreign listener", "local-observability", true, false},
		{"bundled logs stack, foreign listener", "local-otlp-logs", true, false},
		{"bundled stack, own listener", "local-observability", false, true},
		{"operator destination is not checked", "otlp-localhost", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := verifyBundledCollector
			t.Cleanup(func() { verifyBundledCollector = previous })
			var checked atomic.Int64
			verifyBundledCollector = func(conn net.Conn) error {
				checked.Add(1)
				if tc.foreign {
					return errors.New("local peer socket belongs to another account")
				}
				return previous(conn)
			}
			for _, protocol := range []string{ProtocolHTTP, ProtocolGRPCProtobuf} {
				sent := exportOneTestLog(t, tc.destination, protocol, false)
				if sent != tc.wantSent {
					t.Fatalf("%s: collector received a record = %v, want %v", protocol, sent, tc.wantSent)
				}
			}
			if bundled := bundledLocalStackDestination(tc.destination); bundled != (checked.Load() > 0) {
				t.Fatalf("listener checks = %d for destination %s", checked.Load(), tc.destination)
			}
		})
	}
}

// GAP-2608: a managed gateway runs as a service account (_defenseclaw,
// LocalSystem) that never runs the bundled stack; the administrator collector
// runs as its own account. A managed gateway delivers to it under the
// bundled stack name and runs no listener check; a per-user gateway keeps the
// GAP-1087 refusal for the same listener.
func TestManagedGatewayDeliversToTheAdministratorCollectorUnderTheBundledName(t *testing.T) {
	previous := verifyBundledCollector
	t.Cleanup(func() { verifyBundledCollector = previous })
	var checked atomic.Int64
	verifyBundledCollector = func(net.Conn) error {
		checked.Add(1)
		return errors.New("local peer socket belongs to another account")
	}
	for _, destination := range []string{"local-observability", "local-otlp-logs"} {
		for _, protocol := range []string{ProtocolHTTP, ProtocolGRPCProtobuf} {
			checked.Store(0)
			if !exportOneTestLog(t, destination, protocol, true) {
				t.Fatalf("managed %s %s: the administrator collector received nothing", destination, protocol)
			}
			if got := checked.Load(); got != 0 {
				t.Fatalf("managed %s %s: listener checks = %d, want 0", destination, protocol, got)
			}
			if exportOneTestLog(t, destination, protocol, false) {
				t.Fatalf("per-user %s %s: a foreign listener received a record", destination, protocol)
			}
			if checked.Load() == 0 {
				t.Fatalf("per-user %s %s: the listener was not checked", destination, protocol)
			}
		}
	}
}

// exportOneTestLog exports one log record to a fresh loopback collector of
// this process over protocol and reports whether the collector received it.
func exportOneTestLog(t *testing.T, destination, protocol string, managedService bool) bool {
	t.Helper()
	var received atomic.Int64
	var capture *grpcLogCapture
	endpoint := ""
	if protocol == ProtocolHTTP {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			received.Add(1)
			writer.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)
		endpoint = server.URL
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := grpc.NewServer()
		capture = &grpcLogCapture{requests: make(chan *collectorlogpb.ExportLogsServiceRequest, 4), headers: make(chan metadata.MD, 4)}
		collectorlogpb.RegisterLogsServiceServer(server, capture)
		go server.Serve(listener)
		t.Cleanup(func() {
			server.Stop()
			_ = listener.Close()
		})
		endpoint = listener.Addr().String()
	}
	factory := prepareTestFactory(t, Config{
		Destination: destination, Protocol: protocol, Endpoint: endpoint,
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
		ManagedService: managedService,
	}, Dependencies{})
	adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newOTLPDispatcher(t, destination, adapter)
	enqueueOTLP(t, dispatcher, "record-"+destination, `{"message":"bundled"}`)
	drainOTLP(t, dispatcher)
	_ = adapter.Close(context.Background())
	if capture != nil {
		received.Add(int64(len(capture.requests)))
	}
	return received.Load() > 0
}
