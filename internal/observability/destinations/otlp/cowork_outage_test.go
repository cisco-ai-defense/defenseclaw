// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

func TestCoworkOTLPConnectionOutageClassifiesAndReplays(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	factory := prepareTestFactory(t, Config{
		Destination: "cowork-outage", Protocol: ProtocolHTTPProtobuf,
		Endpoint: "http://" + address, Selected: []observability.Signal{observability.SignalLogs},
		Timeout: time.Second, TLS: TLSConfig{Insecure: true},
		NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close(context.Background()) })
	dispatcher, err := delivery.NewDispatcher(delivery.Config{
		Destination: "cowork-outage", Signal: string(observability.SignalLogs), Enabled: true,
		RetryUntilClosed: true,
		MaxQueueItems:    1, MaxQueueBytes: 8 * 1024 * 1024, MaxBatchItems: 1, MaxBatchBytes: 8 * 1024 * 1024,
		ScheduledDelay: 0, AttemptTimeout: time.Second,
		Retry:   delivery.RetryPolicy{MaxAttempts: 1, InitialBackoff: 5 * time.Millisecond, MaxBackoff: 5 * time.Millisecond},
		Circuit: delivery.CircuitPolicy{TransientFailureThreshold: 1, OpenDuration: 20 * time.Millisecond},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dispatcher.Close(ctx)
	})
	enqueueOTLP(t, dispatcher, "first", `{"message":"first"}`)
	deadline := time.Now().Add(3 * time.Second)
	for dispatcher.Counters().Failed == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	health := dispatcher.DeliveryHealthSnapshot()
	if health.LastFailureClass != delivery.FailureClassTransient || health.LastFailureCode != delivery.FailureCodeConnectionFailed {
		t.Fatalf("collector outage class=%s code=%s", health.LastFailureClass, health.LastFailureCode)
	}
	if got := dispatcher.Counters(); got.Accepted != 1 || got.Rejected != 0 || got.Dropped != 0 {
		t.Fatalf("outage counters: %+v", got)
	}

	serverListener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = server.Serve(serverListener) }()
	t.Cleanup(func() { _ = server.Close() })
	deadline = time.Now().Add(3 * time.Second)
	for dispatcher.Counters().Delivered != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := dispatcher.Counters(); got.Accepted != 1 || got.Delivered != 1 || got.Rejected != 0 || got.Dropped != 0 {
		t.Fatalf("recovery counters: %+v", got)
	}
}
