// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package push

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

// GAP-2115: when the local Splunk stack is stopped another account can bind
// 127.0.0.1:8088. The sink local Splunk setup recorded (local_stack) sends
// its HEC token only to a listener of this account or the system account
// (hookexec.VerifyLocalPeer): an unproven listener gets no byte and the
// batch stays queued. This account's own stack still gets every record, and
// every other Splunk sink (an operator's Splunk may run as its own service
// account) dials as before.
func TestLocalSplunkSinkSendsNoTokenToAnUnprovenListener(t *testing.T) {
	for _, tc := range []struct {
		name                string
		localStack, foreign bool
		wantSent            bool
	}{
		{"local stack, listener of another account", true, true, false},
		{"local stack, this account's listener", true, false, true},
		{"other Splunk sink is not checked", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := verifyLocalStackListener
			t.Cleanup(func() { verifyLocalStackListener = previous })
			var checked atomic.Int64
			verifyLocalStackListener = func(conn net.Conn) error {
				checked.Add(1)
				if tc.foreign {
					return errors.New("local peer socket belongs to another account")
				}
				return previous(conn)
			}
			var received atomic.Int64
			var connections atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Header.Get("Authorization") != "" {
					received.Add(1)
				}
				_, _ = writer.Write([]byte(`{"text":"Success","code":0}`))
			}))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			server.StartTLS()
			t.Cleanup(server.Close)
			adapter, err := NewSplunkHEC(context.Background(), SplunkHECConfig{
				Destination: "splunk-hec-127-0-0-1", Endpoint: server.URL, Token: "local-hec-token",
				TLS:        TLSOptions{InsecureSkipVerify: true},
				Network:    NetworkOptions{AllowPrivateNetworks: true},
				LocalStack: tc.localStack,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(adapter.CloseIdleConnections)
			counters, health := deliverBatchHealth(t, "splunk-hec-127-0-0-1", adapter, `{"record_id":"r1"}`)
			if sent := received.Load() > 0; sent != tc.wantSent {
				t.Fatalf("listener received the HEC token = %v, want %v", sent, tc.wantSent)
			}
			if tc.localStack != (checked.Load() > 0) {
				t.Fatalf("listener checks = %d for local_stack=%v", checked.Load(), tc.localStack)
			}
			if tc.wantSent {
				if counters.Delivered != 1 {
					t.Fatalf("counters = %+v", counters)
				}
				return
			}
			// Nothing reached the peer: the connection was closed before the
			// TLS hello, and the failure is a retryable connection failure,
			// not an ambiguous delivery.
			if counters.Delivered != 0 || health.LastFailureCode != delivery.FailureCodeConnectionFailed {
				t.Fatalf("counters = %+v failure code = %q", counters, health.LastFailureCode)
			}
		})
	}
}
