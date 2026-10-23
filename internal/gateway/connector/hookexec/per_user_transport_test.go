// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPerUserTransportVerifiesConnectedPeerBeforeSending(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "private payload" {
			t.Errorf("body = %q", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	address := server.Listener.Addr().String()
	dial := (&net.Dialer{}).DialContext
	verified := false
	client := verifiedPerUserHTTPClient(time.Second, address, dial, func(net.Conn) error {
		if !verified {
			return errors.New("connected peer is not this account")
		}
		return nil
	})
	post := func(url string) error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader("private payload"))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer secret")
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := post(server.URL); err == nil || received.Load() != 0 {
		t.Fatalf("unverified peer received %d requests; error = %v", received.Load(), err)
	}
	verified = true
	if err := post(server.URL); err != nil || received.Load() != 1 {
		t.Fatalf("verified peer received %d requests; error = %v", received.Load(), err)
	}
	if err := post("http://127.0.0.1:1/other"); err == nil || received.Load() != 1 {
		t.Fatalf("unconfigured target received a request; error = %v", err)
	}
}

func TestConnectedSocketNameRequiresTheExactClientPort(t *testing.T) {
	want := "127.0.0.1:18970->127.0.0.1:1234"
	for _, tc := range []struct {
		name    string
		matches bool
	}{
		{want, true},
		{"TCP " + want + " (ESTABLISHED)", true},
		{"127.0.0.1:18970->127.0.0.1:12345", false},
		{"127.0.0.1:18971->127.0.0.1:1234", false},
	} {
		if got := connectedSocketNameMatches(tc.name, want); got != tc.matches {
			t.Errorf("connected socket %q matched %v, want %v", tc.name, got, tc.matches)
		}
	}
}

func TestPerUserGatewayClientCanUseARequestContextWithoutAnOverallTimeout(t *testing.T) {
	client, err := NewPerUserGatewayHTTPClient(0, "127.0.0.1:18970")
	if err != nil {
		t.Fatal(err)
	}
	if client.Timeout != 0 {
		t.Fatalf("context-bound sandbox operation was limited to %s", client.Timeout)
	}
}
