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

// TestGAP0295VerifiedConnectionTimeFollowsOwnerProof pins the timestamp
// used by the restart-window proof to the verified connection.
func TestGAP0295VerifiedConnectionTimeFollowsOwnerProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	address := server.Listener.Addr().String()
	var verifiedAt time.Time
	client := verifiedPerUserHTTPClient(time.Second, address, (&net.Dialer{}).DialContext, func(net.Conn) error {
		verifiedAt = time.Now()
		return nil
	})
	ctx, check := withPerUserPeerCheck(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	ends := check.ends.Load()
	if ends == nil || ends.at.IsZero() || ends.at.Before(verifiedAt) {
		t.Fatalf("verified connection time = %v, owner proof returned at %v", ends, verifiedAt)
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
