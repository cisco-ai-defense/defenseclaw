// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPerUserWindowsWaitsOnlyForMissingAcceptedTuple(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reads, checks := 0, 0
	err := awaitPerUserWindowsSocket(ctx, func() (uint32, error) {
		reads++
		if reads < 3 {
			return 0, errConnectedSocketNotFound
		}
		return 4242, nil
	}, func(pid uint32) error {
		checks++
		if pid != 4242 {
			return errors.New("wrong process")
		}
		return nil
	})
	if err != nil || reads != 3 || checks != 1 {
		t.Fatalf("same-account accepted row after connect: reads=%d checks=%d err=%v", reads, checks, err)
	}
	for _, tc := range []struct {
		name    string
		inspect func() (uint32, error)
		owned   func(uint32) error
	}{
		{"foreign owner", func() (uint32, error) { return 99, nil }, func(uint32) error { return errors.New("foreign account") }},
		{"table read error", func() (uint32, error) { return 0, errors.New("table unreadable") }, func(uint32) error { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			err := awaitPerUserWindowsSocket(context.Background(), func() (uint32, error) {
				reads++
				return tc.inspect()
			}, tc.owned)
			if err == nil || reads != 1 {
				t.Fatalf("unverified peer retried or allowed: reads=%d err=%v", reads, err)
			}
		})
	}
	short, stop := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer stop()
	if err := awaitPerUserWindowsSocket(short, func() (uint32, error) {
		return 0, errConnectedSocketNotFound
	}, func(uint32) error { return nil }); !errors.Is(err, errConnectedSocketNotFound) {
		t.Fatalf("absent tuple was accepted after retry budget: %v", err)
	}
}

func TestPerUserWindowsPluginTransportUsesConnectedPeerProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer private" {
			t.Errorf("bearer = %q", got)
		}
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer server.Close()
	addr := server.Listener.Addr().(*net.TCPAddr)
	reply, err := PostPerUserHook(context.Background(), addr.String(), "/api/v1/opencode/hook",
		map[string]string{"Authorization": "Bearer private"}, []byte(`{"tool_input":"ordinary patch"}`))
	if err != nil || reply.Status != http.StatusOK {
		t.Fatalf("same-account plugin POST: reply=%+v err=%v", reply, err)
	}
}

func TestPerUserWindowsMissingAcceptedTupleIsRetryable(t *testing.T) {
	client := managedIPv4Endpoint{addr: [4]byte{203, 0, 113, 1}, port: 65535}
	server := managedIPv4Endpoint{addr: [4]byte{198, 51, 100, 1}, port: 65534}
	_, err := connectedManagedGatewayPIDForEndpoints(client, server)
	if !errors.Is(err, errConnectedSocketNotFound) {
		t.Fatalf("missing accepted row must have the retryable error: %v", err)
	}
}
