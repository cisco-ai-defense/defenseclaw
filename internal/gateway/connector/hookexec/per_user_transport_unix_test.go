// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnixPerUserHookProvesConnectedListenerBeforeSending(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	addr := server.Listener.Addr().String()
	client, err := newPerUserHookHTTPClient(2*time.Second, addr)
	if err != nil {
		t.Fatal(err)
	}
	previous := perUserConnectedPeer
	t.Cleanup(func() { perUserConnectedPeer = previous })
	perUserConnectedPeer = func(_, _ *net.TCPAddr) error {
		return errors.New("connected socket belongs to another account")
	}
	post := func() error {
		req, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewBufferString("private payload"))
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
	if err := post(); err == nil || received.Load() != 0 {
		t.Fatalf("foreign listener received %d requests; error = %v", received.Load(), err)
	}
	perUserConnectedPeer = func(_, _ *net.TCPAddr) error {
		return nil
	}
	if err := post(); err != nil || received.Load() != 1 {
		t.Fatalf("same-account listener received %d requests; error = %v", received.Load(), err)
	}
}

func TestPerUserPluginPostDoesNotContactAForeignListener(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	addr := server.Listener.Addr().String()
	previous := perUserConnectedPeer
	t.Cleanup(func() { perUserConnectedPeer = previous })
	perUserConnectedPeer = func(_, _ *net.TCPAddr) error {
		return errors.New("connected socket belongs to another account")
	}
	post := func() error {
		_, err := PostPerUserHook(context.Background(), addr, "/api/v1/amp/hook",
			map[string]string{"Authorization": "Bearer secret"}, []byte(`{"private":"event"}`))
		return err
	}
	err := post()
	if err == nil || received.Load() != 0 {
		t.Fatalf("foreign listener received %d requests; error = %v", received.Load(), err)
	}
	// hook-post exits with the outage status for it, so the Amp and
	// OpenCode plugins take the outage decision instead of a block of their
	// own (sa-port-peer review: peer checks never block the user's call).
	if !PerUserPostOutage(err) {
		t.Fatalf("PerUserPostOutage(%v) = false, want the outage status for an unproven listener", err)
	}
	perUserConnectedPeer = func(_, _ *net.TCPAddr) error {
		return nil
	}
	if err := post(); err != nil || received.Load() != 1 {
		t.Fatalf("same-account listener received %d hook posts; error = %v", received.Load(), err)
	}
}

func TestPerUserGatewayClientKeepsCLITokenAndBodyOffUnverifiedSocket(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	addr := server.Listener.Addr().String()
	previous := perUserConnectedPeer
	t.Cleanup(func() { perUserConnectedPeer = previous })
	perUserConnectedPeer = func(_, _ *net.TCPAddr) error {
		return errors.New("accepted socket belongs to another account")
	}
	client, err := NewPerUserGatewayHTTPClient(2*time.Second, addr)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/skill/scan", bytes.NewBufferString(`{"target":"private"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer gateway-secret")
	if _, err := client.Do(req); err == nil || received.Load() != 0 {
		t.Fatalf("unverified listener received %d CLI requests; error = %v", received.Load(), err)
	}
}

func TestPerUserPluginPostRefusesRedirect(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	addr := source.Listener.Addr().String()
	_, err := PostPerUserHook(context.Background(), addr, "/api/v1/amp/hook",
		map[string]string{"Authorization": "Bearer secret"}, []byte(`{"private":"event"}`))
	if err == nil || reached.Load() != 0 {
		t.Fatalf("redirect reached another endpoint %d times; error = %v", reached.Load(), err)
	}
}
