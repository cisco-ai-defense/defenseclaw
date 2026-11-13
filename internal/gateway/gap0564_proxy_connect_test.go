// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/netguard/netguardtest"
)

func TestGAP0564RealProviderProxyConnectDisconnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	route, err := (netguard.EgressProxy{HTTPSProxy: "http://" + listener.Addr().String()}).Route()
	if err != nil {
		t.Fatal(err)
	}
	oldRoute := enterpriseEgress.Swap(route)
	defer enterpriseEgress.Store(oldRoute)
	provider, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "openai", Model: "openai/test-model", APIKey: "test-placeholder",
		BaseURL: "https://example.com",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, callErr := provider.ChatCompletion(ctx, &ChatRequest{
			Model: "openai/test-model", Messages: []ChatMessage{{Role: "user", Content: "list fixtures"}},
		})
		done <- callErr
	}()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("judge did not reach proxy")
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "CONNECT ") {
		t.Fatalf("proxy request: %q, %v", line, err)
	}
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			t.Fatalf("proxy headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	cancel()
	select {
	case callErr := <-done:
		if !errors.Is(callErr, context.Canceled) {
			t.Fatalf("judge cancellation cause = %v", callErr)
		}
	case <-time.After(time.Second):
		t.Fatal("judge call stayed in proxy setup after cancellation")
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("proxy connection stayed open: %v", err)
	}
}

func TestGAP0564RealProviderProxyBenignAnswer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"proxy-answer","object":"chat.completion","created":1,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`, allFalseInjectionJSON)
	}))
	defer server.Close()
	proxy := netguardtest.NewRecordingProxy(t, map[string]string{"example.com:443": server.Listener.Addr().String()})
	route, err := (netguard.EgressProxy{HTTPSProxy: proxy.URL}).Route()
	if err != nil {
		t.Fatal(err)
	}
	oldRoute := enterpriseEgress.Swap(route)
	defer enterpriseEgress.Store(oldRoute)
	caCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	provider, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "openai", Model: "openai/test-model", APIKey: "test-placeholder", BaseURL: "https://example.com",
		TLS: &config.TLSConfig{CACertPEM: string(caCert)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	judge := &LLMJudge{
		cfg: &config.JudgeConfig{Enabled: true, Injection: true}, model: "test-model",
		provider: provider, rp: &guardrail.RulePack{},
	}
	verdict := judge.runInjectionJudge(t.Context(), "please list the files in this folder", false)
	if verdict == nil || verdict.Action != "allow" {
		t.Fatalf("benign proxy judge answer = %+v, want allow", verdict)
	}
	if targets := proxy.Targets(); len(targets) != 1 || targets[0] != "example.com:443" {
		t.Fatalf("proxy targets = %v", targets)
	}
}
