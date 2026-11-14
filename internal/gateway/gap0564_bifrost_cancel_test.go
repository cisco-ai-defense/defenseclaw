// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The real provider must retain the caller's cancellation cause after the
// transport closes, so judge records can name a stopped request correctly.
func TestGAP0564RealProviderCancellationReason(t *testing.T) {
	entered := make(chan struct{}, 1)
	disconnected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		entered <- struct{}{}
		<-r.Context().Done()
		disconnected <- struct{}{}
	}))
	defer server.Close()
	defer server.CloseClientConnections()
	provider, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "openai", Model: "openai/test-model", APIKey: "test-placeholder", BaseURL: server.URL,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, callErr := provider.ChatCompletion(ctx, &ChatRequest{
			Model: "openai/test-model", Messages: []ChatMessage{{Role: "user", Content: "summarize these files"}},
		})
		done <- callErr
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("model transport did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("model cancellation cause = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("model transport did not stop after cancellation")
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("model transport stayed connected after cancellation")
	}
}

func TestGAP0564RealProviderDeadlineDisconnect(t *testing.T) {
	entered := make(chan struct{}, 1)
	disconnected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		entered <- struct{}{}
		<-r.Context().Done()
		disconnected <- struct{}{}
	}))
	defer server.Close()
	defer server.CloseClientConnections()
	provider, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "openai", Model: "openai/test-model", APIKey: "test-placeholder", BaseURL: server.URL,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, callErr := provider.ChatCompletion(ctx, &ChatRequest{
			Model: "openai/test-model", Messages: []ChatMessage{{Role: "user", Content: "summarize these files"}},
		})
		done <- callErr
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("model transport did not start")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("model deadline cause = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("model transport did not stop at deadline")
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("model transport stayed connected after deadline")
	}
}

// Cancellation during TLS setup must release the model connection as well as
// the judge call. The peer deliberately leaves the handshake unfinished.
func TestGAP0564RealProviderTLSHandshakeDisconnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	provider, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "openai", Model: "openai/test-model", APIKey: "test-placeholder",
		BaseURL: "https://" + listener.Addr().String(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, callErr := provider.ChatCompletion(ctx, &ChatRequest{
			Model: "openai/test-model", Messages: []ChatMessage{{Role: "user", Content: "summarize these files"}},
		})
		done <- callErr
	}()
	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("model did not open its TLS connection")
	}
	defer conn.Close()
	handshakeStarted := make(chan bool, 1)
	disconnected := make(chan struct{}, 1)
	go func() {
		buffer := make([]byte, 4096)
		n, _ := conn.Read(buffer)
		handshakeStarted <- n > 0
		_, _ = io.Copy(io.Discard, conn)
		disconnected <- struct{}{}
	}()
	select {
	case ok := <-handshakeStarted:
		if !ok {
			t.Fatal("model connection ended before TLS setup began")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("model did not begin TLS setup")
	}
	cancel()
	select {
	case callErr := <-done:
		if !errors.Is(callErr, context.Canceled) {
			t.Fatalf("model cancellation cause = %v, want context.Canceled", callErr)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS setup kept the judge call open after cancellation")
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("TLS setup kept the model connection open after cancellation")
	}
}

func TestGAP0564RealProviderTLSBenignAnswer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"gap0564-tls-answer","object":"chat.completion","created":1,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`, allFalseInjectionJSON)
	}))
	defer server.Close()
	caCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	provider, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "openai", Model: "openai/test-model", APIKey: "test-placeholder", BaseURL: server.URL,
		TLS: &config.TLSConfig{CACertPEM: string(caCert)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	judge := &LLMJudge{
		cfg:   &config.JudgeConfig{Enabled: true, Injection: true},
		model: "test-model", provider: provider, rp: &guardrail.RulePack{},
	}
	verdict := judge.runInjectionJudge(t.Context(), "please list the files in this folder", false)
	if verdict == nil || verdict.Action != "allow" {
		t.Fatalf("benign TLS judge answer = %+v, want allow", verdict)
	}
}

func TestGAP0564RealProviderHookWindowDisconnect(t *testing.T) {
	entered := make(chan struct{}, 1)
	disconnected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		entered <- struct{}{}
		<-r.Context().Done()
		disconnected <- struct{}{}
	}))
	defer server.Close()
	defer server.CloseClientConnections()
	provider, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "openai", Model: "openai/test-model", APIKey: "test-placeholder", BaseURL: server.URL,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.DetectionStrategy = "judge_first"
	cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"codex"}, HookTimeout: 4}
	api := &APIServer{scannerCfg: cfg}
	api.SetHookJudge(&LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: provider, rp: &guardrail.RulePack{}})
	done := make(chan *ScanVerdict, 1)
	go func() {
		done <- api.runHookJudge(boundedHookContext(time.Now().Add(-3*time.Second)), "prompt", "prompt", "codex",
			"please list the files in this folder", "", nil)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("judge transport did not start")
	}
	select {
	case verdict := <-done:
		if verdict != nil {
			t.Fatalf("expired judge changed hook verdict: %+v", verdict)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hook did not finish at its answer window")
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("judge transport stayed connected after hook completion")
	}
}

// A completed model request still supplies the benign judge answer.
func TestGAP0564RealProviderBenignAnswer(t *testing.T) {
	answered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"gap0564-answer","object":"chat.completion","created":1,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`, allFalseInjectionJSON)
		answered <- struct{}{}
	}))
	defer server.Close()
	provider, err := NewProviderForLLMConfig(&config.LLMConfig{
		Provider: "openai", Model: "openai/test-model", APIKey: "test-placeholder-benign", BaseURL: server.URL,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	judge := &LLMJudge{
		cfg:   &config.JudgeConfig{Enabled: true, Injection: true},
		model: "test-model", provider: provider, rp: &guardrail.RulePack{},
	}
	verdict := judge.runInjectionJudge(t.Context(), "please list the files in this folder", false)
	if verdict == nil || verdict.Action != "allow" {
		t.Fatalf("benign judge answer = %+v, want allow", verdict)
	}
	select {
	case <-answered:
	case <-time.After(time.Second):
		t.Fatal("benign model response was not used")
	}
}
