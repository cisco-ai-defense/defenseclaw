// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

func TestGAP0370ReceiptCapabilityPrecedesDelayedHookWork(t *testing.T) {
	cfg := &config.Config{DeploymentMode: "per_user"}
	cfg.Gateway.Token = "test-gateway-token"
	api := &APIServer{scannerCfg: cfg}
	continueHook := make(chan struct{})
	entered := make(chan struct{})
	received := make(chan string, 1)
	server := httptest.NewServer(api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-continueHook
		delivery := api.beginHookDeliveryReceipt(w, r)
		if delivery == nil {
			received <- "missing receipt channel"
			return
		}
		if _, err := delivery.readPayload(); err != nil {
			received <- err.Error()
			return
		}
		received <- delivery.offer(w, func() {
			_, _ = io.WriteString(w, "{\"action\":\"allow\"}\n")
		})
	})))
	defer server.Close()
	defer func() {
		select {
		case <-continueHook:
		default:
			close(continueHook)
		}
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer writer.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/v1/codex/hook", reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Gateway.Token)
	req.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	req.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len("{}")))
	advertised := make(chan struct{}, 1)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
			if code == http.StatusEarlyHints {
				advertised <- struct{}{}
			}
			return nil
		},
	}))
	done := make(chan error, 1)
	go func() {
		resp, err := server.Client().Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()
	if _, err := io.WriteString(writer, "{}"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("authenticated hook did not enter its handler")
	}
	select {
	case <-advertised:
	case <-time.After(time.Second):
		t.Fatal("receipt capability did not precede delayed hook work")
	}
	close(continueHook)
	// The delivered outcome can still follow after the delayed work.
	if _, err := io.WriteString(writer, "late\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != "late\n" {
		t.Fatalf("gateway receipt = %q, want delivered block", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGAP0370OrdinaryHookRequestStillReceivesAllow(t *testing.T) {
	cfg := &config.Config{DeploymentMode: "per_user"}
	cfg.Gateway.Token = "test-gateway-token"
	api := &APIServer{scannerCfg: cfg}
	server := httptest.NewServer(api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{\"action\":\"allow\"}\n")
	})))
	defer server.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/codex/hook", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Gateway.Token)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"action":"allow"`) {
		t.Fatalf("ordinary hook result: status=%d body=%q err=%v", resp.StatusCode, body, err)
	}
}
