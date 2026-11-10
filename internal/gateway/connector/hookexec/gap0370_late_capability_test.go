// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A current gateway can finish admission after the compatibility wait.
// Its capability response keeps the original request available until the
// hook reports the answer it delivered at the deadline.
func TestGAP0370LateCapabilityCarriesDeadlineBlock(t *testing.T) {
	shortAnswerBudget(t, 1500*time.Millisecond)
	token := make(chan string, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set(HookDeliveryCapabilityHeader, "1")
			w.WriteHeader(http.StatusOK)
			return
		}
		controller := http.NewResponseController(w)
		if err := controller.EnableFullDuplex(); err != nil {
			token <- err.Error()
			return
		}
		time.Sleep(800 * time.Millisecond)
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusEarlyHints)
		length, _ := strconv.Atoi(r.Header.Get(HookDeliveryPayloadBytesHeader))
		body := bufio.NewReader(r.Body)
		if _, err := io.ReadFull(body, make([]byte, length)); err != nil {
			token <- err.Error()
			return
		}
		line, err := body.ReadString('\n')
		if err != nil {
			token <- err.Error()
		} else {
			token <- line
		}
		<-release
	}))
	defer server.Close()
	defer close(release)
	result, _ := runAgainstGateway(t, "codex", server.Listener.Addr().String(), func(opts *Options) {
		opts.FailMode = "closed"
		if err := os.MkdirAll(filepath.Join(opts.Home, "logs"), 0o700); err != nil {
			t.Fatal(err)
		}
		opts.Exit = func(int) {}
	})
	if !blocked(result) {
		t.Fatalf("agent answer code=%d stdout=%q stderr=%q, want block", result.code, result.stdout, result.stderr)
	}
	select {
	case got := <-token:
		if got != HookDeliveryReceiptLate {
			t.Fatalf("gateway receipt = %q, want delivered block", got)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway did not receive the deadline receipt")
	}
}

func TestGAP0370EarlierPerUserGatewayStillAllowsBenignCall(t *testing.T) {
	shortAnswerBudget(t, 2500*time.Millisecond)
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			received <- err.Error()
			return
		}
		received <- string(body)
		time.Sleep(1500 * time.Millisecond)
		_, _ = io.WriteString(w, "{\"action\":\"allow\",\"codex_output\":{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}}\n")
	}))
	defer server.Close()
	result, _ := runAgainstGateway(t, "codex", server.Listener.Addr().String(), func(opts *Options) {
		opts.FailMode = "closed"
	})
	if blocked(result) {
		t.Fatalf("earlier gateway benign answer code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
	select {
	case got := <-received:
		if !strings.HasSuffix(got, HookDeliveryReleased) {
			t.Fatalf("earlier gateway body ended with %q, want compatibility release", got)
		}
	case <-time.After(time.Second):
		t.Fatal("earlier gateway did not receive the released call")
	}
}
