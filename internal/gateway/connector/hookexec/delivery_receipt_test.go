// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The managed OpenCode plugin runs this hook, so its tool calls send the
// receipt too (GAP-0286).
func TestManagedHookAcknowledgesItsCommittedAnswerOnTheSameRequest(t *testing.T) {
	for _, connector := range []string{"claudecode", "codex", "opencode"} {
		if !DeliveryReceiptEvent(connector, managedToolEvent(connector)) {
			t.Errorf("DeliveryReceiptEvent(%s) = false, want the receipt the hook sends", connector)
		}
		for _, busyFirst := range []bool{false, true} {
			t.Run(connector+"/busy="+strconv.FormatBool(busyFirst), func(t *testing.T) {
				received := make(chan string, 1)
				var attempts atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if busyFirst && attempts.Add(1) == 1 {
						_, _ = io.Copy(io.Discard, r.Body)
						w.Header().Set("Retry-After", "1")
						w.WriteHeader(http.StatusTooManyRequests)
						return
					}
					if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
						received <- err.Error()
						return
					}
					w.Header().Set("Connection", "close")
					w.WriteHeader(http.StatusEarlyHints)
					length, _ := strconv.Atoi(r.Header.Get(HookDeliveryPayloadBytesHeader))
					payload := make([]byte, length)
					if _, err := io.ReadFull(r.Body, payload); err != nil {
						received <- err.Error()
						return
					}
					w.Header().Set(HookDeliveryRequiredHeader, "1")
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, "{\"action\":\"allow\"}\n")
					_ = http.NewResponseController(w).Flush()
					ack := make([]byte, len(HookDeliveryReceiptAck))
					_, err := io.ReadFull(r.Body, ack)
					if err != nil {
						received <- err.Error()
						return
					}
					_, _ = io.WriteString(w, HookDeliveryConfirmed)
					_ = http.NewResponseController(w).Flush()
					received <- string(ack)
				}))
				defer server.Close()
				result, _ := runAgainstGateway(t, connector, server.Listener.Addr().String(), managedToolCall(connector))
				if blocked(result) || strings.Contains(result.stdout+result.stderr, managedGatewayNoAnswerReason) {
					t.Fatalf("managed answer code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
				}
				if got := <-received; got != HookDeliveryReceiptAck {
					t.Fatalf("delivery receipt = %q, want %q (code=%d stdout=%q stderr=%q)", got, HookDeliveryReceiptAck, result.code, result.stdout, result.stderr)
				}
			})
		}
	}
}

func TestManagedHookFallsBackToAnOlderGatewayDuringUpgrade(t *testing.T) {
	bodySeen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			bodySeen <- err.Error()
			return
		}
		bodySeen <- string(body)
		_, _ = io.WriteString(w, `{"action":"allow"}`)
	}))
	defer server.Close()
	result, _ := runAgainstGateway(t, "codex", server.Listener.Addr().String(), managedCodex)
	if result.code != 0 || strings.Contains(result.stdout+result.stderr, managedGatewayNoAnswerReason) {
		t.Fatalf("older gateway answer code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
	if body := <-bodySeen; !json.Valid([]byte(body)) || strings.Contains(body, "ack") {
		t.Fatalf("older gateway received %q, want only the original hook JSON", body)
	}
}

// A gateway that advertised the receipt, then gave no answer, does not hold
// the hook past its answer budget: the request body ends with the request,
// so the transport's failed round trip does not wait for it forever.
func TestManagedHookEndsAnAdvertisedReceiptRequestAtItsDeadline(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
			return
		}
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusEarlyHints)
		length, _ := strconv.Atoi(r.Header.Get(HookDeliveryPayloadBytesHeader))
		_, _ = io.ReadFull(r.Body, make([]byte, length))
		<-release
	}))
	defer server.Close()
	defer close(release)
	done := make(chan runResult, 1)
	go func() {
		result, _ := runAgainstGateway(t, "codex", server.Listener.Addr().String(), managedCodex)
		done <- result
	}()
	select {
	case result := <-done:
		if !blocked(result) || !strings.Contains(result.stdout+result.stderr, managedGatewayNoAnswerReason) {
			t.Fatalf("unanswered call code=%d stdout=%q stderr=%q, want the closed no-answer block", result.code, result.stdout, result.stderr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hook waited past its answer budget for a gateway that advertised the receipt")
	}
}

func managedToolEvent(connector string) string {
	if connector == "opencode" {
		return "tool.execute.before"
	}
	return "PreToolUse"
}

func managedToolCall(connector string) func(*Options) {
	return func(opts *Options) {
		managedCodex(opts)
		opts.Event = managedToolEvent(connector)
		if connector == "opencode" {
			opts.Stdin = strings.NewReader(`{"hook_event_name":"tool.execute.before","tool_name":"bash","tool_input":{"command":"ls"}}`)
		}
	}
}

// A 103 that comes after the capability wait (a slow peer lookup, a loaded
// host, a retry just after a restart) does not block a call the gateway
// answered in time: the body ended with the released marker, which the
// gateway reads in place of a receipt, and the hook takes the answer.
func TestManagedHookTakesTheAnswerAfterALateEarlyHint(t *testing.T) {
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * hookDeliveryCapabilityWait)
		if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
			received <- err.Error()
			return
		}
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusEarlyHints)
		length, _ := strconv.Atoi(r.Header.Get(HookDeliveryPayloadBytesHeader))
		if _, err := io.ReadFull(r.Body, make([]byte, length)); err != nil {
			received <- err.Error()
			return
		}
		w.Header().Set(HookDeliveryRequiredHeader, "1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"action\":\"allow\"}\n")
		_ = http.NewResponseController(w).Flush()
		line := make([]byte, len(HookDeliveryReleased))
		_, err := io.ReadFull(r.Body, line)
		if err != nil {
			received <- err.Error()
			return
		}
		received <- string(line)
	}))
	defer server.Close()
	result, _ := runAgainstGateway(t, "codex", server.Listener.Addr().String(), managedCodex)
	if blocked(result) {
		t.Fatalf("answer after a late 103 was blocked: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
	if got := <-received; got != HookDeliveryReleased {
		t.Fatalf("gateway read %q after its answer, want the released marker", got)
	}
}
