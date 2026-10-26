// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The managed OpenCode plugin runs this hook, so its tool calls send the
// receipt too (GAP-0286).
func TestManagedHookAcknowledgesItsCommittedAnswerOnTheSameRequest(t *testing.T) {
	for _, connector := range []string{"claudecode", "codex", "hermes", "opencode"} {
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

// The hook has received a complete gateway answer and committed an explicit
// allow to the agent. A slow return from its output writer must not let the
// answer timer cancel the HTTP request before the receipt reaches the gateway.
func TestManagedHookReceiptSurvivesAnswerDeadlineAfterAllowIsWritten(t *testing.T) {
	const budget = 1500 * time.Millisecond
	shortAnswerBudget(t, budget)
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(w)
		if err := controller.EnableFullDuplex(); err != nil {
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
		_, _ = io.WriteString(w, `{"action":"allow","codex_output":{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}}`+"\n")
		if err := controller.Flush(); err != nil {
			received <- err.Error()
			return
		}
		ack := make([]byte, len(HookDeliveryReceiptAck))
		_, err := io.ReadFull(r.Body, ack)
		if err != nil {
			received <- err.Error()
			return
		}
		received <- string(ack)
		_, _ = io.WriteString(w, HookDeliveryConfirmed)
		_ = controller.Flush()
	}))
	defer server.Close()

	output := &pauseAfterExplicitAllow{wrote: make(chan struct{}), resume: make(chan struct{})}
	defer output.unblock()
	home := t.TempDir()
	token := "authenticated-generation-token"
	var stderr bytes.Buffer
	started := time.Now()
	ctx := t.Context()
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, Options{
			Connector:                 "codex",
			Event:                     "PreToolUse",
			HookContractID:            "codex-hooks-v4",
			APIAddr:                   server.Listener.Addr().String(),
			FailMode:                  "closed",
			ManagedEnterprise:         true,
			AuthenticatedManagedToken: &token,
			Home:                      home,
			HookDir:                   filepath.Join(home, "hooks"),
			Stdin:                     strings.NewReader(`{"hook_event_name":"PreToolUse"}`),
			Stdout:                    output,
			Stderr:                    &stderr,
			HTTPClient:                &http.Client{},
			StartedAt:                 started,
		})
	}()
	select {
	case <-output.wrote:
	case <-time.After(budget):
		t.Fatal("the hook did not write the gateway's allow before its answer deadline")
	}
	time.Sleep(max(0, time.Until(started.Add(budget))+100*time.Millisecond))
	output.unblock()
	select {
	case code := <-done:
		if code != 0 || !strings.Contains(output.String(), `"permissionDecision":"allow"`) {
			t.Fatalf("agent answer code=%d stdout=%q stderr=%q, want explicit allow", code, output.String(), stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hook did not finish its receipt")
	}
	select {
	case got := <-received:
		if got != HookDeliveryReceiptAck {
			t.Fatalf("gateway receipt = %q, want %q after the agent accepted allow", got, HookDeliveryReceiptAck)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway did not receive the hook's receipt")
	}
}

type pauseAfterExplicitAllow struct {
	bytes.Buffer
	wrote  chan struct{}
	resume chan struct{}
	once   sync.Once
}

func (w *pauseAfterExplicitAllow) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if bytes.Contains(p, []byte(`"permissionDecision":"allow"`)) {
		w.once.Do(func() { close(w.wrote) })
		<-w.resume
	}
	return n, err
}

func (w *pauseAfterExplicitAllow) unblock() {
	select {
	case <-w.resume:
	default:
		close(w.resume)
	}
}

// A gateway that receives the receipt but never finishes the HTTP response
// cannot hold the agent's hook to the longer request timeout.
func TestManagedHookReceiptWaitHasItsOwnDeadline(t *testing.T) {
	shortAnswerBudget(t, 500*time.Millisecond)
	release := make(chan struct{})
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(w)
		if err := controller.EnableFullDuplex(); err != nil {
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
		_, _ = io.WriteString(w, `{"action":"allow","codex_output":{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}}`+"\n")
		if err := controller.Flush(); err != nil {
			received <- err.Error()
			return
		}
		ack := make([]byte, len(HookDeliveryReceiptAck))
		_, err := io.ReadFull(r.Body, ack)
		if err != nil {
			received <- err.Error()
			return
		}
		received <- string(ack)
		<-release
	}))
	defer server.Close()
	defer close(release)
	result, elapsed := runAgainstGateway(t, "codex", server.Listener.Addr().String(), managedCodex)
	if result.code != 0 || !strings.Contains(result.stdout, `"permissionDecision":"allow"`) {
		t.Fatalf("agent answer code=%d stdout=%q stderr=%q, want allow", result.code, result.stdout, result.stderr)
	}
	select {
	case got := <-received:
		if got != HookDeliveryReceiptAck {
			t.Fatalf("gateway receipt = %q, want %q", got, HookDeliveryReceiptAck)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not receive the hook receipt")
	}
	if elapsed > 4*time.Second {
		t.Fatalf("hook waited %s for a missing receipt confirmation, want the separate %s deadline", elapsed, hookDeliveryReceiptTimeout)
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
	switch connector {
	case "hermes":
		return "pre_tool_call"
	case "opencode":
		return "tool.execute.before"
	default:
		return "PreToolUse"
	}
}

func managedToolCall(connector string) func(*Options) {
	return func(opts *Options) {
		managedCodex(opts)
		opts.Event = managedToolEvent(connector)
		switch connector {
		case "opencode":
			opts.Stdin = strings.NewReader(`{"hook_event_name":"tool.execute.before","tool_name":"bash","tool_input":{"command":"ls"}}`)
		case "hermes":
			opts.Stdin = strings.NewReader(`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo ok"}}`)
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
		time.Sleep(hookDeliveryCapabilityWait + 300*time.Millisecond)
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

// GAP-0683: a socket-activated gateway reads the first call about 800 ms
// after the connection was accepted. Its 103 still comes inside the
// capability wait, so the hook acknowledges the answer and the gateway
// audits the call as the allow it was, not unconfirmed.
func TestManagedHookReceiptCoversAGatewayStillStarting(t *testing.T) {
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(800 * time.Millisecond)
		if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
			received <- err.Error()
			return
		}
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
		line := make([]byte, len(HookDeliveryReceiptAck))
		if _, err := io.ReadFull(r.Body, line[:1]); err != nil {
			received <- err.Error()
			return
		}
		if string(line[:1]) == HookDeliveryReleased {
			received <- HookDeliveryReleased
			return
		}
		if _, err := io.ReadFull(r.Body, line[1:]); err != nil {
			received <- err.Error()
			return
		}
		received <- string(line)
		_, _ = io.WriteString(w, HookDeliveryConfirmed)
		_ = http.NewResponseController(w).Flush()
	}))
	defer server.Close()
	result, _ := runAgainstGateway(t, "codex", server.Listener.Addr().String(), managedCodex)
	if blocked(result) {
		t.Fatalf("first call to a starting gateway was blocked: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
	if got := <-received; got != HookDeliveryReceiptAck {
		t.Fatalf("gateway read %q after its answer, want the receipt %q", got, HookDeliveryReceiptAck)
	}
}
