// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/gorilla/websocket"
)

func TestHILTApprovalManagerResolveFromMessage(t *testing.T) {
	m := NewHILTApprovalManager(nil, nil, nil)
	pending := &pendingHILTApproval{
		id:        "hilt-test",
		sessionID: "sess-1",
		result:    make(chan bool, 1),
	}
	m.pending["hilt-test"] = pending

	if !m.ResolveFromMessage("sess-1", "user", "approve hilt-test") {
		t.Fatal("expected approval message to resolve pending request")
	}
	select {
	case approved := <-pending.result:
		if !approved {
			t.Fatal("approved=false, want true")
		}
	default:
		t.Fatal("approval result was not delivered")
	}
	if m.ResolveFromMessage("sess-1", "assistant", "deny hilt-test") {
		t.Fatal("assistant messages must not resolve approvals")
	}
}

func TestHILTApprovalManagerDefaultSessionIDRequiresSingleActiveSession(t *testing.T) {
	m := NewHILTApprovalManager(nil, nil, nil)
	if got := m.defaultSessionID(); got != "" {
		t.Fatalf("defaultSessionID() = %q, want empty with no sessions", got)
	}

	m.TrackSession("sess-1")
	if got := m.defaultSessionID(); got != "sess-1" {
		t.Fatalf("defaultSessionID() = %q, want sess-1", got)
	}

	m.TrackSession("sess-2")
	if got := m.defaultSessionID(); got != "" {
		t.Fatalf("defaultSessionID() = %q, want empty with multiple sessions", got)
	}
}

func TestHILTApprovalManagerRequestUsesSingleActiveSessionFallback(t *testing.T) {
	received := make(chan receivedRequest, 5)
	srv := startMockGW(t, rpcRecordingLoop(received))
	client := connectToMockGW(t, srv)
	m := NewHILTApprovalManager(client, nil, nil)
	m.TrackSession("session-1")

	done := make(chan string, 1)
	go func() {
		_, status, _ := m.Request(context.Background(), "", "exec", "HIGH", "matched test policy", 20*time.Millisecond)
		done <- status
	}()

	rpc := drainRPC(t, received)
	if rpc.Method != "sessions.send" {
		t.Fatalf("Method = %q, want sessions.send", rpc.Method)
	}

	var params map[string]string
	if err := json.Unmarshal(rpc.Params, &params); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
	if params["key"] != "session-1" {
		t.Fatalf("sessions.send key = %q, want session-1", params["key"])
	}

	select {
	case status := <-done:
		if status != hiltStatusTimeout {
			t.Fatalf("status = %q, want %q", status, hiltStatusTimeout)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("approval request did not finish")
	}
}

func TestHILTApprovalManagerRequestRetriesActiveSessionWhenProvidedSessionFails(t *testing.T) {
	received := make(chan receivedRequest, 5)
	srv := startMockGW(t, rpcFailingSessionSendLoop(received, "run-session-id"))
	client := connectToMockGW(t, srv)
	m := NewHILTApprovalManager(client, nil, nil)
	m.TrackSession("agent:main:main")

	done := make(chan string, 1)
	go func() {
		_, status, _ := m.Request(context.Background(), "run-session-id", "exec", "HIGH", "matched test policy", 20*time.Millisecond)
		done <- status
	}()

	first := drainRPC(t, received)
	assertSessionSendKey(t, first, "run-session-id")

	second := drainRPC(t, received)
	assertSessionSendKey(t, second, "agent:main:main")

	select {
	case status := <-done:
		if status != hiltStatusTimeout {
			t.Fatalf("status = %q, want %q", status, hiltStatusTimeout)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("approval request did not finish")
	}
}

func TestOpenClawInspectConfirmNativeSurfaceLeavesConfirm(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "openclaw"
	cfg.Guardrail.HILT.Enabled = true
	cfg.Guardrail.HILT.MinSeverity = "HIGH"
	cfg.Gateway.ApprovalTimeout = 30
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)

	verdict := &ToolInspectVerdict{
		Action:   guardrailActionConfirm,
		Severity: "HIGH",
		Reason:   "matched test policy",
	}

	api.resolveOpenClawInspectConfirm(context.Background(), &ToolInspectRequest{
		Tool:            "exec",
		SessionID:       "run-session-id",
		ApprovalSurface: "native",
	}, verdict)

	if verdict.Action != guardrailActionConfirm || verdict.RawAction != guardrailActionConfirm {
		t.Fatalf("action=%q raw=%q, want confirm/confirm for native approval surface", verdict.Action, verdict.RawAction)
	}
	if verdict.ApprovalTimeoutMS != 30000 {
		t.Fatalf("approval_timeout_ms = %d, want 30000", verdict.ApprovalTimeoutMS)
	}
}

func rpcFailingSessionSendLoop(received chan<- receivedRequest, failKey string) func(*testing.T, *websocket.Conn) {
	return func(t *testing.T, conn *websocket.Conn) {
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var req RequestFrame
			if err := json.Unmarshal(raw, &req); err != nil {
				continue
			}
			paramsJSON, _ := json.Marshal(req.Params)
			received <- receivedRequest{Method: req.Method, ID: req.ID, Params: paramsJSON}

			resp := ResponseFrame{Type: "res", ID: req.ID, OK: true, Payload: json.RawMessage(`{}`)}
			if req.Method == "sessions.send" && sessionSendKey(paramsJSON) == failKey {
				resp.OK = false
				resp.Payload = nil
				resp.Error = &FrameError{Code: "NOT_FOUND", Message: "session not found"}
			}
			data, _ := json.Marshal(resp)
			conn.WriteMessage(websocket.TextMessage, data)
		}
	}
}

func assertSessionSendKey(t *testing.T, rpc receivedRequest, want string) {
	t.Helper()
	if rpc.Method != "sessions.send" {
		t.Fatalf("Method = %q, want sessions.send", rpc.Method)
	}
	if got := sessionSendKey(rpc.Params); got != want {
		t.Fatalf("sessions.send key = %q, want %q", got, want)
	}
}

func sessionSendKey(raw json.RawMessage) string {
	var params map[string]string
	_ = json.Unmarshal(raw, &params)
	return params["key"]
}
