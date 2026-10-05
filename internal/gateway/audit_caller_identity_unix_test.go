// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// waitForAuditRow polls the audit store until match finds a row.
func waitForAuditRow(t *testing.T, store *audit.Store, what string, match func(audit.Event) bool) audit.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		events, err := store.ListEvents(500)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if match(event) {
				return event
			}
		}
		if time.Now().After(deadline) {
			actions := make([]string, 0, len(events))
			for _, event := range events {
				actions = append(actions, event.Action)
			}
			t.Fatalf("no %s audit row; rows: %v", what, actions)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestHookSocketAuditRowsNameTheVerifiedCaller: the rows an administrator
// reviews for a standalone user's calls (rejected connector hooks, direct
// inspect calls, refused requests and foreign-hook guard denials) name the
// kernel-verified account, the connector and, for refusals, the route and
// reason, instead of leaving them to the gateway journal.
func TestHookSocketAuditRowsNameTheVerifiedCaller(t *testing.T) {
	useTestPeerResolver(t, &slowPeerResolver{slowUID: -1, started: make(chan struct{}), release: make(chan struct{})})
	restoreCredentials := hookSocketPeerCredentials
	hookSocketPeerCredentials = func(net.Conn) (peercred.Credentials, error) {
		return peercred.Credentials{UID: 7101, GID: 7101, PID: 301}, nil
	}
	t.Cleanup(func() { hookSocketPeerCredentials = restoreCredentials })
	socket, _, store := startTestHookSocketServer(t, hookSocketTestServer{ledger: `{"version":1,"ok":true,"protected_targets":[{"user":"user7101","uid":7101,"connector":"claudecode","ok":true}]}`})
	client := hookSocketClient(socket, 10*time.Second)
	post := func(path, connectorName string, body any) int {
		t.Helper()
		data, _ := json.Marshal(body)
		request, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:18970"+path, strings.NewReader(string(data)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "claude-code-hook/1.0")
		if connectorName != "" {
			request.Header.Set("X-DefenseClaw-Connector", connectorName)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}
	hasCaller := func(event audit.Event) bool {
		return event.Structured[auditUserIDKey] == "7101" && event.Structured[auditUserNameKey] == "user7101"
	}

	// A rejected connector hook (no event name).
	post("/api/v1/claude-code/hook", "", map[string]any{})
	waitForAuditRow(t, store, "rejected connector-hook with the caller", func(event audit.Event) bool {
		return event.Action == string(audit.ActionConnectorHook) && event.Structured["result"] == "rejected" && hasCaller(event)
	})

	// A direct inspect call.
	if status := post("/api/v1/inspect/tool", "claudecode", map[string]any{"tool": "Bash", "args": map[string]any{"command": "echo attribution"}}); status != http.StatusOK {
		t.Fatalf("inspect = %d", status)
	}
	inspect := waitForAuditRow(t, store, "inspect-tool row with the caller", func(event audit.Event) bool {
		return strings.HasPrefix(event.Action, "inspect-tool-") && hasCaller(event)
	})
	if inspect.Connector != "claudecode" || inspect.Structured["route"] != "/api/v1/inspect/tool" {
		t.Fatalf("inspect row connector=%q structured=%v", inspect.Connector, inspect.Structured)
	}

	// A refused request: the caller is not enrolled for cursor.
	if status := post("/api/v1/cursor/hook", "", map[string]any{"hook_event_name": "beforeShellExecution"}); status != http.StatusForbidden {
		t.Fatalf("unenrolled connector = %d", status)
	}
	refusal := waitForAuditRow(t, store, "api-auth-failure with the principal", func(event audit.Event) bool {
		return event.Action == string(audit.ActionAPIAuthFailure) && event.Structured["defenseclaw.admin.principal_ref"] == "uid:7101"
	})
	if refusal.Structured["defenseclaw.admin.reason"] != managedHookReasonUIDUnregistered ||
		!strings.Contains(auditStringValue(refusal.Structured["defenseclaw.admin.target_ref"]), "/api/v1/cursor/hook") ||
		refusal.Connector != "cursor" {
		t.Fatalf("refusal row connector=%q structured=%v", refusal.Connector, refusal.Structured)
	}

	// A foreign-hook guard denial recorded by the session exchange.
	exchange := map[string]any{
		"key":           map[string]any{"connector": "claudecode", "session": "audit-session", "process": "audit-process"},
		"session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}},
	}
	if status := post("/api/v1/foreign-hook-session/claudecode", "", exchange); status != http.StatusOK {
		t.Fatalf("session exchange = %d", status)
	}
	denial := waitForAuditRow(t, store, "foreign-hook denial", func(event audit.Event) bool {
		return event.Action == string(audit.ActionConnectorHook) && event.Structured["event"] == "foreign_hook_session" && hasCaller(event)
	})
	extra, _ := denial.Structured["extra"].(map[string]any)
	if denial.Connector != "claudecode" || denial.Structured["action"] != "block" ||
		extra["file"] != "/repo/.claude/settings.json" || extra["session_block"] != "session_recorded" ||
		!strings.Contains(auditStringValue(denial.Structured["reason"]), "enterprise_foreign_hook_blocked") {
		t.Fatalf("denial row connector=%q structured=%v", denial.Connector, denial.Structured)
	}

	// The caller sends the finding fields: an oversized request still
	// writes a bounded row.
	huge := strings.Repeat("x", 40<<10)
	flood := map[string]any{
		"key":           map[string]any{"connector": "claudecode", "session": "flood-session", "process": "flood-process"},
		"session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: " + huge,
			"findings": []map[string]any{{"connector": "claudecode", "scope": huge, "path": "/repo/" + huge, "digest": huge, "reason": huge}}},
	}
	if status := post("/api/v1/foreign-hook-session/claudecode", "", flood); status != http.StatusOK {
		t.Fatalf("oversized session exchange = %d", status)
	}
	row := waitForAuditRow(t, store, "oversized foreign-hook denial", func(event audit.Event) bool {
		extra, _ := event.Structured["extra"].(map[string]any)
		file, _ := extra["file"].(string)
		return event.Structured["event"] == "foreign_hook_session" && strings.HasPrefix(file, "/repo/x")
	})
	rowExtra, _ := row.Structured["extra"].(map[string]any)
	for _, key := range []string{"file", "scope", "digest", "finding_reason"} {
		value, _ := rowExtra[key].(string)
		if value == "" || len(value) > foreignHookAuditFieldLimit {
			t.Fatalf("audit field %s has %d bytes, want 1..%d", key, len(value), foreignHookAuditFieldLimit)
		}
	}
	if reason := auditStringValue(row.Structured["reason"]); len(reason) > foreignHookAuditReasonLimit {
		t.Fatalf("audit reason has %d bytes, want at most %d", len(reason), foreignHookAuditReasonLimit)
	}
	if data, _ := json.Marshal(row.Structured); len(data) > 8<<10 {
		t.Fatalf("oversized request wrote a %d-byte audit row", len(data))
	}
}
