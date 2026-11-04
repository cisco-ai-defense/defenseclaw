// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// coworkCapture is one hook event of a real Cowork session (Claude Desktop
// 4.4212.0, engine 2.1.309, macOS), delivered by a plugin hook or by the
// machine managed-settings drop-in. User, host, paths and addresses are
// replaced.
type coworkCapture struct {
	Route   string                 `json:"route"`
	Payload map[string]interface{} `json:"payload"`
}

func readCoworkCaptures(t *testing.T) []coworkCapture {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "claudecode", "cowork-2.1.309.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []coworkCapture
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		var capture coworkCapture
		if err := json.Unmarshal(scanner.Bytes(), &capture); err != nil {
			t.Fatal(err)
		}
		out = append(out, capture)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// asClaudeCode is the capture as the same call from Claude Code's own tools:
// the workspace shell and fetch become Bash and WebFetch.
func (c coworkCapture) asClaudeCode() map[string]interface{} {
	payload := map[string]interface{}{}
	for k, v := range c.Payload {
		payload[k] = v
	}
	switch payload["tool_name"] {
	case "mcp__workspace__bash":
		payload["tool_name"] = "Bash"
		delete(payload, "mcp_server")
	case "mcp__workspace__web_fetch":
		payload["tool_name"] = "WebFetch"
		delete(payload, "mcp_server")
	}
	return payload
}

func postCoworkCapture(t *testing.T, api *APIServer, payload map[string]interface{}, cowork *hookexec.CoworkContext) map[string]interface{} {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cowork != nil {
		req.Header.Set(hookexec.CoworkHeader, cowork.HeaderValue())
	}
	w := httptest.NewRecorder()
	inboundTraceContextMiddleware(http.HandlerFunc(api.handleAgentHook("claudecode"))).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%v %v: status %d body %s", payload["hook_event_name"], payload["tool_name"], w.Code, w.Body.String())
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed
}

// Every event of a real Cowork session reaches the claudecode route, is
// allowed (the session did ordinary work), gets the verdict of the same
// call from Claude Code's own tools, and is counted on the Cowork surface.
func TestCoworkCaptureReplaysThroughTheClaudeCodeRoute(t *testing.T) {
	captures := readCoworkCaptures(t)
	if len(captures) < 80 {
		t.Fatalf("%d captured events; the fixture is incomplete", len(captures))
	}
	cowork := &hookexec.CoworkContext{SessionID: "c29dbbfa-8209-4e91-84c4-7191c9491c94", WorkspaceHostPaths: []string{"/Users/alice/Desktop/cowork-hook-probe-work"}}
	for _, mode := range []string{"action", "observe"} {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = mode
		cfg.Guardrail.Connector = "claudecode"
		health := NewSidecarHealth()
		api := &APIServer{scannerCfg: cfg, health: health}
		tools := map[string]int{}
		for _, capture := range captures {
			got := postCoworkCapture(t, api, capture.Payload, cowork)
			want := postCoworkCapture(t, api, capture.asClaudeCode(), nil)
			event, tool := capture.Payload["hook_event_name"], capture.Payload["tool_name"]
			if got["action"] != "allow" {
				t.Errorf("%s %s %v %v: action %v, want allow (benign session)\n%v", mode, capture.Route, event, tool, got["action"], got)
			}
			for _, field := range []string{"action", "raw_action", "severity", "would_block"} {
				if got[field] != want[field] {
					t.Errorf("%s %v %v: %s=%v, Claude Code tools give %v", mode, event, tool, field, got[field], want[field])
				}
			}
			if name, _ := tool.(string); name != "" {
				tools[name]++
			}
		}
		for _, tool := range []string{"mcp__workspace__bash", "mcp__workspace__web_fetch", "Read", "Write", "Edit", "Glob", "Grep", "Agent"} {
			if tools[tool] == 0 {
				t.Errorf("fixture has no %s call", tool)
			}
		}
		claude := connByName(health.Snapshot().Connectors)["claudecode"]
		surface, ok := claude.Surfaces[connector.CoworkSurface]
		if !ok || surface.Requests != int64(len(captures)) || surface.LastActivityAt == nil || surface.LastSessionStartAt == nil {
			t.Errorf("%s: claudecode surfaces = %+v, want %d Cowork requests with a time", mode, claude.Surfaces, len(captures))
		}
		if claude.Requests != int64(2*len(captures)) {
			t.Errorf("%s: claudecode requests = %d, want %d", mode, claude.Requests, 2*len(captures))
		}
	}
}
