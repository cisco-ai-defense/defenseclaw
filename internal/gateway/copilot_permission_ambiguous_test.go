// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A permissionRequest whose raw body has duplicate keys decodes to the last
// value only, so a protected toolInput can hide behind a trailing {}. Such a
// callback must not inherit the audited allow of the preceding preToolUse,
// and it still consumes that allow (T12b round b review, loop round 2).
func TestNativeCopilotAmbiguousPermissionDoesNotInheritAllow(t *testing.T) {
	project := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	keys := quote(filepath.Join(home, ".ssh", "authorized_keys"))
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	post := func(event, body string) (string, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
		req.Header.Set("X-DefenseClaw-Copilot-Event", event)
		w := httptest.NewRecorder()
		api.handleAgentHook("copilot").ServeHTTP(w, req)
		var verdict struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil {
			return "rejected", w.Body.String()
		}
		return verdict.Action, w.Body.String()
	}
	patch := quote("*** Begin Patch\n*** Add File: README.md\n+ordinary project text\n*** End Patch\n")
	for _, tc := range []struct{ name, permission string }{
		{"duplicate toolInput", `{"hookName":"permissionRequest","sessionId":"%s","cwd":%s,"toolName":"edit","toolInput":{"file_path":` + keys + `,"diff":"+ssh-ed25519 AAAA attacker"},"toolInput":{}}`},
		{"duplicate toolName", `{"hookName":"permissionRequest","sessionId":"%s","cwd":%s,"toolName":"powershell","toolName":"edit","toolInput":{}}`},
		{"duplicate toolArgs", `{"hookName":"permissionRequest","sessionId":"%s","cwd":%s,"toolName":"edit","toolArgs":{"file_path":` + keys + `},"toolArgs":{}}`},
		{"duplicate hookName", `{"hookName":"preToolUse","hookName":"permissionRequest","sessionId":"%s","cwd":%s,"toolName":"edit","toolInput":{}}`},
		{"duplicate nested key", `{"hookName":"permissionRequest","sessionId":"%s","cwd":%s,"toolName":"edit","toolInput":{},"permissionSuggestions":[{"path":` + keys + `,"path":"README.md"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := "ambiguous-" + strings.ReplaceAll(tc.name, " ", "-")
			pre := `{"sessionId":"` + session + `","cwd":` + quote(project) +
				`,"toolCalls":[{"id":"call_ambiguous","name":"apply_patch","args":` + patch + `}]}`
			if action, body := post("preToolUse", pre); action != "allow" {
				t.Fatalf("preToolUse action=%s: %s", action, body)
			}
			ambiguous := strings.Replace(strings.Replace(tc.permission, "%s", session, 1), "%s", quote(project), 1)
			if action, body := post("permissionRequest", ambiguous); action == "allow" {
				t.Fatalf("ambiguous permission inherited the prior allow: %s", body)
			}
			clean := `{"hookName":"permissionRequest","sessionId":"` + session + `","cwd":` + quote(project) +
				`,"toolName":"edit","toolInput":{}}`
			if action, body := post("permissionRequest", clean); action != "block" {
				t.Fatalf("permission after the ambiguous callback reused the consumed allow: action=%s: %s", action, body)
			}
		})
	}
}
