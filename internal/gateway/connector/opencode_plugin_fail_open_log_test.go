// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// rel-1-0-2 GAP-0446 item 1: an OpenCode tool call that goes ahead because
// DefenseClaw could not check it (fail mode open) writes the same
// hook-failures.jsonl line as the shell and native hooks, in the install's
// data directory, so the gateway's fail-open report finds it.
func TestOpenCodePluginFailOpenWritesAHookFailureLine(t *testing.T) {
	nodeForTest(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Event string `json:"hook_event_name"`
		}
		_ = json.Unmarshal(body, &payload)
		if payload.Event == "tool.execute.before" || payload.Event == "tool.execute.after" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"allow","mode":"observe"}`)
	}))
	t.Cleanup(server.Close)
	dataDir := testenv.PrivateTempDir(t)
	token := filepath.Join(dataDir, "hooks", ".hook-opencode.token")
	if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := templateData{
		APIAddr:      strings.TrimPrefix(server.URL, "http://"),
		TokenFileJS:  javaScriptStringContent(token),
		FailMode:     "open",
		Managed:      true,
		SecureClient: true,
	}
	harness := strings.Replace(openCodePluginHarness, `console.log("allow");`, `await plugin["tool.execute.after"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C" + i }, { output: "marker" }); console.log("allow");`, 1)
	lines := runNodeHarness(t, harness, writeRenderedPlugin(t, "opencode-plugin.js", "defenseclaw.mjs", data), "1")
	if len(lines) == 0 || lines[0] != "allow" {
		t.Fatalf("fail-open verdicts = %q, want allow", lines)
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, "logs", "hook-failures.jsonl"))
	if err != nil {
		t.Fatalf("no hook-failures line for the fail-open call: %v", err)
	}
	var entry map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &entry); err != nil {
		t.Fatalf("hook-failures line %q: %v", raw, err)
	}
	if entry["connector"] != "opencode" || entry["hook"] != "opencode-plugin" || entry["fail_mode"] != "open" ||
		entry["category"] != "transport" || entry["reason"] != "gateway returned HTTP 503" || entry["ts"] == "" {
		t.Fatalf("hook-failures line = %v", entry)
	}
}
