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
	"net"
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
	// The tool calls meet a gateway that refuses the connection: the outage
	// fail mode open covers. An HTTP 503 is an answer and blocks
	// (TestOpenCodePluginTakesItsInstalledModeAndStrictAvailability).
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := listener.Addr().String()
	_ = listener.Close()
	dataDir := testenv.PrivateTempDir(t)
	token := filepath.Join(dataDir, "hooks", ".hook-opencode.token")
	if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := templateData{
		APIAddr:     refused,
		TokenFileJS: javaScriptStringContent(token),
		FailMode:    "open",
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
		entry["category"] != "transport" || entry["reason"] == "" || entry["ts"] == "" {
		t.Fatalf("hook-failures line = %v", entry)
	}
}
