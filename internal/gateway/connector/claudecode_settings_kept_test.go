// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestClaudeCodeSettingsKeepsHooks (substrate-1 GAP-0615, GAP-0619): the
// settings Setup writes keep every hook under the home they name and "~";
// any one dropped event, another home, an edited guard, extra arguments, a
// narrowed matcher, a condition, an async handler or a shorter timeout do
// not.
func TestClaudeCodeSettingsKeepsHooks(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home", "alice")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	opts := SetupOpts{DataDir: filepath.Join(home, ".defenseclaw"), APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000", AgentVersion: "2.1.270"}
	if err := NewClaudeCodeConnector().Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	parse := func(text string) map[string]any {
		decoder := json.NewDecoder(bytes.NewReader([]byte(text)))
		decoder.UseNumber()
		var doc map[string]any
		if err := decoder.Decode(&doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	installed := string(raw)
	if got := ClaudeCodeSettingsKeepsHooks(parse(installed)["hooks"], []string{"~", home}); got != "" {
		t.Fatalf("Setup's own settings miss %s", got)
	}
	tilde := strings.ReplaceAll(installed, home+"/.defenseclaw/", "~/.defenseclaw/")
	if got := ClaudeCodeSettingsKeepsHooks(parse(tilde)["hooks"], []string{"~", "/sandbox"}); got != "" {
		t.Fatalf("the ~ spelling misses %s", got)
	}
	if len(claudeCodeSettingsRequiredGroups()) < 5 {
		t.Fatalf("required events %d", len(claudeCodeSettingsRequiredGroups()))
	}
	firstHandler := func(doc map[string]any, event string) map[string]any {
		return doc["hooks"].(map[string]any)[event].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	}
	for name, mutate := range map[string]func(map[string]any){
		"drop Stop":       func(doc map[string]any) { delete(doc["hooks"].(map[string]any), "Stop") },
		"drop PreToolUse": func(doc map[string]any) { delete(doc["hooks"].(map[string]any), "PreToolUse") },
		"guard swallowed": func(doc map[string]any) {
			h := firstHandler(doc, "PreToolUse")
			h["command"] = h["command"].(string) + " || true"
		},
		"other script": func(doc map[string]any) {
			h := firstHandler(doc, "PreToolUse")
			h["command"] = "/tmp/x/.defenseclaw/hooks/claude-code-hook.sh"
		},
		"extra args":    func(doc map[string]any) { firstHandler(doc, "PreToolUse")["args"] = []any{"--off"} },
		"condition":     func(doc map[string]any) { firstHandler(doc, "PreToolUse")["if"] = "Bash(nothing)" },
		"async":         func(doc map[string]any) { firstHandler(doc, "PreToolUse")["async"] = true },
		"short timeout": func(doc map[string]any) { firstHandler(doc, "PreToolUse")["timeout"] = json.Number("1") },
		"narrowed matcher": func(doc map[string]any) {
			doc["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["matcher"] = "NoSuchTool"
		},
		"not a command": func(doc map[string]any) { firstHandler(doc, "PreToolUse")["type"] = "prompt" },
	} {
		doc := parse(installed)
		mutate(doc)
		if got := ClaudeCodeSettingsKeepsHooks(doc["hooks"], []string{"~", home}); got == "" {
			t.Errorf("%s: still reads as kept", name)
		}
	}
	if got := ClaudeCodeSettingsKeepsHooks(parse(installed)["hooks"], []string{"~", "/sandbox"}); got == "" {
		t.Error("a command under another home reads as the guest's hook")
	}
	if got := ClaudeCodeSettingsKeepsHooks(nil, []string{"~", home}); got == "" {
		t.Error("no hooks member reads as kept")
	}
}
