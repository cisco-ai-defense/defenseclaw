// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// The Python fail-mode status (cli/defenseclaw/fail_mode.py
// _claude_native_registration_problem, cli/tests/test_fail_mode_runtime.py)
// reads testdata/claudecode_linux_peruser_handlers.json, so the per-user
// Linux Claude Code handlers Setup writes and the ones status accepts cannot
// drift: status looked for claude-code-hook.sh in the native direct-argv
// handlers and reported every packaged per-user install stale
// (rel-1-0-6 GAP-0569).
func TestClaudeCodeLinuxPerUserHandlersMatchTheSharedGolden(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix registration")
	}
	data, err := os.ReadFile(filepath.Join("testdata", "claudecode_linux_peruser_handlers.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Account string                 `json:"account"`
		APIAddr string                 `json:"api_addr"`
		Hooks   map[string]interface{} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	invocation := func(account string) (string, []string) {
		bin := filepath.Join(account, ".local", "bin")
		return filepath.Join(bin, "defenseclaw-hook-post"), []string{
			"guard-user-hook", filepath.Join(bin, "defenseclaw-hook-user"), "hook", "--connector", "claudecode",
			"--hook-home", filepath.Join(account, ".defenseclaw"), "--api-addr", golden.APIAddr,
		}
	}
	registry := map[string]claudeCodeHookGroup{}
	for _, group := range claudeCodeAllHookGroups {
		registry[group.eventType] = group
	}
	events := make([]string, 0, len(golden.Hooks))
	for event := range golden.Hooks {
		events = append(events, event)
	}
	sort.Strings(events)
	var groups []claudeCodeHookGroup
	sawAsync := false
	for _, event := range events {
		group, ok := registry[event]
		if !ok {
			t.Fatalf("golden event %s is not a Claude Code hook group", event)
		}
		sawAsync = sawAsync || group.async
		groups = append(groups, group)
	}
	if !sawAsync || len(groups) < 2 {
		t.Fatalf("golden must hold a synchronous and an asynchronous event, has %v", events)
	}
	command, args := invocation(golden.Account)
	rendered := map[string]interface{}{}
	appendClaudeCodeHookGroups(rendered, command, args, groups)
	raw, err := json.Marshal(rendered)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, golden.Hooks) {
		pretty, _ := json.MarshalIndent(rendered, "", "  ")
		t.Fatalf("per-user Linux handlers Setup writes differ from the golden:\n%s", pretty)
	}
	if runtime.GOOS != "linux" {
		return
	}
	// A packaged per-user Linux layout selects exactly this invocation.
	account := t.TempDir()
	t.Setenv("HOME", account)
	dataDir := filepath.Join(account, ".defenseclaw")
	hooks := filepath.Join(dataDir, "hooks")
	bin := filepath.Join(account, ".local", "bin")
	for _, dir := range []string{hooks, bin} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"defenseclaw-hook-user", "defenseclaw-hook-post"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(hooks, ".gateway-helper"),
		[]byte(filepath.Join(bin, "defenseclaw-gateway")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gotCommand, gotArgs := claudeCodeHookInvocation(SetupOpts{DataDir: dataDir, APIAddr: golden.APIAddr},
		filepath.Join(hooks, "claude-code-hook.sh"))
	wantCommand, wantArgs := invocation(account)
	if gotCommand != wantCommand || !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("per-user Linux invocation = %q %q, want %q %q", gotCommand, gotArgs, wantCommand, wantArgs)
	}
	if strings.Contains(gotCommand, "claude-code-hook.sh") {
		t.Fatalf("native invocation names the shell hook: %q", gotCommand)
	}
}
