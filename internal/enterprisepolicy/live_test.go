// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// The live checks run a real client binary. These tests re-execute the
// test binary as a fake Codex app-server or Claude Code CLI through a small
// wrapper script (the live environment is minimal, so the script carries
// the fake's settings).
func TestMain(m *testing.M) {
	switch os.Getenv("DC_FAKE_AGENT") {
	case "codex":
		fakeCodexAppServer()
		os.Exit(0)
	case "claude":
		os.Exit(fakeClaudeCLI())
	}
	os.Exit(m.Run())
}

func fakeCodexAppServer() {
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var request struct {
			ID     *int   `json:"id"`
			Method string `json:"method"`
		}
		if json.Unmarshal(scanner.Bytes(), &request) != nil || request.ID == nil {
			continue
		}
		var result any
		switch request.Method {
		case "initialize":
			result = map[string]any{"userAgent": "fake"}
		case "configRequirements/read":
			result = map[string]any{"requirements": map[string]any{"allowManagedHooksOnly": os.Getenv("DC_FAKE_LOCK") == "true"}}
		case "hooks/list":
			result = map[string]any{"data": []any{map[string]any{"hooks": []any{map[string]any{
				"command": os.Getenv("DC_FAKE_COMMAND"), "enabled": os.Getenv("DC_FAKE_ENABLED") == "true", "trusted": true,
			}}}}}
		}
		_ = encoder.Encode(map[string]any{"id": *request.ID, "result": result})
	}
}

func fakeClaudeCLI() int {
	base := os.Getenv("ANTHROPIC_BASE_URL")
	if provider := os.Getenv("DC_FAKE_PROVIDER"); provider != "" {
		// The user's settings route Claude Code to Bedrock. Command-line
		// --settings outrank them; managed settings outrank both.
		var flag struct {
			Env map[string]string `json:"env"`
		}
		for i, arg := range os.Args {
			if arg == "--settings" && i+1 < len(os.Args) {
				_ = json.Unmarshal([]byte(os.Args[i+1]), &flag)
			}
		}
		if provider == "managed-bedrock" || flag.Env["CLAUDE_CODE_USE_BEDROCK"] != "0" {
			fmt.Println(`{"type":"result","duration_api_ms":3795,"stop_reason":"end_turn","total_cost_usd":0.03}`)
			return 0
		}
		base = flag.Env["ANTHROPIC_BASE_URL"]
	}
	post := func(body string) (map[string]any, error) {
		response, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		var decoded map[string]any
		if response.Header.Get("Content-Type") == "text/event-stream" {
			return decodeFakeMessageStream(response.Body)
		}
		return decoded, json.NewDecoder(response.Body).Decode(&decoded)
	}
	// Claude Code streams the agent turn, which offers the tools.
	first, err := post(`{"stream":true,"tools":[{"name":"Bash"}],"messages":[{"role":"user","content":"go"}]}`)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	content, _ := first["content"].([]any)
	toolUseID := ""
	for _, raw := range content {
		block, _ := raw.(map[string]any)
		input, _ := block["input"].(map[string]any)
		command, _ := input["command"].(string)
		id, _ := block["id"].(string)
		if command == "" || id == "" {
			continue
		}
		toolUseID = id
		if os.Getenv("DC_FAKE_HOOK_LOG") != "" {
			// Stand-in for DefenseClaw's managed PreToolUse hook reporting the
			// call to the gateway, which records it in its event history.
			file, err := os.OpenFile(os.Getenv("DC_FAKE_HOOK_LOG"), os.O_APPEND|os.O_WRONLY, 0o600)
			if err == nil {
				fmt.Fprintln(file, fakeHookCall(os.Getenv("DC_FAKE_HOOK_SHAPE"), id, command))
				_ = file.Close()
			}
		}
	}
	result, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": toolUseID}}}}})
	if _, err := post(string(result)); err != nil {
		return 1
	}
	if n, _ := strconv.Atoi(os.Getenv("DC_FAKE_FLOOD")); n > 0 {
		// A chatty client writing to both streams at once.
		chunk := bytes.Repeat([]byte("x"), 32<<10)
		var wg sync.WaitGroup
		for _, stream := range []*os.File{os.Stdout, os.Stderr} {
			wg.Add(1)
			go func(stream *os.File) {
				defer wg.Done()
				for written := 0; written < n; written += len(chunk) {
					if _, err := stream.Write(chunk); err != nil {
						return
					}
				}
			}(stream)
		}
		wg.Wait()
	}
	fmt.Println(`{"result":"done"}`)
	return 0
}

// decodeFakeMessageStream rebuilds the message of a Messages API event
// stream: its tool_use blocks with their streamed input, and its text.
func decodeFakeMessageStream(body io.Reader) (map[string]any, error) {
	var content []any
	var current map[string]any
	partial := ""
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		data, ok := strings.CutPrefix(scanner.Text(), "data: ")
		if !ok {
			continue
		}
		var event struct {
			Type         string         `json:"type"`
			ContentBlock map[string]any `json:"content_block"`
			Delta        map[string]any `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return nil, err
		}
		switch event.Type {
		case "content_block_start":
			current, partial = event.ContentBlock, ""
		case "content_block_delta":
			if text, ok := event.Delta["partial_json"].(string); ok {
				partial += text
			}
		case "content_block_stop":
			if partial != "" {
				var input map[string]any
				_ = json.Unmarshal([]byte(partial), &input)
				current["input"] = input
			}
			content = append(content, current)
		}
	}
	return map[string]any{"content": content}, scanner.Err()
}

// fakeHookCall renders what the fake hook reports for one Claude Code
// PreToolUse call; shape selects reports that must not prove hook contact.
func fakeHookCall(shape, toolUseID, command string) string {
	call := map[string]any{
		"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": toolUseID,
		"tool_input": map[string]string{"command": command}, "user_id": strconv.Itoa(os.Getuid()),
	}
	switch shape {
	case "other-user":
		call["user_id"] = strconv.Itoa(os.Getuid() + 1)
	case "other-tool-call":
		call["tool_use_id"] = "toolu_canary"
	}
	line, _ := json.Marshal(call)
	return string(line)
}

// fakeEventHistory answers the live check's event-history query from the
// fake hook's reports, the way the gateway's audit database would; the
// match against real v8 records is covered in the gateway package.
func fakeEventHistory(t *testing.T, log string, queries *[]audit.HookToolInvocationQuery) func(context.Context, audit.HookToolInvocationQuery) (audit.HookToolInvocationEvidence, error) {
	t.Helper()
	return func(_ context.Context, query audit.HookToolInvocationQuery) (audit.HookToolInvocationEvidence, error) {
		if queries != nil {
			*queries = append(*queries, query)
		}
		var evidence audit.HookToolInvocationEvidence
		data, err := os.ReadFile(log)
		if err != nil {
			return evidence, err
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var call struct {
				ToolUseID string `json:"tool_use_id"`
				UserID    string `json:"user_id"`
			}
			if json.Unmarshal([]byte(line), &call) != nil || call.ToolUseID != query.ToolCallID || query.Connector != ConnectorClaudeCode {
				continue
			}
			if query.UserID != "" && call.UserID != query.UserID {
				evidence.Mismatches = append(evidence.Mismatches, fmt.Sprintf("a tool call record for user %q", call.UserID))
				continue
			}
			evidence.Matched = true
		}
		return evidence, nil
	}
}

func fakeAgentScript(t *testing.T, agent string, env map[string]string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("wrapper script is POSIX sh")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var script bytes.Buffer
	script.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&script, "export DC_FAKE_AGENT=%s\n", shellQuote(agent))
	for key, value := range env {
		fmt.Fprintf(&script, "export %s=%s\n", key, shellQuote(value))
	}
	fmt.Fprintf(&script, "exec %s -test.run='^$' \"$@\"\n", shellQuote(self))
	path := filepath.Join(t.TempDir(), agent)
	if err := os.WriteFile(path, script.Bytes(), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyLiveCodexAppServer(t *testing.T) {
	opts := testOptions(t)
	home := t.TempDir()
	good := fakeAgentScript(t, "codex", map[string]string{"DC_FAKE_LOCK": "true", "DC_FAKE_ENABLED": "true", "DC_FAKE_COMMAND": codexHookCommandForEvent(opts, "PreToolUse")})
	result, err := VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorCodex, AgentBinary: good, Home: home, Timeout: 30 * time.Second})
	if err != nil || !result.Verified || len(result.Evidence) != 2 {
		t.Fatalf("a locked client with trusted hooks must verify: %+v %v", result, err)
	}

	disabled := fakeAgentScript(t, "codex", map[string]string{"DC_FAKE_LOCK": "false", "DC_FAKE_ENABLED": "false", "DC_FAKE_COMMAND": codexHookCommandForEvent(opts, "PreToolUse")})
	result, err = VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorCodex, AgentBinary: disabled, Home: home, Timeout: 30 * time.Second})
	if err != nil || result.Verified || result.HookContact != "no" || len(result.Problems) < 2 {
		t.Fatalf("an unlocked client with disabled hooks must fail: %+v %v", result, err)
	}
}

func TestVerifyLiveClaudeCanary(t *testing.T) {
	opts := testOptions(t)
	home := t.TempDir()
	log := filepath.Join(t.TempDir(), "hook-calls.jsonl")
	writeFile(t, log, "")
	var queries []audit.HookToolInvocationQuery
	hooked := fakeAgentScript(t, "claude", map[string]string{"DC_FAKE_HOOK_LOG": log})
	started := time.Now()
	result, err := VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorClaudeCode, AgentBinary: hooked, Home: home, UID: os.Getuid(), HookRecords: fakeEventHistory(t, log, &queries), Timeout: 30 * time.Second})
	if err != nil || !result.Verified || result.HookContact != "yes" {
		t.Fatalf("a hooked run must reach the gateway: %+v %v", result, err)
	}
	// The stub gave the canary call a tool call id derived from the nonce,
	// and the check asked the event history for exactly that call.
	if !strings.Contains(readFile(t, log), canaryToolCallID(result.Nonce)) || len(queries) != 1 {
		t.Fatalf("the canary call must carry the nonce-derived tool call id: %s %+v", readFile(t, log), queries)
	}
	if query := queries[0]; query.Connector != ConnectorClaudeCode || query.ToolCallID != canaryToolCallID(result.Nonce) ||
		query.UserID != strconv.Itoa(os.Getuid()) || query.Since.Before(started) || query.Since.After(time.Now()) {
		t.Fatalf("event-history query: %+v", query)
	}

	shadowed := fakeAgentScript(t, "claude", map[string]string{})
	result, err = VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorClaudeCode, AgentBinary: shadowed, Home: home, UID: os.Getuid(), HookRecords: fakeEventHistory(t, log, nil), Timeout: 30 * time.Second})
	if err != nil || result.Verified || result.HookContact != "no" || !strings.Contains(strings.Join(result.Problems, " "), "server-managed") {
		t.Fatalf("a run without DefenseClaw's hooks must fail and name the likely cause: %+v %v", result, err)
	}

	if _, err := VerifyLive(context.Background(), opts, LiveOptions{Connector: "cursor", AgentBinary: hooked, Home: home}); err == nil {
		t.Fatal("live verification is only implemented for codex and claudecode")
	}
}

// Only the gateway's record of the canary call itself, for the target
// user, proves hook contact; a record of another call or for another user
// does not, and an unreadable or unconfigured event history proves nothing.
func TestVerifyLiveClaudeRequiresTheCanaryToolCallRecord(t *testing.T) {
	opts := testOptions(t)
	home := t.TempDir()
	for _, shape := range []string{"other-user", "other-tool-call"} {
		t.Run(shape, func(t *testing.T) {
			log := filepath.Join(t.TempDir(), "hook-calls.jsonl")
			writeFile(t, log, "")
			agent := fakeAgentScript(t, "claude", map[string]string{"DC_FAKE_HOOK_LOG": log, "DC_FAKE_HOOK_SHAPE": shape})
			result, err := VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorClaudeCode, AgentBinary: agent, Home: home, UID: os.Getuid(), HookRecords: fakeEventHistory(t, log, nil), Timeout: 30 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(readFile(t, log), "PreToolUse") {
				t.Fatalf("the fake hook did not report the call")
			}
			if result.Verified || result.HookContact != "no" {
				t.Fatalf("a %s record must not prove hook contact: %+v", shape, result)
			}
		})
	}
	agent := fakeAgentScript(t, "claude", map[string]string{})
	for name, lo := range map[string]LiveOptions{
		"no event history":       {},
		"missing audit database": {AuditDB: filepath.Join(t.TempDir(), "audit.db")},
	} {
		lo.Connector, lo.AgentBinary, lo.Home, lo.UID, lo.Timeout = ConnectorClaudeCode, agent, home, os.Getuid(), 30*time.Second
		result, err := VerifyLive(context.Background(), opts, lo)
		if err != nil || result.Verified || result.HookContact != "unknown" || len(result.Problems) == 0 {
			t.Fatalf("%s must leave hook contact unproven: %+v %v", name, result, err)
		}
	}
}

// A client that writes more than the cap to stdout and stderr at once must
// neither race on the shared output buffer (run under -race: exec copies the
// two streams on separate goroutines) nor stall or be cut off by a write
// error at the cap.
func TestVerifyLiveClaudeDrainsAChattyClient(t *testing.T) {
	opts := testOptions(t)
	home := t.TempDir()
	log := filepath.Join(t.TempDir(), "hook-calls.jsonl")
	writeFile(t, log, "")
	agent := fakeAgentScript(t, "claude", map[string]string{"DC_FAKE_HOOK_LOG": log, "DC_FAKE_FLOOD": strconv.Itoa(4 << 20)})
	started := time.Now()
	result, err := VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorClaudeCode, AgentBinary: agent, Home: home, UID: os.Getuid(), HookRecords: fakeEventHistory(t, log, nil), Timeout: 40 * time.Second})
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("the check stalled for %s on a chatty client", elapsed)
	}
	if err != nil || !result.Verified {
		t.Fatalf("a chatty hooked client must still verify: %+v %v", result, err)
	}
}

// Output past the cap is discarded rather than failing the write, so exec
// keeps draining the pipes; one buffer may back both streams.
func TestLimitedBufferDiscardsPastTheLimitAndIsConcurrencySafe(t *testing.T) {
	buffer := newLimitedBuffer(10)
	if n, err := buffer.Write([]byte("0123456789abc")); err != nil || n != 13 {
		t.Fatalf("write past the limit = %d, %v; want 13, nil", n, err)
	}
	if got := buffer.String(); got != "0123456789" || !buffer.Truncated() {
		t.Fatalf("buffer = %q truncated=%v", got, buffer.Truncated())
	}
	shared := newLimitedBuffer(1 << 20)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = shared.Write([]byte("0123456789"))
				_ = shared.String()
			}
		}()
	}
	wg.Wait()
	if got := len(shared.String()); got != 8000 {
		t.Fatalf("concurrent writes lost bytes: %d", got)
	}
}

// GAP-1135: a user whose settings route Claude Code to Bedrock made the
// probe call Bedrock instead of the local stub, and the check dumped the
// raw result JSON. The probe's command-line settings point Claude Code at
// the stub; a provider only managed settings can force is named, not
// dumped.
func TestVerifyLiveClaudeOverridesTheUsersModelProvider(t *testing.T) {
	opts := testOptions(t)
	home := t.TempDir()
	log := filepath.Join(t.TempDir(), "hook-calls.jsonl")
	writeFile(t, log, "")
	bedrock := fakeAgentScript(t, "claude", map[string]string{"DC_FAKE_HOOK_LOG": log, "DC_FAKE_PROVIDER": "bedrock"})
	result, err := VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorClaudeCode, AgentBinary: bedrock, Home: home, UID: os.Getuid(), HookRecords: fakeEventHistory(t, log, nil), Timeout: 30 * time.Second})
	if err != nil || !result.Verified || result.HookContact != "yes" {
		t.Fatalf("a user on Bedrock must still reach the stub: %+v %v", result, err)
	}
	managed := fakeAgentScript(t, "claude", map[string]string{"DC_FAKE_PROVIDER": "managed-bedrock"})
	result, err = VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorClaudeCode, AgentBinary: managed, Home: home, UID: os.Getuid(), HookRecords: fakeEventHistory(t, log, nil), Timeout: 30 * time.Second})
	problems := strings.Join(result.Problems, " ")
	if err != nil || result.Verified || !strings.Contains(problems, "CLAUDE_CODE_USE_BEDROCK") || strings.Contains(problems, "total_cost_usd") {
		t.Fatalf("a provider the check cannot override must be named without the raw result: %+v %v", result, err)
	}
}

// GAP-1136: an npm codex launcher whose node is not on the probe's PATH
// made the app-server exit at once, and the check said only "app-server
// closed its output".
func TestVerifyLiveCodexExplainsAnAppServerThatEndsAtOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX launcher script")
	}
	opts := testOptions(t)
	launcher := filepath.Join(t.TempDir(), "codex.js")
	writeFile(t, launcher, "#!/usr/bin/env dc-missing-node-interpreter\n")
	if err := os.Chmod(launcher, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorCodex, AgentBinary: launcher, Home: t.TempDir(), Timeout: 30 * time.Second})
	if err == nil {
		t.Fatal("an app-server that cannot start must fail the check")
	}
	for _, want := range []string{"closed its output (exit status 127)", "stderr: ", "runs dc-missing-node-interpreter, which is not on the probe's PATH", "--agent-binary"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}
