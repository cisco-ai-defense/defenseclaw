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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Static inspection cannot prove what a client actually loads: a
// higher-precedence source DefenseClaw cannot see (Claude server-managed
// settings) or a vendor bug can hide the hooks. Live verification runs the
// real client as the target user.

// LiveOptions selects the client and user for a live check.
type LiveOptions struct {
	Connector   string
	AgentBinary string
	Home        string
	UID         int
	GID         int
	Timeout     time.Duration
	// AuditDB is the gateway's audit database; its v8 event history holds
	// the record a DefenseClaw hook leaves when it reports a tool call.
	AuditDB string
	// HookRecords searches that event history; nil uses AuditDB. Tests
	// replace it.
	HookRecords func(context.Context, audit.HookToolInvocationQuery) (audit.HookToolInvocationEvidence, error)
	// Credential applies the target user's credentials to cmd (unix
	// setuid when running as root); nil runs as the current process.
	Credential func(cmd *exec.Cmd) error
}

// LiveResult is the outcome of a live check.
type LiveResult struct {
	Connector   string   `json:"connector"`
	Client      string   `json:"client"`
	Verified    bool     `json:"verified"`
	HookContact string   `json:"hook_contact"` // yes, no, unknown
	Nonce       string   `json:"nonce,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Problems    []string `json:"problems,omitempty"`
	CheckedAt   string   `json:"checked_at"`
}

func (r *LiveResult) evidence(format string, args ...any) {
	r.Evidence = append(r.Evidence, fmt.Sprintf(format, args...))
}

func (r *LiveResult) problem(format string, args ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
}

func newNonce() string {
	buf := make([]byte, 12)
	_, _ = rand.Read(buf)
	return "defenseclaw-canary-" + hex.EncodeToString(buf)
}

// liveEnv is the minimal environment for the client: the target home, a
// fixed PATH that also contains the client, and nothing from the admin.
func liveEnv(lo LiveOptions, extra ...string) []string {
	if runtimeGOOS() == "windows" {
		systemRoot := os.Getenv("SystemRoot")
		env := []string{
			"SystemRoot=" + systemRoot,
			"USERPROFILE=" + lo.Home,
			"APPDATA=" + filepath.Join(lo.Home, "AppData", "Roaming"),
			"LOCALAPPDATA=" + filepath.Join(lo.Home, "AppData", "Local"),
			"PATH=" + filepath.Dir(lo.AgentBinary) + ";" + filepath.Join(systemRoot, "System32"),
			"NO_COLOR=1",
		}
		return append(env, extra...)
	}
	path := "/usr/bin:/bin"
	if dir := filepath.Dir(lo.AgentBinary); dir != "" {
		path = dir + ":" + path
	}
	env := []string{"HOME=" + lo.Home, "PATH=" + path, "LANG=C.UTF-8", "TERM=dumb", "NO_COLOR=1"}
	return append(env, extra...)
}

// VerifyLive runs the live check for lo.Connector.
func VerifyLive(ctx context.Context, opts Options, lo LiveOptions) (LiveResult, error) {
	if lo.Timeout <= 0 {
		lo.Timeout = 90 * time.Second
	}
	if !filepath.IsAbs(lo.AgentBinary) {
		return LiveResult{}, errors.New("live verification requires an absolute --agent-binary path")
	}
	if !filepath.IsAbs(lo.Home) {
		return LiveResult{}, errors.New("live verification requires the target user's absolute home")
	}
	result := LiveResult{Connector: lo.Connector, Client: lo.AgentBinary, HookContact: "unknown", CheckedAt: opts.now().Format(time.RFC3339)}
	ctx, cancel := context.WithTimeout(ctx, lo.Timeout)
	defer cancel()
	var err error
	switch lo.Connector {
	case ConnectorCodex:
		err = verifyCodexLive(ctx, opts, lo, &result)
	case ConnectorClaudeCode:
		err = verifyClaudeLive(ctx, opts, lo, &result)
	default:
		return result, fmt.Errorf("live verification is implemented for codex and claudecode, not %s", lo.Connector)
	}
	result.Verified = err == nil && len(result.Problems) == 0 && result.HookContact != "no"
	return result, err
}

// verifyCodexLive asks Codex's app-server, running as the user, for the
// effective requirements and hook list.
func verifyCodexLive(ctx context.Context, opts Options, lo LiveOptions, result *LiveResult) error {
	cmd := exec.CommandContext(ctx, lo.AgentBinary, "app-server", "--stdio")
	cmd.Dir = lo.Home
	cmd.Env = liveEnv(lo)
	if lo.Credential != nil {
		if err := lo.Credential(cmd); err != nil {
			return err
		}
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr := newLimitedBuffer(64 << 10)
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start codex app-server: %w", err)
	}
	// The reader waits for the process once its output ends, so a closed
	// output can report how the app-server exited.
	exit := &appServerExit{done: make(chan struct{})}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		<-exit.done
	}()
	responses := make(chan map[string]json.RawMessage, 8)
	go func() {
		defer func() { exit.err = cmd.Wait(); close(exit.done) }()
		defer close(responses)
		scanner := bufio.NewScanner(io.LimitReader(stdout, 8<<20))
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		for scanner.Scan() {
			var envelope map[string]json.RawMessage
			if json.Unmarshal(scanner.Bytes(), &envelope) == nil {
				responses <- envelope
			}
		}
	}()
	encoder := json.NewEncoder(stdin)
	call := func(id int, method string) (json.RawMessage, error) {
		if err := encoder.Encode(map[string]any{"method": method, "id": id, "params": map[string]any{}}); err != nil {
			return nil, err
		}
		for {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("%s: %w", method, ctx.Err())
			case envelope, ok := <-responses:
				if !ok {
					return nil, fmt.Errorf("%s: %s", method, codexAppServerEnded(lo, exit, stderr))
				}
				var got int
				if json.Unmarshal(envelope["id"], &got) != nil || got != id {
					continue
				}
				if raw, bad := envelope["error"]; bad {
					return nil, fmt.Errorf("%s failed: %s", method, raw)
				}
				return envelope["result"], nil
			}
		}
	}
	if err := encoder.Encode(map[string]any{"method": "initialize", "id": 1, "params": map[string]any{"clientInfo": map[string]string{"name": "defenseclaw", "title": "DefenseClaw", "version": "1"}}}); err != nil {
		// The app-server is gone before it read a request.
		return fmt.Errorf("initialize: %s", codexAppServerEnded(lo, exit, stderr))
	}
	if _, err := waitFor(ctx, responses, 1); err != nil {
		if errors.Is(err, errAppServerClosed) {
			return fmt.Errorf("initialize: %s", codexAppServerEnded(lo, exit, stderr))
		}
		return err
	}
	_ = encoder.Encode(map[string]any{"method": "initialized"})
	requirements, err := call(2, "configRequirements/read")
	if err != nil {
		return err
	}
	var parsed struct {
		Requirements *struct {
			AllowManagedHooksOnly *bool `json:"allowManagedHooksOnly"`
		} `json:"requirements"`
	}
	if err := json.Unmarshal(requirements, &parsed); err != nil {
		return fmt.Errorf("decode configRequirements/read: %w", err)
	}
	policy := opts.PolicyFor(ConnectorCodex)
	switch {
	case parsed.Requirements != nil && parsed.Requirements.AllowManagedHooksOnly != nil && *parsed.Requirements.AllowManagedHooksOnly:
		result.evidence("Codex resolves allow_managed_hooks_only = true for this user")
	case policy.ManagedHooksOnly == "enforce":
		result.problem("Codex does not resolve allow_managed_hooks_only = true for this user")
	}
	hooks, err := call(3, "hooks/list")
	if err != nil {
		result.problem("hooks/list is unavailable (Codex before 0.129 has no trust introspection): %v", err)
		return nil
	}
	groups, err := connector.ManagedHookGroupsForOS(codexConnector, opts.agentVersion(codexConnector), opts.goos())
	if err != nil {
		result.problem("resolve the managed Codex hook groups: %v", err)
		return nil
	}
	commands := codexOwnedCommands(opts, groups)
	enabled, disabled := 0, 0
	walkJSON(hooks, func(node map[string]any) {
		if command, _ := node["command"].(string); !commands[command] {
			return
		}
		if node["enabled"] == false || node["trusted"] == false {
			disabled++
			return
		}
		enabled++
	})
	switch {
	case enabled == 0:
		result.problem("hooks/list does not report any enabled, trusted DefenseClaw hook for this user")
		result.HookContact = "no"
	case disabled > 0:
		result.problem("hooks/list reports %d DefenseClaw hooks disabled or untrusted for this user", disabled)
	default:
		result.evidence("hooks/list reports %d DefenseClaw hooks enabled and trusted", enabled)
	}
	return nil
}

var errAppServerClosed = errors.New("app-server closed its output")

// appServerExit is the app-server's exit, known once done is closed.
type appServerExit struct {
	done chan struct{}
	err  error
}

// codexAppServerEnded explains an app-server that closed its output: its
// exit status, what it printed on stderr and, for a launcher script whose
// interpreter is not on the probe's PATH, what to pass instead (GAP-1136).
func codexAppServerEnded(lo LiveOptions, exit *appServerExit, stderr *limitedBuffer) string {
	status := "still running"
	select {
	case <-exit.done:
		var exitErr *exec.ExitError
		switch {
		case errors.As(exit.err, &exitErr):
			status = exitErr.ProcessState.String()
		case exit.err != nil:
			status = exit.err.Error()
		default:
			status = "exit status 0"
		}
	case <-time.After(2 * time.Second):
	}
	message := "the Codex app-server closed its output (" + status + ")"
	if text := strings.TrimSpace(truncate(stderr.String(), 400)); text != "" {
		message += "; stderr: " + text
	} else {
		message += "; it printed nothing on stderr"
	}
	if hint := missingScriptInterpreter(lo); hint != "" {
		message += "; " + hint
	}
	return message
}

// missingScriptInterpreter names the fix when binary is a "#!/usr/bin/env
// <interpreter>" launcher (the npm codex.js runs node) and the interpreter
// is on none of the directories of the probe's minimal PATH.
func missingScriptInterpreter(lo LiveOptions) string {
	binary := lo.AgentBinary
	file, err := os.Open(binary)
	if err != nil {
		return ""
	}
	defer file.Close()
	head := make([]byte, 256)
	n, _ := io.ReadFull(file, head)
	line, _, _ := strings.Cut(string(head[:n]), "\n")
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if !strings.HasPrefix(line, "#!") || len(fields) < 2 || filepath.Base(fields[0]) != "env" {
		return ""
	}
	interpreter := fields[len(fields)-1]
	for _, entry := range liveEnv(lo) {
		if value, ok := strings.CutPrefix(entry, "PATH="); ok {
			for _, dir := range filepath.SplitList(value) {
				if info, err := os.Stat(filepath.Join(dir, interpreter)); err == nil && !info.IsDir() {
					return ""
				}
			}
			return fmt.Sprintf("%s is a launcher script that runs %s, which is not on the probe's PATH (%s); pass --agent-binary the native Codex executable (for an npm install, node_modules/@openai/codex-<platform>/vendor/<target>/bin/codex inside the package) or link %s next to %s", binary, interpreter, value, interpreter, binary)
		}
	}
	return ""
}

func waitFor(ctx context.Context, responses <-chan map[string]json.RawMessage, id int) (map[string]json.RawMessage, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case envelope, ok := <-responses:
			if !ok {
				return nil, errAppServerClosed
			}
			var got int
			if json.Unmarshal(envelope["id"], &got) == nil && got == id {
				return envelope, nil
			}
		}
	}
}

func walkJSON(raw json.RawMessage, visit func(map[string]any)) {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return
	}
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			visit(v)
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(value)
}

// verifyClaudeLive runs Claude Code, as the user, against a local
// Messages API stub that asks for one harmless Bash call whose tool call id
// is derived from a nonce. DefenseClaw's managed PreToolUse hook reports the
// call to the gateway, which records a tool.invocation.requested event in
// its v8 event history (the audit database). Finding that record proves the
// effective policy loaded DefenseClaw's hooks regardless of which managed
// source Claude chose. The tool call id is an identifier, which every
// built-in redaction profile keeps; the tool arguments may be redacted.
func verifyClaudeLive(ctx context.Context, opts Options, lo LiveOptions, result *LiveResult) error {
	started := time.Now()
	nonce := newNonce()
	result.Nonce = nonce
	toolCallID := canaryToolCallID(nonce)
	stub, err := startMessagesStub(nonce, toolCallID)
	if err != nil {
		return err
	}
	defer stub.Close()
	cmd := exec.CommandContext(ctx, lo.AgentBinary, "-p", "Run the canary command.", "--output-format", "json", "--max-turns", "2")
	cmd.Dir = lo.Home
	cmd.Env = liveEnv(lo, "ANTHROPIC_BASE_URL=http://"+stub.addr, "ANTHROPIC_API_KEY=defenseclaw-live-check", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1")
	if lo.Credential != nil {
		if err := lo.Credential(cmd); err != nil {
			return err
		}
	}
	// One serialized buffer backs both streams: exec copies them on separate
	// goroutines, and output past the cap is discarded so the client never
	// blocks on a full pipe.
	output := newLimitedBuffer(2 << 20)
	cmd.Stdout = output
	cmd.Stderr = output
	runErr := cmd.Run()
	if stub.requests() == 0 {
		result.problem("Claude Code never reached the local Messages stub: %v %s", runErr, strings.TrimSpace(truncate(output.String(), 400)))
		return nil
	}
	result.evidence("Claude Code sent %d Messages requests to the local stub", stub.requests())
	find := lo.HookRecords
	if find == nil && strings.TrimSpace(lo.AuditDB) != "" {
		find = func(ctx context.Context, query audit.HookToolInvocationQuery) (audit.HookToolInvocationEvidence, error) {
			return audit.FindHookToolInvocation(ctx, lo.AuditDB, query)
		}
	}
	if find == nil {
		result.problem("no gateway audit database configured; search its event history for the tool.invocation.requested record with tool call id %s to confirm hook contact", toolCallID)
		return nil
	}
	evidence, err := find(ctx, audit.HookToolInvocationQuery{
		Connector: ConnectorClaudeCode, ToolCallID: toolCallID, Since: started, UserID: liveTargetUID(lo),
	})
	switch {
	case err != nil:
		result.problem("read the gateway event history: %v", err)
	case evidence.Matched:
		result.HookContact = "yes"
		result.evidence("the gateway recorded the canary tool call %s from Claude Code for this user", toolCallID)
	case len(evidence.Mismatches) > 0:
		result.HookContact = "no"
		result.problem("the canary tool call %s reached the gateway only as %s; that does not prove DefenseClaw's managed hooks ran for this user", toolCallID, strings.Join(evidence.Mismatches, ", "))
	default:
		result.HookContact = "no"
		result.problem("the gateway did not record the canary tool call %s: Claude Code ran without DefenseClaw's managed hooks (a higher-precedence source such as server-managed settings may be shadowing them), or tool.activity log collection is off", toolCallID)
	}
	return nil
}

// canaryToolCallID is the tool_use id the stub gives the canary call; Claude
// Code passes it to the PreToolUse hook as tool_use_id.
func canaryToolCallID(nonce string) string {
	return "toolu_" + strings.ReplaceAll(nonce, "-", "_")
}

// liveTargetUID is the target's decimal POSIX uid, which hooks report as
// user.id; empty skips the user check (Windows hooks report a SID).
func liveTargetUID(lo LiveOptions) string {
	if runtimeGOOS() == "windows" || lo.UID < 0 {
		return ""
	}
	return strconv.Itoa(lo.UID)
}

type messagesStub struct {
	server *http.Server
	addr   string
	mu     sync.Mutex
	count  int
}

func (s *messagesStub) requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func (s *messagesStub) Close() { _ = s.server.Close() }

func startMessagesStub(nonce, toolCallID string) (*messagesStub, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	stub := &messagesStub{addr: listener.Addr().String()}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		stub.mu.Lock()
		stub.count++
		first := stub.count == 1
		stub.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if first && !bytes.Contains(body, []byte(`"tool_result"`)) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "msg_canary_1", "type": "message", "role": "assistant", "model": "claude-canary",
				"content": []any{map[string]any{
					"type": "tool_use", "id": toolCallID, "name": "Bash",
					"input": map[string]any{"command": "echo " + nonce, "description": "DefenseClaw live policy check"},
				}},
				"stop_reason": "tool_use",
				"usage":       map[string]int{"input_tokens": 1, "output_tokens": 1},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_canary_2", "type": "message", "role": "assistant", "model": "claude-canary",
			"content":     []any{map[string]any{"type": "text", "text": "done"}},
			"stop_reason": "end_turn",
			"usage":       map[string]int{"input_tokens": 1, "output_tokens": 1},
		})
	})
	stub.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = stub.server.Serve(listener) }()
	return stub, nil
}
