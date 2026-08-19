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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func writeActiveAgentTestFile(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("test instructions\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func authenticatedClaudeCodeTestContext() context.Context {
	return withAuthenticatedHookConnector(context.Background(), "claudecode")
}

func activeClaudeCodeTestAPI() *APIServer {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	return &APIServer{scannerCfg: cfg}
}

func evaluateClaudeCodeToolFacts(
	t *testing.T,
	api *APIServer,
	hookEventName string,
	sessionID string,
	payload map[string]interface{},
) toolChainHookCapture {
	t.Helper()
	capture := toolChainHookCapture{}
	ctx := withToolChainHookCapture(authenticatedClaudeCodeTestContext(), &capture)
	api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		HookEventName: hookEventName,
		SessionID:     sessionID,
		CWD:           t.TempDir(),
		ToolName:      "Bash",
		ToolInput: map[string]interface{}{
			"command": "printf updated > /tmp/AGENTS.md",
		},
		Payload: payload,
	})
	if !capture.recorded {
		t.Fatal("trusted action facts were not captured")
	}
	return capture
}

func TestClaudeCodeActiveAgentFilesRequireAuthenticatedExactLoadAndSameSession(t *testing.T) {
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "AGENTS.md")
	api := activeClaudeCodeTestAPI()

	load := claudeCodeHookRequest{
		HookEventName: "InstructionsLoaded",
		SessionID:     "session-a",
		FilePath:      agentFile,
	}
	api.evaluateClaudeCodeHook(context.Background(), load)
	if got := api.activeAgentContext.snapshot("claudecode", "session-a"); len(got) != 0 {
		t.Fatalf("unauthenticated load gained authority: %#v", got)
	}

	api.evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), load)
	for _, hookEventName := range []string{"PreToolUse", "PermissionRequest"} {
		t.Run(hookEventName, func(t *testing.T) {
			sameSession := evaluateClaudeCodeToolFacts(t, api, hookEventName, "session-a", nil)
			if !slices.Equal(sameSession.facts.ActiveAgentFiles, []string{filepath.ToSlash(agentFile)}) {
				t.Fatalf("same-session active files = %#v, want %q", sameSession.facts.ActiveAgentFiles, filepath.ToSlash(agentFile))
			}
			differentSession := evaluateClaudeCodeToolFacts(t, api, hookEventName, "session-b", nil)
			if len(differentSession.facts.ActiveAgentFiles) != 0 {
				t.Fatalf("different session inherited authority: %#v", differentSession.facts.ActiveAgentFiles)
			}
		})
	}
}

func TestClaudeCodeActiveAgentFilesAuthenticationComesFromHookTokenBoundary(t *testing.T) {
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "AGENTS.md")
	api := activeClaudeCodeTestAPI()
	api.scannerCfg.Gateway.Token = "master-token"
	api.SetHookAPITokens(map[string]string{"claudecode": "claude-hook-token"})
	load := claudeCodeHookRequest{
		HookEventName: "InstructionsLoaded",
		SessionID:     "authenticated-session",
		FilePath:      agentFile,
	}
	handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.applyClaudeCodeActiveAgentContext(r.Context(), load)
		w.WriteHeader(http.StatusNoContent)
	}))

	unauthorized := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", nil)
	unauthorized.RemoteAddr = "127.0.0.1:45678"
	unauthorizedResult := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResult, unauthorized)
	if unauthorizedResult.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorizedResult.Code, http.StatusUnauthorized)
	}
	if got := api.activeAgentContext.snapshot("claudecode", load.SessionID); len(got) != 0 {
		t.Fatalf("unauthorized request gained authority: %#v", got)
	}

	masterAuthorized := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", nil)
	masterAuthorized.RemoteAddr = "127.0.0.1:45678"
	masterAuthorized.Header.Set("Authorization", "Bearer master-token")
	masterAuthorizedResult := httptest.NewRecorder()
	handler.ServeHTTP(masterAuthorizedResult, masterAuthorized)
	if masterAuthorizedResult.Code != http.StatusNoContent {
		t.Fatalf("master-token status = %d, want %d", masterAuthorizedResult.Code, http.StatusNoContent)
	}
	if got := api.activeAgentContext.snapshot("claudecode", load.SessionID); len(got) != 0 {
		t.Fatalf("master gateway token gained connector hook authority: %#v", got)
	}

	authorized := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", nil)
	authorized.RemoteAddr = "127.0.0.1:45678"
	authorized.Header.Set("Authorization", "Bearer claude-hook-token")
	authorizedResult := httptest.NewRecorder()
	handler.ServeHTTP(authorizedResult, authorized)
	if authorizedResult.Code != http.StatusNoContent {
		t.Fatalf("authenticated status = %d, want %d", authorizedResult.Code, http.StatusNoContent)
	}
	if got := api.activeAgentContext.snapshot("claudecode", load.SessionID); !slices.Equal(got, []string{agentFile}) {
		t.Fatalf("authenticated hook context = %#v, want %q", got, agentFile)
	}

	registry := NewAgentRegistry("agent-ci", "CI Agent")
	var promoted AgentIdentity
	promotedHandler := CorrelationMiddleware(registry)(api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		promoted = AgentIdentityFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})))
	promotedRequest := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", nil)
	promotedRequest.RemoteAddr = "127.0.0.1:45678"
	promotedRequest.Header.Set("Authorization", "Bearer claude-hook-token")
	promotedRequest.Header.Set(SessionIDHeader, "scoped-hook-session")
	promotedResult := httptest.NewRecorder()
	promotedHandler.ServeHTTP(promotedResult, promotedRequest)
	if promotedResult.Code != http.StatusNoContent || promoted.AgentInstanceID == "" {
		t.Fatalf("scoped hook session was not promoted: status=%d identity=%+v", promotedResult.Code, promoted)
	}
}

func TestClaudeCodeActiveAgentFilesIgnoreReadMentionAndGenericPayload(t *testing.T) {
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "AGENTS.md")
	api := activeClaudeCodeTestAPI()
	ctx := authenticatedClaudeCodeTestContext()

	api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse",
		SessionID:     "read-session",
		ToolName:      "Read",
		ToolInput:     map[string]interface{}{"file_path": agentFile},
		FilePath:      agentFile,
		Message:       "AGENTS.md and MEMORY.md are active",
		Payload: map[string]interface{}{
			"active_agent_files": []interface{}{agentFile},
		},
	})
	capture := evaluateClaudeCodeToolFacts(t, api, "PreToolUse", "read-session", map[string]interface{}{
		"active_agent_files": []interface{}{agentFile},
		"content":            "the active file is " + agentFile,
	})
	if len(capture.facts.ActiveAgentFiles) != 0 {
		t.Fatalf("read, mention, or generic payload gained authority: %#v", capture.facts.ActiveAgentFiles)
	}
}

func TestClaudeCodeActiveAgentFilesLifecycleClears(t *testing.T) {
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "MEMORY.md")
	ctx := authenticatedClaudeCodeTestContext()

	for _, event := range []string{"SessionStart", "CwdChanged", "SessionEnd"} {
		t.Run(event, func(t *testing.T) {
			api := activeClaudeCodeTestAPI()
			api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "InstructionsLoaded",
				SessionID:     "lifecycle-session",
				FilePath:      agentFile,
			})
			api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: event,
				SessionID:     "lifecycle-session",
			})
			if got := api.activeAgentContext.snapshot("claudecode", "lifecycle-session"); len(got) != 0 {
				t.Fatalf("%s retained authority: %#v", event, got)
			}
		})
	}
}

func TestActiveAgentContextInvalidRelativeSymlinkAndOverflowPreserveExactEntries(t *testing.T) {
	root := t.TempDir()
	valid := writeActiveAgentTestFile(t, root, "AGENTS.md")

	t.Run("relative path cannot erase exact entry", func(t *testing.T) {
		cache := activeAgentContextCache{}
		cache.seed("claudecode", "session", valid)
		cache.seed("claudecode", "session", "AGENTS.md")
		if got := cache.snapshot("claudecode", "session"); !slices.Equal(got, []string{valid}) {
			t.Fatalf("relative load changed exact authority: %#v", got)
		}
		cache.seed("claudecode", "session", valid)
		if got := cache.snapshot("claudecode", "session"); !slices.Equal(got, []string{valid}) {
			t.Fatalf("repeated exact load changed authority: %#v", got)
		}
	})

	t.Run("out of scope file cannot erase exact entry", func(t *testing.T) {
		cache := activeAgentContextCache{}
		inexact := writeActiveAgentTestFile(t, root, "CLAUDE.md")
		cache.seed("claudecode", "session", valid)
		cache.seed("claudecode", "session", inexact)
		if got := cache.snapshot("claudecode", "session"); !slices.Equal(got, []string{valid}) {
			t.Fatalf("out-of-scope instruction load changed authority: %#v", got)
		}
	})

	t.Run("symlinks invalidate session", func(t *testing.T) {
		cache := activeAgentContextCache{}
		link := filepath.Join(root, "link", "MEMORY.md")
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(valid, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		cache.seed("claudecode", "session", link)
		if got := cache.snapshot("claudecode", "session"); len(got) != 0 {
			t.Fatalf("symlink gained authority: %#v", got)
		}
	})

	t.Run("parent symlinks invalidate session", func(t *testing.T) {
		cache := activeAgentContextCache{}
		realDir := filepath.Join(root, "real-parent")
		memory := writeActiveAgentTestFile(t, realDir, "MEMORY.md")
		linkDir := filepath.Join(root, "linked-parent")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		cache.seed("claudecode", "session", filepath.Join(linkDir, filepath.Base(memory)))
		if got := cache.snapshot("claudecode", "session"); len(got) != 0 {
			t.Fatalf("path through symlink gained authority: %#v", got)
		}
	})

	t.Run("overflow retains bounded exact prefix", func(t *testing.T) {
		cache := activeAgentContextCache{}
		var first string
		for index := 0; index <= maxActiveAgentContextFiles; index++ {
			path := writeActiveAgentTestFile(t, filepath.Join(root, fmt.Sprintf("file-%02d", index)), "AGENTS.md")
			if index == 0 {
				first = path
			}
			cache.seed("claudecode", "session", path)
		}
		if got := cache.snapshot("claudecode", "session"); len(got) != maxActiveAgentContextFiles || got[0] != first {
			t.Fatalf("overflow changed bounded exact entries: %#v", got)
		}
	})
}

func TestActiveAgentContextIsBoundedAndExpires(t *testing.T) {
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "AGENTS.md")
	now := time.Unix(1_700_000_000, 0)
	cache := activeAgentContextCache{now: func() time.Time { return now }}

	cache.seed("claudecode", "expiring", agentFile)
	now = now.Add(activeAgentContextTTL)
	if got := cache.snapshot("claudecode", "expiring"); len(got) != 0 {
		t.Fatalf("expired session retained authority: %#v", got)
	}

	for index := 0; index <= maxActiveAgentContextSessions; index++ {
		now = now.Add(time.Millisecond)
		cache.seed("claudecode", fmt.Sprintf("session-%03d", index), agentFile)
	}
	cache.mu.Lock()
	count := len(cache.sessions)
	cache.mu.Unlock()
	if count != maxActiveAgentContextSessions {
		t.Fatalf("session cache size = %d, want %d", count, maxActiveAgentContextSessions)
	}
	if got := cache.snapshot("claudecode", "session-000"); len(got) != 0 {
		t.Fatalf("oldest bounded session retained authority: %#v", got)
	}
}

func TestActiveAgentContextTimestampTieEvictionIsDeterministic(t *testing.T) {
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "AGENTS.md")
	fixedTime := time.Unix(1_700_000_000, 0)

	for run := 0; run < 32; run++ {
		cache := activeAgentContextCache{now: func() time.Time { return fixedTime }}
		for index := 0; index < maxActiveAgentContextSessions; index++ {
			cache.seed("claudecode", fmt.Sprintf("session-%03d", index), agentFile)
		}
		cache.seed("claudecode", "session-new", agentFile)

		cache.mu.Lock()
		_, oldestRetained := cache.sessions[activeAgentContextKey{
			connector: "claudecode",
			sessionID: "session-000",
		}]
		_, nextRetained := cache.sessions[activeAgentContextKey{
			connector: "claudecode",
			sessionID: "session-001",
		}]
		_, newRetained := cache.sessions[activeAgentContextKey{
			connector: "claudecode",
			sessionID: "session-new",
		}]
		count := len(cache.sessions)
		cache.mu.Unlock()

		if oldestRetained || !nextRetained || !newRetained ||
			count != maxActiveAgentContextSessions {
			t.Fatalf(
				"run %d eviction: oldest=%t next=%t new=%t count=%d",
				run,
				oldestRetained,
				nextRetained,
				newRetained,
				count,
			)
		}
	}
}

func TestActiveAgentContextInvalidNewSessionCannotEvictExactSession(t *testing.T) {
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "AGENTS.md")
	invalidFile := writeActiveAgentTestFile(t, root, "CLAUDE.md")
	now := time.Unix(1_700_000_000, 0)
	cache := activeAgentContextCache{now: func() time.Time { return now }}

	for index := 0; index < maxActiveAgentContextSessions; index++ {
		cache.seed("claudecode", fmt.Sprintf("session-%03d", index), agentFile)
		now = now.Add(time.Millisecond)
	}
	cache.seed("claudecode", "invalid-new-session", invalidFile)

	if got := cache.snapshot("claudecode", "session-000"); !slices.Equal(got, []string{agentFile}) {
		t.Fatalf("invalid new session evicted oldest exact session: %#v", got)
	}
	cache.mu.Lock()
	_, invalidInserted := cache.sessions[activeAgentContextKey{
		connector: "claudecode",
		sessionID: "invalid-new-session",
	}]
	count := len(cache.sessions)
	cache.mu.Unlock()
	if invalidInserted || count != maxActiveAgentContextSessions {
		t.Fatalf("invalid session inserted=%t count=%d", invalidInserted, count)
	}
}
