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
	sessionID string,
	payload map[string]interface{},
) toolChainHookCapture {
	t.Helper()
	capture := toolChainHookCapture{}
	ctx := withToolChainHookCapture(authenticatedClaudeCodeTestContext(), &capture)
	api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse",
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
	sameSession := evaluateClaudeCodeToolFacts(t, api, "session-a", nil)
	if !slices.Equal(sameSession.facts.ActiveAgentFiles, []string{agentFile}) {
		t.Fatalf("same-session active files = %#v, want %q", sameSession.facts.ActiveAgentFiles, agentFile)
	}
	differentSession := evaluateClaudeCodeToolFacts(t, api, "session-b", nil)
	if len(differentSession.facts.ActiveAgentFiles) != 0 {
		t.Fatalf("different session inherited authority: %#v", differentSession.facts.ActiveAgentFiles)
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
	capture := evaluateClaudeCodeToolFacts(t, api, "read-session", map[string]interface{}{
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

func TestActiveAgentContextInvalidRelativeSymlinkAndOverflowFailClosed(t *testing.T) {
	root := t.TempDir()
	valid := writeActiveAgentTestFile(t, root, "AGENTS.md")

	t.Run("relative invalidates session", func(t *testing.T) {
		cache := activeAgentContextCache{}
		cache.seed("claudecode", "session", valid)
		cache.seed("claudecode", "session", "AGENTS.md")
		if got := cache.snapshot("claudecode", "session"); len(got) != 0 {
			t.Fatalf("relative load retained authority: %#v", got)
		}
		cache.seed("claudecode", "session", valid)
		if got := cache.snapshot("claudecode", "session"); len(got) != 0 {
			t.Fatalf("poisoned session regained authority: %#v", got)
		}
	})

	t.Run("inexact file invalidates session", func(t *testing.T) {
		cache := activeAgentContextCache{}
		inexact := writeActiveAgentTestFile(t, root, "CLAUDE.md")
		cache.seed("claudecode", "session", valid)
		cache.seed("claudecode", "session", inexact)
		if got := cache.snapshot("claudecode", "session"); len(got) != 0 {
			t.Fatalf("inexact instruction file retained authority: %#v", got)
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

	t.Run("overflow invalidates session", func(t *testing.T) {
		cache := activeAgentContextCache{}
		for index := 0; index <= maxActiveAgentContextFiles; index++ {
			path := writeActiveAgentTestFile(t, filepath.Join(root, fmt.Sprintf("file-%02d", index)), "AGENTS.md")
			cache.seed("claudecode", "session", path)
		}
		if got := cache.snapshot("claudecode", "session"); len(got) != 0 {
			t.Fatalf("overflow retained partial authority: %#v", got)
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
