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

func TestActiveAgentContextCachesNativePOSIXCaseSemanticsAtLoad(t *testing.T) {
	if filepath.Separator != '/' {
		t.Skip("POSIX case semantics are covered on POSIX hosts")
	}
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "AGENTS.md")
	canonical, caseInsensitive, valid := exactActiveAgentFile(agentFile)
	if !valid || canonical != agentFile {
		t.Fatalf("exact active file = %q, valid=%t; want %q", canonical, valid, agentFile)
	}
	aliasInfo, aliasErr := os.Lstat(filepath.Join(root, "agents.md"))
	activeInfo, activeErr := os.Lstat(agentFile)
	wantCaseInsensitive := aliasErr == nil && activeErr == nil &&
		os.SameFile(activeInfo, aliasInfo)
	if caseInsensitive != wantCaseInsensitive {
		t.Fatalf(
			"cached case-insensitive identity = %t, native alias=%t",
			caseInsensitive,
			wantCaseInsensitive,
		)
	}

	cache := activeAgentContextCache{}
	cache.seed("claudecode", "session", agentFile)
	snapshot := cache.snapshot("claudecode", "session")
	wantMetadata := []string(nil)
	if wantCaseInsensitive {
		wantMetadata = []string{agentFile}
	}
	if !slices.Equal(snapshot.caseInsensitiveFiles, wantMetadata) {
		t.Fatalf(
			"cached case metadata = %#v, want %#v",
			snapshot.caseInsensitiveFiles,
			wantMetadata,
		)
	}
	if err := os.Remove(agentFile); err != nil {
		t.Fatal(err)
	}
	if afterRemoval := cache.snapshot("claudecode", "session"); !slices.Equal(
		afterRemoval.caseInsensitiveFiles,
		wantMetadata,
	) {
		t.Fatalf("snapshot re-read filesystem after load: %#v", afterRemoval)
	}
}

func TestActiveAgentContextAcceptsNativeCaseAliasesAtLoad(t *testing.T) {
	for _, test := range []struct {
		canonical string
		alias     string
	}{
		{canonical: "AGENTS.md", alias: "agents.md"},
		{canonical: "MEMORY.md", alias: "memory.md"},
	} {
		t.Run(test.canonical, func(t *testing.T) {
			root := t.TempDir()
			canonicalPath := writeActiveAgentTestFile(t, root, test.canonical)
			aliasPath := filepath.Join(filepath.Dir(canonicalPath), test.alias)
			canonicalInfo, canonicalErr := os.Lstat(canonicalPath)
			aliasInfo, aliasErr := os.Lstat(aliasPath)
			if canonicalErr != nil {
				t.Fatal(canonicalErr)
			}
			if aliasErr != nil {
				if !os.IsNotExist(aliasErr) {
					t.Fatal(aliasErr)
				}
				t.Skip("native filesystem is case-sensitive")
			}
			if !os.SameFile(canonicalInfo, aliasInfo) {
				t.Skip("native filesystem is case-sensitive")
			}

			canonical, caseInsensitive, valid := exactActiveAgentFile(aliasPath)
			if !valid || canonical != canonicalPath {
				t.Fatalf(
					"case alias = (%q, %t, %t), want (%q, _, true)",
					canonical,
					caseInsensitive,
					valid,
					canonicalPath,
				)
			}
			if filepath.Separator == '/' && !caseInsensitive {
				t.Fatal("POSIX case alias did not retain native case proof")
			}
			if filepath.Separator != '/' && caseInsensitive {
				t.Fatal("Windows case alias unexpectedly produced POSIX case metadata")
			}

			cache := activeAgentContextCache{}
			cache.seed("claudecode", "case-alias-session", aliasPath)
			snapshot := cache.snapshot("claudecode", "case-alias-session")
			if !slices.Equal(snapshot.files, []string{canonicalPath}) {
				t.Fatalf("case alias cached as %#v, want %q", snapshot.files, canonicalPath)
			}
		})
	}
}

func TestActiveAgentContextRejectsUnrelatedLowercaseFileOnCaseSensitivePOSIX(t *testing.T) {
	if filepath.Separator != '/' {
		t.Skip("POSIX case-sensitive behavior is covered on POSIX hosts")
	}
	root := t.TempDir()
	canonicalPath := writeActiveAgentTestFile(t, root, "AGENTS.md")
	aliasPath := filepath.Join(root, "agents.md")
	if aliasInfo, err := os.Lstat(aliasPath); err == nil {
		canonicalInfo, canonicalErr := os.Lstat(canonicalPath)
		if canonicalErr != nil {
			t.Fatal(canonicalErr)
		}
		if os.SameFile(canonicalInfo, aliasInfo) {
			t.Skip("native filesystem is case-insensitive")
		}
		t.Fatal("unexpected pre-existing lowercase entry")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(aliasPath, []byte("unrelated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if canonical, caseInsensitive, valid := exactActiveAgentFile(canonicalPath); !valid || canonical != canonicalPath || caseInsensitive {
		t.Fatalf(
			"exact file beside unrelated lowercase entry = (%q, %t, %t)",
			canonical,
			caseInsensitive,
			valid,
		)
	}

	if canonical, caseInsensitive, valid := exactActiveAgentFile(aliasPath); valid {
		t.Fatalf(
			"unrelated lowercase file = (%q, %t, %t), want invalid",
			canonical,
			caseInsensitive,
			valid,
		)
	}
	cache := activeAgentContextCache{}
	cache.seed("claudecode", "case-sensitive-session", aliasPath)
	if got := cache.snapshot("claudecode", "case-sensitive-session"); len(got.files) != 0 || len(got.caseInsensitiveFiles) != 0 ||
		got.uncertain || got.caseInsensitiveUncertain {
		t.Fatalf("unrelated lowercase file context = %#v", got)
	}
}

func TestClaudeCodeLowercaseInstructionsLoadedUsesCanonicalActiveFile(t *testing.T) {
	root := t.TempDir()
	canonicalPath := writeActiveAgentTestFile(t, root, "AGENTS.md")
	aliasPath := filepath.Join(filepath.Dir(canonicalPath), "agents.md")
	canonicalInfo, canonicalErr := os.Lstat(canonicalPath)
	aliasInfo, aliasErr := os.Lstat(aliasPath)
	if canonicalErr != nil {
		t.Fatal(canonicalErr)
	}
	if aliasErr != nil {
		if !os.IsNotExist(aliasErr) {
			t.Fatal(aliasErr)
		}
		t.Skip("native filesystem is case-sensitive")
	}
	if !os.SameFile(canonicalInfo, aliasInfo) {
		t.Skip("native filesystem is case-sensitive")
	}

	installDefaultProfileConnector(t, "claudecode")
	api := activeClaudeCodeTestAPI()
	api.evaluateClaudeCodeHook(
		authenticatedClaudeCodeTestContext(),
		claudeCodeHookRequest{
			HookEventName: "InstructionsLoaded",
			SessionID:     "lowercase-load-session",
			FilePath:      aliasPath,
		},
	)
	snapshot := api.activeAgentContext.snapshot(
		"claudecode",
		"lowercase-load-session",
	)
	if !slices.Equal(snapshot.files, []string{canonicalPath}) {
		t.Fatalf("lowercase load cached %#v, want %q", snapshot.files, canonicalPath)
	}

	mutation := evaluateClaudeCodeToolFacts(
		t,
		api,
		"PreToolUse",
		"lowercase-load-session",
		nil,
		"Write",
		map[string]interface{}{"file_path": aliasPath},
	)
	if finding := findingWithID(mutation.findings, "COG-AGENTS-MD"); finding == nil || !finding.contributesToEnforcement() {
		t.Fatalf("lowercase active-file mutation finding = %+v", finding)
	}
}

func TestActiveAgentContextReseedClearsStaleCaseProof(t *testing.T) {
	cache := activeAgentContextCache{}
	key := activeAgentContextKey{connector: "claudecode", sessionID: "session"}
	const activePath = "/repo/AGENTS.md"
	cache.seedLoadedFile(key, activePath, true, time.Unix(1, 0))
	if got := cache.snapshot("claudecode", "session"); !slices.Equal(
		got.caseInsensitiveFiles,
		[]string{activePath},
	) {
		t.Fatalf("initial case proof = %#v, want %q", got, activePath)
	}

	cache.seedLoadedFile(key, activePath, false, time.Unix(2, 0))
	if got := cache.snapshot("claudecode", "session"); len(
		got.caseInsensitiveFiles,
	) != 0 {
		t.Fatalf("reseed retained stale case proof: %#v", got)
	}
}

func TestActiveAgentContextOverflowCarriesOnlyProvenLostCaseSemantics(t *testing.T) {
	for _, test := range []struct {
		name                string
		lostCaseInsensitive bool
	}{
		{name: "case-sensitive lost file"},
		{name: "case-insensitive lost file", lostCaseInsensitive: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := activeAgentContextCache{}
			key := activeAgentContextKey{
				connector: "claudecode",
				sessionID: "overflow-session",
			}
			for index := 0; index < maxActiveAgentContextFiles; index++ {
				cache.seedLoadedFile(
					key,
					fmt.Sprintf("/repo/retained-%02d/AGENTS.md", index),
					index == 0,
					time.Unix(int64(index+1), 0),
				)
			}
			cache.seedLoadedFile(
				key,
				"/repo/lost/AGENTS.md",
				test.lostCaseInsensitive,
				time.Unix(maxActiveAgentContextFiles+1, 0),
			)

			snapshot := cache.snapshot("claudecode", "overflow-session")
			if len(snapshot.files) != maxActiveAgentContextFiles ||
				!snapshot.uncertain ||
				snapshot.caseInsensitiveUncertain != test.lostCaseInsensitive ||
				len(snapshot.caseInsensitiveFiles) != 1 {
				t.Fatalf("overflow snapshot = %#v", snapshot)
			}

			cache.begin("claudecode", "overflow-session")
			reset := cache.snapshot("claudecode", "overflow-session")
			if len(reset.files) != 0 || len(reset.caseInsensitiveFiles) != 0 ||
				reset.uncertain || reset.caseInsensitiveUncertain {
				t.Fatalf("lifecycle reset retained overflow authority: %#v", reset)
			}
		})
	}
}

func TestActiveAgentContextEvictionCarriesOnlyActualAuthority(t *testing.T) {
	nextTime := int64(0)
	cache := activeAgentContextCache{now: func() time.Time {
		nextTime++
		return time.Unix(nextTime, 0)
	}}
	const (
		emptySession           = "session-empty"
		caseSensitiveSession   = "session-case-sensitive"
		caseInsensitiveSession = "session-case-insensitive"
	)
	cache.begin("claudecode", emptySession)
	cache.seedLoadedFile(
		activeAgentContextKey{connector: "claudecode", sessionID: caseSensitiveSession},
		"/repo/case-sensitive/AGENTS.md",
		false,
		cache.currentTime(),
	)
	cache.seedLoadedFile(
		activeAgentContextKey{connector: "claudecode", sessionID: caseInsensitiveSession},
		"/repo/case-insensitive/AGENTS.md",
		true,
		cache.currentTime(),
	)
	for index := 3; index < maxActiveAgentContextSessions; index++ {
		cache.begin("claudecode", fmt.Sprintf("session-filler-%03d", index))
	}

	cache.begin("claudecode", "session-new-1")
	emptyEvicted := cache.snapshot("claudecode", emptySession)
	if len(emptyEvicted.files) != 0 || emptyEvicted.uncertain ||
		emptyEvicted.caseInsensitiveUncertain {
		t.Fatalf("known-empty eviction poisoned global context: %#v", emptyEvicted)
	}

	cache.begin("claudecode", "session-new-2")
	caseSensitiveEvicted := cache.snapshot("claudecode", caseSensitiveSession)
	if !caseSensitiveEvicted.uncertain ||
		caseSensitiveEvicted.caseInsensitiveUncertain {
		t.Fatalf("case-sensitive eviction = %#v", caseSensitiveEvicted)
	}
	unrelated := cache.snapshot("claudecode", "unrelated-session")
	if unrelated.uncertain || unrelated.caseInsensitiveUncertain {
		t.Fatalf("unrelated session inherited eviction uncertainty: %#v", unrelated)
	}
	cache.end("claudecode", caseSensitiveSession)
	ended := cache.snapshot("claudecode", caseSensitiveSession)
	if ended.uncertain || ended.caseInsensitiveUncertain {
		t.Fatalf("SessionEnd retained evicted uncertainty: %#v", ended)
	}

	cache.begin("claudecode", "session-new-3")
	caseInsensitiveEvicted := cache.snapshot("claudecode", caseInsensitiveSession)
	if !caseInsensitiveEvicted.uncertain ||
		!caseInsensitiveEvicted.caseInsensitiveUncertain {
		t.Fatalf("case-insensitive eviction = %#v", caseInsensitiveEvicted)
	}

	cache.begin("claudecode", caseInsensitiveSession)
	reset := cache.snapshot("claudecode", caseInsensitiveSession)
	if len(reset.files) != 0 || reset.uncertain ||
		reset.caseInsensitiveUncertain {
		t.Fatalf("lifecycle reset inherited global uncertainty: %#v", reset)
	}
}

func TestActiveAgentContextDoesNotTreatHardLinkAsCaseInsensitiveVolume(t *testing.T) {
	if filepath.Separator != '/' {
		t.Skip("POSIX case semantics are covered on POSIX hosts")
	}
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "AGENTS.md")
	alias := filepath.Join(root, "agents.md")
	if _, err := os.Lstat(alias); err == nil {
		t.Skip("native case-insensitive volume cannot create a casing hard link")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Link(agentFile, alias); err != nil {
		t.Skipf("hard links are unavailable: %v", err)
	}
	_, caseInsensitive, valid := exactActiveAgentFile(agentFile)
	if !valid || caseInsensitive {
		t.Fatalf(
			"hard-link identity marked volume case-insensitive: valid=%t caseInsensitive=%t",
			valid,
			caseInsensitive,
		)
	}
}

func evaluateClaudeCodeToolFacts(
	t *testing.T,
	api *APIServer,
	hookEventName string,
	sessionID string,
	payload map[string]interface{},
	toolName string,
	toolInput map[string]interface{},
) toolChainHookCapture {
	t.Helper()
	capture := toolChainHookCapture{}
	ctx := withToolChainHookCapture(authenticatedClaudeCodeTestContext(), &capture)
	api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		HookEventName: hookEventName,
		SessionID:     sessionID,
		CWD:           t.TempDir(),
		ToolName:      toolName,
		ToolInput:     toolInput,
		Payload:       payload,
	})
	if !capture.recorded {
		t.Fatal("trusted action facts were not captured")
	}
	return capture
}

func TestClaudeCodeActiveAgentFilesRequireAuthenticatedExactLoadAndSameSession(t *testing.T) {
	installDefaultProfileConnector(t, "claudecode")
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "AGENTS.md")
	api := activeClaudeCodeTestAPI()
	now := time.Unix(1_700_000_000, 0)
	api.activeAgentContext.now = func() time.Time { return now }

	load := claudeCodeHookRequest{
		HookEventName: "InstructionsLoaded",
		SessionID:     "session-a",
		FilePath:      agentFile,
	}
	api.evaluateClaudeCodeHook(context.Background(), load)
	if got := api.activeAgentContext.snapshot("claudecode", "session-a"); len(got.files) != 0 || got.uncertain {
		t.Fatalf("unauthenticated load gained authority: %#v", got)
	}

	api.evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), load)
	loadedContext := api.activeAgentContext.snapshot("claudecode", "session-a")
	now = now.Add(24 * time.Hour)
	mutation := map[string]interface{}{
		"file_path": agentFile,
		"content":   "updated",
	}
	for _, hookEventName := range []string{"PreToolUse", "PermissionRequest"} {
		t.Run(hookEventName, func(t *testing.T) {
			sameSession := evaluateClaudeCodeToolFacts(t, api, hookEventName, "session-a", nil, "Write", mutation)
			if !slices.Equal(sameSession.facts.ActiveAgentFiles, []string{filepath.ToSlash(agentFile)}) {
				t.Fatalf("same-session active files = %#v, want %q", sameSession.facts.ActiveAgentFiles, filepath.ToSlash(agentFile))
			}
			if !slices.Equal(
				sameSession.facts.ActiveAgentFilesCaseInsensitive,
				loadedContext.caseInsensitiveFiles,
			) {
				t.Fatalf(
					"same-session case metadata = %#v, want %#v",
					sameSession.facts.ActiveAgentFilesCaseInsensitive,
					loadedContext.caseInsensitiveFiles,
				)
			}
			if sameSession.facts.ActiveAgentFilesUncertain {
				t.Fatal("idle exact session became uncertain without a lifecycle reset")
			}
			if finding := findingWithID(sameSession.findings, "COG-AGENTS-MD"); finding == nil || !finding.contributesToEnforcement() {
				t.Fatalf("idle active-file mutation was not enforceable: %+v", sameSession.findings)
			}
			differentSession := evaluateClaudeCodeToolFacts(t, api, hookEventName, "session-b", nil, "Write", mutation)
			if len(differentSession.facts.ActiveAgentFiles) != 0 {
				t.Fatalf("different session inherited authority: %#v", differentSession.facts.ActiveAgentFiles)
			}
			if finding := findingWithID(differentSession.findings, "COG-AGENTS-MD"); finding != nil {
				t.Fatalf("known-absent context used a filename heuristic: %+v", differentSession.findings)
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
	if got := api.activeAgentContext.snapshot("claudecode", load.SessionID); len(got.files) != 0 {
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
	if got := api.activeAgentContext.snapshot("claudecode", load.SessionID); len(got.files) != 0 {
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
	if got := api.activeAgentContext.snapshot("claudecode", load.SessionID); !slices.Equal(got.files, []string{agentFile}) || got.uncertain {
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
	}, "Read", map[string]interface{}{"file_path": agentFile})
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
			if got := api.activeAgentContext.snapshot("claudecode", "lifecycle-session"); len(got.files) != 0 {
				t.Fatalf("%s retained authority: %#v", event, got)
			}
		})
	}
}

func TestActiveAgentContextInvalidRelativeSymlinkAndOverflowPreserveExactEntries(t *testing.T) {
	installDefaultProfileConnector(t, "claudecode")
	root := t.TempDir()
	valid := writeActiveAgentTestFile(t, root, "AGENTS.md")
	assertIdentityFailureFailsClosed := func(
		t *testing.T,
		filePath string,
		ruleID string,
		retainExact bool,
	) {
		t.Helper()
		const sessionID = "identity-failure-session"
		api := activeClaudeCodeTestAPI()
		ctx := authenticatedClaudeCodeTestContext()
		var wantFiles []string
		if retainExact {
			api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "InstructionsLoaded",
				SessionID:     sessionID,
				FilePath:      valid,
			})
			wantFiles = []string{valid}
		}
		api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "InstructionsLoaded",
			SessionID:     sessionID,
			FilePath:      filePath,
		})
		if got := api.activeAgentContext.snapshot("claudecode", sessionID); !slices.Equal(got.files, wantFiles) || !got.uncertain ||
			got.caseInsensitiveUncertain {
			t.Fatalf("unprovable load context = %#v", got)
		}
		mutation := evaluateClaudeCodeToolFacts(
			t,
			api,
			"PreToolUse",
			sessionID,
			nil,
			"Write",
			map[string]interface{}{
				"file_path": filePath,
				"content":   "updated",
			},
		)
		finding := findingWithID(mutation.findings, ruleID)
		if finding == nil || !finding.contributesToEnforcement() {
			t.Fatalf("unprovable active-file mutation finding = %+v", finding)
		}
	}

	t.Run("relative path cannot erase exact entry", func(t *testing.T) {
		cache := activeAgentContextCache{}
		cache.seed("claudecode", "session", valid)
		cache.seed("claudecode", "session", "AGENTS.md")
		if got := cache.snapshot("claudecode", "session"); !slices.Equal(got.files, []string{valid}) || got.uncertain {
			t.Fatalf("relative load changed exact authority: %#v", got)
		}
		cache.seed("claudecode", "session", valid)
		if got := cache.snapshot("claudecode", "session"); !slices.Equal(got.files, []string{valid}) {
			t.Fatalf("repeated exact load changed authority: %#v", got)
		}
	})

	t.Run("out of scope file cannot erase exact entry", func(t *testing.T) {
		cache := activeAgentContextCache{}
		inexact := writeActiveAgentTestFile(t, root, "CLAUDE.md")
		cache.seed("claudecode", "session", valid)
		cache.seed("claudecode", "session", inexact)
		if got := cache.snapshot("claudecode", "session"); !slices.Equal(got.files, []string{valid}) || got.uncertain {
			t.Fatalf("out-of-scope instruction load changed authority: %#v", got)
		}
	})

	t.Run("direct symlink marks fresh session uncertain", func(t *testing.T) {
		link := filepath.Join(root, "link", "MEMORY.md")
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(valid, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		assertIdentityFailureFailsClosed(t, link, "COG-MEMORY", false)
	})

	t.Run("parent symlink preserves exact entry and marks uncertainty", func(t *testing.T) {
		realDir := filepath.Join(root, "real-parent")
		memory := writeActiveAgentTestFile(t, realDir, "MEMORY.md")
		linkDir := filepath.Join(root, "linked-parent")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		assertIdentityFailureFailsClosed(
			t,
			filepath.Join(linkDir, filepath.Base(memory)),
			"COG-MEMORY",
			true,
		)
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
		if got := cache.snapshot("claudecode", "session"); len(got.files) != maxActiveAgentContextFiles || got.files[0] != first || !got.uncertain {
			t.Fatalf("overflow changed bounded exact entries: %#v", got)
		}
	})
}

func TestActiveAgentContextIsBoundedAndRetainsIdleSessions(t *testing.T) {
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "AGENTS.md")
	now := time.Unix(1_700_000_000, 0)
	cache := activeAgentContextCache{now: func() time.Time { return now }}

	cache.seed("claudecode", "idle", agentFile)
	now = now.Add(24 * time.Hour)
	if got := cache.snapshot("claudecode", "idle"); !slices.Equal(got.files, []string{agentFile}) || got.uncertain {
		t.Fatalf("idle session lost authority without a lifecycle reset: %#v", got)
	}

	cache = activeAgentContextCache{now: func() time.Time { return now }}
	for index := 0; index <= maxActiveAgentContextSessions; index++ {
		now = now.Add(time.Millisecond)
		cache.seed("claudecode", fmt.Sprintf("session-%03d", index), agentFile)
	}
	cache.mu.Lock()
	count := len(cache.sessions)
	evictionCount := len(cache.evictions)
	cache.mu.Unlock()
	if count != maxActiveAgentContextSessions {
		t.Fatalf("session cache size = %d, want %d", count, maxActiveAgentContextSessions)
	}
	if evictionCount != 1 {
		t.Fatalf("session eviction index size = %d, want 1", evictionCount)
	}
	if got := cache.snapshot("claudecode", "session-000"); len(got.files) != 0 || !got.uncertain {
		t.Fatalf("evicted session loss was not explicit: %#v", got)
	}
}

func TestActiveAgentContextEvictionIndexIsBoundedAndFailsClosedOnOverflow(t *testing.T) {
	cache := activeAgentContextCache{}
	for index := 0; index < maxActiveAgentContextSessions; index++ {
		cache.seedLoadedFile(
			activeAgentContextKey{
				connector: "claudecode",
				sessionID: fmt.Sprintf("session-%03d", index),
			},
			fmt.Sprintf("/repo/session-%03d/AGENTS.md", index),
			false,
			time.Unix(int64(index+1), 0),
		)
	}
	for index := 0; index < maxActiveAgentContextEvictions; index++ {
		cache.seedLoadedFile(
			activeAgentContextKey{
				connector: "claudecode",
				sessionID: fmt.Sprintf("replacement-%03d", index),
			},
			fmt.Sprintf("/repo/replacement-%03d/AGENTS.md", index),
			index == 0,
			time.Unix(int64(maxActiveAgentContextSessions+index+1), 0),
		)
	}
	cache.seedLoadedFile(
		activeAgentContextKey{connector: "claudecode", sessionID: "overflow"},
		"/repo/overflow/AGENTS.md",
		false,
		time.Unix(2*maxActiveAgentContextSessions+1, 0),
	)

	cache.mu.Lock()
	sessionCount := len(cache.sessions)
	evictionCount := len(cache.evictions)
	cache.mu.Unlock()
	if sessionCount != maxActiveAgentContextSessions ||
		evictionCount != maxActiveAgentContextEvictions {
		t.Fatalf(
			"bounded indexes = sessions:%d evictions:%d, want %d each",
			sessionCount,
			evictionCount,
			maxActiveAgentContextSessions,
		)
	}
	if got := cache.snapshot("claudecode", "missing-after-overflow"); !got.uncertain || !got.caseInsensitiveUncertain {
		t.Fatalf("eviction-index overflow did not preserve lost authority: %#v", got)
	}
}

func TestClaudeCodeActiveAgentContextCapacityLossUsesProvenCaseSemantics(t *testing.T) {
	installDefaultProfileConnector(t, "claudecode")
	root := t.TempDir()
	agentFile := writeActiveAgentTestFile(t, root, "AGENTS.md")
	api := activeClaudeCodeTestAPI()
	fixedTime := time.Unix(1_700_000_000, 0)
	api.activeAgentContext.now = func() time.Time { return fixedTime }

	for index := 0; index < maxActiveAgentContextSessions; index++ {
		api.activeAgentContext.seed(
			"claudecode",
			fmt.Sprintf("session-%03d", index),
			agentFile,
		)
	}
	api.activeAgentContext.seed("claudecode", "session-new", agentFile)

	mutation := map[string]interface{}{
		"file_path": agentFile,
		"content":   "updated",
	}
	mutating := evaluateClaudeCodeToolFacts(
		t,
		api,
		"PreToolUse",
		"session-000",
		nil,
		"Write",
		mutation,
	)
	if len(mutating.facts.ActiveAgentFiles) != 0 ||
		!mutating.facts.ActiveAgentFilesUncertain {
		t.Fatalf("evicted session did not preserve explicit uncertainty: %+v", mutating.facts)
	}
	if finding := findingWithID(mutating.findings, "COG-AGENTS-MD"); finding == nil || !finding.contributesToEnforcement() {
		t.Fatalf("uncertain exact mutation was not enforceable: %+v", mutating.findings)
	}

	aliasPath := filepath.Join(filepath.Dir(agentFile), "agents.md")
	aliasInfo, aliasErr := os.Lstat(aliasPath)
	agentInfo, agentErr := os.Lstat(agentFile)
	wantCaseInsensitiveUncertain := filepath.Separator == '/' &&
		aliasErr == nil && agentErr == nil && os.SameFile(agentInfo, aliasInfo)
	if mutating.facts.ActiveAgentFilesCaseInsensitiveUncertain !=
		wantCaseInsensitiveUncertain {
		t.Fatalf(
			"evicted case uncertainty = %t, want %t",
			mutating.facts.ActiveAgentFilesCaseInsensitiveUncertain,
			wantCaseInsensitiveUncertain,
		)
	}
	foldedMutation := evaluateClaudeCodeToolFacts(
		t,
		api,
		"PreToolUse",
		"session-000",
		nil,
		"Write",
		map[string]interface{}{
			"file_path": aliasPath,
			"content":   "updated",
		},
	)
	foldedFinding := findingWithID(foldedMutation.findings, "COG-AGENTS-MD")
	wantFoldedEnforcement := filepath.Separator != '/' ||
		wantCaseInsensitiveUncertain
	if (foldedFinding != nil && foldedFinding.contributesToEnforcement()) !=
		wantFoldedEnforcement {
		t.Fatalf(
			"uncertain folded finding = %+v, want enforcement=%t",
			foldedFinding,
			wantFoldedEnforcement,
		)
	}

	read := evaluateClaudeCodeToolFacts(
		t,
		api,
		"PreToolUse",
		"session-000",
		nil,
		"Read",
		map[string]interface{}{"file_path": agentFile},
	)
	if finding := findingWithID(read.findings, "COG-AGENTS-MD"); finding != nil {
		t.Fatalf("uncertain context turned an exact read into a mutation: %+v", read.findings)
	}

	ctx := authenticatedClaudeCodeTestContext()
	unrelated := evaluateClaudeCodeToolFacts(
		t,
		api,
		"PreToolUse",
		"unrelated-session",
		nil,
		"Write",
		mutation,
	)
	if unrelated.facts.ActiveAgentFilesUncertain ||
		unrelated.facts.ActiveAgentFilesCaseInsensitiveUncertain {
		t.Fatalf("unrelated session inherited capacity loss: %+v", unrelated.facts)
	}
	if finding := findingWithID(unrelated.findings, "COG-AGENTS-MD"); finding != nil {
		t.Fatalf("unrelated session inherited active-file enforcement: %+v", unrelated.findings)
	}

	api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		HookEventName: "SessionEnd",
		SessionID:     "session-000",
	})
	ended := evaluateClaudeCodeToolFacts(
		t,
		api,
		"PreToolUse",
		"session-000",
		nil,
		"Write",
		mutation,
	)
	if ended.facts.ActiveAgentFilesUncertain ||
		ended.facts.ActiveAgentFilesCaseInsensitiveUncertain {
		t.Fatalf("SessionEnd retained evicted capacity loss: %+v", ended.facts)
	}
	if finding := findingWithID(ended.findings, "COG-AGENTS-MD"); finding != nil {
		t.Fatalf("SessionEnd retained active-file enforcement: %+v", ended.findings)
	}

	api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		HookEventName: "SessionStart",
		SessionID:     "session-000",
	})
	knownEmpty := evaluateClaudeCodeToolFacts(
		t,
		api,
		"PreToolUse",
		"session-000",
		nil,
		"Write",
		mutation,
	)
	if knownEmpty.facts.ActiveAgentFilesUncertain ||
		knownEmpty.facts.ActiveAgentFilesCaseInsensitiveUncertain ||
		len(knownEmpty.facts.ActiveAgentFiles) != 0 {
		t.Fatalf("authenticated session reset did not establish known-empty context: %+v", knownEmpty.facts)
	}
	if finding := findingWithID(knownEmpty.findings, "COG-AGENTS-MD"); finding != nil {
		t.Fatalf("known-empty reset context inherited unrelated saturation: %+v", knownEmpty.findings)
	}

	api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		HookEventName: "InstructionsLoaded",
		SessionID:     "session-000",
		FilePath:      agentFile,
	})
	reloaded := evaluateClaudeCodeToolFacts(
		t,
		api,
		"PermissionRequest",
		"session-000",
		nil,
		"Write",
		mutation,
	)
	if reloaded.facts.ActiveAgentFilesUncertain ||
		reloaded.facts.ActiveAgentFilesCaseInsensitiveUncertain ||
		!slices.Equal(
			reloaded.facts.ActiveAgentFiles,
			[]string{filepath.ToSlash(agentFile)},
		) {
		t.Fatalf("reloaded reset session did not regain exact context: %+v", reloaded.facts)
	}
	if finding := findingWithID(reloaded.findings, "COG-AGENTS-MD"); finding == nil || !finding.contributesToEnforcement() {
		t.Fatalf("reloaded active-file mutation was not enforceable: %+v", reloaded.findings)
	}

	api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		HookEventName: "CwdChanged",
		SessionID:     "session-000",
	})
	changedDirectory := evaluateClaudeCodeToolFacts(
		t,
		api,
		"PreToolUse",
		"session-000",
		nil,
		"Write",
		mutation,
	)
	if changedDirectory.facts.ActiveAgentFilesUncertain ||
		changedDirectory.facts.ActiveAgentFilesCaseInsensitiveUncertain ||
		len(changedDirectory.facts.ActiveAgentFiles) != 0 {
		t.Fatalf("CwdChanged did not establish known-empty context: %+v", changedDirectory.facts)
	}
	if finding := findingWithID(changedDirectory.findings, "COG-AGENTS-MD"); finding != nil {
		t.Fatalf("CwdChanged inherited stale instruction authority: %+v", changedDirectory.findings)
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
		evicted := cache.snapshot("claudecode", "session-000")

		if oldestRetained || !nextRetained || !newRetained ||
			count != maxActiveAgentContextSessions || !evicted.uncertain {
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

	if got := cache.snapshot("claudecode", "session-000"); !slices.Equal(got.files, []string{agentFile}) || got.uncertain {
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
