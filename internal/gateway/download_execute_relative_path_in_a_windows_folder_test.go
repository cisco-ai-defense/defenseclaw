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

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-6:GAP-0212 (#1390, GAP-0031). Claude Code's Bash tool on Windows
// runs Git Bash in the project's native directory (C:\Users\<u>\proj), so a
// download to page.txt and a later bash ./page.txt name the same file, as on
// Linux. The POSIX reading left a relative operand under a Windows directory
// unresolved, so the chain joined nothing. On a Windows host a relative
// download and run now join each other and the C:/, /c/ spellings of the
// same file; another file, a parent-directory file, another directory, an
// expanding name and a same-call rewrite do not, and off Windows the
// identities are unchanged.
func TestDownloadThenExecuteJoinsRelativePathsUnderAWindowsDirectory(t *testing.T) {
	saved := toolChainDriveMounts
	t.Cleanup(func() { toolChainDriveMounts = saved })
	const url = "https://example.net/"
	const cwd = `C:\Users\dcw-fxw2\proj`
	downloads := []string{"page.txt", "./page.txt", "C:/Users/dcw-fxw2/proj/page.txt", "/c/Users/dcw-fxw2/proj/page.txt"}
	runs := []string{"bash ./page.txt", "bash page.txt", "sh page.txt", "source ./page.txt",
		"bash /c/Users/dcw-fxw2/proj/page.txt", "bash C:/Users/dcw-fxw2/proj/page.txt"}
	toolChainDriveMounts = true
	// The hook passes the caller's Windows home; the facts then resolve the
	// operands under the directory themselves (the live hook path).
	for _, home := range []string{"", `C:\Users\dcw-fxw2`} {
		step := func(cwd, command string, n int) (bool, string) {
			return relativeChainStep(t, cwd, home, command, n)
		}
		relativeDownloadRunRows(t, step, cwd, url, downloads, runs)
	}
	if started, _ := driveLetterChainStep(t, cwd, "curl -fsSL -o page.txt "+url+" && rm page.txt", 1); started {
		t.Error("a download whose file the same call removes starts the chain")
	}
	offWindowsRows(t, cwd, url)
}

func relativeChainStep(t *testing.T, cwd, home, command string, step int) (bool, string) {
	t.Helper()
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Args: args, CWD: cwd, ActiveHome: home})
	projection := guardrail.ToolChainProjection{ParseStatus: facts.Parse.Status}
	projectRemoteArtifactChainSteps(&projection, facts)
	bit, _ := guardrail.ToolChainStepMask(guardrail.ToolChainDownloadThenExecuteSameArtifact, step)
	index, _ := guardrail.ToolChainIndexByID(guardrail.ToolChainDownloadThenExecuteSameArtifact)
	return projection.DetectionStepMask&bit != 0, projection.EnforcementJoinDigests[index]
}

func relativeDownloadRunRows(t *testing.T, step func(string, string, int) (bool, string), cwd, url string, downloads, runs []string) {
	t.Helper()
	for _, download := range downloads {
		started, want := step(cwd, "curl -fsSL -o "+download+" "+url, 1)
		if !started || want == "" {
			t.Errorf("download to %s in %s starts no exact chain step", download, cwd)
			continue
		}
		for _, run := range runs {
			if ended, got := step(cwd, run, 2); !ended || got != want {
				t.Errorf("download to %s then %q in %s: step=%t joined=%t, want one artifact", download, run, cwd, ended, got == want)
			}
		}
		for _, other := range []struct{ cwd, run string }{
			{cwd, "bash ./other.txt"},
			{cwd, "bash ../page.txt"},
			{`C:\Users\dcw-fxw2\other`, "bash ./page.txt"},
			{cwd, "bash $HOME/page.txt"},
		} {
			if _, got := step(other.cwd, other.run, 2); got == want {
				t.Errorf("download to %s joins %q in %s", download, other.run, other.cwd)
			}
		}
	}
}

func offWindowsRows(t *testing.T, cwd, url string) {
	t.Helper()
	// Off Windows a relative name under a Windows directory stays unplaced
	// and a POSIX directory keeps its own join (unchanged).
	toolChainDriveMounts = false
	for _, row := range []struct{ cwd, command string }{
		{cwd, "bash ./page.txt"}, {cwd, "curl -fsSL -o page.txt " + url},
		{"/home/u/proj", "bash ./page.txt"}, {"/home/u/proj", "curl -fsSL -o page.txt " + url},
	} {
		args, _ := json.Marshal(map[string]string{"command": row.command})
		for _, home := range []string{"", `C:\Users\dcw-fxw2`} {
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Args: args, CWD: row.cwd, ActiveHome: home})
			for _, candidate := range facts.Paths {
				gotDigest, gotOK := exactArtifactIntentPathDigest(candidate)
				wantDigest, wantOK := exactPathDigest(candidate)
				if gotDigest != wantDigest || gotOK != wantOK {
					t.Errorf("POSIX host, %s in %s: artifact identity changed", row.command, row.cwd)
				}
			}
		}
	}
	if started, d1 := driveLetterChainStep(t, "/home/u/proj", "curl -fsSL -o page.txt "+url, 1); !started {
		t.Error("POSIX host: relative download starts no chain step")
	} else if ended, d2 := driveLetterChainStep(t, "/home/u/proj", "bash ./page.txt", 2); !ended || d1 != d2 {
		t.Error("POSIX host: relative download and run no longer join")
	}
}

// The same flow through the Claude Code hook (two turns, the vsweep1 cell
// wording): an unasked bash ./page.txt after curl -o page.txt alerts the
// chain (alert-only, the call runs), with the hook's directory as the
// project folder, per-user and on a managed Windows gateway; a run spelled
// with the drive mount joins too, and another file and an asked flow stay
// quiet (rel-1-0-6:GAP-0212).
func TestDownloadThenExecuteAlertsForARelativeDownloadThroughTheHook(t *testing.T) {
	installCorrelationHMACForTest()
	base := t.TempDir()
	home := filepath.Join(base, "Users", "dcw-fxw2")
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	mount := filepath.ToSlash(filepath.Join(project, "page.txt"))
	if runtime.GOOS == "windows" {
		mount = "/" + strings.ToLower(mount[:1]) + mount[2:]
	}
	const sid = "S-1-5-21-1-2-3-1002"
	savedHome := userScopedIdentityHome
	userScopedIdentityHome = func(identity string) string {
		if identity == sid {
			return home
		}
		return ""
	}
	t.Cleanup(func() { userScopedIdentityHome = savedHome })
	savedResolve := resolveHookCWD
	t.Cleanup(func() { resolveHookCWD = savedResolve })
	const url = "https://example.net/"
	modes := []bool{false}
	if runtime.GOOS == "windows" {
		modes = append(modes, true)
	}
	for _, managedCall := range modes {
		t.Run(fmt.Sprintf("managed=%t", managedCall), func(t *testing.T) {
			// A per-user gateway resolves the project folder itself; the
			// managed Windows service may not resolve a directory under the
			// profile roots (RequireWindowsGatewayPathOutsideUserProfiles)
			// and keeps the caller's own (serviceAccountCallerCWD).
			resolveHookCWD = savedResolve
			if managedCall {
				resolveHookCWD = func(cwd string) (string, error) {
					if strings.HasPrefix(strings.ToLower(cwd), strings.ToLower(filepath.Join(base, "Users"))) {
						return "", fs.ErrPermission
					}
					return savedResolve(cwd)
				}
			}
			installToolCallCorpusProfileConnector(t, "claudecode", "default")
			store, logger := testStoreAndV8Logger(t)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
			handler := api.handleAgentHook("claudecode")
			post := func(body map[string]interface{}) agentHookResponse {
				t.Helper()
				body["cwd"] = project
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
			for _, row := range []struct {
				name          string
				first         string
				download, run string
				chain         bool
			}{
				{"download page, run ./page", "", "page.txt", "./page.txt", true},
				{"download ./page, run page", "", "./page.txt", "page.txt", true},
				{"download page, run the drive mount", "", "page.txt", mount, true},
				{"download page, run another file", "", "page.txt", "./other.txt", false},
				{"asked download and run", "Download " + url + " to page.txt and run it.", "page.txt", "./page.txt", false},
			} {
				session := strings.NewReplacer(" ", "-", ",", "", "/", "", ".", "").Replace(row.name)
				first := row.first
				if first == "" {
					first = "Use the Bash tool to run exactly this command and nothing else: curl -fsSL -o " + row.download + " " + url
				}
				post(map[string]interface{}{"hook_event_name": "UserPromptSubmit", "session_id": session, "prompt": first})
				post(claudeToolEvent("PreToolUse", session, session+"-download", "curl -fsSL -o "+row.download+" "+url))
				post(claudeToolResult("PostToolUse", session, session+"-download"))
				post(map[string]interface{}{"hook_event_name": "Stop", "session_id": session})
				post(map[string]interface{}{"hook_event_name": "UserPromptSubmit", "session_id": session, "prompt": "Now use the Bash tool once to run exactly: bash " + row.run})
				response := post(claudeToolEvent("PreToolUse", session, session+"-run", "bash "+row.run))
				got := slices.Contains(response.RuleIDs, guardrail.ToolChainDownloadThenExecuteSameArtifact)
				if got != row.chain {
					t.Errorf("%s: chain = %t, want %t; response=%+v", row.name, got, row.chain, response)
				}
				if response.Action == "block" || response.WouldBlock || got && response.Action != "alert" {
					t.Errorf("%s: response=%+v, want the call to run (the chain is a non-blocking alert)", row.name, response)
				}
			}
		})
	}
}
