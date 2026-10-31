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

// driveLetterChainStep is the step and join digest one Bash command adds to
// chain.download_then_execute_same_artifact.
func driveLetterChainStep(t *testing.T, cwd, command string, step int) (bool, string) {
	t.Helper()
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Args: args, CWD: cwd})
	projection := guardrail.ToolChainProjection{ParseStatus: facts.Parse.Status}
	projectRemoteArtifactChainSteps(&projection, facts)
	bit, ok := guardrail.ToolChainStepMask(guardrail.ToolChainDownloadThenExecuteSameArtifact, step)
	index, indexed := guardrail.ToolChainIndexByID(guardrail.ToolChainDownloadThenExecuteSameArtifact)
	if !ok || !indexed {
		t.Fatal("chain.download_then_execute_same_artifact is not registered")
	}
	return projection.DetectionStepMask&bit != 0, projection.EnforcementJoinDigests[index]
}

// rel-1-0-6:GAP-0182 (#1390). In Git Bash on Windows, C:/x and a quoted C:\x
// name the drive file, as /c/x does; the POSIX reading leaves them relative,
// so a download to C:/Users/<u>/proj/page.txt and a run of the same file
// never started or ended chain.download_then_execute_same_artifact. On a
// Windows host every spelling now names one artifact, whatever the hook's
// directory; another file, another drive and a drive-relative C:x do not
// join, and off Windows the identities are unchanged.
func TestDownloadThenExecuteJoinsDriveLetterSpellingsOnWindows(t *testing.T) {
	saved := toolChainDriveMounts
	t.Cleanup(func() { toolChainDriveMounts = saved })
	const url = "https://example.net/"
	spellings := []string{
		"C:/Users/dcw-fxw1/proj/page.txt",
		`"C:\Users\dcw-fxw1\proj\page.txt"`,
		"c:/users/DCW-FXW1/proj/./page.txt",
		"/c/Users/dcw-fxw1/proj/page.txt",
		"/C/Users/dcw-fxw1/proj/page.txt",
	}
	toolChainDriveMounts = true
	for _, cwd := range []string{"", `C:\Users\dcw-fxw1\proj`, "/c/Users/dcw-fxw1/proj"} {
		for _, download := range spellings {
			started, want := driveLetterChainStep(t, cwd, "curl -fsSL -o "+download+" "+url, 1)
			if !started || want == "" {
				t.Errorf("cwd %q: download to %s starts no exact chain step", cwd, download)
				continue
			}
			for _, run := range spellings {
				for _, command := range []string{"bash " + run, "sh " + run, "source " + run} {
					ended, got := driveLetterChainStep(t, cwd, command, 2)
					if !ended || got != want {
						t.Errorf("cwd %q: download to %s then %q: step=%t joined=%t, want one artifact", cwd, download, command, ended, got == want)
					}
				}
			}
			for _, other := range []string{
				"bash C:/Users/dcw-fxw1/proj/other.txt",
				"bash D:/Users/dcw-fxw1/proj/page.txt",
				"bash /d/Users/dcw-fxw1/proj/page.txt",
				"bash C:/Users/dcw-fxw1/page.txt",
			} {
				if _, got := driveLetterChainStep(t, cwd, other, 2); got == want {
					t.Errorf("cwd %q: download to %s joins %q", cwd, download, other)
				}
			}
		}
		// C:page.txt is relative to drive C's own directory: no exact file.
		if started, _ := driveLetterChainStep(t, cwd, "curl -fsSL -o C:page.txt "+url, 1); started && cwd != "/c/Users/dcw-fxw1/proj" {
			t.Errorf("cwd %q: a drive-relative download starts an exact chain step", cwd)
		}
	}

	// Off Windows C:/x stays a relative POSIX path: same digests as before.
	toolChainDriveMounts = false
	for _, cwd := range []string{"", "/home/u/proj"} {
		for _, spelling := range spellings {
			args, _ := json.Marshal(map[string]string{"command": "bash " + spelling})
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Args: args, CWD: cwd})
			for _, candidate := range facts.Paths {
				gotDigest, gotOK := exactArtifactIntentPathDigest(candidate)
				wantDigest, wantOK := exactPathDigest(candidate)
				if gotDigest != wantDigest || gotOK != wantOK {
					t.Errorf("POSIX host, cwd %q, %s: artifact identity changed", cwd, spelling)
				}
			}
		}
	}
}

// The same flow through the Claude Code hook (two turns, the S01 cell
// wording): an unasked run of the file downloaded as C:/... alerts the chain
// (alert-only, the call runs) whether the run spells it C:/... or /c/...,
// per-user and on a managed Windows gateway; a download the user asked to
// run and another file stay quiet (rel-1-0-6:GAP-0182).
func TestDownloadThenExecuteAlertsForADriveLetterDownloadThroughTheHook(t *testing.T) {
	installCorrelationHMACForTest()
	saved := toolChainDriveMounts
	toolChainDriveMounts = true
	t.Cleanup(func() { toolChainDriveMounts = saved })
	base := t.TempDir()
	home := filepath.Join(base, "Users", "dcw-fxw1")
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	// The drive spelling of the project file: the real path on Windows, a
	// fixed one elsewhere (the hook's directory is not needed to place it).
	drive := "C:/Users/dcw-fxw1/proj/page.txt"
	if runtime.GOOS == "windows" {
		drive = filepath.ToSlash(filepath.Join(project, "page.txt"))
	}
	mount := "/" + strings.ToLower(drive[:1]) + drive[2:]
	backslash := `"` + strings.ReplaceAll(drive, "/", `\`) + `"`
	other := strings.TrimSuffix(drive, "page.txt") + "other.txt"
	const sid = "S-1-5-21-1-2-3-1001"
	savedHome := userScopedIdentityHome
	userScopedIdentityHome = func(identity string) string {
		if identity == sid {
			return home
		}
		return ""
	}
	t.Cleanup(func() { userScopedIdentityHome = savedHome })
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
				{"download C:/, run C:/", "", drive, drive, true},
				{"download C:/, run /c/", "", drive, mount, true},
				{"download /c/, run C:/", "", mount, drive, true},
				{"download quoted C:\\, run C:/", "", backslash, drive, true},
				{"download C:/, run another file", "", drive, other, false},
				{"asked download and run", "Download " + url + " to " + drive + " and run it.", drive, mount, false},
			} {
				session := strings.NewReplacer(" ", "-", ",", "", ":", "", "/", "", `\`, "").Replace(row.name)
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
