// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// dynamicWordParityProject is a project in a home with an authorized_keys
// file and, in the project, a link to it (disklink) beside ordinary files.
func dynamicWordParityProject(t *testing.T) (home, project string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home = filepath.Join(t.TempDir(), "home")
	project = filepath.Join(home, "proj")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(keys), filepath.Join(project, "build")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{keys, filepath.Join(project, "report.txt"), filepath.Join(project, "a.txt"),
		filepath.Join(project, "README.md")} {
		if err := os.WriteFile(name, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(keys, filepath.Join(project, "disklink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Chdir(project)
	return home, project
}

// postDynamicWordParity sends command to the hook route in one cell. A
// managed cell carries the hook client write evidence, edited by evidence
// when it is set; a per-user cell is judged without it, as shipped.
func postDynamicWordParity(t *testing.T, home, project, connector string, managed bool, command string,
	evidence func(map[string]string)) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	body := mustJSON(t, map[string]any{"session_id": "parity-session", "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": command, "description": "d"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if managed {
		header := hookpaths.Resolve(body)
		if evidence != nil {
			targets, ok := hookpaths.Decode(header)
			if !ok {
				t.Fatalf("%s: client evidence does not decode", command)
			}
			evidence(targets)
			encoded, err := json.Marshal(targets)
			if err != nil {
				t.Fatal(err)
			}
			header = base64.RawURLEncoding.EncodeToString(encoded)
		}
		req.Header.Set(hookpaths.Header, header)
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	return recorder.Body.String()
}

func checkDynamicWordParity(t *testing.T, allowed, blocked []string) {
	t.Helper()
	home, project := dynamicWordParityProject(t)
	const block, allow = `{"action":"block"`, `{"action":"allow"`
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s managed=%v", connector, managed), func(t *testing.T) {
				for _, command := range allowed {
					if got := postDynamicWordParity(t, home, project, connector, managed, command, nil); !strings.HasPrefix(got, allow) {
						t.Errorf("%s = %.300s, want allow", command, got)
					}
				}
				for _, command := range blocked {
					got := postDynamicWordParity(t, home, project, connector, managed, command, nil)
					if !strings.HasPrefix(got, block) || !strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%s = %.300s, want block", command, got)
					}
				}
			})
		}
	}
}

// rel-1-0-6:GAP-0229: an eval-assigned redirect onto an ordinary file is
// allowed by managed Claude Code as by managed Codex and both per-user
// cells, in a project that also holds a keys link; the same form onto the
// link blocks in every cell.
func TestEvalAssignedRedirectOntoAnOrdinaryFileGetsThePerUserVerdictInEveryCell(t *testing.T) {
	checkDynamicWordParity(t,
		[]string{
			`f=other; eval f=report.txt; echo marker >> "$f"`,
			`eval f=report.txt; echo marker >> $f`,
			`f=report.txt; eval true; echo marker >> "$f"`,
		},
		[]string{
			`f=other; eval f=disklink; echo marker >> "$f"`,
			`eval f=disklink; echo marker >> $f`,
			`eval cd ~/.ssh; echo marker >> authorized_keys`,
		})
}

// rel-1-0-6:GAP-0229: managed Claude Code keeps the conservative block of
// the eval form when the client evidence is truncated or has no reading of
// the starting directory.
func TestManagedClaudeCodeKeepsTheEvalRedirectBlockWithoutACompleteClientReading(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	if runtime.GOOS != "linux" {
		t.Skip("only a Linux managed gateway reads the starting directory from the client")
	}
	const command = `f=other; eval f=report.txt; echo marker >> "$f"`
	for name, edit := range map[string]func(map[string]string){
		"truncated": func(targets map[string]string) { targets[hookpaths.TruncatedKey] = "1" },
		"no starting directory": func(targets map[string]string) {
			delete(targets, hookpaths.DirectoryFactPrefix+project)
		},
		"unreadable starting directory": func(targets map[string]string) {
			targets[hookpaths.DirectoryFactPrefix+project] = "?"
		},
	} {
		got := postDynamicWordParity(t, home, project, "claudecode", true, command, edit)
		if !strings.HasPrefix(got, `{"action":"block"`) {
			t.Errorf("%s: %s = %.300s, want block", name, command, got)
		}
	}
	got := postDynamicWordParity(t, home, project, "claudecode", true, `eval "$CMD"; echo marker >> "$f"`, nil)
	if !strings.HasPrefix(got, `{"action":"block"`) {
		t.Errorf("eval of a dynamic script = %.300s, want block", got)
	}
}

// rel-1-0-2:GAP-0004 (corpus FP-0004 and FP-0005 neighbours): an unquoted
// copy source with one known plain value gets the verdict of its quoted
// spelling in every cell, so managed Codex and Claude Code on macOS and
// Linux match per-user. A source that may expand to an option stays unknown.
func TestUnquotedCopyWordWithOneKnownValueGetsTheQuotedVerdictInEveryCell(t *testing.T) {
	checkDynamicWordParity(t,
		[]string{
			`for f in a.txt README.md; do cp $f build/; done; echo hi > report.txt`,
			`for f in a.txt README.md; do cp "$f" build/; done; echo hi > report.txt`,
			`f=a.txt; cp $f out.txt`,
			`v=a.txt; cp $v out.txt && echo ok`,
			`f=a.txt; cp $f build/ && echo hi > report.txt`,
			`F=a.txt; cp ${F} out.txt && echo done > report.txt`,
		},
		[]string{
			`cp $f build/ && echo hi > report.txt`,
			`T=--target-directory=$HOME/.ssh; cp $T a.txt`,
			`for f in a.txt; do cp $f disklink; done`,
			`for f in a.txt README.md; do cp $f build/; done; echo hi > disklink`,
			`f=a.txt; read f; cp $f build/ && echo hi > report.txt`,
			`for f in a.txt; do IFS=.; cp $f build/; done; echo hi > report.txt`,
			// rel-1-0-2:GAP-0004 review: rebinding through a wrapper or a
			// deferred string keeps the word unknown.
			`f=a.txt; command read f; cp $f build/ && echo hi > report.txt`,
			`f=a.txt; wait -p f; cp $f build/ && echo hi > report.txt`,
			`f=a.txt; trap "read f" DEBUG; cp $f build/ && echo hi > report.txt`,
			`f=a.txt; command eval "$X"; cp $f build/ && echo hi > report.txt`,
			`for f in a.txt; do command read f; cp $f build/; done; echo hi > report.txt`,
		})
}

// rel-1-0-6:GAP-0235: a copy destination named by a parameter with one
// known plain value writes that file, so managed hooks give the per-user
// verdict; the same word naming the keys link blocks in every cell, and a
// destination word that may hold another value stays unknown.
func TestCopyDestinationWordWithOneKnownValueGetsThePerUserVerdictInEveryCell(t *testing.T) {
	checkDynamicWordParity(t,
		[]string{
			`f=out2.txt; cp a.txt $f`,
			`f=out2.txt; cp a.txt "$f" && echo hi > report.txt`,
			`f=out2.txt; cp a.txt $f && echo hi > report.txt`,
			`for d in build; do cp a.txt $d; done; echo hi > report.txt`,
			`f=a.txt; g=out3.txt; cp $f $g && echo hi >> report.txt`,
		},
		[]string{
			`f=disklink; cp a.txt $f`,
			`f=disklink; cp a.txt "$f" && echo hi > report.txt`,
			`for d in disklink; do cp a.txt $d; done`,
			`f=out2.txt; f=disklink; cp a.txt $f`,
			`for f in out2.txt disklink; do cp a.txt $f; done`,
			`f=out2.txt; command read f; cp a.txt $f && echo hi > report.txt`,
			`f=out2.txt; trap "read f" DEBUG; cp a.txt $f && echo hi > report.txt`,
		})
}
