// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// These tests exercise the actual client encoder and hook route. The mode-zero
// parent gives the gateway the same incomplete home walk as ProtectHome.
func TestR103B36ReviewRealClientOperandForms(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "alice")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "scope"), filepath.Join(project, "ordinary"), filepath.Join(project, "Scope"), filepath.Join(project, "café"), filepath.Join(project, "cafe\u0301")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, dest := range map[string]string{"into-scope": "scope", "into-ordinary": "ordinary"} {
		if err := os.Symlink(dest, filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("# fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keys, filepath.Join(project, "ordinary", "key-alias")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	api := &APIServer{scannerCfg: &config.Config{}, health: NewSidecarHealth()}
	api.scannerCfg.Guardrail.Mode = "action"
	api.scannerCfg.Guardrail.Connector = "claudecode"
	post := func(t *testing.T, command string, edit func(map[string]string)) string {
		t.Helper()
		if err := os.Chmod(homes, 0o700); err != nil {
			t.Fatal(err)
		}
		body := mustJSON(t, map[string]any{"session_id": "review", "hook_event_name": "PreToolUse", "cwd": project,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": t.Name(),
			"tool_input": map[string]any{"command": command, "description": "Review fixture"}})
		header := hookpaths.Resolve(body)
		targets, ok := hookpaths.Decode(header)
		if !ok {
			t.Fatal("real client did not encode a valid header")
		}
		if edit != nil {
			edit(targets)
			header = encodeTargets(t, targets)
		}
		if err := os.Chmod(homes, 0); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
		req.Header.Set(hookpaths.Header, header)
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
		recorder := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
		return recorder.Body.String()
	}
	for _, row := range []struct {
		name, operand string
		block         bool
	}{
		{"relative outside", "../project/ordinary/n", false},
		{"trailing slash", "ordinary/n/", false},
		{"double slash", "ordinary//n", false},
		{"case distinct", "Scope/n", false},
		{"unicode composed", "café/n", false},
		{"unicode decomposed", "cafe\u0301/n", false},
		{"symlinked ordinary parent", "into-ordinary/n", false},
		{"dot dot traverses scope", "scope/../n", true},
		{"double slash in scope", "scope//n", true},
		{"symlinked scope parent", "into-scope/n", true},
		{"same inode alias", "ordinary/key-alias", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := post(t, "tar -C scope -xf pkg.tar; echo hi > "+row.operand, nil)
			want := `{"action":"allow"`
			if row.block {
				want = `{"action":"block"`
			}
			if !strings.HasPrefix(got, want) {
				t.Fatalf("verdict = %.300s, want %s", got, want)
			}
		})
	}
	t.Run("old client missing fact", func(t *testing.T) {
		got := post(t, "tar -C scope -xf pkg.tar; echo hi > ordinary/n", func(m map[string]string) {
			delete(m, hookpaths.OpaqueScopeFactPrefix+filepath.Join(project, "ordinary", "n"))
		})
		if !strings.HasPrefix(got, `{"action":"block"`) {
			t.Fatalf("verdict = %.300s, want block", got)
		}
	})
	t.Run("wrong operand key", func(t *testing.T) {
		got := post(t, "tar -C scope -xf pkg.tar; echo hi > ordinary/n", func(m map[string]string) {
			key := hookpaths.OpaqueScopeFactPrefix + filepath.Join(project, "ordinary", "n")
			delete(m, key)
			m[key+"/"] = "0"
		})
		if !strings.HasPrefix(got, `{"action":"block"`) {
			t.Fatalf("verdict = %.300s, want block", got)
		}
	})
	t.Run("malformed fact truncates header", func(t *testing.T) {
		got := post(t, "tar -C scope -xf pkg.tar; echo hi > ordinary/n", func(m map[string]string) {
			m[hookpaths.OpaqueScopeFactPrefix+filepath.Join(project, "ordinary", "n")] = "bad"
		})
		if !strings.HasPrefix(got, `{"action":"block"`) {
			t.Fatalf("verdict = %.300s, want block", got)
		}
	})
	t.Run("HOME differs from account home", func(t *testing.T) {
		alternate := filepath.Join(root, "alternate-home")
		if err := os.MkdirAll(filepath.Join(alternate, "scope"), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HOME", alternate)
		if got := post(t, `tar -C "$HOME/scope" -xf pkg.tar; echo hi > ordinary/n`, nil); !strings.HasPrefix(got, `{"action":"allow"`) {
			t.Fatalf("ordinary write = %.300s, want allow", got)
		}
		if got := post(t, "tar -C scope -xf pkg.tar; echo hi > "+filepath.Join(home, ".ssh", "authorized_keys"), nil); !strings.HasPrefix(got, `{"action":"block"`) {
			t.Fatalf("account-home key write = %.300s, want block", got)
		}
	})
	t.Run("forged call does not seed later verdict", func(t *testing.T) {
		command := "tar -C scope -xf pkg.tar; echo hi > ordinary/n"
		if got := post(t, command, func(m map[string]string) {
			m[hookpaths.OpaqueScopeFactPrefix+filepath.Join(project, "ordinary", "n")] = "0"
		}); !strings.HasPrefix(got, `{"action":"allow"`) {
			t.Fatalf("forged call = %.300s, want allow", got)
		}
		if got := post(t, command, func(m map[string]string) {
			delete(m, hookpaths.OpaqueScopeFactPrefix+filepath.Join(project, "ordinary", "n"))
		}); !strings.HasPrefix(got, `{"action":"block"`) {
			t.Fatalf("later call = %.300s, want block", got)
		}
	})
}

func TestR103B36ReviewConflictingCommandFields(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell operands")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(project, "scope"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ command, cmd string }{
		{"tar -C scope -xf pkg.tar; echo hi > outside", "echo hi > scope/n"},
		{"echo hi > scope/n", "tar -C scope -xf pkg.tar; echo hi > outside"},
	} {
		body, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": project,
			"hook_event_name": "PreToolUse", "session_id": "review-conflict", "tool_use_id": "review-conflict",
			"tool_input": map[string]string{"command": row.command, "cmd": row.cmd}})
		if err != nil {
			t.Fatal(err)
		}
		m, ok := hookpaths.Decode(hookpaths.Resolve(body))
		if !ok {
			t.Fatal("invalid client header")
		}
		// A fact for one command cannot be reused for the conflicting alias.
		for key := range m {
			if strings.HasPrefix(key, hookpaths.OpaqueScopeFactPrefix) && strings.HasSuffix(key, "/scope/n") {
				t.Fatal("client emitted a safe fact for the conflicting scoped operand")
			}
		}
		cfg := &config.Config{}
		cfg.Guardrail.Mode, cfg.Guardrail.Connector = "action", "claudecode"
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
		request.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
		request = request.WithContext(withManagedHookPeer(request.Context(), managedHookPeer{Home: home}))
		recorder := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(recorder, request)
		if !strings.HasPrefix(recorder.Body.String(), `{"action":"block"`) {
			t.Fatalf("conflicting command aliases = %.300s, want block", recorder.Body.String())
		}
	}
}

func TestR103B36ReviewPerUserModeIgnoresOpaqueFact(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX path walk")
	}
	root := t.TempDir()
	hidden := filepath.Join(root, "hidden")
	home := filepath.Join(hidden, "home")
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(project, "scope"), 0o700); err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: "Bash", Command: "tar -C scope -xf pkg.tar; echo hi > ordinary/n",
		CWD: project, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
	target := filepath.Join(project, "ordinary", "n")
	request := trustedActionRequest{Input: input, Connector: "claudecode", ResolvedWriteTargets: map[string]string{
		hookpaths.CWDKey: project, hookpaths.OpaqueScopeFactPrefix + target: "0",
	}}
	if err := os.Chmod(hidden, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hidden, 0o700) })
	if !trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)) {
		t.Fatal("per-user decision accepted a fact on an incomplete walk")
	}
}
