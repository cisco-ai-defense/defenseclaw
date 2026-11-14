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

// r104ReviewProtectedWrite runs the protected-file proof the way a per-user
// gateway does (no client map) and the way a managed gateway does (the hook
// client's map, for Claude Code and Codex). It returns the decisions in that
// order.
func r104ReviewProtectedWrite(t *testing.T, command, cwd, home string) []bool {
	t.Helper()
	input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home,
		DialectHint: actionfacts.DialectPOSIX}
	decisions := []bool{trustedExistingAuthorizedKeysSymlinkWrite(trustedActionRequest{Input: input}, actionfacts.Analyze(input))}
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
	if !ok {
		t.Fatal("client proof did not decode")
	}
	if runtime.GOOS == "windows" {
		// A Windows hook client sends no write evidence (hookexec
		// setHookRequestFacts): the managed gateway judges the call alone.
		targets = nil
	}
	for _, connector := range []string{"claudecode", "codex"} {
		request := trustedActionRequest{Input: input, Connector: connector,
			ProtectedHomeHook: true, ResolvedWriteTargets: targets}
		decisions = append(decisions, trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)))
	}
	return decisions
}

func r104ReviewHome(t *testing.T) (home, cwd string) {
	t.Helper()
	keepTempDirOffDevice(t)
	home = t.TempDir()
	cwd = filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(protected, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return home, cwd
}

func TestGAP0529CopyFieldSplitBothConnectors(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{cwd, filepath.Join(home, ".ssh"), filepath.Join(home, "build")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	for _, row := range []struct {
		name, command string
		blocked       bool
	}{
		{"protected ordinary destination", `t=" $HOME/.ssh"; cp a.txt $t`, true},
		{"protected single parameter destination", `t="a.txt $HOME/.ssh"; cp $t`, true},
		{"protected single parameter option", `t="-t $HOME/.ssh a.txt"; cp $t`, true},
		{"ordinary option word", `t="-t $HOME/build"; cp $t a.txt`, false},
		{"ordinary single parameter destination", `t="a.txt $HOME/build"; cp $t`, false},
		{"ordinary single parameter option", `t="-t $HOME/build a.txt"; cp $t`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			for i, got := range r104ReviewProtectedWrite(t, row.command, cwd, home) {
				if got != row.blocked {
					t.Errorf("cell %d (per-user, managed Claude Code, managed Codex) blocked=%t, want %t", i, got, row.blocked)
				}
			}
		})
	}
}

func TestGAP0548OptionWordBothConnectorTools(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{cwd, filepath.Join(home, "build")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	command := `t="-t $HOME/build"; cp $t a.txt`
	for _, row := range []struct{ connector, tool, argument string }{
		{"claudecode", "Bash", "command"},
		{"codex", "exec_command", "cmd"},
	} {
		t.Run(row.connector, func(t *testing.T) {
			input := actionfacts.Input{Tool: row.tool, Command: command, CWD: cwd,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
			toolInput := map[string]string{row.argument: command}
			if row.connector == "codex" {
				toolInput["workdir"] = cwd
			}
			payload, err := json.Marshal(map[string]any{"session_id": "gap0548", "hook_event_name": "PreToolUse",
				"tool_use_id": "gap0548-tool", "tool_name": row.tool, "cwd": cwd,
				"tool_input": toolInput})
			if err != nil {
				t.Fatal(err)
			}
			header := hookpaths.Resolve(payload)
			targets, ok := hookpaths.Decode(header)
			if !ok {
				t.Fatal("client proof did not decode")
			}
			if runtime.GOOS == "windows" {
				targets = nil
			}
			for _, managed := range []bool{false, true} {
				request := trustedActionRequest{Input: input, Connector: row.connector,
					ProtectedHomeHook: managed, ResolvedWriteTargets: targets}
				if trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)) {
					t.Errorf("managed=%t: ordinary option target was blocked", managed)
				}
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = row.connector
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
				if managed {
					if runtime.GOOS != "windows" {
						req.Header.Set(hookpaths.Header, header)
					}
					req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
				}
				if row.connector == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				recorder := httptest.NewRecorder()
				api.handleAgentHook(row.connector).ServeHTTP(recorder, req)
				if body := recorder.Body.String(); !strings.HasPrefix(body, `{"action":"allow"`) {
					t.Errorf("managed=%t: gateway status %d body %.300s, want allow", managed, recorder.Code, body)
				}
			}
		})
	}
}

func TestR104ReviewFixDecisions(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	for _, dir := range []string{filepath.Join(cwd, "sub"), filepath.Join(home, ".ssh", "sub")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, command string
		blocked       bool
	}{
		{"called function writer", `f() { python3 -c 'open("alias","a").write("marker")'; }; f`, true},
		{"nested called function writer", `f() { python3 -c 'open("alias","a").write("marker")'; }; g() { f; }; g`, true},
		{"uncalled function protected mention", `f() { python3 -c 'open("alias","a").write("marker")'; }; echo ok`, false}, // GAP-1535
		{"dormant caller protected mention", `f() { python3 -c 'open("alias","a").write("marker")'; }; g() { f; }; echo ok`, true},
		{"function argument protected mention", `f() { python3 -c 'open("alias","a").write("marker")'; }; echo f`, true},
		{"literal writer in reachable caller", `f() { python3 -c 'open("alias","a").write("marker")'; }; g() { f; }; g`, true},
		{"Python FileIO", `python3 -c 'import io; io.FileIO("alias","w").write(b"marker")'`, true},
		{"Python imported FileIO", `python3 -c 'from io import FileIO; FileIO("alias",mode="a").write(b"marker")'`, true},
		{"Python FileIO keyword file", `python3 -c 'import io; io.FileIO(file="alias",mode="w").write(b"marker")'`, true},
		{"Python copy2", `python3 -c 'import shutil; shutil.copy2("payload","alias")'`, true},
		{"Python copy2 optional argument", `python3 -c 'import shutil; shutil.copy2("payload","alias",follow_symlinks=True)'`, true},
		{"Python copy2 keyword destination", `python3 -c 'import shutil; shutil.copy2("payload",dst="alias")'`, true},
		{"Python copy", `python3 -c 'import shutil; shutil.copy("payload","alias")'`, true},
		{"Node copyFileSync", `node -e 'require("fs").copyFileSync("payload","alias")'`, true},
		{"Node async copyFile", `node -e 'require("fs").copyFile("payload","alias",()=>{})'`, true},
		{"Perl File Copy", `perl -e 'use File::Copy; copy("payload","alias")'`, true},
		{"Perl qualified copy", `perl -e 'File::Copy::copy("payload","alias")'`, true},
		{"Perl bare copy", `perl -e 'use File::Copy; copy "payload", "alias"'`, true},
		{"FileIO protected named read", `python3 -c 'import io; io.FileIO("alias","r").read()'`, true},
		{"Perl protected named copy", `perl -e 'sub copy { return 1 }; copy("payload","alias")'`, true},
		{"protected named copy source", `node -e 'require("fs").copyFileSync("alias","out.txt")'`, true},
		{"copy destination control", `python3 -c 'import shutil; shutil.copy2("payload","out.txt")'`, false},
		// The project contains a symlink, so T7's import-path proof cannot
		// certify that Python keeps an inert string inert at runtime.
		{"Python hash comment beside uncertain import path", `python3 -c '#open("alias","a").write("marker")'`, true},
		{"bound pattern redirect", `printf -v f %s 'ali*'; echo marker >> $f`, true},
		{"bound pattern loop", `for f in 'ali*'; do echo marker >> $f; done`, true},
		{"quoted bound pattern", `printf -v f %s 'ali*'; echo marker >> "$f"`, false},
		// GAP-1742: a link after a top-level cd is judged by its operands; an
		// unexported CDPATH is a documented limit of the pre-tool check.
		{"search-path cd writes the link", `cd sub && ln -s ../authorized_keys b && echo marker > b`, false},
		{"search-path cd writes another file", `cd sub && ln -s ../a b && echo marker > out.txt`, false},
		{"explicit cd writes the link", `cd ./sub && ln -s ../authorized_keys b && echo marker > b`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, got := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if got != tc.blocked {
					t.Fatalf("decision %d (per-user, managed claudecode, managed codex) = %v, want %v", i, got, tc.blocked)
				}
			}
		})
	}
}
