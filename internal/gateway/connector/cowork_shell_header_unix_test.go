// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// coworkShellHookRun runs the rendered per-user Claude Code shell hook as a
// child of agent (an executable that runs the script) and returns the
// X-DefenseClaw-Cowork header the gateway received.
func coworkShellHookRun(t *testing.T, agent string, env []string) string {
	t.Helper()
	var mu sync.Mutex
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Get(hookexec.CoworkHeader)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"action":"allow","claude_code_output":{"continue":true}}`))
	}))
	t.Cleanup(server.Close)
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	hookDir := filepath.Join(home, "hooks")
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, SetupOpts{
		DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "test-hook-token", HookFailMode: "closed",
	}, NewClaudeCodeConnector()); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(hookDir, "claude-code-hook.sh")
	// "; exit" keeps the agent shell from exec'ing the hook in its place, so
	// the hook's parent is the agent executable.
	cmd := exec.Command(agent, "-c", "bash '"+script+"'; exit $?")
	cmd.Env = append([]string{"HOME=" + home, "DEFENSECLAW_HOME=" + home, "PATH=" + os.Getenv("PATH")}, env...)
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"mcp__workspace__bash","tool_input":{"command":"echo ok"},"mcp_server":{"name":"workspace","source":"sdk"}}`)
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), `"continue":true`) {
		t.Fatalf("hook: %v, output %s", err, out)
	}
	mu.Lock()
	defer mu.Unlock()
	return got
}

// coworkEngineCopy is a bash copy placed where Claude Desktop keeps the
// Claude Code engine it bundles: dir, relative to a temporary home.
func coworkEngineCopy(t *testing.T, dir string) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	data, err := os.ReadFile(bash)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(t.TempDir(), dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	engine := filepath.Join(dir, "claude")
	if err := os.WriteFile(engine, data, 0o700); err != nil {
		t.Fatal(err)
	}
	return engine
}

// The Unix shell hook, which Cowork's plugin route runs as Claude Code CLI
// does, names the Cowork session like the native runner: only with
// CLAUDE_CODE_IS_COWORK=1 and Claude Desktop's engine as its caller.
func TestClaudeShellHookSendsTheCoworkContext(t *testing.T) {
	engine := coworkEngineCopy(t, filepath.Join("Library", "Application Support", "Claude", "claude-code", "2.1.309", "5af865b9901c", "claude.app", "Contents", "MacOS"))
	paths := `["/Users/alice/Desktop/work","/Users/alice/Documents/q4 \"final\""]`
	coworkEnv := []string{
		hookexec.CoworkEnvFlag + "=1",
		hookexec.CoworkEnvSessionID + "=c29dbbfa-8209-4e91-84c4-7191c9491c94",
		hookexec.CoworkEnvWorkspaceHostPaths + "=" + paths,
	}
	header := coworkShellHookRun(t, engine, coworkEnv)
	cowork, ok := hookexec.ParseCoworkHeader(header)
	if !ok || cowork.SessionID != "c29dbbfa-8209-4e91-84c4-7191c9491c94" ||
		len(cowork.WorkspaceHostPaths) != 2 || cowork.WorkspaceHostPaths[1] != `/Users/alice/Documents/q4 "final"` {
		t.Fatalf("%s = %q (%+v, %v)", hookexec.CoworkHeader, header, cowork, ok)
	}
	if !strings.Contains(header, base64.StdEncoding.EncodeToString([]byte(paths))) {
		t.Fatalf("header %q does not carry the folder list as base64", header)
	}

	// Every engine folder of the Claude Desktop table, not only the first
	// party one: here the Linux third-party folder, ~/.config/Claude-3p
	// (GAP-0029).
	thirdParty := coworkEngineCopy(t, filepath.Join(".config", "Claude-3p", "claude-code", "2.1.317"))
	if got := coworkShellHookRun(t, thirdParty, coworkEnv); got == "" {
		t.Fatalf("the engine in Claude-3p sent no %s", hookexec.CoworkHeader)
	}

	bash, _ := exec.LookPath("bash")
	if got := coworkShellHookRun(t, bash, coworkEnv); got != "" {
		t.Fatalf("a caller that is not the Desktop engine sent %s=%q", hookexec.CoworkHeader, got)
	}
	if got := coworkShellHookRun(t, engine, coworkEnv[1:]); got != "" {
		t.Fatalf("a call without %s=1 sent %s=%q", hookexec.CoworkEnvFlag, hookexec.CoworkHeader, got)
	}
	// A session ID outside the identifier alphabet is sent empty, never as is.
	header = coworkShellHookRun(t, engine, []string{hookexec.CoworkEnvFlag + "=1", hookexec.CoworkEnvSessionID + "=bad id;x"})
	if cowork, ok := hookexec.ParseCoworkHeader(header); !ok || cowork.SessionID != "" {
		t.Fatalf("bad session id header %q (%+v, %v)", header, cowork, ok)
	}
}

// The shell hook's engine check is rendered from the tables the native runner
// classifies by (GAP-0029): an engine in the engine folder of every Claude
// Desktop data root of every OS, in any case, and the Desktop app markers are
// Claude Desktop's engine for both; other paths are for neither.
func TestClaudeShellHookEngineCheckMatchesTheNativeRunner(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	pattern := templateData{}.ClaudeDesktopEngineCaseSH()
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	hookDir := filepath.Join(home, "hooks")
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, SetupOpts{
		DataDir: home, APIAddr: "127.0.0.1:1", APIToken: "test-hook-token", HookFailMode: "closed",
	}, NewClaudeCodeConnector()); err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(hookDir, "claude-code-hook.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "\n      "+pattern+") return 0 ;;\n") {
		t.Fatalf("claude-code-hook.sh does not check the engine with %q", pattern)
	}

	var engines []string
	for _, goos := range []string{"darwin", "linux", "windows"} {
		folders := claudedesktop.FoldersForHome(goos, "/home/alice")
		for _, root := range claudedesktop.Roots(goos) {
			dir := strings.ReplaceAll(root.Pattern(folders), "*", "pzs8sxrjxfjjc") + "/" + claudedesktop.EngineFolder
			engines = append(engines, dir+"/2.1.317/claude", dir+"/2.1.317/a33aa5518497/claude.app/Contents/MacOS/claude")
		}
	}
	engines = append(engines, strings.ToUpper(engines[0]), "/Applications/Claude.app/Contents/MacOS/Claude")
	others := []string{
		"/home/u/.local/share/claude/versions/2.1.317",
		"/home/u/.config/Claude-3p/claude-code",
		"/home/u/.config/Claude-3p/claude-code-vm/2.1.317/claude",
		"/home/u/.config/Claude-4p/claude-code/2.1.317/claude",
		"/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js",
		"/Applications/Cursor.app/Contents/MacOS/Cursor",
		"/usr/bin/bash",
	}
	paths := append(append([]string(nil), engines...), others...)
	check := `for exe in "$@"; do exe="$(printf '%s' "$exe" | LC_ALL=C tr '[:upper:]' '[:lower:]')"; case "$exe" in ` +
		pattern + `) echo 1 ;; *) echo 0 ;; esac; done`
	out, err := exec.Command(bash, append([]string{"-c", check, "bash"}, paths...)...).Output()
	if err != nil {
		t.Fatal(err)
	}
	shell := strings.Fields(string(out))
	if len(shell) != len(paths) {
		t.Fatalf("shell answered %d of %d paths: %q", len(shell), len(paths), out)
	}
	for i, path := range paths {
		want := i < len(engines)
		if native := ClassifyAgentSurface("claudecode", path, nil) == HostSurfaceDesktop; native != want {
			t.Errorf("native runner: %s Desktop engine = %v, want %v", path, native, want)
		}
		if got := shell[i] == "1"; got != want {
			t.Errorf("shell hook: %s Desktop engine = %v, want %v", path, got, want)
		}
	}
}
