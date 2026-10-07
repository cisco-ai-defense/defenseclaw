// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Any local account can read a process's arguments (ps, /proc/<pid>/cmdline)
// and exec monitors (auditd, Tetragon, EDR) record them. A shell hook that
// hands curl `-H "Authorization: Bearer <token>"` or `-d "$PAYLOAD"`
// discloses the gateway credential and the user's prompt or tool input to
// all of them. The tests below run every rendered hook and PATH shim against
// a fake gateway, record the arguments of every program the hook starts, and
// require that neither the token nor a marker from the payload is among
// them, while the gateway still receives both. A static check then keeps
// every rendered script from putting either on a curl command line again.

const hookArgvPayloadMarker = "dccert-payload-marker"

// hookArgvSystemPATH is the hardened PATH the hooks fall back to; the
// recording wrappers are put in front of it.
const hookArgvSystemPATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

// hookArgvTools are the programs a hook or shim may start through PATH. Each
// one found on the system PATH gets a recording wrapper.
var hookArgvTools = []string{
	"awk", "basename", "cat", "chmod", "curl", "cut", "date", "dirname", "env", "find", "grep",
	"head", "id", "jq", "ls", "mkdir", "mktemp", "mv", "od", "python3", "readlink", "realpath",
	"rm", "sed", "sleep", "sort", "stat", "tail", "touch", "tr", "uname", "wc", "which",
}

// hookArgvRecorder is a directory of wrappers that log the arguments of each
// call (and, on Linux, the /proc/<pid>/cmdline of the wrapper process, which
// is what another account would read) and its environment, which monitors
// that capture process environments record, before they exec the real
// program.
type hookArgvRecorder struct {
	dir    string
	log    string
	envLog string
}

func newHookArgvRecorder(t *testing.T) *hookArgvRecorder {
	t.Helper()
	logDir := t.TempDir()
	r := &hookArgvRecorder{dir: t.TempDir(), log: filepath.Join(logDir, "argv.log"), envLog: filepath.Join(logDir, "env.log")}
	cat, envBin := hookArgvLookPath("cat"), hookArgvLookPath("env")
	if cat == "" || envBin == "" {
		t.Skip("cat and env are required")
	}
	for _, name := range hookArgvTools {
		// The macOS /usr/bin/python3 may be the developer-tools stub that
		// _dc_python3_usable refuses by path; keep its path visible.
		if name == "python3" && runtime.GOOS == "darwin" {
			continue
		}
		real := hookArgvLookPath(name)
		if real == "" {
			continue
		}
		wrapper := "#!/bin/sh\n" +
			"{\n" +
			"  printf '%s' " + shellSingleQuoteForTest(name) + "\n" +
			"  for a in \"$@\"; do printf '\\037%s' \"$a\"; done\n" +
			"  printf '\\036'\n" +
			"  if [ -r /proc/$$/cmdline ]; then " + shellSingleQuoteForTest(cat) + " /proc/$$/cmdline; printf '\\036'; fi\n" +
			"} >> " + shellSingleQuoteForTest(r.log) + "\n" +
			"{ printf '%s\\n' " + shellSingleQuoteForTest(name) + "; " + shellSingleQuoteForTest(envBin) + "; printf '\\036'; } >> " + shellSingleQuoteForTest(r.envLog) + "\n" +
			"exec " + shellSingleQuoteForTest(real) + " \"$@\"\n"
		if err := os.WriteFile(filepath.Join(r.dir, name), []byte(wrapper), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(r.dir, "curl")); err != nil {
		t.Skip("curl is required to run shell hooks")
	}
	if _, err := os.Stat(filepath.Join(r.dir, "jq")); err != nil {
		t.Skip("jq is required to run shell hooks")
	}
	return r
}

func hookArgvLookPath(name string) string {
	for _, dir := range filepath.SplitList(hookArgvSystemPATH) {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return path
		}
	}
	return ""
}

func (r *hookArgvRecorder) reset(t *testing.T) {
	t.Helper()
	for _, log := range []string{r.log, r.envLog} {
		if err := os.WriteFile(log, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// requireNoneInEnvironment fails if any recorded child process started with
// one of secrets in its environment.
func (r *hookArgvRecorder) requireNoneInEnvironment(t *testing.T, secrets ...string) {
	t.Helper()
	data, err := os.ReadFile(r.envLog)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("no child process environment was recorded")
	}
	for _, rec := range strings.Split(string(data), "\x1e") {
		name, env, _ := strings.Cut(strings.TrimLeft(rec, "\n"), "\n")
		for _, line := range strings.Split(env, "\n") {
			for _, secret := range secrets {
				if strings.Contains(line, secret) {
					t.Fatalf("%s started with %q in its environment: %s", name, secret, line)
				}
			}
		}
	}
}

// records returns one entry per recorded call or cmdline, with the argument
// separators made readable.
func (r *hookArgvRecorder) records(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(r.log)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, rec := range strings.Split(string(data), "\x1e") {
		if rec == "" {
			continue
		}
		rec = strings.NewReplacer("\x1f", " ", "\x00", " ").Replace(rec)
		out = append(out, rec)
	}
	return out
}

// requireNone fails if any recorded command line carries one of secrets.
func (r *hookArgvRecorder) requireNone(t *testing.T, secrets ...string) {
	t.Helper()
	for _, rec := range r.records(t) {
		for _, secret := range secrets {
			if strings.Contains(rec, secret) {
				t.Fatalf("a child process command line carries %q:\n%s", secret, rec)
			}
		}
	}
}

// requireCurlUsesDescriptors fails unless a recorded curl call sent its body
// from a descriptor and, when authenticated, its header from a descriptor
// config file.
func (r *hookArgvRecorder) requireCurlUsesDescriptors(t *testing.T, authenticated bool) {
	t.Helper()
	for _, rec := range r.records(t) {
		if !strings.HasPrefix(rec, "curl ") {
			continue
		}
		if !strings.Contains(rec, " --data-binary @/dev/fd/9") {
			continue
		}
		if authenticated && !strings.Contains(rec, " --config /dev/fd/8") {
			t.Fatalf("authenticated curl call reads no descriptor config:\n%s", rec)
		}
		return
	}
	t.Fatalf("no curl call read its body from a descriptor; recorded:\n%s", strings.Join(r.records(t), "\n"))
}

// hookArgvCurlrcEnv points both places curl reads a .curlrc from before HOME
// (which the hooks replace) at one that traces every request, bearer and body
// included, to the returned file. The agent controls this environment; with
// -q as its first argument curl reads no .curlrc at all.
func hookArgvCurlrcEnv(t *testing.T) (env []string, trace string) {
	t.Helper()
	dir := t.TempDir()
	trace = filepath.Join(dir, "trace")
	for _, name := range []string{".curlrc", "curlrc"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("trace-ascii = \""+trace+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"CURL_HOME=" + dir, "XDG_CONFIG_HOME=" + dir}, trace
}

func requireNoCurlTrace(t *testing.T, trace string) {
	t.Helper()
	if _, err := os.Stat(trace); err == nil {
		t.Fatalf("a gateway request read the agent's .curlrc and traced itself to %s", trace)
	}
}

// hookArgvGateway records each request and answers allow.
type hookArgvGateway struct {
	mu       sync.Mutex
	requests []hookArgvRequest
}

type hookArgvRequest struct {
	path, authorization, body string
}

func (g *hookArgvGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	g.requests = append(g.requests, hookArgvRequest{path: r.URL.Path, authorization: r.Header.Get("Authorization"), body: string(body)})
	g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"action":"allow"}`)
}

func (g *hookArgvGateway) take() []hookArgvRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := g.requests
	g.requests = nil
	return out
}

func newHookArgvGateway(t *testing.T) (*hookArgvGateway, string) {
	t.Helper()
	g := &hookArgvGateway{}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return g, strings.TrimPrefix(srv.URL, "http://")
}

// hookArgvCase is one hook invocation whose payload carries the marker.
type hookArgvCase struct {
	script string
	args   []string
	env    []string
	stdin  string
	route  string
}

func hookArgvConnectorCase(t *testing.T, connector string) hookArgvCase {
	t.Helper()
	m := hookArgvPayloadMarker
	switch connector {
	case "claudecode":
		return hookArgvCase{script: "claude-code-hook.sh", stdin: `{"hook_event_name":"UserPromptSubmit","session_id":"s1","prompt":"` + m + `"}`, route: "/api/v1/claude-code/hook"}
	case "codex":
		return hookArgvCase{script: "codex-hook.sh", args: codexBoundShellHookArgsForTest(t, "codex-hook.sh", "PreToolUse")[1:],
			stdin: `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"echo ` + m + `"}}`, route: "/api/v1/codex/hook"}
	case "copilot":
		return hookArgvCase{script: "copilot-hook.sh", args: []string{"--event", "preToolUse"},
			stdin: `{"sessionId":"s1","timestamp":1790483549431,"cwd":"/work/proj","toolName":"bash","toolArgs":{"command":"echo ` + m + `"}}`, route: "/api/v1/copilot/hook"}
	case "cursor":
		return hookArgvCase{script: "cursor-hook.sh", stdin: `{"hook_event_name":"beforeShellExecution","conversation_id":"c1","command":"echo ` + m + `","cwd":"/work/proj"}`, route: "/api/v1/cursor/hook"}
	case "kiro":
		return hookArgvCase{script: "kiro-hook.sh", args: []string{"--hook-surface", "v2"},
			stdin: `{"hook_event_name":"preToolUse","cwd":"/work/proj","session_id":"s1","tool_name":"shell","tool_input":{"command":"echo ` + m + `"}}`, route: "/api/v1/kiro/hook"}
	case "devin":
		return hookArgvCase{script: "devin-hook.sh", stdin: `{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"/work/proj","tool_name":"exec","tool_input":{"command":"echo ` + m + `"}}`, route: "/api/v1/devin/hook"}
	case "hermes":
		return hookArgvCase{script: "hermes-hook.sh", stdin: `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo ` + m + `"},"session_id":"s1","cwd":"/work/p","extra":{}}`, route: "/api/v1/hermes/hook"}
	case "openhands":
		return hookArgvCase{script: "openhands-hook.sh", stdin: `{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"echo ` + m + `"},"session_id":"s1","working_dir":"/work/p","metadata":{}}`, route: "/api/v1/openhands/hook"}
	case "antigravity":
		return hookArgvCase{script: "antigravity-hook.sh", args: []string{"PreToolUse"}, stdin: `{"toolName":"run_command","toolInput":{"CommandLine":"echo ` + m + `"}}`, route: "/api/v1/antigravity/hook"}
	}
	t.Fatalf("no hook case for connector %q", connector)
	return hookArgvCase{}
}

// hookArgvInspectCases cover the shared inspect-* scripts, including a tool
// input larger than one argument may be on Linux (128 KiB), which the
// inspect-tool hook used to hand jq with --arg.
func hookArgvInspectCases() []hookArgvCase {
	m := hookArgvPayloadMarker
	large := `{"command":"` + strings.Repeat("x", 200<<10) + m + `"}`
	return []hookArgvCase{
		{script: "inspect-tool.sh", env: []string{"TOOL_NAME=Bash"}, stdin: `{"command":"echo ` + m + `"}`, route: "/api/v1/inspect/tool"},
		{script: "inspect-tool.sh", env: []string{"TOOL_NAME=Bash"}, stdin: large, route: "/api/v1/inspect/tool"},
		{script: "inspect-tool-response.sh", env: []string{"TOOL_NAME=Bash"}, stdin: `{"output":"` + m + `"}`, route: "/api/v1/inspect/tool-response"},
		{script: "inspect-request.sh", stdin: `{"content":"` + m + `"}`, route: "/api/v1/inspect/request"},
		{script: "inspect-response.sh", stdin: `{"content":"` + m + `"}`, route: "/api/v1/inspect/response"},
	}
}

// hookArgvShellConnectors are the connectors with a host shell hook.
var hookArgvShellConnectors = []Connector{
	NewClaudeCodeConnector(), NewCodexConnector(), NewCopilotConnector(), NewCursorConnector(), NewKiroConnector(),
	NewDevinConnector(), NewHermesConnector(), NewOpenHandsConnector(), NewAntigravityConnector(),
}

// runHookArgvCase runs one hook with the recorder's wrappers on its baked
// PATH and returns its exit code and output.
func runHookArgvCase(t *testing.T, hookDir string, tc hookArgvCase, env []string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemBashForTest(t), append([]string{filepath.Join(hookDir, tc.script)}, tc.args...)...)
	cmd.Env = append(append(append(hookArgvBaseEnv(), hookArgvInheritedEnv()...), env...), tc.env...)
	cmd.Stdin = strings.NewReader(tc.stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %s: %v", tc.script, err)
	}
	return code, stdout.String(), stderr.String()
}

// hookArgvInheritedEnv exports, as an agent's environment may, every name the
// hooks keep the bearer, the payload or the gateway's answer in. An
// assignment keeps the export bit of an inherited variable, which would put
// the value in the environment of every child process.
func hookArgvInheritedEnv() []string {
	var env []string
	for _, name := range []string{"API_TOKEN", "PAYLOAD", "CONTENT", "TOOL_INPUT", "TOOL_OUTPUT", "INSPECT_BODY", "RESPONSE", "RESULT", "OUTPUT"} {
		env = append(env, name+"=dccert-inherited")
	}
	return env
}

// hookArgvBaseEnv is the test process environment without DefenseClaw
// overrides, Kerberos session state (which would start the gateway binary for
// session facts) or proxies.
func hookArgvBaseEnv() []string {
	var out []string
	for _, entry := range sanitizedTestEnv() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "HOME", "KRB5CCNAME", "TOOL_NAME", "CLAUDE_TOOL_NAME":
			continue
		}
		out = append(out, entry)
	}
	return out
}

// TestShellHooksKeepTokenAndPayloadOffEveryCommandLine runs every per-user
// connector hook and the shared inspect-* scripts, with a connector-scoped
// token, against a fake gateway.
func TestShellHooksKeepTokenAndPayloadOffEveryCommandLine(t *testing.T) {
	gateway, addr := newHookArgvGateway(t)
	for _, conn := range hookArgvShellConnectors {
		conn := conn
		t.Run(conn.Name(), func(t *testing.T) {
			token := "dccert-fake-token-" + conn.Name()
			hookDir := t.TempDir()
			if err := WriteHookScriptsForConnectorObject(hookDir, addr, token, conn); err != nil {
				t.Fatalf("write hooks: %v", err)
			}
			rec := newHookArgvRecorder(t)
			bakeHookPathForTest(t, filepath.Join(hookDir, "_hardening.sh"), rec.dir+":"+hookArgvSystemPATH)
			cases := []hookArgvCase{hookArgvConnectorCase(t, conn.Name())}
			if conn.Name() == "claudecode" {
				cases = append(cases, hookArgvInspectCases()...)
			}
			for _, tc := range cases {
				rec.reset(t)
				gateway.take()
				home := t.TempDir()
				curlrcEnv, trace := hookArgvCurlrcEnv(t)
				code, stdout, stderr := runHookArgvCase(t, hookDir, tc, append([]string{"HOME=" + home, "DEFENSECLAW_HOME=" + home}, curlrcEnv...))
				requireNoCurlTrace(t, trace)
				requests := gateway.take()
				if code != 0 || len(requests) != 1 {
					t.Fatalf("%s: exit %d, %d gateway requests, want an allowed call with one request\nstdout=%s\nstderr=%s", tc.script, code, len(requests), stdout, stderr)
				}
				req := requests[0]
				if req.path != tc.route || req.authorization != "Bearer "+token || !strings.Contains(req.body, hookArgvPayloadMarker) {
					t.Fatalf("%s: gateway got path %q, authorization %q, body with marker %v; want %s, the scoped bearer and the payload",
						tc.script, req.path, req.authorization, strings.Contains(req.body, hookArgvPayloadMarker), tc.route)
				}
				rec.requireNone(t, token, hookArgvPayloadMarker)
				rec.requireNoneInEnvironment(t, token, hookArgvPayloadMarker)
				rec.requireCurlUsesDescriptors(t, true)
			}
		})
	}
}

// TestLegacySharedTokenHooksKeepTokenOffEveryCommandLine covers the shared
// .token file an older setup wrote (sourced, not read as one line).
func TestLegacySharedTokenHooksKeepTokenOffEveryCommandLine(t *testing.T) {
	gateway, addr := newHookArgvGateway(t)
	const token = "dccert-fake-token-legacy"
	hookDir := t.TempDir()
	if err := WriteHookScriptsWithToken(hookDir, addr, token); err != nil {
		t.Fatalf("write hooks: %v", err)
	}
	rec := newHookArgvRecorder(t)
	bakeHookPathForTest(t, filepath.Join(hookDir, "_hardening.sh"), rec.dir+":"+hookArgvSystemPATH)
	for _, tc := range append([]hookArgvCase{hookArgvConnectorCase(t, "claudecode")}, hookArgvInspectCases()[0]) {
		rec.reset(t)
		home := t.TempDir()
		code, stdout, stderr := runHookArgvCase(t, hookDir, tc, []string{"HOME=" + home, "DEFENSECLAW_HOME=" + home})
		requests := gateway.take()
		if code != 0 || len(requests) != 1 || requests[0].authorization != "Bearer "+token {
			t.Fatalf("%s: exit %d, requests %+v\nstdout=%s\nstderr=%s", tc.script, code, requests, stdout, stderr)
		}
		rec.requireNone(t, token, hookArgvPayloadMarker)
		rec.requireNoneInEnvironment(t, token, hookArgvPayloadMarker)
		rec.requireCurlUsesDescriptors(t, true)
	}
}

// TestStandaloneSocketHooksKeepPayloadOffEveryCommandLine covers the
// enterprise standalone hooks, which send no bearer over the hook socket but
// used to put the whole payload on curl's command line, and the Hermes
// foreign-hook guard's session report.
func TestStandaloneSocketHooksKeepPayloadOffEveryCommandLine(t *testing.T) {
	f := newHookSocketFixture(t, "dcav", nil)
	guard := filepath.Join(f.root, "guard")
	// A guard that gives no answer makes the Hermes hook report the block
	// to the session route itself.
	if err := os.WriteFile(guard, []byte("#!/bin/sh\ncat >/dev/null\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, conn := range hookArgvShellConnectors {
		conn := conn
		for _, withGuard := range []bool{false, true} {
			if withGuard && conn.Name() != "hermes" {
				continue
			}
			name := conn.Name()
			if withGuard {
				name += "/foreign-hook-guard"
			}
			t.Run(name, func(t *testing.T) {
				dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
				hookDir := filepath.Join(dataDir, "hooks")
				opts := SetupOpts{
					DataDir:            dataDir,
					APIAddr:            f.held.Addr().String(),
					APIToken:           "dccert-fake-token-socket",
					HookAPIToken:       "dccert-fake-token-socket",
					HookAPITokenScoped: true,
					ManagedEnterprise:  true,
					HookFailMode:       "closed",
					ManagedHookSocket:  f.socket,
					ManagedServiceUID:  os.Getuid(),
				}
				if withGuard {
					opts.ForeignHookGuardBinary = guard
				}
				if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
					t.Fatal(err)
				}
				rec := newHookArgvRecorder(t)
				bakeHookPathForTest(t, filepath.Join(hookDir, "_hardening.sh"), rec.dir+":"+hookArgvSystemPATH)
				tc := hookArgvConnectorCase(t, conn.Name())
				if withGuard {
					tc.stdin = `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"ls"},"session_id":"` + hookArgvPayloadMarker + `","cwd":"/work/p","extra":{}}`
					tc.route = "/api/v1/foreign-hook-session/hermes"
				}
				f.gateway.mu.Lock()
				f.gateway.paths, f.gateway.authorization, f.gateway.bodies = nil, nil, nil
				f.gateway.mu.Unlock()
				code, stdout, stderr := runHookArgvCase(t, hookDir, tc, []string{"HOME=" + filepath.Dir(dataDir)})
				paths, authorization, bodies := f.gateway.recorded()
				if code != 0 || len(paths) != 1 || paths[0] != tc.route || authorization[0] != "" || !strings.Contains(bodies[0], hookArgvPayloadMarker) {
					t.Fatalf("exit %d, socket requests %v (authorization %q), want one bearer-free %s carrying the payload\nstdout=%s\nstderr=%s",
						code, paths, authorization, tc.route, stdout, stderr)
				}
				rec.requireNone(t, "dccert-fake-token-socket", hookArgvPayloadMarker)
				rec.requireNoneInEnvironment(t, "dccert-fake-token-socket", hookArgvPayloadMarker)
				rec.requireCurlUsesDescriptors(t, false)
			})
		}
	}
	if n := f.tcpConnections.Load(); n != 0 {
		t.Fatalf("a standalone hook connected to the TCP API port %d times", n)
	}
}

// TestPathShimsKeepTokenOffEveryCommandLine runs each PATH shim. The tool
// arguments are the shim's own command line, so only the gateway request
// must not carry them.
func TestPathShimsKeepTokenOffEveryCommandLine(t *testing.T) {
	gateway, addr := newHookArgvGateway(t)
	const token = "dccert-fake-token-shim"
	shimDir := t.TempDir()
	if err := WriteShimScriptsWithToken(shimDir, addr, token); err != nil {
		t.Fatal(err)
	}
	rec := newHookArgvRecorder(t)
	for _, name := range shimBinaries {
		t.Run(name, func(t *testing.T) {
			rec.reset(t)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, systemBashForTest(t), filepath.Join(shimDir, name), "--version", hookArgvPayloadMarker)
			curlrcEnv, trace := hookArgvCurlrcEnv(t)
			cmd.Env = append(append(hookArgvBaseEnv(), curlrcEnv...), "HOME="+t.TempDir(), "PATH="+shimDir+":"+rec.dir+":/usr/bin:/bin")
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			_ = cmd.Run() // the real tool may be missing; the inspection request came first
			requireNoCurlTrace(t, trace)
			requests := gateway.take()
			if len(requests) != 1 || requests[0].path != "/api/v1/inspect/tool" || requests[0].authorization != "Bearer "+token ||
				!strings.Contains(requests[0].body, hookArgvPayloadMarker) {
				t.Fatalf("shim %s: gateway requests %+v, want one authenticated inspection carrying the tool arguments\n%s", name, requests, out.String())
			}
			rec.requireNone(t, token)
			rec.requireNoneInEnvironment(t, token)
			for _, call := range rec.records(t) {
				if strings.Contains(call, "/api/v1/inspect/tool") && strings.Contains(call, hookArgvPayloadMarker) {
					t.Fatalf("shim %s put the tool arguments on the gateway request's command line:\n%s", name, call)
				}
			}
			rec.requireCurlUsesDescriptors(t, true)
		})
	}
}

// writeShimRealTools puts a stand-in for every shimmed tool in a new
// directory. Each one records its arguments and its environment in the
// returned log directory; the curl stand-in then runs the real curl, which
// also sends the curl shim's own inspection request.
func writeShimRealTools(t *testing.T) (binDir, logDir string) {
	t.Helper()
	envBin, curlBin := hookArgvLookPath("env"), hookArgvLookPath("curl")
	if envBin == "" || curlBin == "" {
		t.Skip("env and curl are required")
	}
	binDir, logDir = t.TempDir(), t.TempDir()
	for _, tool := range shimBinaries {
		next := "exit 0\n"
		if tool == "curl" {
			next = "exec " + shellSingleQuoteForTest(curlBin) + " \"$@\"\n"
		}
		script := "#!/bin/sh\n" +
			"f=" + shellSingleQuoteForTest(logDir) + "/$$\n" +
			"printf '%s\\n' \"$*\" > \"$f.args\"\n" +
			shellSingleQuoteForTest(envBin) + " > \"$f.env\"\n" + next
		if err := os.WriteFile(filepath.Join(binDir, tool), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return binDir, logDir
}

// shimRealToolRun is one recorded start of a stand-in tool.
type shimRealToolRun struct {
	args string
	env  []string
}

func readShimRealToolRuns(t *testing.T, logDir string) []shimRealToolRun {
	t.Helper()
	envFiles, err := filepath.Glob(filepath.Join(logDir, "*.env"))
	if err != nil {
		t.Fatal(err)
	}
	var runs []shimRealToolRun
	for _, envFile := range envFiles {
		env, err := os.ReadFile(envFile)
		if err != nil {
			t.Fatal(err)
		}
		args, err := os.ReadFile(strings.TrimSuffix(envFile, ".env") + ".args")
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, shimRealToolRun{args: strings.TrimSpace(string(args)), env: strings.Split(strings.TrimSpace(string(env)), "\n")})
	}
	return runs
}

// runShimForTest runs one PATH shim with the stand-in tools behind it and
// returns its exit code and output.
func runShimForTest(t *testing.T, shimDir, name, binDir string, env ...string) (int, string) {
	t.Helper()
	jq := hookArgvLookPath("jq")
	if jq == "" {
		t.Skip("jq is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemBashForTest(t), filepath.Join(shimDir, name), "--version", hookArgvPayloadMarker)
	cmd.Env = append(append(hookArgvBaseEnv(), env...), "HOME="+t.TempDir(),
		"PATH="+strings.Join([]string{shimDir, binDir, filepath.Dir(jq), "/usr/bin", "/bin"}, ":"))
	out, err := cmd.CombinedOutput()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run shim %s: %v", name, err)
	}
	return code, string(out)
}

// TestPathShimsLeaveTheRealToolsEnvironmentAlone: the real tool inherits the
// shim's environment, and an assignment keeps the export bit of an inherited
// variable. Run from an agent environment that exports the names the shims
// used for their own values (a user's API_TOKEN, ACTION, ...) and an empty
// DEFENSECLAW_GATEWAY_TOKEN, so that the bearer comes from the .token file,
// every shim must start the real tool, on the allow path and with the gateway
// down, with the user's values unchanged and no copy of the bearer.
func TestPathShimsLeaveTheRealToolsEnvironmentAlone(t *testing.T) {
	const token = "dccert-fake-token-shim-env"
	gateway, liveAddr := newHookArgvGateway(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	downAddr := listener.Addr().String()
	_ = listener.Close()
	userEnv := []string{"DEFENSECLAW_GATEWAY_TOKEN="}
	for _, name := range []string{"API_TOKEN", "API_ADDR", "AUTH_CONFIG", "INSPECT_BODY", "RESPONSE", "RESULT",
		"HTTP_CODE", "ACTION", "REASON", "SHIM_DIR", "REAL_BINARY", "CURL_BIN"} {
		userEnv = append(userEnv, name+"=dccert-user-value")
	}
	for _, state := range []struct{ name, addr string }{{"allow", liveAddr}, {"gateway-down", downAddr}} {
		shimDir := t.TempDir()
		if err := WriteShimScriptsWithToken(shimDir, state.addr, token); err != nil {
			t.Fatal(err)
		}
		for _, name := range shimBinaries {
			t.Run(state.name+"/"+name, func(t *testing.T) {
				binDir, logDir := writeShimRealTools(t)
				gateway.take()
				code, out := runShimForTest(t, shimDir, name, binDir, userEnv...)
				requests := gateway.take()
				if state.name == "allow" && (len(requests) != 1 || requests[0].authorization != "Bearer "+token) {
					t.Fatalf("gateway requests %+v, want one inspection with the bearer from .token\n%s", requests, out)
				}
				ran := false
				for _, run := range readShimRealToolRuns(t, logDir) {
					got := map[string]bool{}
					for _, line := range run.env {
						if strings.Contains(line, token) {
							t.Fatalf("%q started with the gateway bearer in its environment: %s", run.args, line)
						}
						got[line] = true
					}
					for _, want := range userEnv {
						if !got[want] {
							t.Errorf("%q started without the inherited %s", run.args, want)
						}
					}
					ran = ran || strings.Contains(run.args, hookArgvPayloadMarker)
				}
				if code != 0 || !ran {
					t.Fatalf("shim exit %d, real tool started %v, want the real tool run\n%s", code, ran, out)
				}
			})
		}
	}
}

// curlArgvViolations reports what a curl command line in script would
// disclose: a credential, the hook payload, or a body or config given inline
// rather than from a descriptor. Process substitutions on the command
// (N< <(printf ...)) are descriptors, not arguments, and must be written by
// the printf builtin.
func curlArgvViolations(script string) []string {
	var out []string
	for _, line := range shellLogicalLines(script) {
		line = templateDirective.ReplaceAllString(line, "")
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if authArgsUse.MatchString(line) && !authArgsCaller.MatchString(line) {
			out = append(out, "Authorization header array expanded outside defenseclaw_gateway_post/defenseclaw_sandbox_post: "+strings.TrimSpace(line))
		}
		loc := curlCommand.FindStringIndex(line)
		if loc == nil {
			continue
		}
		argv := line[loc[0]:]
		for {
			m := processSubstitution.FindStringIndex(argv)
			if m == nil {
				break
			}
			writer := argv[m[0]:m[1]]
			if !strings.Contains(writer, "<(printf ") {
				out = append(out, "a descriptor is not written by the printf builtin: "+writer)
			}
			argv = argv[:m[0]] + argv[m[1]:]
		}
		for _, rule := range curlArgvRules {
			if rule.re.MatchString(argv) {
				out = append(out, rule.what+": "+strings.TrimSpace(line))
			}
		}
		// A .curlrc in the agent's CURL_HOME or XDG_CONFIG_HOME could trace
		// the bearer and body to a file, or turn an HTTP 401 into a transport
		// failure; curl skips every .curlrc only when -q comes first.
		if curlRequest.MatchString(argv) && !curlNoRC.MatchString(argv) {
			out = append(out, "a curl request that reads a .curlrc (-q is not its first argument): "+strings.TrimSpace(line))
		}
	}
	return out
}

var (
	templateDirective   = regexp.MustCompile(`\{\{[^}]*\}\}`)
	curlCommand         = regexp.MustCompile(`(?:^|[\s;|&(])(?:curl|"\$_DC_SHIM_CURL")\s`)
	processSubstitution = regexp.MustCompile(`\d+<\s*<\(printf '[^']*'(?:\s+"[^"]*")*\)|\d+<\s*<\([^)]*\)`)
	curlRequest         = regexp.MustCompile(`--data-binary|-X\s+POST|https?://`)
	curlNoRC            = regexp.MustCompile(`^(?:[\s;|&(])?(?:curl|"\$_DC_SHIM_CURL")\s+-q\s`)
	authArgsUse         = regexp.MustCompile(`"\$\{AUTH_HEADER_ARGS\[@\]`)
	authArgsCaller      = regexp.MustCompile(`^\s*(?:RESPONSE="?\$\()?(?:defenseclaw_gateway_post|defenseclaw_sandbox_post)\s`)
	curlArgvRules       = []struct {
		re   *regexp.Regexp
		what string
	}{
		{regexp.MustCompile(`(?i)authorization`), "Authorization on a curl command line"},
		{regexp.MustCompile(`AUTH_HEADER_ARGS|TOKEN\b|TOKEN\}|_TOKEN`), "a token variable on a curl command line"},
		{regexp.MustCompile(`\$\{?[A-Za-z_]*(?:PAYLOAD|CONTENT|TOOL_INPUT|TOOL_OUTPUT|BODY|JSON|body|payload)\b`), "the hook payload on a curl command line"},
		{regexp.MustCompile(`(?:^|\s)(?:-d|--data|--data-raw|--data-ascii|--data-urlencode|--json|-F|--form)(?:\s|=)`), "an inline request body option"},
		{regexp.MustCompile(`--data-binary\s+(?:["']?[^@"'\s]|["']?@[^-/"'\s]|["']?@/(?:[^d]|d[^e]))`), "--data-binary not reading stdin or a descriptor"},
		{regexp.MustCompile(`(?:--config|-K)\s+["']?(?:[^/"'\s-]|/(?:[^d]|d[^e]))`), "--config not reading a descriptor"},
	}
)

// shellLogicalLines joins backslash-continued lines.
func shellLogicalLines(script string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(script, "\n") {
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	return out
}

// TestCurlArgvCheckCatchesTheOldHookTransport keeps the static check honest:
// the transport every connector hook used before is a violation.
func TestCurlArgvCheckCatchesTheOldHookTransport(t *testing.T) {
	for _, script := range []string{
		`curl -s -X POST "http://${API_ADDR}/x" -H "Authorization: Bearer ${API_TOKEN}" --max-time 10 2>/dev/null`,
		"curl -s -X POST \"http://${API_ADDR}/x\" \\\n  \"${AUTH_HEADER_ARGS[@]+\"${AUTH_HEADER_ARGS[@]}\"}\" \\\n  --data-binary @- 2>/dev/null",
		`curl -s -X POST "http://${API_ADDR}/x" -d "$PAYLOAD" 2>/dev/null`,
		`"$_DC_SHIM_CURL" -s -X POST "http://${_DC_SHIM_ADDR}/x" --data-binary "{\"a\":1}"`,
		`curl -s --config "$HOME/.curlrc-token" --data-binary @/dev/fd/9 http://x 9< <(printf '%s' "$PAYLOAD")`,
		`curl -s --data-binary @/dev/fd/9 http://x 9< <(/usr/bin/printf '%s' "$PAYLOAD")`,
		`defenseclaw_hook_post() { other_helper "http://x" "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}"; }`,
		`curl -s --noproxy '*' -X POST "http://x" --config /dev/fd/8 --data-binary @/dev/fd/9 8< <(printf '%s\n' "$A") 9< <(printf '%s' "$B")`,
	} {
		if len(curlArgvViolations(script)) == 0 {
			t.Errorf("the check accepts a command line that discloses a secret or the payload:\n%s", script)
		}
	}
	for _, script := range []string{
		`curl -q -s -w '\n%{http_code}' -X POST "$_dc_post_url" "${_dc_post_args[@]+"${_dc_post_args[@]}"}" --config /dev/fd/8 --data-binary @/dev/fd/9 2>/dev/null 8< <(printf 'header = "%s"\n' "$_dc_post_auth") 9< <(printf '%s' "$_dc_post_body")`,
		`printf '%s' "$JSON" | curl -q -s -X POST "http://x" --config /dev/fd/7 --data-binary @- 7< <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN") || true`,
		`RESPONSE=$(defenseclaw_gateway_post "http://${API_ADDR}/x" 5 "$CONTENT" -H "Content-Type: application/json" "${AUTH_HEADER_ARGS[@]+"${AUTH_HEADER_ARGS[@]}"}") || {`,
	} {
		if v := curlArgvViolations(script); len(v) != 0 {
			t.Errorf("the check rejects a descriptor transport: %v\n%s", v, script)
		}
	}
}

// TestRenderedHookScriptsKeepSecretsOffCurlCommandLines applies the check to
// every script DefenseClaw renders that can call the gateway: the templates
// themselves, the per-user, standalone-socket and sandbox renders of every
// connector, the PATH shims and the Codex notify bridges.
func TestRenderedHookScriptsKeepSecretsOffCurlCommandLines(t *testing.T) {
	scripts := map[string]string{}
	add := func(prefix string, dir string) {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			scripts[prefix+"/"+entry.Name()] = string(data)
		}
	}
	for _, set := range []struct {
		dir   string
		read  func(string) ([]byte, error)
		names func() ([]string, error)
	}{
		{"hooks", hookFS.ReadFile, func() ([]string, error) { return embeddedNames(hookFS.ReadDir, "hooks") }},
		{"shims", shimFS.ReadFile, func() ([]string, error) { return embeddedNames(shimFS.ReadDir, "shims") }},
	} {
		names, err := set.names()
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			if !strings.HasSuffix(name, ".sh") {
				continue
			}
			data, err := set.read(set.dir + "/" + name)
			if err != nil {
				t.Fatal(err)
			}
			scripts["template/"+set.dir+"/"+name] = string(data)
		}
	}
	for _, conn := range hookArgvShellConnectors {
		dir := t.TempDir()
		if err := WriteHookScriptsForConnectorObject(dir, "127.0.0.1:18970", "dccert-fake-token", conn); err != nil {
			t.Fatal(err)
		}
		add("per-user/"+conn.Name(), dir)
		socketDir := filepath.Join(t.TempDir(), ".defenseclaw", "hooks")
		opts := SetupOpts{
			DataDir:                filepath.Dir(socketDir),
			APIAddr:                "127.0.0.1:18970",
			APIToken:               "dccert-fake-token",
			ManagedEnterprise:      true,
			HookFailMode:           "closed",
			ManagedHookSocket:      "/var/run/defenseclaw/hook.sock",
			ManagedServiceUID:      461,
			ForeignHookGuardBinary: "/opt/cisco/defenseclaw/bin/defenseclaw-hook",
		}
		if err := WriteHookScriptsForConnectorObjectWithOpts(socketDir, opts, conn); err != nil {
			t.Fatal(err)
		}
		add("standalone/"+conn.Name(), socketDir)
	}
	if !strings.Contains(scripts["standalone/hermes/hermes-hook.sh"], "foreign-hook-check") {
		t.Fatal("the standalone Hermes render carries no foreign-hook guard to check")
	}
	shimDir := t.TempDir()
	if err := WriteShimScriptsWithToken(shimDir, "127.0.0.1:18970", "dccert-fake-token"); err != nil {
		t.Fatal(err)
	}
	add("shims", shimDir)
	for _, socket := range []string{"", "/var/run/defenseclaw/hook.sock"} {
		dataDir := t.TempDir()
		if err := writeCodexNotifyBridge(SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", ManagedEnterprise: socket != "", ManagedHookSocket: socket, ManagedServiceUID: 461}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dataDir, "notify-bridge.sh"))
		if err != nil {
			t.Fatal(err)
		}
		scripts["notify-bridge"+socket] = string(data)
	}
	for _, tc := range sandboxHookCases() {
		for _, file := range sandboxArtifactsFor(t, tc.provider, tc.version).Files {
			if bytes.HasPrefix(file.Data, []byte("#!")) || strings.HasSuffix(file.Path, ".sh") {
				scripts["sandbox/"+tc.connector+file.Path] = string(file.Data)
			}
		}
	}

	names := make([]string, 0, len(scripts))
	for name := range scripts {
		names = append(names, name)
	}
	sort.Strings(names)
	curlScripts := 0
	for _, name := range names {
		if curlCommand.MatchString(scripts[name]) {
			curlScripts++
		}
		for _, v := range curlArgvViolations(scripts[name]) {
			t.Errorf("%s: %s", name, v)
		}
	}
	if curlScripts < 20 {
		t.Fatalf("only %d of %d rendered scripts run curl; the check would pass without looking", curlScripts, len(scripts))
	}
}

func embeddedNames(readDir func(string) ([]os.DirEntry, error), dir string) ([]string, error) {
	entries, err := readDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}
