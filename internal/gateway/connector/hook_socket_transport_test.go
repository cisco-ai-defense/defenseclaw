// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// shellHookSocketConnectorTemplates are the connector shell hooks a
// per-user enterprise registration can run.
var shellHookSocketConnectorTemplates = []string{
	"antigravity-hook.sh", "claude-code-hook.sh", "codex-hook.sh", "copilot-hook.sh",
	"cursor-hook.sh", "devin-hook.sh", "hermes-hook.sh",
	"kiro-hook.sh", "openhands-hook.sh",
}

// TestShellHookTemplatesCarryTheSocketTransportOnlyWhenConfigured: every
// connector shell hook sends its one gateway request through the unix hook
// socket, without a bearer, when a standalone socket is configured, and
// contains no trace of it otherwise.
func TestShellHookTemplatesCarryTheSocketTransportOnlyWhenConfigured(t *testing.T) {
	transport := shellHookSocketTransport("/opt/cisco/defenseclaw/run/hook's.sock", 497, "/opt/defenseclaw/bin/defenseclaw-hook")
	for _, name := range shellHookSocketConnectorTemplates {
		content, err := hookFS.ReadFile("hooks/" + name)
		if err != nil {
			t.Fatal(err)
		}
		base := templateData{APIAddr: "127.0.0.1:18970", FailMode: "closed", Managed: true, TokenFile: ".token-x", ScopedToken: true, ConnectorName: "x"}
		tcp, err := renderTemplate(string(content), base)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(tcp, "DEFENSECLAW_HOOK_SOCKET") || strings.Contains(tcp, "unix-socket") {
			t.Fatalf("%s: the TCP render mentions the hook socket", name)
		}
		base.HookSocketTransportSH = transport
		socket, err := renderTemplate(string(content), base)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Count(socket, `--unix-socket "${DEFENSECLAW_HOOK_SOCKET}"`) != 1 {
			t.Fatalf("%s: the gateway request does not use the hook socket", name)
		}
		if !strings.Contains(socket, "DEFENSECLAW_HOOK_SOCKET='/opt/cisco/defenseclaw/run/hook'\"'\"'s.sock'\n") ||
			!strings.Contains(socket, "DEFENSECLAW_HOOK_SOCKET_UID=497\n") {
			t.Fatalf("%s: socket path or service uid not rendered as one shell word", name)
		}
		// The administrator-owned binary that reads the Kerberos cache is
		// named before the identity headers are built (GAP-0194).
		if !strings.Contains(socket, "DEFENSECLAW_SESSION_FACTS_BIN='/opt/defenseclaw/bin/defenseclaw-hook'\nexport DEFENSECLAW_SESSION_FACTS_BIN\n") ||
			strings.Contains(tcp, "DEFENSECLAW_SESSION_FACTS_BIN") {
			t.Fatalf("%s: session facts binary rendered wrongly", name)
		}
		block := strings.Index(socket, "if ! defenseclaw_hook_socket_trusted; then")
		auth := strings.Index(socket, "\nAUTH_HEADER_ARGS=()")
		failDefined := strings.Index(socket, "\nfail_unreachable() {")
		if block < 0 || auth < block || failDefined < 0 || failDefined > block {
			t.Fatalf("%s: the socket check must run after fail_unreachable is defined and before the bearer header is built", name)
		}
	}
}

// recordingHookSocketGateway records each request and answers with response
// (by default an allow that names the hook socket).
type recordingHookSocketGateway struct {
	response      any
	mu            sync.Mutex
	authorization []string
	paths         []string
	bodies        []string
}

func (g *recordingHookSocketGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	g.authorization = append(g.authorization, r.Header.Get("Authorization"))
	g.paths = append(g.paths, r.URL.Path)
	g.bodies = append(g.bodies, string(body))
	g.mu.Unlock()
	response := g.response
	if response == nil {
		response = map[string]interface{}{
			"action":      "allow",
			"hook_output": map[string]string{"decision": "allow", "transport_marker": "hook-socket"},
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// recorded returns copies of the request paths, Authorization headers and
// bodies the gateway received.
func (g *recordingHookSocketGateway) recorded() (paths, authorization, bodies []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.paths...), append([]string(nil), g.authorization...), append([]string(nil), g.bodies...)
}

// hookSocketFixture is a recording gateway on a unix hook socket whose
// directory only this account can write, plus a listener on a TCP port that
// stands for another local user holding the API port: a standalone bridge
// must reach the gateway only through the socket and never connect to it.
type hookSocketFixture struct {
	root, runDir, socket string
	gateway              *recordingHookSocketGateway
	held                 net.Listener
	tcpConnections       atomic.Int32
}

func newHookSocketFixture(t *testing.T, prefix string, response any) *hookSocketFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the standalone hook socket is unix-only")
	}
	// Unix socket paths are length-limited; keep the directory short.
	root, err := os.MkdirTemp("/tmp", prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	f := &hookSocketFixture{root: root, runDir: filepath.Join(root, "run"), gateway: &recordingHookSocketGateway{response: response}}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f.socket = filepath.Join(f.runDir, "hook.sock")
	listener, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: f.gateway}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	if f.held, err = net.Listen("tcp4", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.held.Close() })
	go func() {
		for {
			conn, err := f.held.Accept()
			if err != nil {
				return
			}
			f.tcpConnections.Add(1)
			_ = conn.Close()
		}
	}()
	return f
}

// untrustSocketDir makes the socket directory writable by anyone: it then
// proves nothing about who listens on the socket.
func (f *hookSocketFixture) untrustSocketDir(t *testing.T) {
	t.Helper()
	if err := os.Chmod(f.runDir, 0o777); err != nil {
		t.Fatal(err)
	}
}

// requireOnlyTheTrustedRequest fails unless the gateway received exactly one
// bearer-free request for path over the socket and nothing reached the TCP
// port.
func (f *hookSocketFixture) requireOnlyTheTrustedRequest(t *testing.T, path string) {
	t.Helper()
	paths, authorization, _ := f.gateway.recorded()
	if len(paths) != 1 || paths[0] != path || authorization[0] != "" {
		t.Fatalf("hook socket requests = %v (authorization %q), want one bearer-free request for %s", paths, authorization, path)
	}
	if n := f.tcpConnections.Load(); n != 0 {
		t.Fatalf("the standalone bridge connected to the TCP API port %d times", n)
	}
}

// TestManagedStandaloneShellHookUsesOnlyTheVerifiedHookSocket runs a real
// per-user shell hook rendered for a standalone install. It must reach the
// gateway through the hook socket without a bearer, never touch the TCP
// port (which another local user may hold), and fail closed without sending
// anything when the socket directory could have been written by someone
// else.
func TestManagedStandaloneShellHookUsesOnlyTheVerifiedHookSocket(t *testing.T) {
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is required to run shell hooks")
	}
	f := newHookSocketFixture(t, "dcsh", nil)
	dataDir := filepath.Join(f.root, "home", ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	opts := SetupOpts{
		DataDir:            dataDir,
		APIAddr:            f.held.Addr().String(),
		APIToken:           "connector-scoped-token-shared-by-every-user",
		HookAPIToken:       "connector-scoped-token-shared-by-every-user",
		HookAPITokenScoped: true,
		ManagedEnterprise:  true,
		HookFailMode:       "closed",
		ManagedHookSocket:  f.socket,
		ManagedServiceUID:  os.Getuid(),
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewOpenHandsConnector()); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hookDir, "openhands-hook.sh")
	bakeHookPathForTest(t, hookPath, filepath.Dir(curlPath)+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")

	run := func() (int, string, string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", hookPath)
		cmd.Env = append(os.Environ(), "HOME="+filepath.Join(f.root, "home"))
		cmd.Stdin = strings.NewReader(`{"event_type":"PreToolUse","tool_name":"execute_bash","tool_input":{"command":"echo marker"}}`)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatalf("run hook: %v", err)
		}
		return code, stdout.String(), stderr.String()
	}

	if code, stdout, stderr := run(); code != 0 || !strings.Contains(stdout, "hook-socket") {
		t.Fatalf("hook over the verified socket: exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
	f.untrustSocketDir(t)
	if code, stdout, stderr := run(); code != 2 || !strings.Contains(stderr, "hook socket") {
		t.Fatalf("untrusted socket directory: exit %d stdout=%q stderr=%q, want a closed failure", code, stdout, stderr)
	}
	f.requireOnlyTheTrustedRequest(t, "/api/v1/openhands/hook")
}

// TestManagedStandaloneCodexNotifyBridgeUsesOnlyTheVerifiedHookSocket runs
// the Codex notify bridge rendered for a standalone install. It must send
// the turn through the hook socket without reading or sending the codex
// bearer, never touch the TCP port (which another local user may hold), and
// drop the event without sending anything when the socket directory could
// have been written by someone else. Without a socket it keeps TCP.
func TestManagedStandaloneCodexNotifyBridgeUsesOnlyTheVerifiedHookSocket(t *testing.T) {
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is required to run the notify bridge")
	}
	f := newHookSocketFixture(t, "dcnb", nil)
	dataDir := filepath.Join(f.root, "home", ".defenseclaw")
	tokenPath, err := HookAPITokenFilePath(dataDir, "codex")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("codex-token-shared-by-every-user\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{
		DataDir:           dataDir,
		APIAddr:           f.held.Addr().String(),
		ManagedEnterprise: true,
		ManagedHookSocket: f.socket,
		ManagedServiceUID: os.Getuid(),
	}
	if err := writeCodexNotifyBridge(opts); err != nil {
		t.Fatal(err)
	}
	bridgePath := filepath.Join(dataDir, "notify-bridge.sh")
	bridge, err := os.ReadFile(bridgePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(bridge), `--unix-socket "${DEFENSECLAW_HOOK_SOCKET}"`) != 1 ||
		strings.Contains(string(bridge), "TOKEN_FILE") || strings.Contains(string(bridge), "Authorization") {
		t.Fatalf("the standalone notify bridge does not use only the hook socket:\n%s", bridge)
	}

	const payload = `{"type":"agent-turn-complete","turn-id":"marker"}`
	run := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", bridgePath, payload)
		cmd.Env = []string{"PATH=" + filepath.Dir(curlPath) + ":/usr/bin:/bin"}
		if output, err := cmd.CombinedOutput(); err != nil || len(output) != 0 {
			t.Fatalf("notify bridge: %v output=%q, want a silent success", err, output)
		}
	}
	run()
	if _, _, bodies := f.gateway.recorded(); len(bodies) != 1 || bodies[0] != payload {
		t.Fatalf("notify bodies = %q, want the one turn", bodies)
	}
	f.untrustSocketDir(t)
	run()
	f.requireOnlyTheTrustedRequest(t, "/api/v1/codex/notify")

	opts.ManagedHookSocket = ""
	if err := writeCodexNotifyBridge(opts); err != nil {
		t.Fatal(err)
	}
	if bridge, err = os.ReadFile(bridgePath); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bridge), "DEFENSECLAW_HOOK_SOCKET") || !strings.Contains(string(bridge), "--config '/dev/fd/8'") {
		t.Fatalf("the notify bridge without a hook socket does not keep the TCP transport:\n%s", bridge)
	}
}

// TestHookTransportDriftedTreatsAnUnrecordedTransportAsTCP: a lock records
// the transport its hooks were rendered for, a lock written before the
// transport was recorded counts as TCP, and any change of transport, socket
// path or trusted service uid is drift. TCP locks serialize as before.
func TestHookTransportDriftedTreatsAnUnrecordedTransportAsTCP(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows hooks always use the TCP transport")
	}
	conn, ok := NewDefaultRegistry().Get("codex")
	if !ok {
		t.Fatal("codex connector is not registered")
	}
	tcp := SetupOpts{ManagedEnterprise: true, DataDir: t.TempDir()}
	socket := tcp
	socket.ManagedHookSocket = "/var/run/defenseclaw/hook.sock"
	socket.ManagedServiceUID = 461
	otherUID := socket
	otherUID.ManagedServiceUID = 462
	unmanaged := socket
	unmanaged.ManagedEnterprise = false

	roundTrip := func(entry HookContractLockEntry) (HookContractLockEntry, string) {
		t.Helper()
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		var out HookContractLockEntry
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		return out, string(data)
	}
	var preUpgrade HookContractLockEntry
	if err := json.Unmarshal([]byte(`{"connector":"codex","registration_posture":{"managed_enterprise":true,"guardrail_mode":"observe","hilt_enabled":false}}`), &preUpgrade); err != nil {
		t.Fatal(err)
	}
	tcpLock, tcpJSON := roundTrip(newHookContractLockEntry(tcp, conn, "test"))
	if strings.Contains(tcpJSON, "hook_socket") {
		t.Fatalf("a TCP lock records a hook socket: %s", tcpJSON)
	}
	socketLock, socketJSON := roundTrip(newHookContractLockEntry(socket, conn, "test"))
	if !strings.Contains(socketJSON, `"hook_socket":"/var/run/defenseclaw/hook.sock"`) || !strings.Contains(socketJSON, `"hook_socket_service_uid":461`) {
		t.Fatalf("a socket lock does not record its transport: %s", socketJSON)
	}

	for _, tc := range []struct {
		name  string
		lock  HookContractLockEntry
		opts  SetupOpts
		drift bool
	}{
		{"no posture, socket configured", HookContractLockEntry{Connector: "codex"}, socket, true},
		{"pre-upgrade posture, TCP configured", preUpgrade, tcp, false},
		{"TCP lock, socket outside a managed install", tcpLock, unmanaged, false},
		{"socket lock, same socket", socketLock, socket, false},
		{"socket lock, other service uid", socketLock, otherUID, true},
	} {
		if got := HookTransportDrifted(tc.lock, tc.opts); got != tc.drift {
			t.Errorf("%s: HookTransportDrifted = %v, want %v", tc.name, got, tc.drift)
		}
	}
}
