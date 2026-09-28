//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func shortGatewaySocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "dcg")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestBindManagedHookSocket(t *testing.T) {
	dir := shortGatewaySocketDir(t)
	path := filepath.Join(dir, "hook.sock")
	listener, err := bindManagedHookSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o666 {
		t.Fatalf("socket not created as a world-connectable socket: %v %v", info, err)
	}
	_ = listener.Close()

	// A stale socket this account owns is replaced.
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if unixListener, ok := stale.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	_ = stale.Close()
	listener, err = bindManagedHookSocket(path)
	if err != nil {
		t.Fatalf("stale own socket not replaced: %v", err)
	}
	_ = listener.Close()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("closing the hook socket listener left its path behind: %v", err)
	}

	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bindManagedHookSocket(regular); err == nil {
		t.Fatal("a regular file must never be replaced")
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := bindManagedHookSocket(filepath.Join(dir, "other.sock")); err == nil {
		t.Fatal("a world-writable socket directory must be refused")
	}
	if _, err := bindManagedHookSocket("relative.sock"); err == nil {
		t.Fatal("relative socket path must be refused")
	}
}

// TestBindManagedHookSocketWaitsForALiveListenerToLeave: during an
// overlapping restart the new gateway waits for the old one to release the
// socket and then binds it, instead of replacing it or running without it.
func TestBindManagedHookSocketWaitsForALiveListenerToLeave(t *testing.T) {
	path := filepath.Join(shortGatewaySocketDir(t), "hook.sock")
	live, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	restoreBudget := apiListenRetryBudget
	restoreInterval := hookSocketHeldRetryInterval
	t.Cleanup(func() {
		apiListenRetryBudget = restoreBudget
		hookSocketHeldRetryInterval = restoreInterval
	})
	apiListenRetryBudget = 10 * time.Second
	hookSocketHeldRetryInterval = 20 * time.Millisecond
	const hold = 300 * time.Millisecond
	released := make(chan struct{})
	go func() {
		time.Sleep(hold)
		_ = live.Close()
		close(released)
	}()
	listener, err := bindManagedHookSocketWhenFree(context.Background(), path)
	if err != nil {
		t.Fatalf("bind after the live listener left: %v", err)
	}
	defer listener.Close()
	select {
	case <-released:
	default:
		t.Fatal("the hook socket was bound while another listener still served it")
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("the new hook socket does not answer: %v", err)
	}
	_ = conn.Close()

	// A listener that is still live when the budget ends is left alone.
	apiListenRetryBudget = 100 * time.Millisecond
	if again, err := bindManagedHookSocketWhenFree(context.Background(), path); !errors.Is(err, errHookSocketInUse) {
		if again != nil {
			_ = again.Close()
		}
		t.Fatalf("bind over a socket that stays live = %v, want errHookSocketInUse", err)
	}
	if conn, err := net.DialTimeout("unix", path, time.Second); err != nil {
		t.Fatalf("the live socket stopped answering after a refused bind: %v", err)
	} else {
		_ = conn.Close()
	}
}

// TestHookSocketListenerCloseRemovesOnlyItsOwnSocket: a gateway that exits
// after its path was taken over must not delete the socket now at the path.
func TestHookSocketListenerCloseRemovesOnlyItsOwnSocket(t *testing.T) {
	path := filepath.Join(shortGatewaySocketDir(t), "hook.sock")
	first, err := bindManagedHookSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	second, err := bindManagedHookSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := first.Close(); err != nil {
		t.Fatalf("close the first listener: %v", err)
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("closing the first listener removed the second listener's socket: %v", err)
	}
	_ = conn.Close()
	if err := second.Close(); err != nil {
		t.Fatalf("close the second listener: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("closing the second listener left its socket behind: %v", err)
	}
}

// hookSocketTestServer configures startTestHookSocketServer.
type hookSocketTestServer struct {
	ledger        string         // guardian authorization ledger (trusted without the ownership checks); "" writes none
	machinePolicy []string       // the descriptor's machine-policy connectors
	health        *SidecarHealth // nil selects a fresh one
}

// startTestHookSocketServer runs the real standalone hook socket server on a
// temporary socket, with this account as the service account, and returns
// the socket path, the API server and the audit store.
func startTestHookSocketServer(t *testing.T, opts hookSocketTestServer) (string, *APIServer, *audit.Store) {
	t.Helper()
	dir := shortGatewaySocketDir(t)
	socket := filepath.Join(dir, "hook.sock")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, "")
	if opts.ledger != "" {
		if err := os.MkdirAll(managed.HookGuardianAuthorizationDir(dataDir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(managed.HookGuardianAuthorizationPath(dataDir), []byte(opts.ledger), 0o600); err != nil {
			t.Fatal(err)
		}
		restoreValidate := validateManagedGuardianAuthorization
		validateManagedGuardianAuthorization = func(string, string) error { return nil }
		t.Cleanup(func() { validateManagedGuardianAuthorization = restoreValidate })
	}
	current, err := osuser.Current()
	if err != nil {
		t.Fatal(err)
	}
	restoreDescriptor := loadStandaloneRuntimeDescriptor
	restoreInherited := inheritedHookListener
	t.Cleanup(func() {
		loadStandaloneRuntimeDescriptor = restoreDescriptor
		inheritedHookListener = restoreInherited
	})
	loadStandaloneRuntimeDescriptor = func(string) (*managed.RuntimeDescriptor, error) {
		return &managed.RuntimeDescriptor{
			SchemaVersion:           managed.RuntimeDescriptorSchemaVersion,
			Profile:                 managed.ProfileStandalone,
			ServiceUser:             current.Username,
			ServiceUID:              os.Getuid(),
			APIAddr:                 managed.StandaloneAPIAddr,
			HookSocket:              socket,
			MachinePolicyConnectors: opts.machinePolicy,
		}, nil
	}
	inheritedHookListener = func() (net.Listener, bool, error) { return nil, false, nil }

	fixture := newSidecarRuntimeFixture(t, true)
	fingerprintEngine, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := fixture.store
	logger := audit.NewLogger(store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{
		runtime: fixture.runtime, redactionEngine: fingerprintEngine,
	})
	cfg := &config.Config{DeploymentMode: "managed_enterprise", DataDir: dataDir}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Mode = "observe"
	health := opts.health
	if health == nil {
		health = NewSidecarHealth()
	}
	api := NewAPIServer("127.0.0.1:0", health, nil, store, logger, cfg)
	api.SetConnectorRegistry(connector.NewDefaultRegistry())
	// The refusal rows come from the API's own canonical runtime binding.
	api.bindOTLPObservabilityRuntime(fixture.runtime)

	ctx, cancel := context.WithCancel(context.Background())
	server, listener, err := api.newManagedHookSocketServer(ctx, func(h http.Handler) http.Handler { return h })
	if err != nil || server == nil {
		cancel()
		t.Fatalf("hook socket server: %v %v", server, err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
	})
	return socket, api, store
}

// hookSocketClient opens a fresh connection for every request, so each
// request is a new accepted connection on the server.
func hookSocketClient(socket string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
}

// hookSocketCall sends one request to the hook socket. It returns an error
// instead of failing the test, so goroutines can use it.
func hookSocketCall(client *http.Client, method, path string, headers map[string]string, body []byte) (int, string, error) {
	request, err := http.NewRequest(method, "http://127.0.0.1:18970"+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(data), nil
}

func hookSocketPost(client *http.Client, path string, body []byte) (int, string, error) {
	return hookSocketCall(client, http.MethodPost, path, nil, body)
}

// TestManagedHookSocketServesOnlyAuthorizedHookRoutes runs the real hook
// socket server: kernel credentials identify the caller, the ledger and the
// descriptor decide, a caller past its request budget is answered 429, and
// management routes are not reachable at all.
func TestManagedHookSocketServesOnlyAuthorizedHookRoutes(t *testing.T) {
	current, err := osuser.Current()
	if err != nil {
		t.Fatal(err)
	}
	socket, api, _ := startTestHookSocketServer(t, hookSocketTestServer{
		ledger:        fmt.Sprintf(`{"version":1,"ok":true,"protected_targets":[{"user":%q,"connector":"claudecode","ok":true}]}`, current.Username),
		machinePolicy: []string{"codex"},
	})
	client := hookSocketClient(socket, 10*time.Second)
	post := func(path string, headers map[string]string, body interface{}) (int, string) {
		t.Helper()
		payload, _ := json.Marshal(body)
		all := map[string]string{"X-DefenseClaw-Client": "claude-code-hook/1.0"}
		for key, value := range headers {
			all[key] = value
		}
		status, text, err := hookSocketCall(client, http.MethodPost, path, all, payload)
		if err != nil {
			t.Fatal(err)
		}
		return status, text
	}
	event := map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "s1", "tool_use_id": "t1",
		"tool_name": "Bash", "tool_input": map[string]interface{}{"command": "echo hello"},
	}

	if status, body := post("/api/v1/claude-code/hook", nil, event); status == http.StatusForbidden || status == http.StatusUnauthorized {
		t.Fatalf("enrolled per-user connector refused: %d %s", status, body)
	}
	if status, body := post("/api/v1/cursor/hook", nil, event); status != http.StatusForbidden || !strings.Contains(body, managedHookReasonUIDUnregistered) {
		t.Fatalf("unenrolled per-user connector: %d %s", status, body)
	}
	if status, body := post("/api/v1/inspect/tool", map[string]string{"X-DefenseClaw-Connector": "cursor"},
		map[string]interface{}{"tool": "Bash", "args": map[string]interface{}{"command": "id"}}); status != http.StatusForbidden {
		t.Fatalf("inspect for an unenrolled connector: %d %s", status, body)
	}
	if status, body := post("/api/v1/inspect/tool", map[string]string{"X-DefenseClaw-Connector": "claudecode"},
		map[string]interface{}{"tool": "Bash", "args": map[string]interface{}{"command": "id"}}); status == http.StatusForbidden || status == http.StatusUnauthorized {
		t.Fatalf("inspect for the enrolled connector refused: %d %s", status, body)
	}
	for _, path := range []string{"/status", "/config/patch", "/enforce/allow", "/v1/guardrail/config", "/api/v1/admin/shutdown"} {
		if status, _ := post(path, map[string]string{"Authorization": "Bearer anything"}, map[string]string{}); status != http.StatusNotFound && status != http.StatusForbidden {
			t.Fatalf("management route %s reachable on the hook socket: %d", path, status)
		}
	}

	// Each account has its own request budget; past it the socket answers 429.
	now := time.Now()
	api.hookCallerLimits.mu.Lock()
	api.hookCallerLimits.callers, api.hookCallerLimits.rate, api.hookCallerLimits.burst = nil, 1, 1
	api.hookCallerLimits.now = func() time.Time { return now }
	api.hookCallerLimits.mu.Unlock()
	post("/api/v1/claude-code/hook", nil, event)
	if status, body := post("/api/v1/claude-code/hook", nil, event); status != http.StatusTooManyRequests || !strings.Contains(body, managedHookReasonRateLimited) {
		t.Fatalf("a request past the caller's budget: %d %s", status, body)
	}
}

// TestManagedHookSocketServesHealth: the Linux and macOS lifecycle reads
// gateway readiness from the hook socket, because another local account can
// hold 127.0.0.1:18970 and answer /health there. The socket answers GET
// /health for any local caller, as the TCP API does, and reports the API
// listener's state; every other route still needs peer authorization.
func TestManagedHookSocketServesHealth(t *testing.T) {
	health := NewSidecarHealth()
	health.SetAPI(StateError, "listen tcp 127.0.0.1:18970: bind: address already in use",
		map[string]interface{}{"addr": "127.0.0.1:18970", "tcp_bind_retrying": true})
	// No ledger: the caller has no row and sends no credential.
	socket, _, _ := startTestHookSocketServer(t, hookSocketTestServer{health: health})
	client := hookSocketClient(socket, 10*time.Second)

	status, body, err := hookSocketCall(client, http.MethodGet, "/health", nil, nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("GET /health on the hook socket: %d %s %v", status, body, err)
	}
	var document struct {
		API struct {
			State   string                 `json:"state"`
			Details map[string]interface{} `json:"details"`
		} `json:"api"`
		Provenance map[string]interface{} `json:"provenance"`
	}
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatalf("health document: %v\n%s", err, body)
	}
	if document.API.State != string(StateError) || document.API.Details["tcp_bind_retrying"] != true || document.Provenance == nil {
		t.Fatalf("the hook socket health must carry the API listener state: %s", body)
	}
	if status, body, _ := hookSocketPost(client, "/health", []byte("{}")); status == http.StatusOK {
		t.Fatalf("POST /health must not bypass peer authorization: %d %s", status, body)
	}
	if status, body, _ := hookSocketCall(client, http.MethodGet, "/status", nil, nil); status != http.StatusForbidden && status != http.StatusNotFound {
		t.Fatalf("a management route is reachable on the hook socket: %d %s", status, body)
	}
}

// The managed OpenCode plugin reaches the gateway through the hook binary
// over the hook socket for users DefenseClaw never enrolled per user: once
// the descriptor records OpenCode as machine policy the socket admits every
// local user for it and answers with the hook_output the plugin applies.
// Without that record an unenrolled user stays refused.
func TestManagedHookSocketAdmitsTheManagedOpenCodePlugin(t *testing.T) {
	post := func(t *testing.T, machinePolicy []string) (int, string) {
		t.Helper()
		// A healthy ledger that enrolls nobody for OpenCode.
		socket, _, _ := startTestHookSocketServer(t, hookSocketTestServer{
			ledger: `{"version":1,"ok":true,"protected_targets":[]}`, machinePolicy: machinePolicy,
		})
		// The payload the managed plugin hands the hook binary, which
		// forwards it unchanged with the plugin's client name.
		payload, _ := json.Marshal(map[string]interface{}{
			"hook_event_name": "tool.execute.before", "tool_name": "bash",
			"tool_input": map[string]interface{}{"command": "echo hello"},
			"session_id": "s1", "tool_call_id": "c1", "cwd": filepath.Dir(socket),
			"load_heartbeat": true, "arguments_authoritative": true, "mcp_identity_status": "not_mcp",
		})
		status, body, err := hookSocketCall(hookSocketClient(socket, 10*time.Second), http.MethodPost,
			"/api/v1/opencode/hook", map[string]string{"X-DefenseClaw-Client": "opencode-plugin/1.0"}, payload)
		if err != nil {
			t.Fatal(err)
		}
		return status, body
	}

	status, body := post(t, []string{"opencode"})
	if status != http.StatusOK {
		t.Fatalf("machine-policy OpenCode refused for an unenrolled user: %d %s", status, body)
	}
	// The plugin reads mode and, on a block, hook_output.decision.
	var answer struct {
		Action     string                 `json:"action"`
		Mode       string                 `json:"mode"`
		HookOutput map[string]interface{} `json:"hook_output"`
	}
	if err := json.Unmarshal([]byte(body), &answer); err != nil || answer.Mode != "observe" || answer.Action != "allow" {
		t.Fatalf("unexpected answer for an allowed call: %v %s", err, body)
	}
	if decision, _ := answer.HookOutput["decision"].(string); decision == "deny" || decision == "block" {
		t.Fatalf("an allowed call must not carry a block decision: %s", body)
	}
	if status, body := post(t, nil); status != http.StatusForbidden || !strings.Contains(body, managedHookReasonUIDUnregistered) {
		t.Fatalf("per-user OpenCode for an unenrolled user: %d %s", status, body)
	}
}
