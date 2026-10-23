// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCodexHookNativeTransportUsesScopedTokenAndPayload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	const scopedToken = "codex-scoped-transport-token"
	const payload = `{"hook_event_name":"PreToolUse","tool_name":"Read","private":"payload-must-not-enter-argv"}`
	type receivedRequest struct{ authorization, body string }
	received := make(chan receivedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body bytes.Buffer
		_, _ = body.ReadFrom(r.Body)
		received <- receivedRequest{r.Header.Get("Authorization"), body.String()}
		_, _ = w.Write([]byte(`{"action":"allow","codex_output":{"decision":"allow"}}`))
	}))
	defer server.Close()
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	hooksDir := filepath.Join(home, "hooks")
	if err := WriteHookScriptsForConnectorObject(
		hooksDir, strings.TrimPrefix(server.URL, "http://"), scopedToken, NewCodexConnector(),
	); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", codexBoundShellHookArgsForTest(t, filepath.Join(hooksDir, "codex-hook.sh"), "PreToolUse")...)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home,
		"DEFENSECLAW_GATEWAY_TOKEN=inherited-generic-token", "API_TOKEN=inherited-api-token", "PAYLOAD=inherited-payload")
	cmd.Stdin = strings.NewReader(payload)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run Codex hook: %v\n%s", err, output)
	}
	select {
	case got := <-received:
		if got.authorization != "Bearer "+scopedToken || got.body != payload {
			t.Fatalf("native request header/body = %+v", got)
		}
		if strings.Contains(got.authorization+got.body, "inherited-") {
			t.Fatalf("native request inherited unrelated credentials or payload: %+v", got)
		}
	default:
		t.Fatal("Codex hook made no native request to the verified gateway")
	}
	if !strings.Contains(string(output), `"decision":"allow"`) {
		t.Fatalf("hook response = %q", output)
	}
}

func TestCodexHookPreservesTokenMetacharactersInNativeTransport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	const scopedToken = "codex-scoped\\token-\"quoted"
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"action":"allow","codex_output":{"decision":"allow"}}`))
	}))
	defer server.Close()
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	hooksDir := filepath.Join(home, "hooks")
	if err := WriteHookScriptsForConnectorObject(
		hooksDir, strings.TrimPrefix(server.URL, "http://"), scopedToken, NewCodexConnector(),
	); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", codexBoundShellHookArgsForTest(t, filepath.Join(hooksDir, "codex-hook.sh"), "PreToolUse")...)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home)
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Read"}`)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run Codex hook: %v\n%s", err, output)
	}
	select {
	case got := <-received:
		if got != "Bearer "+scopedToken {
			t.Fatalf("native Authorization header = %q, want exact token", got)
		}
	default:
		t.Fatal("Codex hook made no native request")
	}
}

func TestCodexHookRejectsTokenLineBreakBeforeNativeRequest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer server.Close()
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	hooksDir := filepath.Join(home, "hooks")
	if err := WriteHookScriptsForConnectorObject(
		hooksDir, strings.TrimPrefix(server.URL, "http://"), "initial-scoped-token", NewCodexConnector(),
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, ".hook-codex.token"), []byte("invalid\rtoken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", codexBoundShellHookArgsForTest(t, filepath.Join(hooksDir, "codex-hook.sh"), "PreToolUse")...)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home)
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Read"}`)
	output, _ := cmd.CombinedOutput()
	if strings.Contains(string(output), "invalid\rtoken") || received.Load() != 0 {
		t.Fatalf("invalid token escaped to output or gateway: requests=%d output=%q", received.Load(), output)
	}
}

func codexBoundShellHookArgsForTest(t *testing.T, hookPath, event string) []string {
	t.Helper()
	contract, err := codexHookContractForSetup(SetupOpts{})
	if err != nil {
		t.Fatalf("resolve default Codex hook contract: %v", err)
	}
	return []string{hookPath, "--event", event, "--hook-contract", contract.ContractID}
}
