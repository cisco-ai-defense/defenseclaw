// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1744: a call the gateway answered with a server error (a Codex start
// refused because its runtime registration cannot be repaired, HTTP 503) is
// blocked, but the block said the hook "could not reach its gateway" and to
// check its status. The gateway is up: the block names its answer.
func TestPerUserShellHookNamesTheGatewaysServerErrorAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"Codex runtime registration is unavailable"}`))
	}))
	defer server.Close()
	for _, conn := range []Connector{NewCodexConnector(), NewClaudeCodeConnector()} {
		t.Run(conn.Name(), func(t *testing.T) {
			invoke := hookArgvConnectorCase(t, conn.Name())
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			writeOutageTierConfig(t, home, outageDefaultTierConfig)
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "scoped-test-token", HookFailMode: "open"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, invoke.script)}, invoke.args...)...)
			cmd.Stdin = strings.NewReader(invoke.stdin)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
			output, err := cmd.CombinedOutput()
			text := string(output)
			if !hookCallBlocked(err, text) {
				t.Fatalf("a gateway server error must block (exit %v):\n%s", err, text)
			}
			if !strings.Contains(text, "answered with an error (HTTP 503: Codex runtime registration is unavailable)") ||
				strings.Contains(text, "could not reach its gateway") {
				t.Fatalf("the block does not name the gateway's answer:\n%s", text)
			}
			// The stderr line names the answer too: not an unreachable
			// gateway or a fail-mode outcome (GAP-1744 reopen).
			if strings.Contains(text, "gateway unreachable") || strings.Contains(text, "fail mode closed") ||
				!strings.Contains(text, "the gateway answered with an error (HTTP 503: Codex runtime registration is unavailable)") {
				t.Fatalf("stderr reads as an outage:\n%s", text)
			}
		})
	}
}

// GAP-1744: when the gateway's error names its repair step, that step is
// the block's next step (no "run doctor" after it).
func TestPerUserShellHookUsesTheRepairStepTheGatewayNamed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"Codex runtime registration is unavailable; run: defenseclaw setup codex --yes"}`))
	}))
	defer server.Close()
	for _, conn := range []Connector{NewCodexConnector(), NewClaudeCodeConnector()} {
		t.Run(conn.Name(), func(t *testing.T) {
			invoke := hookArgvConnectorCase(t, conn.Name())
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			writeOutageTierConfig(t, home, outageDefaultTierConfig)
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "scoped-test-token", HookFailMode: "open"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, invoke.script)}, invoke.args...)...)
			cmd.Stdin = strings.NewReader(invoke.stdin)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
			output, err := cmd.CombinedOutput()
			text := string(output)
			if !hookCallBlocked(err, text) {
				t.Fatalf("a gateway server error must block (exit %v):\n%s", err, text)
			}
			if !strings.Contains(text, "run: defenseclaw setup codex --yes).") || strings.Contains(text, "Run defenseclaw doctor") {
				t.Fatalf("the block does not name the gateway's repair step:\n%s", text)
			}
		})
	}
}
