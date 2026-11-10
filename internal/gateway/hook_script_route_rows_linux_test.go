// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The flood lane's call-to-row join on the shipped script, with nothing
// written by the test but the calls: the installed Claude Code hook posts each
// call to the real handler, which serves it, loses its audit write, or drops
// the connection. Every call the script answered has a row after the failure
// report ran (calls_without_any_row 0) and only a call it denied has a block
// row, whether the row comes from the gateway (its decision row, or the line
// it kept when its audit write failed) or from the line the script itself
// wrote for a connection that was cut (GAP-1031).
func TestInstalledScriptCallsAllHaveARowOnceTheFailureReportRan(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the installed hook helper")
	}
	f := newAuditFailureHookFixture(t, "")
	home := t.TempDir()
	data := filepath.Join(home, ".defenseclaw")
	f.api.scannerCfg.DataDir = data
	hookDir := filepath.Join(data, "hooks")
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}

	var mode atomic.Value
	mode.Store("serve")
	hook := f.api.handleAgentHook("claudecode")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load().(string) {
		case "drop":
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		case "audit_fail":
			f.emitter.fail = true
			defer func() { f.emitter.fail = false }()
			hook.ServeHTTP(w, r)
		default:
			hook.ServeHTTP(w, r)
		}
	}))
	defer server.Close()

	if err := connector.WriteHookScriptsForConnectorObjectWithOpts(hookDir, connector.SetupOpts{
		DataDir: data, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "scoped-test-token", HookFailMode: "open",
	}, connector.NewClaudeCodeConnector()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "config.yaml"), []byte("config_version: 9\nobservability: {}\nguardrail:\n  mode: action\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "gateway.pid"), []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", filepath.Join(binDir, "defenseclaw-hook-post"), "./cmd/defenseclaw-hook-post")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the hook helper: %v: %s", err, output)
	}
	// The script proves the gateway binary beside the helper; the helper
	// binary stands in for it, as nothing here runs a gateway command.
	helper, err := os.ReadFile(filepath.Join(binDir, "defenseclaw-hook-post"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "defenseclaw-gateway"), helper, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".gateway-helper"), []byte(filepath.Join(binDir, "defenseclaw-gateway")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	call := func(toolID string) (string, error) {
		body, err := json.Marshal(map[string]any{
			"session_id": "script-" + toolID, "hook_event_name": "PreToolUse", "cwd": work,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": toolID,
			"tool_input": map[string]any{"command": "echo ok"},
		})
		if err != nil {
			return "", err
		}
		cmd := exec.Command("bash", filepath.Join(hookDir, "claude-code-hook.sh"))
		cmd.Dir = work
		cmd.Stdin = bytes.NewReader(body)
		cmd.Env = []string{"HOME=" + home, "DEFENSECLAW_HOME=" + data, "DEFENSECLAW_GATEWAY_AUTOSTART=0", "PATH=/usr/local/bin:/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	calls := []struct{ id, mode string }{
		{"toolu_served", "serve"},
		{"toolu_audit_lost", "audit_fail"},
		{"toolu_cut", "drop"},
		{"toolu_served_after", "serve"},
	}
	denied := map[string]bool{}
	for _, c := range calls {
		mode.Store(c.mode)
		out, err := call(c.id)
		if err != nil {
			t.Fatalf("%s (%s): %v %q", c.id, c.mode, err, out)
		}
		denied[c.id] = strings.Contains(out, `"permissionDecision":"deny"`)
	}
	mode.Store("serve")
	if denied["toolu_served"] || denied["toolu_audit_lost"] || denied["toolu_served_after"] {
		t.Fatalf("the script denied a call the gateway answered: %v", denied)
	}

	if err := reportHookFailureCallsIn(filepath.Join(data, "logs"), f.api.logger, time.Now()); err != nil {
		t.Fatal(err)
	}
	joined := joinByToolID(t, f.api.store)
	for _, c := range calls {
		got := joined[c.id]
		if len(got) == 0 {
			t.Errorf("%s (%s): no row for a call the script answered (calls_without_any_row)", c.id, c.mode)
		}
		blocked := false
		for _, outcome := range got {
			blocked = blocked || outcome == "block"
		}
		if blocked != denied[c.id] {
			t.Errorf("%s (%s): the script denied=%v and the rows say %v (block_for_allowed_call or a lost block)", c.id, c.mode, denied[c.id], got)
		}
	}
}
