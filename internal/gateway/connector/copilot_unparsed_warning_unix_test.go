// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPerUserCopilotUnparsedObserveWarningIsVisible(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required")
	}
	const warning = "DefenseClaw could not read this Copilot tool call; it was allowed in observe mode and recorded for review."
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-test" {
			t.Errorf("unexpected hook authorization")
		}
		_, _ = w.Write([]byte(`{"action":"allow","raw_action":"alert","reason":"` + warning +
			`","rule_ids":["HOOK-TOOL-CALL-UNPARSED"]}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := WriteHookScriptsWithToken(dir, strings.TrimPrefix(server.URL, "http://"), "tok-test"); err != nil {
		t.Fatal(err)
	}
	dcHome := t.TempDir()
	installNativeGatewayForHookTest(t, dcHome)
	cmd := exec.Command("bash", filepath.Join(dir, "copilot-hook.sh"), "--event", "preToolUse")
	cmd.Env = append(os.Environ(), "HOME="+dcHome, "DEFENSECLAW_HOME="+dcHome,
		"DEFENSECLAW_GATEWAY_AUTOSTART=0")
	cmd.Stdin = strings.NewReader(`{"sessionId":"native","cwd":"/tmp","toolCalls":[{"id":"c1","name":"apply_patch","args":"invalid"}]}`)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("hook failed: %v, stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), `"permissionDecision":"deny"`) ||
		!strings.Contains(stderr.String(), warning) {
		t.Fatalf("warning absent or call denied: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}
