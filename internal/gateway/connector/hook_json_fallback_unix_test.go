// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The awk tier runs where neither jq nor a usable python3 is available.
// It must validate the whole answer before an action can allow a tool.
func TestShellFallbackRejectsMalformedGatewayJSON(t *testing.T) {
	for _, tc := range []struct {
		name, body, action string
		valid              bool
	}{
		{"ordinary allow", `{"action":"allow","extra":{"n":[true,2,null]}}`, "allow", true},
		{"invalid nested literal", `{"action":"allow","extra":[invalid]}`, "", false},
		{"truncated nested object", `{"action":"allow","extra":{"n":1}`, "", false},
		{"missing comma", `{"action":"allow" "extra":1}`, "", false},
		{"bad escape", `{"action":"allow","extra":"\q"}`, "", false},
		{"bad number", `{"action":"allow","extra":01}`, "", false},
		{"duplicate action", `{"action":"block","action":"allow"}`, "", false},
		{"duplicate nested key", `{"action":"allow","extra":{"x":1,"x":2}}`, "", false},
		{"escaped duplicate key", `{"action":"allow","act\u0069on":"block"}`, "", false},
		{"trailing document", `{"action":"allow"}{}`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `source hooks/_hardening.sh; defenseclaw_json_string_field "$1" action strict`, "--", tc.body)
			out, err := cmd.CombinedOutput()
			if tc.valid {
				if err != nil || strings.TrimSpace(string(out)) != tc.action {
					t.Fatalf("valid response: output %q error %v", out, err)
				}
			} else if err == nil {
				t.Fatalf("malformed response accepted: %q", out)
			}
		})
	}
}

func TestShellFallbackUpgradeReplacesV9Helper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(path, []byte("#!/bin/bash\n# defenseclaw-managed-hook v9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeHookHelpers(dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if parseHookSchemaVersion(got) != 10 || !strings.Contains(string(got), "function obj(level") {
		t.Fatal("upgrade retained the old shell decision parser")
	}
}

func TestShellMalformedHTTP200CannotUseOpenMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"action":"allow","extra":[invalid]}`))
	}))
	defer server.Close()

	// Keep curl, bash, awk and sed, but force the supported awk parser tier.
	path := t.TempDir()
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || entry.Name() == "jq" || strings.HasPrefix(entry.Name(), "python") {
				continue
			}
			link := filepath.Join(path, entry.Name())
			if _, err := os.Lstat(link); os.IsNotExist(err) {
				_ = os.Symlink(filepath.Join(dir, entry.Name()), link)
			}
		}
	}
	for _, conn := range []Connector{NewClaudeCodeConnector(), NewCodexConnector()} {
		t.Run(conn.Name(), func(t *testing.T) {
			invoke := hookArgvConnectorCase(t, conn.Name())
			if conn.Name() == "claudecode" {
				invoke.stdin = `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
			}
			home := t.TempDir()
			hooks := filepath.Join(home, "hooks")
			if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, SetupOpts{
				DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "test-token", HookFailMode: "open",
			}, conn); err != nil {
				t.Fatal(err)
			}
			bakeHookPathForTest(t, filepath.Join(hooks, invoke.script), path)
			cmd := exec.Command("bash", append([]string{filepath.Join(hooks, invoke.script)}, invoke.args...)...)
			cmd.Stdin = strings.NewReader(invoke.stdin)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home)
			out, err := cmd.CombinedOutput()
			if !hookCallBlocked(err, string(out)) {
				t.Fatalf("malformed HTTP 200 allowed a tool: %v %s", err, out)
			}
		})
	}
}
