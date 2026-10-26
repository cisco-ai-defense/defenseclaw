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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testdata/unix_hook_fail_mode_lines.json holds every line of a Unix hook
// render that assigns a fail mode, for the hooks whose installed mode the
// Python fail-mode resolver reads back (cli/defenseclaw/fail_mode.py,
// _read_baked_hook_render): the per-user render ("<script>/<mode>") and the
// authenticated Secure Client delivery render ("<script>/secure-client/<mode>"),
// whose Antigravity, Devin, Hermes and Kiro hooks take DEFENSECLAW_FAIL_MODE
// from the agent's environment (#1163). cli/tests/test_fail_mode_runtime.py
// runs these lines under bash and checks the resolver reports what they set, so
// a render change that the resolver cannot read fails here first and is
// regenerated with DEFENSECLAW_UPDATE_GOLDEN=1.
func TestUnixHookFailModeLinesMatchTheSharedGolden(t *testing.T) {
	got := map[string][]string{}
	for _, agent := range []struct {
		conn   Connector
		script string
	}{
		{NewClaudeCodeConnector(), "claude-code-hook.sh"},
		{NewCodexConnector(), "codex-hook.sh"},
		{NewDevinConnector(), "devin-hook.sh"},
		{NewAntigravityConnector(), "antigravity-hook.sh"},
		{NewCopilotConnector(), "copilot-hook.sh"},
		{NewHermesConnector(), "hermes-hook.sh"},
		{NewKiroConnector(), "kiro-hook.sh"},
	} {
		for _, secureClient := range []bool{false, true} {
			for _, mode := range []string{"open", "closed"} {
				home := t.TempDir()
				hookDir := filepath.Join(home, "hooks")
				opts := SetupOpts{DataDir: home, APIAddr: "127.0.0.1:1", APIToken: "scoped-test-token", HookFailMode: mode}
				key := agent.script + "/" + mode
				if secureClient {
					// An authenticated Secure Client deployment
					// (SecureClientDeploymentVerified is true in tests).
					opts.ManagedEnterprise = true
					opts.SecureClientHookDelivery = true
					key = agent.script + "/secure-client/" + mode
				}
				if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, agent.conn); err != nil {
					t.Fatal(err)
				}
				body, err := os.ReadFile(filepath.Join(hookDir, agent.script))
				if err != nil {
					t.Fatal(err)
				}
				var lines []string
				for _, line := range strings.Split(string(body), "\n") {
					if strings.Contains(line, "FAIL_MODE=") {
						lines = append(lines, line)
					}
				}
				got[key] = lines
			}
		}
	}
	rendered, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, '\n')
	path := filepath.Join("testdata", "unix_hook_fail_mode_lines.json")
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, rendered, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1): %v", err)
	}
	if string(want) != string(rendered) {
		t.Fatalf("hook fail-mode lines changed; regenerate with DEFENSECLAW_UPDATE_GOLDEN=1 and keep cli/defenseclaw/fail_mode.py reading them\n got: %s\nwant: %s", rendered, want)
	}
}
