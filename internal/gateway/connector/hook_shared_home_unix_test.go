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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 1.0.4 review (GAP-0315): the shared inspect-* scripts have one copy per data
// directory, so the renderer bakes no fail mode into them. Their missing or
// disabled DEFENSECLAW_HOME exit must therefore read the installed mode from
// the sidecars next to the script: a closed installation blocks, missing
// state reads closed, and an older open record now also closes, even when
// the agent's environment claims a managed hook
// (DEFENSECLAW_MANAGED_HOOK=1). DEFENSECLAW_FAIL_MODE is not read (1.0.4 lead
// directive).
func TestSharedInspectHookHomeUnavailableReadsTheInstalledMode(t *testing.T) {
	for _, invoke := range hookArgvInspectCases() {
		if len(invoke.stdin) > 4096 {
			continue
		}
		for _, install := range []string{"closed", "open", "open-state-removed"} {
			for _, home := range []string{"missing", "disabled"} {
				for _, tc := range []struct {
					name string
					env  []string
				}{
					{"no-env", nil},
					{"env-open", []string{"DEFENSECLAW_FAIL_MODE=open"}},
					{"env-closed", []string{"DEFENSECLAW_FAIL_MODE=closed"}},
					{"strict", []string{"DEFENSECLAW_STRICT_AVAILABILITY=true"}},
					{"managed-marker-env-closed", []string{"DEFENSECLAW_MANAGED_HOOK=1", "DEFENSECLAW_FAIL_MODE=closed"}},
					{"managed-marker-strict", []string{"DEFENSECLAW_MANAGED_HOOK=1", "DEFENSECLAW_STRICT_AVAILABILITY=1"}},
					{"managed-marker-secure-client-env-open", []string{"DEFENSECLAW_MANAGED_HOOK=1", "_DC_SECURE_CLIENT_HOOK=1",
						"_DC_SECURE_CLIENT_DELIVERY=1", "DEFENSECLAW_FAIL_MODE=open"}},
				} {
					t.Run(invoke.script+"/"+install+"/"+home+"/"+tc.name, func(t *testing.T) {
						dataDir := t.TempDir()
						hookDir := filepath.Join(dataDir, "hooks")
						mode := strings.TrimSuffix(install, "-state-removed")
						opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:1", APIToken: "scoped-test-token", HookFailMode: mode}
						if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewCodexConnector()); err != nil {
							t.Fatal(err)
						}
						if install == "open-state-removed" {
							matches, _ := filepath.Glob(filepath.Join(hookDir, ".hookcfg*"))
							if len(matches) == 0 {
								t.Fatal("setup wrote no fail-mode sidecar")
							}
							for _, match := range matches {
								if err := os.Remove(match); err != nil {
									t.Fatal(err)
								}
							}
						}
						defenseclawHome := filepath.Join(dataDir, "missing")
						if home == "disabled" {
							defenseclawHome = filepath.Join(dataDir, "retired")
							if err := os.MkdirAll(defenseclawHome, 0o700); err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(filepath.Join(defenseclawHome, ".disabled"), nil, 0o600); err != nil {
								t.Fatal(err)
							}
						}
						cmd := exec.Command("bash", filepath.Join(hookDir, invoke.script))
						cmd.Stdin = strings.NewReader(invoke.stdin)
						cmd.Env = append(sanitizedTestEnv(), "HOME="+dataDir, "DEFENSECLAW_HOME="+defenseclawHome)
						cmd.Env = append(cmd.Env, invoke.env...)
						cmd.Env = append(cmd.Env, tc.env...)
						output, err := cmd.CombinedOutput()
						if err == nil {
							t.Fatalf("per-user hook allowed a missing home:\n%s", output)
						}
						if !strings.Contains(string(output), "hook home unavailable") {
							t.Fatalf("the block did not come from the unavailable-home exit:\n%s", output)
						}
						if home == "missing" {
							if _, statErr := os.Stat(defenseclawHome); !os.IsNotExist(statErr) {
								t.Fatalf("the hook created the missing DEFENSECLAW_HOME: %v", statErr)
							}
						}
					})
				}
			}
		}
	}
}

// 1.0.4 review (GAP-0315): a per-user hook never takes the managed or Secure
// Client markers from the agent's environment. With them inherited, an open
// install still closes an outage under strict availability with the
// per-user hook's own answer.
func TestPerUserHooksIgnoreAnInheritedManagedMarker(t *testing.T) {
	marker := []string{"DEFENSECLAW_MANAGED_HOOK=1", "_DC_SECURE_CLIENT_HOOK=1", "_DC_SECURE_CLIENT_DELIVERY=1"}
	type hookRun struct {
		name   string
		conn   Connector
		invoke hookArgvCase
	}
	var runs []hookRun
	for _, conn := range []Connector{NewClaudeCodeConnector(), NewCodexConnector(), NewCursorConnector(), NewDevinConnector(),
		NewHermesConnector(), NewKiroConnector(), NewAntigravityConnector()} {
		runs = append(runs, hookRun{conn.Name(), conn, hookArgvConnectorCase(t, conn.Name())})
	}
	for _, invoke := range hookArgvInspectCases() {
		if len(invoke.stdin) <= 4096 {
			runs = append(runs, hookRun{invoke.script, NewCodexConnector(), invoke})
		}
	}
	for _, run := range runs {
		t.Run(run.name, func(t *testing.T) {
			home := t.TempDir()
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: "127.0.0.1:1", APIToken: "scoped-test-token", HookFailMode: "open"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, run.conn); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(filepath.Join(hookDir, run.invoke.script))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), "\nunset DEFENSECLAW_MANAGED_HOOK _DC_SECURE_CLIENT_HOOK _DC_SECURE_CLIENT_DELIVERY\n") {
				t.Fatalf("%s does not drop the inherited managed markers", run.invoke.script)
			}
			// The marker must not survive into the hook's helpers: probe it
			// with the helper the hook sources, as the hook sets it up.
			probe := exec.Command("bash", "-c", `HOOK_DIR="$1"; eval "$(sed -n '/^unset DEFENSECLAW_MANAGED_HOOK/p' "$2")"; . "$1/_hardening.sh"; `+
				`defenseclaw_secure_client_hook && echo SECURE_CLIENT; echo "MARKER=${DEFENSECLAW_MANAGED_HOOK:-}"`,
				"probe", hookDir, filepath.Join(hookDir, run.invoke.script))
			probe.Env = append(append(sanitizedTestEnv(), "HOME="+home), marker...)
			out, err := probe.CombinedOutput()
			if err != nil || strings.Contains(string(out), "SECURE_CLIENT") || !strings.Contains(string(out), "MARKER=\n") {
				t.Fatalf("inherited markers survived the per-user hook header: %v\n%s", err, out)
			}

			cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, run.invoke.script)}, run.invoke.args...)...)
			cmd.Stdin = strings.NewReader(run.invoke.stdin)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_STRICT_AVAILABILITY=1")
			cmd.Env = append(cmd.Env, run.invoke.env...)
			cmd.Env = append(cmd.Env, marker...)
			output, err := cmd.CombinedOutput()
			if !hookCallBlocked(err, string(output)) {
				t.Fatalf("an inherited managed marker kept an open hook open under strict availability:\n%s", output)
			}
		})
	}
}
