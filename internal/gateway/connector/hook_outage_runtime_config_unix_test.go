// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

// oss-outage-open review (loop round 3): a per-user shell hook asks the config
// of its own runtime (config.yaml in the data directory above its hooks
// folder) for the outage mode, with the gateway binary found from that data
// directory. The agent's DEFENSECLAW_CONFIG or DEFENSECLAW_HOME, which name
// another default-tier config, a gateway.pid that points at another program,
// or a HOME with a fake gateway binary, neither reopen an outage the runtime's
// strict config closes nor close one its default config opens.
func TestPerUserShellHookOutageReadsOnlyItsRuntimesConfig(t *testing.T) {
	for _, conn := range []Connector{NewClaudeCodeConnector(), NewCodexConnector(), NewCopilotConnector(), NewCursorConnector(),
		NewDevinConnector(), NewKiroConnector(), NewAntigravityConnector(), NewHermesConnector()} {
		for _, tc := range []struct {
			name, runtime, agent string
			env                  func(home, other string) []string
			fakeBinary           bool
			fakeHomeBinary       bool
			opens                bool
		}{
			{name: "DEFENSECLAW_CONFIG names a default config elsewhere", runtime: outageStrictTierConfig, agent: outageDefaultTierConfig,
				env: func(home, other string) []string {
					return []string{"DEFENSECLAW_HOME=" + home, "DEFENSECLAW_CONFIG=" + filepath.Join(other, "config.yaml")}
				}},
			{name: "DEFENSECLAW_HOME names a default home elsewhere", runtime: outageStrictTierConfig, agent: outageDefaultTierConfig,
				env: func(_, other string) []string { return []string{"DEFENSECLAW_HOME=" + other} }},
			{name: "DEFENSECLAW_HOME names a gateway.pid of another program", runtime: outageStrictTierConfig, agent: outageDefaultTierConfig,
				env: func(_, other string) []string { return []string{"DEFENSECLAW_HOME=" + other} }, fakeBinary: true},
			{name: "HOME names a fake gateway binary", runtime: outageStrictTierConfig, agent: outageDefaultTierConfig,
				env: func(home, _ string) []string { return []string{"DEFENSECLAW_HOME=" + home} }, fakeHomeBinary: true},
			{name: "the environment names a strict config elsewhere", runtime: outageDefaultTierConfig, agent: outageStrictTierConfig,
				env: func(_, other string) []string {
					return []string{"DEFENSECLAW_HOME=" + other, "DEFENSECLAW_CONFIG=" + filepath.Join(other, "config.yaml")}
				}, opens: true},
		} {
			t.Run(conn.Name()+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				invoke := hookArgvConnectorCase(t, conn.Name())
				home := t.TempDir()
				other := t.TempDir()
				installNativeGatewayForHookTest(t, home)
				hookDir := filepath.Join(home, "hooks")
				// Rendered in the default tier: the record says open.
				opts := SetupOpts{DataDir: home, APIAddr: freeLoopbackAddrForOutageTest(t), APIToken: "scoped-test-token", HookFailMode: "open"}
				if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
					t.Fatal(err)
				}
				writeOutageTierConfig(t, home, tc.runtime)
				writeOutageTierConfig(t, other, tc.agent)
				if tc.fakeBinary {
					fake := filepath.Join(other, "bin", "defenseclaw-gateway")
					if err := os.MkdirAll(filepath.Dir(fake), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(fake, []byte("#!/bin/sh\necho open\n"), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(other, "gateway.pid"), []byte(`{"pid":1,"executable":"`+fake+`"}`), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				agentHome := home
				if tc.fakeHomeBinary {
					agentHome = other
					fake := filepath.Join(other, ".local", "bin", "defenseclaw-gateway")
					if err := os.MkdirAll(filepath.Dir(fake), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(fake, []byte("#!/bin/sh\necho open\n"), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, invoke.script)}, invoke.args...)...)
				cmd.Stdin = strings.NewReader(invoke.stdin)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+agentHome, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
				if tc.env != nil {
					cmd.Env = append(cmd.Env, tc.env(home, other)...)
				}
				output, err := cmd.CombinedOutput()
				if blocked := hookCallBlocked(err, string(output)); blocked == tc.opens {
					t.Fatalf("blocked=%v, want %v (exit %v):\n%s", blocked, !tc.opens, err, output)
				}
			})
		}
	}
}
