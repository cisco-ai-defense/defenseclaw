// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/nativeinstallstate"
)

func TestLauncherArgs(t *testing.T) {
	tests := []struct {
		name string
		exe  string
		args []string
		want []string
	}{
		{name: "cli", exe: "defenseclaw.exe", args: []string{"status"}, want: []string{"-I", "-c", moduleEntryPointScript, `C:\repo`, "status"}},
		{name: "scanner", exe: "skill-scanner.exe", args: []string{"scan", "fixture"}, want: []string{"-I", "-c", consoleEntryPointScript, "skill-scanner", `C:\repo`, "scan", "fixture"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := launcherArgs(test.exe, `C:\repo`, test.args)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("launcherArgs() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestLauncherArgsRejectsUnknownName(t *testing.T) {
	if _, err := launcherArgs("renamed.exe", `C:\repo`, nil); err == nil {
		t.Fatal("launcherArgs() accepted an unknown launcher name")
	}
}

func TestLauncherEnvRehydratesManagedConnectorHomes(t *testing.T) {
	t.Setenv("CODEX_HOME", `C:\project\codex`)
	t.Setenv("CLAUDE_CONFIG_DIR", `C:\project\claude`)
	t.Setenv("DEFENSECLAW_HOME", `C:\project\defenseclaw`)
	state := nativeinstallstate.State{
		InstallRoot:     `C:\Users\tester\Programs\DefenseClaw`,
		DataRoot:        `C:\Users\tester\.defenseclaw`,
		CodexHome:       `D:\Agent Profiles\Codex`,
		ClaudeConfigDir: `D:\Agent Profiles\Claude`,
	}
	env := launcherEnv(
		`C:\Users\tester\Programs\DefenseClaw\bin`,
		`C:\Users\tester\Programs\DefenseClaw\runtime\python`,
		state.InstallRoot,
		state,
		true,
	)
	joined := strings.Join(env, "\n")
	for _, expected := range []string{
		"CODEX_HOME=" + state.CodexHome,
		"CLAUDE_CONFIG_DIR=" + state.ClaudeConfigDir,
		"DEFENSECLAW_HOME=" + state.DataRoot,
		"DEFENSECLAW_INSTALL_ROOT=" + state.InstallRoot,
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("launcher environment missing %q: %v", expected, env)
		}
	}
	for _, inherited := range []string{`C:\project\codex`, `C:\project\claude`, `C:\project\defenseclaw`} {
		if strings.Contains(joined, inherited) {
			t.Fatalf("launcher retained ambient profile %q: %v", inherited, env)
		}
	}
	if os.Getenv("CODEX_HOME") == state.CodexHome {
		t.Fatal("launcher environment construction mutated the parent process")
	}
}
