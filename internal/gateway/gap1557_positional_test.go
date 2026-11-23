// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP1557WindowsPS51PositionalArgvBodySelection(t *testing.T) {
	argv := []string{"powershell.exe", "-wd", `C:\Users\alice\.defenseclaw`, "Set-Content -Path config.yaml -Value marker"}
	call, ok := actionfacts.ShellLauncherCall(argv)
	if !ok {
		t.Fatal("no PowerShell launcher body")
	}
	input := actionfacts.Input{WindowsHookHost: true}
	twin, read, _ := launcherCallTwin(trustedActionRequest{Input: input}, actionfacts.Facts{}, call, argv, 0, true)
	if !read || twin.Input.Command != call.Body || twin.Input.DialectHint != actionfacts.DialectPowerShell {
		t.Fatalf("native Windows PowerShell 5.1: reading=%q, want body %q", twin.Input.Command, call.Body)
	}

	pwsh := []string{"pwsh.exe", "-wd", `C:\Users\alice\.defenseclaw`, "Set-Content -Path config.yaml -Value marker"}
	call, ok = actionfacts.ShellLauncherCall(pwsh)
	if !ok {
		t.Fatal("no pwsh launcher body")
	}
	twin, read, _ = launcherCallTwin(trustedActionRequest{Input: input}, actionfacts.Facts{}, call, pwsh, 0, true)
	if !read || twin.Input.Command == call.Body {
		t.Fatalf("pwsh 7 positional word is a file: reading=%q", twin.Input.Command)
	}

	call, ok = actionfacts.ShellLauncherCall(argv)
	if !ok {
		t.Fatal("no PowerShell launcher body")
	}
	twin, read, _ = launcherCallTwin(trustedActionRequest{}, actionfacts.Facts{}, call, argv, 0, true)
	if !read || twin.Input.Command == call.Body {
		t.Fatalf("non-Windows launcher gained a command-text reading: %q", twin.Input.Command)
	}
}

func TestGAP1557WindowsPS51PositionalArgvHookVerdict(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows path and PowerShell edition required")
	}
	home := filepath.Join(t.TempDir(), "alice")
	state := filepath.Join(home, ".defenseclaw")
	project := filepath.Join(home, "project")
	for _, dir := range []string{state, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "config.yaml"), []byte("x: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	write := "Set-Content -Path config.yaml -Value marker"
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			server := gap0437Server(t, p, "codex", "action")
			baseline, rules := gap0198RoutePost(t, server, "codex", project,
				[]string{"powershell.exe", "-wd", state, "-Command", write}, home, p.managed)
			if baseline == "allow" || !slices.Contains(rules, gap0747StateRule) {
				t.Fatalf("-Command baseline=%q rules=%v, want state-write finding", baseline, rules)
			}
			positional, positionalRules := gap0198RoutePost(t, server, "codex", project,
				[]string{"powershell.exe", "-wd", state, write}, home, p.managed)
			if positional != baseline || !slices.Contains(positionalRules, gap0747StateRule) {
				t.Fatalf("positional=%q rules=%v, -Command=%q rules=%v", positional, positionalRules, baseline, rules)
			}
			benign, benignRules := gap0198RoutePost(t, server, "codex", project,
				[]string{"powershell.exe", "-wd", project, "Set-Content -Path notes.txt -Value marker"}, home, p.managed)
			if benign != "allow" {
				t.Fatalf("ordinary project write=%q rules=%v, want allow", benign, benignRules)
			}
		})
	}
}
