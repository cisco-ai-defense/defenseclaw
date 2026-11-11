// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

// Cowork audit P3-6: the hooks/hooks.json of the DefenseClaw Cowork plugin
// lives in the user's Claude account. Nothing DefenseClaw runs re-renders it
// (connector reconcile, --every-connector, an upgrade), so every handler form
// a release put in a plugin must keep working with the current runtime until
// the user builds and uploads a new plugin. testdata/released-carriers/1.0.8
// holds the plugin hooks.json that 1.0.8 built, captured in the cowork-1-0-8
// round (home folder replaced by __HOME__): on Linux the guard-wrapped
// claude-code-hook.sh command, on Windows (one-line install) the cmd.exe
// launcher guard and, on PreToolUse, defenseclaw-hook-guard.exe
// launcher-guard. The Windows file holds the two captured entries
// (SessionStart, PreToolUse); its other events carry the SessionStart form.
// Current Setup uses a paired guard form, while status names the released
// uploaded plugin as stale until it is rebuilt.
//
// If a change makes this fail, keep the old form running, or teach
// cowork_status (cli/defenseclaw/cowork.py) to report the uploaded plugin as
// stale (cowork_plugin_stale) so the user rebuilds it.

type coworkPluginEntries = map[string][]struct {
	Matcher string                   `json:"matcher"`
	Hooks   []map[string]interface{} `json:"hooks"`
}

// coworkPluginHookEntries parses a Cowork plugin hooks.json and checks that
// it registers the Cowork events, one handler each.
func coworkPluginHookEntries(t *testing.T, data []byte) coworkPluginEntries {
	t.Helper()
	var doc struct {
		Hooks coworkPluginEntries `json:"hooks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var events []string
	for event, entries := range doc.Hooks {
		events = append(events, event)
		if len(entries) != 1 || len(entries[0].Hooks) != 1 {
			t.Fatalf("%s: %d entries, want one handler", event, len(entries))
		}
	}
	sort.Strings(events)
	want := append([]string(nil), CoworkPluginHookEvents...)
	sort.Strings(want)
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want the Cowork events %v", events, want)
	}
	return doc.Hooks
}

// coworkReleasedPlugin is a released plugin hooks.json with home in place of
// __HOME__.
func coworkReleasedPlugin(t *testing.T, release, name, home string) coworkPluginEntries {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "released-carriers", release, name))
	if err != nil {
		t.Fatal(err)
	}
	escaped, err := json.Marshal(home)
	if err != nil {
		t.Fatal(err)
	}
	return coworkPluginHookEntries(t, bytes.ReplaceAll(data, []byte("__HOME__"), bytes.Trim(escaped, `"`)))
}

func TestCoworkReleasedPluginHandlersStillRun(t *testing.T) {
	groups := map[string]claudeCodeHookGroup{}
	for _, group := range hookGroups {
		groups[group.eventType] = group
	}

	t.Run("1.0.8 unix guard-wrapped script", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("the Unix plugin form runs under a POSIX shell")
		}
		home := t.TempDir()
		dataDir := filepath.Join(home, ".defenseclaw")
		script := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
		if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := SaveHookContractLockEntry(dataDir, HookContractLockEntry{Connector: "claudecode", ContractID: "claudecode-test"}); err != nil {
			t.Fatal(err)
		}
		writeScript := func(body string) {
			t.Helper()
			if err := os.WriteFile(script, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		writeScript("exit 0\n")
		released := coworkReleasedPlugin(t, "1.0.8", "cowork-plugin-hooks-unix.json", home)

		// A released plugin still uses the stable script path that Setup and
		// reconcile re-render. The current plugin adds a removal record check.
		raw, err := CoworkPluginHooks(SetupOpts{DataDir: dataDir})
		if err != nil {
			t.Fatal(err)
		}
		current := coworkPluginHookEntries(t, raw)
		if reflect.DeepEqual(current, released) || !strings.Contains(current["PreToolUse"][0].Hooks[0]["command"].(string), dataDir+coworkRemovalMarkerSuffix) {
			t.Fatalf("the current plugin needs the removal record and the released plugin must retain its original form")
		}
		for event, entries := range released {
			if entries[0].Matcher != groups[event].matcher || entries[0].Hooks[0]["timeout"] != float64(groups[event].timeout) {
				t.Fatalf("%s: matcher %q timeout %v, want the Claude Code group %+v", event, entries[0].Matcher, entries[0].Hooks[0]["timeout"], groups[event])
			}
		}

		// The released command runs the script, passes its exit code through,
		// and blocks with exit 2 and the guard sentence when the script is gone.
		command, _ := released["PreToolUse"][0].Hooks[0]["command"].(string)
		run := func() (int, string, string) {
			t.Helper()
			cmd := exec.Command("/bin/sh", "-c", command)
			cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse"}`)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			if exitErr, ok := err.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			return code, stdout.String(), stderr.String()
		}
		writeScript("cat >/dev/null\necho '{\"ran\":true}'\n")
		if code, stdout, _ := run(); code != 0 || strings.TrimSpace(stdout) != `{"ran":true}` {
			t.Fatalf("released command with the script: exit %d stdout %q", code, stdout)
		}
		writeScript("cat >/dev/null\necho denied >&2\nexit 2\n")
		if code, _, stderr := run(); code != 2 || strings.TrimSpace(stderr) != "denied" {
			t.Fatalf("released command with a blocking script: exit %d stderr %q", code, stderr)
		}
		if err := os.Remove(script); err != nil {
			t.Fatal(err)
		}
		if code, _, stderr := run(); code != 2 || !strings.Contains(stderr, coworkMissingHookGuardMessage) {
			t.Fatalf("released command without the script: exit %d stderr %q, want exit 2 and the guard sentence", code, stderr)
		}
	})

	t.Run("1.0.8 windows launcher guard argv", func(t *testing.T) {
		savedSystem := windowsSystemDirectory
		windowsSystemDirectory = func() string { return `C:\Windows\system32` }
		t.Cleanup(func() { windowsSystemDirectory = savedSystem })
		const home = `C:\Users\dcw std1`
		launcher := home + `\.local\bin\defenseclaw-hook.exe`
		guard := home + `\.local\bin\defenseclaw-hook-guard.exe`
		approved := home + `\.local\bin\defenseclaw-hook-guard.approved`
		savedGuard := claudeCodePreToolGuardExecutable
		claudeCodePreToolGuardExecutable = func(string) string { return guard }
		t.Cleanup(func() { claudeCodePreToolGuardExecutable = savedGuard })
		savedPair := claudeChainFor
		claudeChainFor = func(string) (string, string) { return guard, approved }
		t.Cleanup(func() { claudeChainFor = savedPair })
		released := coworkReleasedPlugin(t, "1.0.8", "cowork-plugin-hooks-windows.json", home)

		// The released argv is the per-user Windows Setup form from 1.0.8.
		command, args := claudeCodeWindowsHookInvocation(SetupOpts{}, launcher)
		if err := claudeCodeChainAdmission(SetupOpts{}, command, args, "windows"); err != nil {
			t.Fatalf("current paired guard was refused: %v", err)
		}
		hookArgs := []string{"hook", "--connector", "claudecode"}
		for event, entries := range released {
			handler := entries[0].Hooks[0]
			if entries[0].Matcher != groups[event].matcher || handler["timeout"] != float64(groups[event].timeout) {
				t.Fatalf("%s: matcher %q timeout %v, want the Claude Code group %+v", event, entries[0].Matcher, handler["timeout"], groups[event])
			}
			wantCommand, wantArgs := claudeCodeWindowsCommandProcessor(), claudeCodeLauncherGuardArgs(launcher, hookArgs)
			if event == "PreToolUse" {
				wantCommand, wantArgs = guard, claudeCodePreToolGuardArgs(launcher, hookArgs)
			}
			gotArgs, ok := claudeCodeNativeExecArguments(handler)
			if !ok || handler["command"] != wantCommand || !reflect.DeepEqual(gotArgs, wantArgs) {
				t.Fatalf("%s: released form = %q %q, want %q %q", event, handler["command"], gotArgs, wantCommand, wantArgs)
			}
			currentCommand, currentArgs := claudeCodeHandlerInvocation(event, command, args, true)
			if currentCommand == wantCommand && reflect.DeepEqual(currentArgs, wantArgs) {
				t.Fatalf("%s: current Setup still writes the released form", event)
			}
			if _, _, ok := claudeCodeLauncherGuardParts(map[string]interface{}{
				"command": currentCommand, "args": currentArgs,
			}); !ok {
				t.Fatalf("%s: current paired guard form is not recognized", event)
			}
			// Teardown, doctor and uninstall recognise it as DefenseClaw's own.
			gotLauncher, hookArgs, ok := ClaudeCodeLauncherGuardTarget(handler)
			if !ok || gotLauncher != launcher || strings.Join(hookArgs, " ") != "hook --connector claudecode" {
				t.Fatalf("%s: launcher guard not recognised: %q %q %v", event, gotLauncher, hookArgs, ok)
			}
			if event == "PreToolUse" {
				// defenseclaw-hook-guard.exe and defenseclaw-hook.exe accept its argv.
				if l, h, _, wrapped, open, ok := hookguard.ParseInvocationMode(gotArgs); !ok ||
					l != launcher || strings.Join(h, " ") != "hook --connector claudecode" || wrapped || open {
					t.Fatalf("PreToolUse: the guard refuses the released argv %q", gotArgs)
				}
			}
		}
	})
}
