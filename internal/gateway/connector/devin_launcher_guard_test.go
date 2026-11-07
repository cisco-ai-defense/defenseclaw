// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

const devinGuardTestLauncher = `C:\Users\dcw std1\.local\bin\defenseclaw-hook.exe`

func devinGuardedForTest(event string) string {
	return `'C:/Users/dcw std1/.local/bin/defenseclaw-hook-guard.exe' ` + hookguard.DevinSubcommand + " " + event + " hook --connector devin"
}

// Per-user Windows Devin starts the guard program on PreToolUse,
// PermissionRequest and UserPromptSubmit when it sits beside the launcher;
// Stop and the other events, a managed install, an install without the guard
// and other systems keep the direct start (rel-1-0-6 GAP-0676). Every form
// is owned, and Devin's own word rules split the guarded form into the guard
// argv.
func TestDevinPerUserCommandStartsTheGuardOnItsBlockEvents(t *testing.T) {
	setHookBinaryOverride(t, devinGuardTestLauncher)
	direct := windowsDevinBashHookCommand(devinGuardTestLauncher)
	if direct != `'C:/Users/dcw std1/.local/bin/defenseclaw-hook.exe' hook --connector devin` {
		t.Fatalf("direct form = %q", direct)
	}
	for _, present := range []bool{true, false} {
		stubSiblingLauncherGuard(t, present)
		for _, managed := range []bool{false, true} {
			opts := SetupOpts{ManagedEnterprise: managed}
			owned := devinOwnedHookCommandsForOS("windows", opts, direct)
			for _, event := range devinHookEvents {
				got := devinHookCommandForEvent("windows", opts, direct, event)
				want := direct
				if present && !managed && hookguard.DevinBlockEvent(event) {
					want = devinGuardedForTest(event)
				}
				if got != want {
					t.Fatalf("guard=%v managed=%v %s: %q, want %q", present, managed, event, got, want)
				}
				isOwned := false
				for _, command := range owned {
					isOwned = isOwned || command == got
				}
				if !isOwned || !isDevinBashNativeHookCommand(got) {
					t.Fatalf("guard=%v managed=%v %s: %q is not owned", present, managed, event, got)
				}
			}
		}
	}
	stubSiblingLauncherGuard(t, true)
	for _, tc := range []struct{ goos, hookScript string }{
		{"linux", "'/home/u/.defenseclaw/hooks/devin-hook.sh'"},
		{"windows", "'C:/elsewhere/defenseclaw-hook.exe' hook --connector devin"},
		{"windows", ""},
	} {
		if got := devinHookCommandForEvent(tc.goos, SetupOpts{}, tc.hookScript, "PreToolUse"); got != tc.hookScript {
			t.Fatalf("%s %q: %q, want it unchanged", tc.goos, tc.hookScript, got)
		}
	}
	word, rest, ok := posixHookCommandSplit(devinGuardedForTest("UserPromptSubmit"))
	hookArgs, event, argvOK := hookguard.DevinArgv(strings.Fields(rest))
	if !ok || word != `C:/Users/dcw std1/.local/bin/defenseclaw-hook-guard.exe` || !argvOK || event != "UserPromptSubmit" ||
		!reflect.DeepEqual(hookArgs, []string{"hook", "--connector", "devin"}) {
		t.Fatalf("split = %q %q %v; guard argv %v %q %v", word, rest, ok, hookArgs, event, argvOK)
	}
	quoted := windowsDevinGuardedHookCommand(`C:\Users\o'neil\.local\bin\defenseclaw-hook-guard.exe`, "PreToolUse")
	if word, _, ok := posixHookCommandSplit(quoted); !ok || word != `C:/Users/o'neil/.local/bin/defenseclaw-hook-guard.exe` {
		t.Fatalf("a quote in the path: %q splits to %q %v", quoted, word, ok)
	}
	for _, refused := range []struct{ guard, event string }{
		{`C:\Users\a\.local\bin\defenseclaw-hook-guard.exe`, "Stop"},
		{`C:\Users\a\.local\bin\defenseclaw-hook-guard.exe`, "PostToolUse"},
		{`C:\Users\a\.local\bin\defenseclaw-hook.exe`, "PreToolUse"},
		{`relative\defenseclaw-hook-guard.exe`, "PreToolUse"},
		{`C:\Users\a"b\defenseclaw-hook-guard.exe`, "PreToolUse"},
	} {
		if got := windowsDevinGuardedHookCommand(refused.guard, refused.event); got != "" {
			t.Fatalf("%q %s rendered %q", refused.guard, refused.event, got)
		}
	}
}

// Setup writes one DefenseClaw group per event with the guarded start on the
// block events and keeps foreign groups; a later setup without the guard
// replaces the guarded start with the direct one instead of adding a second
// group; teardown removes every DefenseClaw form.
func TestDevinSetupWritesTheGuardedStartAndTeardownRemovesEveryForm(t *testing.T) {
	setHookBinaryOverride(t, devinGuardTestLauncher)
	direct := windowsDevinBashHookCommand(devinGuardTestLauncher)
	path := filepath.Join(t.TempDir(), "config.json")
	foreign := map[string]interface{}{"matcher": "", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": "echo operator"}}}
	seed, _ := json.Marshal(map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": []interface{}{foreign}}})
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	setup := func(present bool) {
		t.Helper()
		stubSiblingLauncherGuard(t, present)
		opts := SetupOpts{}
		if err := patchDevinHooksForEvents(path, func(event string) string {
			return devinHookCommandForEvent("windows", opts, direct, event)
		}, devinOwnedHookCommandsForOS("windows", opts, direct)...); err != nil {
			t.Fatal(err)
		}
	}
	read := func() map[string][]string {
		t.Helper()
		cfg, err := readDevinJSONObject(path)
		if err != nil {
			t.Fatal(err)
		}
		commands := map[string][]string{}
		for event, raw := range devinHooksObject(path, cfg) {
			groups, _ := raw.([]interface{})
			for _, rawGroup := range groups {
				group, _ := rawGroup.(map[string]interface{})
				handlers, _ := group["hooks"].([]interface{})
				for _, rawHandler := range handlers {
					handler, _ := rawHandler.(map[string]interface{})
					command, _ := handler["command"].(string)
					commands[event] = append(commands[event], command)
				}
			}
		}
		return commands
	}
	for _, present := range []bool{true, false} {
		setup(present)
		got := read()
		for _, event := range devinHookEvents {
			want := []string{direct}
			if present && hookguard.DevinBlockEvent(event) {
				want = []string{devinGuardedForTest(event)}
			}
			if event == "PreToolUse" {
				want = append([]string{"echo operator"}, want...)
			}
			if !reflect.DeepEqual(got[event], want) {
				t.Fatalf("guard=%v %s: %q, want %q", present, event, got[event], want)
			}
		}
	}
	setup(true)
	if err := removeDevinHookReferences(path, devinOwnedHookCommandsForOS("windows", SetupOpts{}, direct)...); err != nil {
		t.Fatal(err)
	}
	if got := read(); !reflect.DeepEqual(got, map[string][]string{"PreToolUse": {"echo operator"}}) {
		t.Fatalf("after teardown: %q", got)
	}
}

// Before a rollback, the Devin guarded starts become the direct start every
// earlier release owns, under the event each is registered on only; a second
// conversion changes nothing, and the restore of an aborted rollback gives
// back the same document, only where the guard program is there
// (rel-1-0-6 GAP-0676, the GAP-1284 rule).
func TestDevinRollbackConvertsTheGuardedStartToTheDirectFormAndBack(t *testing.T) {
	setHookBinaryOverride(t, devinGuardTestLauncher)
	direct := windowsDevinBashHookCommand(devinGuardTestLauncher)
	path := filepath.Join(t.TempDir(), "config.json")
	stubSiblingLauncherGuard(t, true)
	if err := patchDevinHooksForEvents(path, func(event string) string {
		return devinHookCommandForEvent("windows", SetupOpts{}, direct, event)
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks := devinHooksObject(path, cfg)
	// A guarded start under an event Setup never gives it, and a foreign
	// handler, stay as they are.
	misplaced := map[string]interface{}{"type": "command", "command": devinGuardedForTest("PreToolUse")}
	hooks["Stop"] = append(hooks["Stop"].([]interface{}), map[string]interface{}{"matcher": "", "hooks": []interface{}{misplaced}})
	hooks["PreToolUse"] = append(hooks["PreToolUse"].([]interface{}),
		map[string]interface{}{"matcher": "", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": "echo operator"}}})
	original, _ := json.Marshal(cfg)
	pairs := devinWindowsHookFormPairs([]string{devinGuardTestLauncher, devinGuardTestLauncher, ""}, false)
	if len(pairs) != 3 {
		t.Fatalf("pairs cover %d events, want the 3 block events", len(pairs))
	}
	if changed := convertDevinHookForms(hooks, pairs, true); changed != 3 {
		t.Fatalf("converted %d handlers, want 3", changed)
	}
	for _, event := range devinHookEvents {
		groups := hooks[event].([]interface{})
		handler := groups[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
		if handler["command"] != direct {
			t.Fatalf("%s: %q after the conversion, want the direct start", event, handler["command"])
		}
	}
	if misplaced["command"] != devinGuardedForTest("PreToolUse") {
		t.Fatal("a guarded start under Stop was rewritten")
	}
	if changed := convertDevinHookForms(hooks, pairs, true); changed != 0 {
		t.Fatalf("a second conversion changed %d handlers", changed)
	}
	stubSiblingLauncherGuard(t, false)
	if restore := devinWindowsHookFormPairs([]string{devinGuardTestLauncher}, true); len(restore) != 0 {
		t.Fatalf("restore without the guard program has %d events", len(restore))
	}
	stubSiblingLauncherGuard(t, true)
	if changed := convertDevinHookForms(hooks, devinWindowsHookFormPairs([]string{devinGuardTestLauncher}, true), false); changed != 3 {
		t.Fatalf("restored %d handlers, want 3", changed)
	}
	if restored, _ := json.Marshal(cfg); string(restored) != string(original) {
		t.Fatalf("restore did not give back the document:\n%s\n%s", restored, original)
	}
}
