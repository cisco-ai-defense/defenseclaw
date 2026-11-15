// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

type codexReleaseFormsFixture struct {
	Launcher        string                       `json:"launcher"`
	SystemDirectory string                       `json:"system_directory"`
	Forms           map[string]map[string]string `json:"forms"`
	Releases        map[string]string            `json:"releases"`
}

func loadCodexReleaseFormsFixture(t *testing.T) codexReleaseFormsFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "codex_windows_release_hook_forms.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture codexReleaseFormsFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	saved := windowsSystemDirectory
	windowsSystemDirectory = func() string { return fixture.SystemDirectory }
	t.Cleanup(func() { windowsSystemDirectory = saved })
	return fixture
}

// writeCodexReleaseFormsConfig writes a per-user config.toml whose
// DefenseClaw handlers are commands, one per event, beside an operator
// handler, and returns its path.
func writeCodexReleaseFormsConfig(t *testing.T, dir string, commands map[string]string) string {
	t.Helper()
	hooks := map[string]interface{}{}
	for event, command := range commands {
		hooks[event] = []interface{}{map[string]interface{}{"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": command, "command_windows": command, "timeout": 30},
		}}}
	}
	hooks["Stop"] = append(hooks["Stop"].([]interface{}), map[string]interface{}{"hooks": []interface{}{
		map[string]interface{}{"type": "command", "command": "operator-stop.exe", "command_windows": "operator-stop.exe"},
	}})
	data, err := toml.Marshal(map[string]interface{}{"model": "gpt-5", "hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// readCodexReleaseFormsConfig returns the command of every handler by event.
func readCodexReleaseFormsConfig(t *testing.T, path string) map[string][]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]interface{}{}
	if err := parseCodexTOML(data, &cfg); err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for event, raw := range cfg["hooks"].(map[string]interface{}) {
		groups, ok := raw.([]interface{})
		if !ok {
			continue
		}
		for _, group := range groups {
			for _, handler := range group.(map[string]interface{})["hooks"].([]interface{}) {
				h := handler.(map[string]interface{})
				if h["command"] != h["command_windows"] {
					t.Fatalf("%s: command and command_windows differ", event)
				}
				out[event] = append(out[event], h["command"].(string))
			}
		}
	}
	return out
}

// A per-user Windows rollback rewrites the Codex handlers of this release
// into the exact command the target release writes, so its setup finds its
// own handler and its teardown removes it. Writing one bridge for every
// target left the 1.0.8 fallback form, which 1.0.0 to 1.0.7 do not own:
// after a rollback to 1.0.5 its setup added its own 11 handlers beside them,
// and its uninstall left them (rel-1-0-10:GAP-0759). testdata holds what
// every release tag writes; an unknown target gets the form every release
// owns (the 1.0.0 to 1.0.4 bridge), a target that writes this release
// forms needs no rewrite, and the restore of an aborted rollback brings any
// of them back to the form this release renders.
func TestCodexRollbackWritesTheFormTheTargetReleaseOwns(t *testing.T) {
	fixture := loadCodexReleaseFormsFixture(t)
	current := fixture.Forms[fixture.Releases["1.0.10"]]
	targets := []string{""}
	for release := range fixture.Releases {
		targets = append(targets, release)
	}
	sort.Strings(targets)
	for _, target := range targets {
		want := fixture.Forms[fixture.Releases["1.0.0"]]
		if target != "" {
			want = fixture.Forms[fixture.Releases[target]]
		}
		for _, start := range []string{"1.0.10", "1.0.8 converter"} {
			commands := current
			if start != "1.0.10" {
				// What 1.0.9 and this release before the fix wrote for
				// every target: the bridge with the 1.0.8 fallback end.
				commands = map[string]string{}
				for event := range current {
					contract := "codex-hooks-v4"
					commands[event] = windowsNativePowerShellHookCommandForCodexEvent(event, contract, fixture.Launcher)
				}
			}
			dir := t.TempDir()
			configPath := writeCodexReleaseFormsConfig(t, dir, commands)
			previous := CodexConfigPathOverride
			CodexConfigPathOverride = configPath
			opts := SetupOpts{DataDir: filepath.Join(dir, "defenseclaw"), HookExecutable: fixture.Launcher, RollbackTargetVersion: target}
			if _, err := convertCodexConfigHookForms(opts, true, nil); err != nil {
				CodexConfigPathOverride = previous
				t.Fatalf("rollback to %q from %s: %v", target, start, err)
			}
			got := readCodexReleaseFormsConfig(t, configPath)
			expected := want
			if fixture.Releases[target] == fixture.Releases["1.0.10"] {
				// 1.0.9 and later own every form this release writes and
				// the bridge earlier rollbacks wrote: nothing is rewritten.
				expected = commands
			}
			for event, command := range expected {
				if len(got[event]) == 0 || got[event][0] != command {
					CodexConfigPathOverride = previous
					t.Fatalf("rollback to %q from %s: %s is not the command that release writes", target, start, event)
				}
			}
			if stop := got["Stop"]; len(stop) != 2 || stop[1] != "operator-stop.exe" {
				CodexConfigPathOverride = previous
				t.Fatalf("rollback to %q: the operator Stop handler changed: %v", target, stop)
			}
			if _, err := convertCodexConfigHookForms(SetupOpts{DataDir: opts.DataDir, HookExecutable: fixture.Launcher}, false, nil); err != nil {
				CodexConfigPathOverride = previous
				t.Fatal(err)
			}
			restored := readCodexReleaseFormsConfig(t, configPath)
			CodexConfigPathOverride = previous
			for event := range current {
				// The form this release renders now; a handler the
				// rollback kept (a target that writes this release forms)
				// stays as it was.
				wantBack := windowsCodexHookCommandForBinaryEvent(event, "codex-hooks-v4", fixture.Launcher)
				if fixture.Releases[target] == fixture.Releases["1.0.10"] && start == "1.0.10" {
					wantBack = current[event]
				}
				if restored[event][0] != wantBack {
					t.Fatalf("restore after a rollback to %q from %s: %s is not this release form", target, start, event)
				}
			}
		}
	}
}
