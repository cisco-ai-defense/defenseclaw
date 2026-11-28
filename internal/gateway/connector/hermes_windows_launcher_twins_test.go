// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// hermesHookRegistrationForTest returns what a Hermes Setup registers for the
// account whose data directory is dataDir, in the two arguments patchHermesHooks
// and removeHermesHooks take. Unix registers the generated hook script and
// pins no launcher. Windows registers no script: the command is the quoted
// native launcher (defenseclaw-hook.exe, forward slashes) with its connector
// flag, and the launcher is the second argument that makes the command the
// direct form (hermesConfiguredHookCommand).
func hermesHookRegistrationForTest(dataDir string) (hookScript, hookExecutable string) {
	if runtime.GOOS != "windows" {
		return filepath.Join(dataDir, "hooks", "hermes-hook.sh"), ""
	}
	hookExecutable = filepath.Join(filepath.Dir(dataDir), ".local", "bin", "defenseclaw-hook.exe")
	return windowsHermesDirectHookCommand(hookExecutable), hookExecutable
}

// hermesRegisteredTextForTest is the text config.yaml holds for that
// registration whichever YAML quoting writes it: the script path on Unix, the
// launcher path (forward slashes, as the command names it) on Windows.
func hermesRegisteredTextForTest(hookScript, hookExecutable string) string {
	if hookExecutable == "" {
		return hookScript
	}
	return filepath.ToSlash(hookExecutable)
}

// hermesWindowsRepairKeepsAnEditedLauncherForTest is the Windows form of the
// edited-hook-path repair. Setup writes the direct launcher command, a repair
// of an intact file changes no byte, and a command naming a launcher at
// another path is not one Setup writes: it is the account's own entry, kept
// beside the current one (one ownership predicate for Setup, repair and
// teardown).
func hermesWindowsRepairKeepsAnEditedLauncherForTest(t *testing.T, path, hookScript, hookExecutable string) {
	t.Helper()
	command := hermesConfiguredHookCommand(hookScript, hookExecutable)
	if command != hookScript || !strings.HasPrefix(command, `"`+filepath.ToSlash(hookExecutable)+`" `) {
		t.Fatalf("Windows Hermes command = %q, want the quoted launcher %q", command, hookExecutable)
	}
	if err := patchHermesHooks(path, hookScript, hookExecutable); err != nil {
		t.Fatalf("install Hermes hooks: %v", err)
	}
	installed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := patchHermesHooks(path, hookScript, hookExecutable); err != nil {
		t.Fatalf("repair intact Hermes hooks: %v", err)
	}
	if again, err := os.ReadFile(path); err != nil || !bytes.Equal(again, installed) {
		t.Fatalf("repair of an intact config changed it (err %v)\n got %q\nwant %q", err, again, installed)
	}
	moved := filepath.ToSlash(filepath.Join(filepath.Dir(filepath.Dir(hookExecutable)), "xbin", "defenseclaw-hook.exe"))
	edited := strings.ReplaceAll(string(installed), filepath.ToSlash(hookExecutable), moved)
	if edited == string(installed) {
		t.Fatal("fixture did not edit the launcher path")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := patchHermesHooks(path, hookScript, hookExecutable); err != nil {
		t.Fatalf("repair edited Hermes hooks: %v", err)
	}
	config, err := readYAMLObject(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range hermesRequiredHooks {
		entries := config["hooks"].(map[string]interface{})[spec.event].([]interface{})
		if len(entries) != 2 ||
			!strings.HasPrefix(entries[0].(map[string]interface{})["command"].(string), `"`+moved+`" `) ||
			entries[1].(map[string]interface{})["command"] != command {
			t.Fatalf("%s entries = %#v, want the edited launcher kept then one DefenseClaw entry", spec.event, entries)
		}
	}
}
