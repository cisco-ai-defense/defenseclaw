// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// TestCodexRollbackConvertsDirectHooksToEarlierBridgeAndBack pins GAP-2553:
// before a rollback to 1.0.4 the per-user Codex handlers in the direct
// cmd.exe form (GAP-1908) become the bridge 1.0.4 owns, with their trust,
// and only those; an aborted rollback puts them back.
func TestCodexRollbackConvertsDirectHooksToEarlierBridgeAndBack(t *testing.T) {
	savedSystem := windowsSystemDirectory
	windowsSystemDirectory = func() string { return `C:\Windows\System32` }
	t.Cleanup(func() { windowsSystemDirectory = savedSystem })
	const launcher = `C:\Users\dcw std1\.local\bin\defenseclaw-hook.exe`
	const contract = "codex-hooks-v4"
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	dataDir := filepath.Join(dir, "defenseclaw")
	for _, path := range []string{filepath.Dir(configPath), dataDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	previousPath := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousPath })

	directFor := func(hookBinary, event string) string {
		t.Helper()
		command, ok := windowsCmdDirectHookCommand(hookBinary, nativeHookBridgeArguments("codex", event, contract, nil))
		if !ok {
			t.Fatalf("no direct form for %q", hookBinary)
		}
		return command
	}
	handler := func(command string) map[string]interface{} {
		return map[string]interface{}{"type": "command", "command": command, "command_windows": command, "timeout": 30}
	}
	foreign := directFor(`C:\Tools\defenseclaw-hook.exe`, "PreToolUse")
	hooks := map[string]interface{}{
		"PreToolUse": []interface{}{
			map[string]interface{}{"matcher": "*", "hooks": []interface{}{handler(directFor(launcher, "PreToolUse"))}},
			map[string]interface{}{"hooks": []interface{}{handler(foreign)}},
		},
		"SessionStart": []interface{}{
			map[string]interface{}{"matcher": "startup|resume", "hooks": []interface{}{handler(directFor(launcher, "SessionStart"))}},
		},
		// Bound to another event: not the handler of this one.
		"Stop": []interface{}{
			map[string]interface{}{"hooks": []interface{}{handler(directFor(launcher, "PostToolUse"))}},
		},
	}
	keySource := codexHookStateKeySource(configPath)
	state := map[string]interface{}{}
	trust := func(eventType string, groupIndex int) string {
		t.Helper()
		group := hooks[eventType].([]interface{})[groupIndex].(map[string]interface{})
		eventKey := codexHookEventKeyLabel(eventType)
		hash, err := codexCommandHookHashForPlatform("windows", eventKey, group["matcher"], group["hooks"].([]interface{})[0].(map[string]interface{}))
		if err != nil {
			t.Fatal(err)
		}
		key := codexHookStateKey(keySource, eventKey, groupIndex, 0)
		state[key] = map[string]interface{}{"trusted_hash": hash}
		return key
	}
	preKey := trust("PreToolUse", 0)
	foreignKey := trust("PreToolUse", 1)
	trust("Stop", 0)
	// A record that does not prove the handler stays as it is.
	sessionKey := codexHookStateKey(keySource, "session_start", 0, 0)
	state[sessionKey] = map[string]interface{}{"trusted_hash": "sha256:operator"}
	hooks["state"] = state
	rendered, err := toml.Marshal(map[string]interface{}{"model": "gpt-5", "hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte("# operator comment\n"), rendered...)
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	opts := SetupOpts{DataDir: dataDir, HookExecutable: launcher}
	var kept []byte
	count, err := convertCodexConfigHookForms(opts, true, func(_ string, data []byte) error {
		kept = append([]byte(nil), data...)
		return nil
	})
	if err != nil || count != 2 {
		t.Fatalf("convert = %d, %v; want 2 handlers", count, err)
	}
	if !bytes.Equal(kept, original) {
		t.Fatal("the copy kept before the conversion is not the file as found")
	}
	converted, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(converted), "# operator comment") {
		t.Fatalf("operator comment lost:\n%s", converted)
	}
	cfg := map[string]interface{}{}
	if err := parseCodexTOML(converted, &cfg); err != nil {
		t.Fatal(err)
	}
	got := cfg["hooks"].(map[string]interface{})
	gotState := got["state"].(map[string]interface{})
	for _, event := range []string{"PreToolUse", "SessionStart"} {
		group := got[event].([]interface{})[0].(map[string]interface{})
		h := group["hooks"].([]interface{})[0].(map[string]interface{})
		want := windowsNativePowerShellHookCommandForCodexEvent(event, contract, launcher)
		if h["command"] != want || h["command_windows"] != want {
			t.Fatalf("%s handler = %v; want the 1.0.4 bridge", event, h)
		}
	}
	preGroup := got["PreToolUse"].([]interface{})[0].(map[string]interface{})
	preHash, err := codexCommandHookHashForPlatform("windows", "pre_tool_use", preGroup["matcher"], preGroup["hooks"].([]interface{})[0].(map[string]interface{}))
	if err != nil {
		t.Fatal(err)
	}
	if gotState[preKey].(map[string]interface{})["trusted_hash"] != preHash {
		t.Fatal("trust of the converted PreToolUse handler was not carried over")
	}
	if gotState[sessionKey].(map[string]interface{})["trusted_hash"] != "sha256:operator" {
		t.Fatal("a trust record that did not prove the handler was rewritten")
	}
	foreignGroup := got["PreToolUse"].([]interface{})[1].(map[string]interface{})
	if foreignGroup["hooks"].([]interface{})[0].(map[string]interface{})["command"] != foreign {
		t.Fatal("a handler of another launcher was rewritten")
	}
	if gotState[foreignKey] == nil {
		t.Fatal("the trust record of a handler of another launcher was dropped")
	}
	stop := got["Stop"].([]interface{})[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
	if stop["command"] != directFor(launcher, "PostToolUse") {
		t.Fatal("a handler bound to another event was rewritten")
	}

	if count, err := convertCodexConfigHookForms(opts, true, nil); err != nil || count != 0 {
		t.Fatalf("second conversion = %d, %v; want nothing to do", count, err)
	}
	if count, err := convertCodexConfigHookForms(SetupOpts{DataDir: dataDir, HookExecutable: launcher, ManagedEnterprise: true}, false, nil); err != nil || count != 0 {
		t.Fatalf("managed restore = %d, %v; want nothing to do", count, err)
	}
	if count, err := convertCodexConfigHookForms(opts, false, nil); err != nil || count != 2 {
		t.Fatalf("restore = %d, %v; want 2 handlers", count, err)
	}
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	wantCfg, gotCfg := map[string]interface{}{}, map[string]interface{}{}
	if err := parseCodexTOML(original, &wantCfg); err != nil {
		t.Fatal(err)
	}
	if err := parseCodexTOML(restored, &gotCfg); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(wantCfg, gotCfg) {
		t.Fatalf("restore did not give back the direct form:\nwant %v\ngot  %v", wantCfg, gotCfg)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("restore changed the layout:\n%s", restored)
	}
}
