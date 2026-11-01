// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCodexPerUserRollbackLeavesTheBridgeTheEarlierReleaseOwns is the
// GAP-2553 path on Windows: a per-user Setup writes the direct cmd.exe form,
// prepare-rollback rewrites every handler as the trusted 1.0.4 bridge and
// keeps a copy, and an aborted rollback restores the file Setup wrote.
func TestCodexPerUserRollbackLeavesTheBridgeTheEarlierReleaseOwns(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	dataDir := filepath.Join(dir, "defenseclaw")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousPath := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previousPath })
	previousInspector := codexPolicyInspector
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{Source: "per-user rollback test"}, nil
	}
	t.Cleanup(func() { codexPolicyInspector = previousInspector })
	launcher := filepath.Join(dir, "DefenseClaw", windowsHookBinaryName)
	setHookBinaryOverride(t, launcher)

	conn := NewCodexConnector()
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("setup: %v", err)
	}
	setup, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(setup), `\cmd.exe /d /v:off /c `) {
		t.Fatalf("setup did not write the direct form:\n%s", setup)
	}
	groups, err := codexHookGroupsForSetup(opts)
	if err != nil {
		t.Fatal(err)
	}

	count, err := conn.ConvertHooksForRollback(opts)
	if err != nil || count != len(groups) {
		t.Fatalf("ConvertHooksForRollback = %d, %v; want %d handlers", count, err, len(groups))
	}
	converted, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(converted), `/d /v:off /c`) {
		t.Fatalf("a direct handler is left after the conversion:\n%s", converted)
	}
	kept, err := os.ReadFile(filepath.Join(dataDir, "backups", codexRollbackBackupName))
	if err != nil || !bytes.Equal(kept, setup) {
		t.Fatalf("copy before the conversion = %v; want the file Setup wrote", err)
	}
	cfg := map[string]interface{}{}
	if err := parseCodexTOML(converted, &cfg); err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	state := hooks["state"].(map[string]interface{})
	keySource := codexHookStateKeySource(configPath)
	for _, group := range groups {
		eventKey := codexHookEventKeyLabel(group.eventType)
		locations, err := ownedCodexHookLocations("windows", eventKey, hooks[group.eventType], filepath.Join(dataDir, "hooks"))
		if err != nil || len(locations) != 1 {
			t.Fatalf("%s: %d owned handlers, %v; want 1", group.eventType, len(locations), err)
		}
		location := locations[0]
		want := windowsNativePowerShellHookCommandForCodexEvent(group.eventType, codexHandlerContract(t, group.eventType, setup), launcher)
		if location.handler["command"] != want || location.handler["command_windows"] != want {
			t.Fatalf("%s handler is not the 1.0.4 bridge: %v", group.eventType, location.handler)
		}
		key := codexHookStateKey(keySource, eventKey, location.groupIndex, location.handlerIndex)
		entry, _ := state[key].(map[string]interface{})
		if entry == nil || entry["trusted_hash"] != location.currentHash {
			t.Fatalf("%s: the converted handler is not trusted (%v)", group.eventType, entry)
		}
	}

	if count, err := conn.RestoreHooksAfterRollback(opts); err != nil || count != len(groups) {
		t.Fatalf("RestoreHooksAfterRollback = %d, %v; want %d handlers", count, err, len(groups))
	}
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, setup) {
		t.Fatalf("restore did not give back the file Setup wrote:\n%s", restored)
	}
	if ok, reason, err := conn.checkOwnedHookContract(opts); err != nil || !ok {
		t.Fatalf("restored hook contract = %v (%s), %v", ok, reason, err)
	}
}

// codexHandlerContract is the hook contract the direct handler of event in
// the Setup output names.
func codexHandlerContract(t *testing.T, event string, setup []byte) string {
	t.Helper()
	cfg := map[string]interface{}{}
	if err := parseCodexTOML(setup, &cfg); err != nil {
		t.Fatal(err)
	}
	group := cfg["hooks"].(map[string]interface{})[event].([]interface{})[0].(map[string]interface{})
	command, _ := group["hooks"].([]interface{})[0].(map[string]interface{})["command"].(string)
	match := windowsCodexDirectBoundArgumentsPattern.FindStringSubmatch(command)
	if match == nil || match[1] != event {
		t.Fatalf("%s: no bound direct command in %q", event, command)
	}
	return match[2]
}
