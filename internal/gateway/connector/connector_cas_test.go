// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestAtomicTransformMissingTargetPreservesRacingCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new-settings.json")
	hookCalls := 0
	restoreHook := setAtomicTransformBeforeCommitHookForTest(path, func(attempt int) {
		hookCalls++
		if attempt != 0 {
			return
		}
		if err := os.WriteFile(path, []byte(`{"operator":{"kept":true}}`), 0o600); err != nil {
			t.Fatalf("create racing config: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	err := atomicTransformFile(path, 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
		settings := map[string]interface{}{}
		if exists {
			if err := json.Unmarshal(current, &settings); err != nil {
				return atomicTransformResult{}, err
			}
		}
		settings["defenseclaw"] = map[string]interface{}{"installed": true}
		out, err := json.Marshal(settings)
		return atomicTransformResult{Data: out}, err
	})
	if err != nil {
		t.Fatalf("atomicTransformFile: %v", err)
	}
	if hookCalls < 2 {
		t.Fatalf("before-commit hook calls = %d, want retry after racing create", hookCalls)
	}
	settings := readCASJSON(t, path)
	operator, _ := settings["operator"].(map[string]interface{})
	if operator["kept"] != true {
		t.Fatalf("racing create was overwritten: %#v", settings)
	}
	managed, _ := settings["defenseclaw"].(map[string]interface{})
	if managed["installed"] != true {
		t.Fatalf("transform was not merged after retry: %#v", settings)
	}
}

func TestCodexSetupCASPreservesConcurrentEdit(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previous })

	hookCalls := 0
	restoreHook := setAtomicTransformBeforeCompareHookForTest(configPath, func(attempt int) {
		hookCalls++
		if attempt != 0 {
			return
		}
		// Truncate in place: identity is unchanged, but exact-byte comparison
		// must reject the stale transform and merge this new table on retry.
		concurrent := "model = \"gpt-5\"\n\n[concurrent_setup]\nkept = true\n"
		if err := os.WriteFile(configPath, []byte(concurrent), 0o600); err != nil {
			t.Fatalf("inject concurrent Codex setup edit: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	connector := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := connector.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if hookCalls < 2 {
		t.Fatalf("CAS hook calls = %d, want retry after concurrent edit", hookCalls)
	}
	config := readCASTOML(t, configPath)
	concurrent, _ := config["concurrent_setup"].(map[string]interface{})
	if concurrent["kept"] != true {
		t.Fatalf("concurrent Codex setup edit was lost: %#v", config)
	}
	hooks, _ := config["hooks"].(map[string]interface{})
	if err := verifyTrustedCodexHookMatrix(hooks, configPath, filepath.Join(dir, "hooks")); err != nil {
		t.Fatalf("Codex hooks not installed/trusted after retry: %v", err)
	}
	if _, err := os.Stat(managedFileBackupPath(dir, connector.Name(), "config.toml")); !os.IsNotExist(err) {
		t.Fatalf("exact managed backup survived concurrent setup edit: %v", err)
	}
	if err := connector.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown after concurrent setup edit: %v", err)
	}
	config = readCASTOML(t, configPath)
	concurrent, _ = config["concurrent_setup"].(map[string]interface{})
	if concurrent["kept"] != true {
		t.Fatalf("teardown erased concurrent Codex setup edit: %#v", config)
	}
}

func TestCodexTeardownCASPreservesConcurrentEdit(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previous })

	connector := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := connector.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	hookCalls := 0
	restoreHook := setAtomicTransformBeforeCompareHookForTest(configPath, func(attempt int) {
		hookCalls++
		if attempt != 0 {
			return
		}
		// Replace the file atomically: both identity and bytes change after
		// teardown computed its first (exact-backup) result.
		config := readCASTOML(t, configPath)
		config["concurrent_teardown"] = map[string]interface{}{"kept": true}
		out, err := toml.Marshal(config)
		if err != nil {
			t.Fatalf("marshal concurrent Codex teardown edit: %v", err)
		}
		if err := atomicWriteFile(configPath, out, 0o600); err != nil {
			t.Fatalf("inject concurrent Codex teardown edit: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	if err := connector.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if hookCalls < 2 {
		t.Fatalf("CAS hook calls = %d, want retry after concurrent edit", hookCalls)
	}
	config := readCASTOML(t, configPath)
	concurrent, _ := config["concurrent_teardown"].(map[string]interface{})
	if concurrent["kept"] != true {
		t.Fatalf("concurrent Codex teardown edit was lost: %#v", config)
	}
	if hooks, ok := config["hooks"].(map[string]interface{}); ok {
		if locations := codexOwnedHookCount(hooks, filepath.Join(dir, "hooks")); locations != 0 {
			t.Fatalf("DefenseClaw Codex hooks survived teardown: %#v", hooks)
		}
	}
}

func TestClaudeCodeSetupCASPreservesConcurrentEdit(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })

	hookCalls := 0
	restoreHook := setAtomicTransformBeforeCompareHookForTest(settingsPath, func(attempt int) {
		hookCalls++
		if hookCalls != 1 || attempt != 0 {
			return
		}
		concurrent := []byte(`{"theme":"dark","concurrentSetup":{"kept":true}}`)
		if err := os.WriteFile(settingsPath, concurrent, 0o600); err != nil {
			t.Fatalf("inject concurrent Claude setup edit: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	connector := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := connector.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if hookCalls < 2 {
		t.Fatalf("CAS hook calls = %d, want retry after concurrent edit", hookCalls)
	}
	settings := readCASJSON(t, settingsPath)
	concurrent, _ := settings["concurrentSetup"].(map[string]interface{})
	if concurrent["kept"] != true {
		t.Fatalf("concurrent Claude setup edit was lost: %#v", settings)
	}
	if _, ok := settings["hooks"].(map[string]interface{}); !ok {
		t.Fatalf("Claude hooks missing after CAS retry: %#v", settings)
	}
	if _, ok := settings["env"].(map[string]interface{}); !ok {
		t.Fatalf("Claude OTel env missing after CAS retry: %#v", settings)
	}
	if _, err := os.Stat(managedFileBackupPath(dir, connector.Name(), "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("exact managed backup survived concurrent setup edit: %v", err)
	}
	if err := connector.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown after concurrent setup edit: %v", err)
	}
	settings = readCASJSON(t, settingsPath)
	concurrent, _ = settings["concurrentSetup"].(map[string]interface{})
	if concurrent["kept"] != true {
		t.Fatalf("teardown erased concurrent Claude setup edit: %#v", settings)
	}
}

func TestClaudeCodeTeardownCASPreservesConcurrentEdit(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })

	connector := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := connector.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	hookCalls := 0
	restoreHook := setAtomicTransformBeforeCompareHookForTest(settingsPath, func(attempt int) {
		hookCalls++
		if attempt != 0 {
			return
		}
		settings := readCASJSON(t, settingsPath)
		settings["concurrentTeardown"] = map[string]interface{}{"kept": true}
		out, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			t.Fatalf("marshal concurrent Claude teardown edit: %v", err)
		}
		if err := atomicWriteFile(settingsPath, out, 0o600); err != nil {
			t.Fatalf("inject concurrent Claude teardown edit: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	if err := connector.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if hookCalls < 2 {
		t.Fatalf("CAS hook calls = %d, want retry after concurrent edit", hookCalls)
	}
	settings := readCASJSON(t, settingsPath)
	concurrent, _ := settings["concurrentTeardown"].(map[string]interface{})
	if concurrent["kept"] != true {
		t.Fatalf("concurrent Claude teardown edit was lost: %#v", settings)
	}
	if hooks, ok := settings["hooks"].(map[string]interface{}); ok && len(hooks) != 0 {
		t.Fatalf("DefenseClaw Claude hooks survived teardown: %#v", hooks)
	}
	if env, ok := settings["env"].(map[string]interface{}); ok {
		for _, key := range claudeCodeOtelEnvKeys {
			if _, exists := env[key]; exists {
				t.Fatalf("DefenseClaw Claude env %s survived teardown: %#v", key, env)
			}
		}
	}
}

func TestCodexRepeatedSetupDoesNotBlessOperatorDriftForExactRestore(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previous })

	conn := NewCodexConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("first Setup: %v", err)
	}
	config := readCASTOML(t, configPath)
	config["operator_after_setup"] = map[string]interface{}{"kept": true}
	out, err := toml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(configPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	if _, err := os.Stat(managedFileBackupPath(dir, conn.Name(), "config.toml")); !os.IsNotExist(err) {
		t.Fatalf("repeated setup retained unsafe exact backup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	config = readCASTOML(t, configPath)
	operator, _ := config["operator_after_setup"].(map[string]interface{})
	if operator["kept"] != true {
		t.Fatalf("teardown erased operator drift: %#v", config)
	}
}

func TestClaudeRepeatedSetupDoesNotBlessOperatorDriftForExactRestore(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })

	conn := NewClaudeCodeConnector()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("first Setup: %v", err)
	}
	settings := readCASJSON(t, settingsPath)
	settings["operatorAfterSetup"] = map[string]interface{}{"kept": true}
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(settingsPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	if _, err := os.Stat(managedFileBackupPath(dir, conn.Name(), "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("repeated setup retained unsafe exact backup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	settings = readCASJSON(t, settingsPath)
	operator, _ := settings["operatorAfterSetup"].(map[string]interface{})
	if operator["kept"] != true {
		t.Fatalf("teardown erased operator drift: %#v", settings)
	}
}

func readCASTOML(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read TOML %s: %v", path, err)
	}
	result := map[string]interface{}{}
	if err := toml.Unmarshal(data, &result); err != nil {
		t.Fatalf("parse TOML %s: %v\n%s", path, err, data)
	}
	return result
}

func readCASJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read JSON %s: %v", path, err)
	}
	result := map[string]interface{}{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("parse JSON %s: %v\n%s", path, err, data)
	}
	return result
}

func codexOwnedHookCount(hooks map[string]interface{}, hooksDir string) int {
	count := 0
	for eventType, groups := range hooks {
		if eventType == "state" {
			continue
		}
		locations, _ := ownedCodexHookLocations(runtime.GOOS, codexHookEventKeyLabel(eventType), groups, hooksDir)
		count += len(locations)
	}
	return count
}
