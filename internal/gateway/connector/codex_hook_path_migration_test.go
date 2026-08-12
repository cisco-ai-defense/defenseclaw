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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestPatchCodexConfigReplacesTrustedMatrixAfterDataDirChange(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("user-scoped Codex trust state is not installed on Windows")
	}

	root := t.TempDir()
	configPath := filepath.Join(root, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}

	// A same-basename third-party hook is intentionally trusted at the same
	// boundary. A path or basename-only migration would delete it.
	thirdPartyScript := filepath.Join(root, "third-party", "hooks", "codex-hook.sh")
	if err := os.MkdirAll(filepath.Dir(thirdPartyScript), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(thirdPartyScript, []byte("#!/bin/sh\n# third-party hook\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	thirdPartyMatcher := "*"
	thirdPartyHandler := map[string]interface{}{
		"type":    "command",
		"command": thirdPartyScript,
		"timeout": 30,
	}
	thirdPartyHash, err := codexCommandHookHashForPlatform(
		runtime.GOOS,
		"pre_tool_use",
		thirdPartyMatcher,
		thirdPartyHandler,
	)
	if err != nil {
		t.Fatalf("hash third-party hook: %v", err)
	}
	thirdPartyStateKey := codexHookStateKey(
		codexHookStateKeySource(configPath),
		"pre_tool_use",
		0,
		0,
	)
	thirdPartyState := map[string]interface{}{
		"trusted_hash":  thirdPartyHash,
		"enabled":       true,
		"operator_note": "preserve",
	}
	seed := map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{map[string]interface{}{
				"matcher": thirdPartyMatcher,
				"hooks":   []interface{}{thirdPartyHandler},
			}},
			"state": map[string]interface{}{
				thirdPartyStateKey:   thirdPartyState,
				"operator-unrelated": map[string]interface{}{"keep": "verbatim"},
			},
		},
	}
	seeded, err := toml.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, seeded, 0o600); err != nil {
		t.Fatal(err)
	}

	previous := CodexConfigPathOverride
	CodexConfigPathOverride = configPath
	t.Cleanup(func() { CodexConfigPathOverride = previous })

	connector := NewCodexConnector()
	dataDirA := filepath.Join(root, "dc-connector-upgrade.unit-a", "state")
	hookScriptA := filepath.Join(dataDirA, "hooks", "codex-hook.sh")
	first := SetupOpts{
		DataDir:       dataDirA,
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "test-notify-token-a",
		OTLPPathToken: strings.Repeat("a", 48),
	}
	if err := connector.patchCodexConfig(first, hookScriptA); err != nil {
		t.Fatalf("first Codex config patch: %v", err)
	}
	if err := os.RemoveAll(dataDirA); err != nil {
		t.Fatalf("remove predecessor data directory: %v", err)
	}

	dataDirB := filepath.Join(root, "dc-connector-upgrade.unit-b", "state")
	hookScriptB := filepath.Join(dataDirB, "hooks", "codex-hook.sh")
	second := SetupOpts{
		DataDir:       dataDirB,
		APIAddr:       "127.0.0.1:28970",
		APIToken:      "test-notify-token-b",
		OTLPPathToken: strings.Repeat("b", 48),
	}
	if err := connector.patchCodexConfig(second, hookScriptB); err != nil {
		t.Fatalf("second Codex config patch: %v", err)
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]interface{}{}
	if err := toml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse patched Codex config: %v", err)
	}
	hooks, ok := document["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("hooks table has type %T", document["hooks"])
	}
	expectedGroups, err := codexHookGroupsForOptions(second)
	if err != nil {
		t.Fatalf("resolve expected Codex hook contract: %v", err)
	}
	if err := verifyTrustedCodexHookMatrixForGroups(
		hooks,
		configPath,
		filepath.Join(dataDirB, "hooks"),
		expectedGroups,
	); err != nil {
		t.Fatalf("replacement matrix is not trusted: %v", err)
	}

	for _, group := range expectedGroups {
		oldCount := codexTestCommandCount(hooks[group.eventType], hookScriptA)
		newCount := codexTestCommandCount(hooks[group.eventType], hookScriptB)
		if oldCount != 0 || newCount != 1 {
			t.Errorf(
				"%s handler counts: predecessor=%d replacement=%d, want 0 and 1",
				group.eventType,
				oldCount,
				newCount,
			)
		}
	}

	preToolGroups, _ := hooks["PreToolUse"].([]interface{})
	if got := codexTestCommandCount(preToolGroups, thirdPartyScript); got != 1 {
		t.Fatalf("same-basename third-party hook count = %d, want 1: %#v", got, preToolGroups)
	}
	state, ok := hooks["state"].(map[string]interface{})
	if !ok {
		t.Fatalf("hooks.state has type %T", hooks["state"])
	}
	if want := len(expectedGroups) + 2; len(state) != want {
		t.Fatalf("hooks.state entry count = %d, want %d: %#v", len(state), want, state)
	}
	if !codexValueMatches(state[thirdPartyStateKey], thirdPartyState) {
		t.Fatalf("third-party trust state changed: got %#v, want %#v", state[thirdPartyStateKey], thirdPartyState)
	}
	if !codexValueMatches(
		state["operator-unrelated"],
		map[string]interface{}{"keep": "verbatim"},
	) {
		t.Fatalf("unrelated operator state changed: %#v", state["operator-unrelated"])
	}
}

func TestInferTrustedCodexManagedHookCommandsRequiresOwnershipEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("user-scoped Codex trust state is not installed on Windows")
	}

	for _, test := range []struct {
		name      string
		directory string
		body      string
		wantOwned bool
	}{
		{
			name:      "complete trusted third-party matrix is preserved",
			directory: filepath.Join("third-party", "hooks"),
			body:      "#!/bin/sh\n# operator-managed policy hook\n",
		},
		{
			name:      "missing generic defenseclaw-named third-party matrix is preserved",
			directory: filepath.Join("defenseclaw-third-party", "hooks"),
		},
		{
			name:      "live marker-bearing custom matrix is recognized",
			directory: filepath.Join("custom-state", "hooks"),
			body:      "#!/bin/sh\n# defenseclaw-managed-hook v6\n",
			wantOwned: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "codex", "config.toml")
			hooksDir := filepath.Join(root, test.directory)
			script := filepath.Join(hooksDir, "codex-hook.sh")
			if err := os.MkdirAll(hooksDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if test.body != "" {
				if err := os.WriteFile(script, []byte(test.body), 0o700); err != nil {
					t.Fatal(err)
				}
			}

			hooks := buildCodexHooksTableForGroups(configPath, script, codexHookGroups)
			if err := trustOwnedCodexHooks(
				hooks,
				configPath,
				hooksDir,
				codexHookGroups,
			); err != nil {
				t.Fatalf("trust complete fixture matrix: %v", err)
			}
			managed, err := inferTrustedCodexManagedHookCommands(hooks, configPath)
			if err != nil {
				t.Fatalf("infer managed commands: %v", err)
			}
			_, gotOwned := managed[script]
			if gotOwned != test.wantOwned {
				t.Fatalf("owned=%t, want %t: %#v", gotOwned, test.wantOwned, managed)
			}
		})
	}
}

func TestInferTrustedCodexManagedHookCommandsRejectsEditedProfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("user-scoped Codex trust state is not installed on Windows")
	}

	root := t.TempDir()
	configPath := filepath.Join(root, "codex", "config.toml")
	script := filepath.Join(root, "dc-connector-upgrade.edited", "hooks", "codex-hook.sh")
	profiles := codexShippedManagedHookProfiles()
	profile := append([]codexHookGroup(nil), profiles[len(profiles)-1]...)
	profile = append(profile, codexHookGroup{"Notification", "*", 30})
	hooks := buildCodexHooksTableForGroups(configPath, script, profile)
	if err := trustOwnedCodexHooks(
		hooks,
		configPath,
		filepath.Dir(script),
		profile,
	); err != nil {
		t.Fatalf("trust edited fixture matrix: %v", err)
	}

	managed, err := inferTrustedCodexManagedHookCommands(hooks, configPath)
	if err != nil {
		t.Fatalf("infer managed commands: %v", err)
	}
	if _, claimed := managed[script]; claimed {
		t.Fatalf("edited six-event superset was claimed as a shipped profile: %#v", managed)
	}
}

func TestMergeOwnedCodexHooksCollapsesAccumulatedTrustedMatrices(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("user-scoped Codex trust state is not installed on Windows")
	}

	root := t.TempDir()
	configPath := filepath.Join(root, "codex", "config.toml")
	hooks := map[string]interface{}{
		"state": map[string]interface{}{
			"operator-unrelated": map[string]interface{}{"keep": "verbatim"},
		},
	}
	profiles := codexShippedManagedHookProfiles()
	profilesBySize := make(map[int][]codexHookGroup, len(profiles))
	var legacyElevenEvents, currentElevenEvents []codexHookGroup
	for _, profile := range profiles {
		if len(profile) == 11 {
			switch profile[len(profile)-1].timeout {
			case 3:
				legacyElevenEvents = profile
			case 60:
				currentElevenEvents = profile
			}
			continue
		}
		profilesBySize[len(profile)] = profile
	}
	if legacyElevenEvents == nil || currentElevenEvents == nil {
		t.Fatalf(
			"SessionEnd profiles: legacy=%v current=%v, want both shipped timeout variants",
			legacyElevenEvents,
			currentElevenEvents,
		)
	}
	for _, size := range []int{5, 6, 8, 10} {
		if profilesBySize[size] == nil {
			t.Fatalf("shipped Codex hook profile with %d events is missing", size)
		}
	}
	predecessors := []struct {
		command string
		groups  []codexHookGroup
	}{
		{
			command: filepath.Join(root, "dc-connector-upgrade.unit-five", "hooks", "codex-hook.sh"),
			groups:  profilesBySize[5],
		},
		{
			command: filepath.Join(root, "dc-connector-upgrade.unit-six", "hooks", "codex-hook.sh"),
			groups:  profilesBySize[6],
		},
		{
			command: filepath.Join(root, "dc-connector-upgrade.unit-eight", "hooks", "codex-hook.sh"),
			groups:  profilesBySize[8],
		},
		{
			command: filepath.Join(root, "dc-connector-upgrade.unit-ten", "hooks", "codex-hook.sh"),
			groups:  profilesBySize[10],
		},
		{
			command: filepath.Join(root, "dc-connector-upgrade.unit-eleven-legacy", "hooks", "codex-hook.sh"),
			groups:  legacyElevenEvents,
		},
		{
			command: filepath.Join(root, "dc-connector-upgrade.unit-eleven-current", "hooks", "codex-hook.sh"),
			groups:  currentElevenEvents,
		},
	}
	for _, predecessor := range predecessors {
		matrix := buildCodexHooksTableForGroups(configPath, predecessor.command, predecessor.groups)
		for _, group := range predecessor.groups {
			existing, _ := hooks[group.eventType].([]interface{})
			hooks[group.eventType] = append(
				existing,
				matrix[group.eventType].([]interface{})...,
			)
		}
		if err := trustOwnedCodexHooks(
			hooks,
			configPath,
			filepath.Dir(predecessor.command),
			predecessor.groups,
		); err != nil {
			t.Fatalf("trust predecessor %q: %v", predecessor.command, err)
		}
	}
	// Put a separately trusted operator hook after the accumulated matrices.
	// Collapsing the predecessor groups must not move its positional state key.
	operatorMatcher := "^Shell$"
	operatorHandler := map[string]interface{}{
		"type":    "command",
		"command": filepath.Join(root, "operator", "policy-hook"),
		"timeout": 7,
	}
	operatorGroupIndex := len(hooks["PreToolUse"].([]interface{}))
	hooks["PreToolUse"] = append(hooks["PreToolUse"].([]interface{}), map[string]interface{}{
		"matcher": operatorMatcher,
		"hooks":   []interface{}{operatorHandler},
	})
	operatorHash, err := codexCommandHookHashForPlatform(
		runtime.GOOS,
		"pre_tool_use",
		operatorMatcher,
		operatorHandler,
	)
	if err != nil {
		t.Fatalf("hash operator hook: %v", err)
	}
	operatorKey := codexHookStateKey(
		codexHookStateKeySource(configPath),
		"pre_tool_use",
		operatorGroupIndex,
		0,
	)
	operatorState := map[string]interface{}{
		"trusted_hash": operatorHash,
		"enabled":      true,
		"note":         "preserve-position",
	}
	hooks["state"].(map[string]interface{})[operatorKey] = operatorState

	replacementDir := filepath.Join(root, "current", "hooks")
	replacement := filepath.Join(replacementDir, "codex-hook.sh")
	if err := mergeOwnedCodexHooks(
		hooks,
		configPath,
		replacement,
		replacementDir,
		true,
		codexHookGroups,
	); err != nil {
		t.Fatalf("collapse predecessor matrices: %v", err)
	}
	if err := verifyTrustedCodexHookMatrixForGroups(
		hooks,
		configPath,
		replacementDir,
		codexHookGroups,
	); err != nil {
		t.Fatalf("replacement matrix is not trusted: %v", err)
	}
	allKnownGroups := append([]codexHookGroup(nil), codexHookGroups...)
	allKnownGroups = append(allKnownGroups, codexSessionEndHookGroup)
	for _, group := range allKnownGroups {
		groups, _ := hooks[group.eventType].([]interface{})
		if group.eventType == codexSessionEndHookGroup.eventType {
			if len(groups) != 0 {
				t.Errorf("%s group count = %d, want 0: %#v", group.eventType, len(groups), groups)
			}
		} else if group.eventType != "PreToolUse" && len(groups) != 1 {
			t.Errorf("%s group count = %d, want 1: %#v", group.eventType, len(groups), groups)
		}
		if group.eventType != codexSessionEndHookGroup.eventType && codexTestCommandCount(groups, replacement) != 1 {
			got := codexTestCommandCount(groups, replacement)
			t.Errorf("%s replacement handler count = %d, want 1", group.eventType, got)
		}
		for _, predecessor := range predecessors {
			if got := codexTestCommandCount(groups, predecessor.command); got != 0 {
				t.Errorf("%s retained %d predecessor handlers for %q", group.eventType, got, predecessor.command)
			}
		}
	}
	state, ok := hooks["state"].(map[string]interface{})
	if !ok {
		t.Fatalf("hooks.state has type %T", hooks["state"])
	}
	if want := len(codexHookGroups) + 2; len(state) != want {
		t.Fatalf("hooks.state entry count = %d, want %d: %#v", len(state), want, state)
	}
	if !codexValueMatches(
		state["operator-unrelated"],
		map[string]interface{}{"keep": "verbatim"},
	) {
		t.Fatalf("unrelated operator state changed: %#v", state["operator-unrelated"])
	}
	if !codexValueMatches(state[operatorKey], operatorState) {
		t.Fatalf("later operator trust state changed or moved: got %#v, want %#v", state[operatorKey], operatorState)
	}
	if got := codexTestCommandCount(hooks["PreToolUse"], operatorHandler["command"].(string)); got != 1 {
		t.Fatalf("later operator hook count = %d, want 1", got)
	}
}

func codexTestCommandCount(rawGroups interface{}, command string) int {
	groups, _ := rawGroups.([]interface{})
	count := 0
	for _, rawGroup := range groups {
		group, _ := rawGroup.(map[string]interface{})
		handlers, _ := group["hooks"].([]interface{})
		for _, rawHandler := range handlers {
			handler, _ := rawHandler.(map[string]interface{})
			if handler["command"] == command {
				count++
			}
		}
	}
	return count
}
