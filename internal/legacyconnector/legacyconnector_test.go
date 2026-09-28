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

package legacyconnector

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// cascadeEvents are the 12 legacy Cascade hook events 0.8.10 registered.
var cascadeEvents = []string{
	"pre_read_code",
	"post_read_code",
	"pre_write_code",
	"post_write_code",
	"pre_run_command",
	"post_run_command",
	"pre_mcp_tool_use",
	"post_mcp_tool_use",
	"pre_user_prompt",
	"post_cascade_response",
	"post_cascade_response_with_transcript",
	"post_setup_worktree",
}

func TestCanonicalMapsRetiredID(t *testing.T) {
	for _, name := range []string{"windsurf", "Windsurf", "  WINDSURF  ", "wind surf", "\twindsurf\n"} {
		got, migrated := Canonical(name)
		if got != Replacement || !migrated {
			t.Errorf("Canonical(%q) = %q, %v; want %q, true", name, got, migrated, Replacement)
		}
		if !IsRetired(name) {
			t.Errorf("IsRetired(%q) = false", name)
		}
	}
}

func TestCanonicalLeavesOtherNamesAlone(t *testing.T) {
	for _, name := range []string{"", "devin", "Devin", "cursor", "windsurfer", "codeium"} {
		got, migrated := Canonical(name)
		if got != name || migrated {
			t.Errorf("Canonical(%q) = %q, %v; want unchanged, false", name, got, migrated)
		}
	}
}

func TestMigrateConnectorKeysRenamesBlock(t *testing.T) {
	primary, rename, dropped := MigrateConnectorKeys("Windsurf", []string{"codex", "windsurf"})
	if primary != Replacement {
		t.Fatalf("primary = %q, want %q", primary, Replacement)
	}
	if !reflect.DeepEqual(rename, map[string]string{"windsurf": Replacement}) {
		t.Fatalf("rename = %v", rename)
	}
	if len(dropped) != 0 {
		t.Fatalf("dropped = %v, want none", dropped)
	}
}

func TestMigrateConnectorKeysExplicitDevinWins(t *testing.T) {
	primary, rename, dropped := MigrateConnectorKeys("devin", []string{"devin", "windsurf", "codex"})
	if primary != "devin" {
		t.Fatalf("primary = %q", primary)
	}
	if len(rename) != 0 {
		t.Fatalf("rename = %v, want none when an explicit devin block exists", rename)
	}
	if !reflect.DeepEqual(dropped, []string{"windsurf"}) {
		t.Fatalf("dropped = %v, want [windsurf]", dropped)
	}
	if notice := Notice("/etc/dc/config.yaml", dropped); !strings.Contains(notice, `"windsurf"`) ||
		!strings.Contains(notice, "/etc/dc/config.yaml") {
		t.Fatalf("notice does not list the dropped key and path: %s", notice)
	}
}

func TestMigrateConnectorKeysNoOp(t *testing.T) {
	primary, rename, dropped := MigrateConnectorKeys("cursor", []string{"codex", "cursor"})
	if primary != "cursor" || rename != nil || dropped != nil {
		t.Fatalf("MigrateConnectorKeys changed a config without the retired ID: %q %v %v", primary, rename, dropped)
	}
	primary, rename, dropped = MigrateConnectorKeys("", nil)
	if primary != "" || rename != nil || dropped != nil {
		t.Fatalf("empty input changed: %q %v %v", primary, rename, dropped)
	}
}

func TestLegacyPathsAreReadOnlyVendorLocations(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "home", "u")
	ws := filepath.Join(string(filepath.Separator), "src", "proj")
	rules := DesktopLegacyRulePaths(home, ws)
	wantRules := []string{
		filepath.Join(home, ".codeium", "windsurf", "memories", "global_rules.md"),
		filepath.Join(ws, ".windsurf", "rules"),
		filepath.Join(ws, ".windsurfrules"),
	}
	if !reflect.DeepEqual(rules, wantRules) {
		t.Fatalf("rules = %v, want %v", rules, wantRules)
	}
	skills := DesktopLegacySkillPaths(home, "")
	if !reflect.DeepEqual(skills, []string{filepath.Join(home, ".codeium", "windsurf", "skills")}) {
		t.Fatalf("skills without workspace = %v", skills)
	}
	if got := CascadeUserHooksPath(home); got != filepath.Join(home, ".codeium", "windsurf", "hooks.json") {
		t.Fatalf("hooks path = %s", got)
	}
	if OwnedHookScripts("") != nil || BackupDir("") != "" {
		t.Fatal("empty data dir must not resolve owned paths")
	}
}

// writeReleasedCascadeHooks writes the hooks.json shape 0.8.10 left behind:
// every Cascade event has a DefenseClaw entry, and two events also carry
// entries another tool owns.
func writeReleasedCascadeHooks(t *testing.T, path, dataDir string, mode os.FileMode) {
	t.Helper()
	script := filepath.Join(dataDir, "hooks", "windsurf-hook.sh")
	hooks := map[string]interface{}{}
	for _, event := range cascadeEvents {
		hooks[event] = []interface{}{
			map[string]interface{}{"command": script, "show_output": true},
		}
	}
	hooks["pre_run_command"] = append(hooks["pre_run_command"].([]interface{}),
		map[string]interface{}{"command": "/usr/local/bin/other-audit.sh", "show_output": false})
	hooks["pre_user_prompt"] = []interface{}{
		map[string]interface{}{"command": "/opt/team/prompt-check.sh"},
		map[string]interface{}{"command": shellQuote(script), "show_output": true},
	}
	doc := map[string]interface{}{"hooks": hooks, "operator": "kept"}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readHooks(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestRemoveOwnedCascadeHooksKeepsForeignEntries(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	path := CascadeUserHooksPath(home)
	writeReleasedCascadeHooks(t, path, dataDir, 0o600)

	removed, err := RemoveOwnedCascadeHooks(path, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if removed != len(cascadeEvents) {
		t.Fatalf("removed = %d, want %d", removed, len(cascadeEvents))
	}
	doc := readHooks(t, path)
	if doc["operator"] != "kept" {
		t.Fatalf("unrelated top-level key lost: %v", doc)
	}
	hooks := doc["hooks"].(map[string]interface{})
	if len(hooks) != 2 {
		t.Fatalf("remaining events = %v, want only the two with foreign entries", hooks)
	}
	for event, want := range map[string]string{
		"pre_run_command": "/usr/local/bin/other-audit.sh",
		"pre_user_prompt": "/opt/team/prompt-check.sh",
	} {
		list := hooks[event].([]interface{})
		if len(list) != 1 || list[0].(map[string]interface{})["command"] != want {
			t.Fatalf("%s = %v, want only %s", event, list, want)
		}
	}
	if count, err := CountOwnedCascadeHooks(path, dataDir); err != nil || count != 0 {
		t.Fatalf("CountOwnedCascadeHooks after cleanup = %d, %v", count, err)
	}
}

func TestRemoveOwnedCascadeHooksIgnoresLookalikeOutsideDataDir(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	path := CascadeUserHooksPath(home)
	lookalikes := []interface{}{
		map[string]interface{}{"command": filepath.Join(home, "other", "hooks", "windsurf-hook.sh")},
		map[string]interface{}{"command": filepath.Join(dataDir, "hooks", "windsurf-hook.sh") + " --extra"},
		map[string]interface{}{"powershell": "& 'C:\\elsewhere\\defenseclaw-hook.exe' hook --connector windsurf"},
	}
	data, _ := json.Marshal(map[string]interface{}{"hooks": map[string]interface{}{"pre_read_code": lookalikes}})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := RemoveOwnedCascadeHooks(path, dataDir, filepath.Join(home, "bin", "defenseclaw-hook.exe"))
	if err != nil || removed != 0 {
		t.Fatalf("removed = %d, %v; want 0 for lookalikes", removed, err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, data) {
		t.Fatalf("file rewritten although nothing was owned")
	}
}

func TestRemoveOwnedCascadeHooksRemovesNativeCommand(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	path := CascadeUserHooksPath(home)
	bin := filepath.Join(home, ".local", "bin", "defenseclaw-hook.exe")
	entries := []interface{}{
		map[string]interface{}{"powershell": NativeHookCommand(bin), "show_output": true},
		map[string]interface{}{"powershell": "& " + powershellQuote(filepath.Join(dataDir, "hooks", "windsurf-hook.ps1"))},
		map[string]interface{}{"powershell": "Write-Host operator"},
	}
	data, _ := json.Marshal(map[string]interface{}{"hooks": map[string]interface{}{"pre_run_command": entries}})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := RemoveOwnedCascadeHooks(path, dataDir, bin)
	if err != nil || removed != 2 {
		t.Fatalf("removed = %d, %v; want 2", removed, err)
	}
	list := readHooks(t, path)["hooks"].(map[string]interface{})["pre_run_command"].([]interface{})
	if len(list) != 1 || list[0].(map[string]interface{})["powershell"] != "Write-Host operator" {
		t.Fatalf("remaining = %v", list)
	}
}

func TestRemoveOwnedCascadeHooksMalformedLeavesFileUntouched(t *testing.T) {
	home := t.TempDir()
	path := CascadeUserHooksPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("{\"hooks\": {\"pre_read_code\": [ not json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := RemoveOwnedCascadeHooks(path, filepath.Join(home, ".defenseclaw"))
	if err == nil || removed != 0 {
		t.Fatalf("removed = %d, err = %v; want an error and no change", removed, err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, body) {
		t.Fatalf("malformed file was rewritten: %q", after)
	}
}

func TestRemoveOwnedCascadeHooksIdempotent(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	path := CascadeUserHooksPath(home)
	writeReleasedCascadeHooks(t, path, dataDir, 0o600)
	if _, err := RemoveOwnedCascadeHooks(path, dataDir); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)
	removed, err := RemoveOwnedCascadeHooks(path, dataDir)
	if err != nil || removed != 0 {
		t.Fatalf("second pass removed = %d, %v; want 0", removed, err)
	}
	second, _ := os.ReadFile(path)
	if !bytes.Equal(first, second) {
		t.Fatal("second pass rewrote the file")
	}
}

func TestRemoveOwnedCascadeHooksPreservesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	path := CascadeUserHooksPath(home)
	writeReleasedCascadeHooks(t, path, dataDir, 0o644)
	if _, err := RemoveOwnedCascadeHooks(path, dataDir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("mode = %o, want 644", got)
	}
}

func TestRemoveOwnedCascadeHooksMissingFileNoOp(t *testing.T) {
	home := t.TempDir()
	path := CascadeUserHooksPath(home)
	removed, err := RemoveOwnedCascadeHooks(path, filepath.Join(home, ".defenseclaw"))
	if err != nil || removed != 0 {
		t.Fatalf("removed = %d, %v; want 0, nil", removed, err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("cleanup created the file: %v", statErr)
	}
	if count, err := CountOwnedCascadeHooks(path, ""); err != nil || count != 0 {
		t.Fatalf("CountOwnedCascadeHooks on a missing file = %d, %v", count, err)
	}
}
