// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// The Python status and quickstart readers (cli/defenseclaw/hook_integrity.py
// _hook_section, cli/tests/test_hook_integrity_antigravity_devin.py) read
// testdata/antigravity_devin_hooks.json. Antigravity keeps DefenseClaw's hooks
// under top-level defenseclaw-antigravity-<event> keys and Devin's project
// hooks.v1.json holds the event map at its root; status read only a top-level
// hooks key and reported both unregistered after a clean Setup (GAP-0489).
// Regenerate with DEFENSECLAW_UPDATE_GOLDEN=1.

const antigravityDevinGoldenFile = "antigravity_devin_hooks.json"

// The PowerShell path in the golden; Windows renders the real system directory.
const goldenWindowsPowerShell = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

type goldenHookFile struct {
	Connector string                 `json:"connector"`
	GOOS      string                 `json:"goos"`
	Path      string                 `json:"path"`
	Healthy   map[string]interface{} `json:"healthy"`
	Removed   map[string]interface{} `json:"removed"`
}

type antigravityDevinGolden struct {
	DataDir    string                    `json:"data_dir"`
	HookBinary string                    `json:"hook_binary_windows"`
	Files      map[string]goldenHookFile `json:"files"`
}

// A user's own hook set beside DefenseClaw's: Setup keeps it, teardown keeps
// it, and status must not count it as DefenseClaw's.
func foreignTeamHook() map[string]interface{} {
	return map[string]interface{}{
		"matcher": "*",
		"hooks":   []interface{}{map[string]interface{}{"type": "command", "command": "/usr/local/bin/team-audit"}},
	}
}

func readGoldenJSON(t *testing.T, path string, replacements ...string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.NewReplacer(replacements...).Replace(string(data))
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

func writeSeed(t *testing.T, path string, seed map[string]interface{}) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONObject(path, seed); err != nil {
		t.Fatal(err)
	}
}

// jsonText is value as it appears inside a JSON string.
func jsonText(value string) string {
	quoted, _ := json.Marshal(value)
	return string(quoted[1 : len(quoted)-1])
}

func renderAntigravityDevinHookFiles(t *testing.T, golden antigravityDevinGolden) map[string]goldenHookFile {
	t.Helper()
	setHookBinaryOverride(t, golden.HookBinary)
	opts := SetupOpts{DataDir: golden.DataDir}
	normalize := []string{jsonText(windowsSystemPowerShellExe()), jsonText(goldenWindowsPowerShell)}
	files := map[string]goldenHookFile{}
	for _, goos := range []string{"linux", "windows"} {
		dir := t.TempDir()

		antigravity := NewAntigravityConnector()
		path := filepath.Join(dir, "hooks.json")
		writeSeed(t, path, map[string]interface{}{"team-audit": map[string]interface{}{"PreToolUse": []interface{}{foreignTeamHook()}}})
		if err := patchAntigravityHooksForOS(path, antigravity.hookCommandForOS(goos, opts), goos); err != nil {
			t.Fatal(err)
		}
		healthy := readGoldenJSON(t, path, normalize...)
		if err := removeAntigravityOwnedHookEntries(path); err != nil {
			t.Fatal(err)
		}
		files["antigravity_"+goos] = goldenHookFile{
			Connector: "antigravity", GOOS: goos, Path: ".gemini/config/hooks.json",
			Healthy: healthy, Removed: readGoldenJSON(t, path, normalize...),
		}

		devin := NewDevinConnector()
		path = filepath.Join(dir, ".devin", "hooks.v1.json")
		writeSeed(t, path, map[string]interface{}{"PreToolUse": []interface{}{foreignTeamHook()}})
		hook := devin.hookCommandForOS(goos, opts)
		owned := devinOwnedHookCommandsForOS(goos, opts, hook)
		if err := patchDevinHooks(path, hook, owned...); err != nil {
			t.Fatal(err)
		}
		healthy = readGoldenJSON(t, path, normalize...)
		if err := removeDevinHookReferences(path, owned...); err != nil {
			t.Fatal(err)
		}
		files["devin_workspace_"+goos] = goldenHookFile{
			Connector: "devin", GOOS: goos, Path: "workspace/.devin/hooks.v1.json",
			Healthy: healthy, Removed: readGoldenJSON(t, path, normalize...),
		}
	}
	return files
}

func loadAntigravityDevinGolden(t *testing.T) antigravityDevinGolden {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", antigravityDevinGoldenFile))
	if err != nil {
		t.Fatalf("missing golden (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1): %v", err)
	}
	var golden antigravityDevinGolden
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	return golden
}

func TestAntigravityAndDevinHookFilesMatchTheSharedGolden(t *testing.T) {
	golden := antigravityDevinGolden{
		DataDir:    "/home/user/.defenseclaw",
		HookBinary: `C:\Users\user\.local\bin\defenseclaw-hook.exe`,
	}
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") != "1" {
		golden = loadAntigravityDevinGolden(t)
	}
	rendered := renderAntigravityDevinHookFiles(t, golden)
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		golden.Files = rendered
		data, err := json.MarshalIndent(golden, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("testdata", antigravityDevinGoldenFile), append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if len(golden.Files) != len(rendered) {
		t.Fatalf("golden has %d files, Setup renders %d", len(golden.Files), len(rendered))
	}
	for name, want := range golden.Files {
		if runtime.GOOS == "windows" && want.GOOS != "windows" {
			// The POSIX hook path is built with this host's separators.
			continue
		}
		got, ok := rendered[name]
		if !ok {
			t.Errorf("golden file %s is not rendered", name)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s drifted (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1):\n got %v\nwant %v", name, got, want)
		}
	}
	// The status reader needs the shapes the golden pins: DefenseClaw's hook
	// sets only under its own top-level Antigravity keys, Devin's events at
	// the hooks.v1.json root, and the user's hook set kept by both.
	for _, goos := range []string{"linux", "windows"} {
		file := golden.Files["antigravity_"+goos]
		if _, ok := file.Healthy["hooks"]; ok {
			t.Errorf("antigravity %s golden has a hooks key", goos)
		}
		owned := 0
		for key := range file.Healthy {
			if strings.HasPrefix(key, antigravityOwnedHookKeyPrefix) {
				owned++
			}
		}
		if owned != len(antigravityLifecycleEvents) || file.Removed["team-audit"] == nil || len(file.Removed) != 1 {
			t.Errorf("antigravity %s golden: %d owned keys, removed = %v", goos, owned, file.Removed)
		}
		devin := golden.Files["devin_workspace_"+goos]
		if _, ok := devin.Healthy["PreToolUse"]; !ok || devin.Healthy["hooks"] != nil {
			t.Errorf("devin %s golden is not a root event map: %v", goos, devin.Healthy)
		}
	}
}

// Setup itself writes the golden's POSIX files to the paths it records for
// status (hook_config_paths), not only the helpers the golden renders with.
func TestAntigravityAndDevinSetupWritesTheGoldenFiles(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the golden's POSIX files are rendered from a Linux home")
	}
	golden := loadAntigravityDevinGolden(t)
	for _, tc := range []struct {
		name      string
		conn      *hookOnlyConnector
		workspace bool
	}{
		{"antigravity_linux", NewAntigravityConnector(), false},
		{"devin_workspace_linux", NewDevinConnector(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
			dataDir := filepath.Join(home, ".defenseclaw")
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token"}
			if tc.workspace {
				opts.WorkspaceDir = filepath.Join(home, "workspace")
				if err := os.MkdirAll(opts.WorkspaceDir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			want := golden.Files[tc.name]
			path := filepath.Join(home, filepath.FromSlash(want.Path))
			seed := map[string]interface{}{"PreToolUse": []interface{}{foreignTeamHook()}}
			if tc.conn.Name() == "antigravity" {
				seed = map[string]interface{}{"team-audit": seed}
			}
			writeSeed(t, path, seed)
			if err := tc.conn.Setup(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			if paths := HookConfigPathsForConnector(tc.conn, opts); !reflect.DeepEqual(paths, []string{path}) {
				t.Fatalf("hook_config_paths = %v, want [%s]", paths, path)
			}
			got := readGoldenJSON(t, path, jsonText(dataDir), jsonText(golden.DataDir))
			if !reflect.DeepEqual(got, want.Healthy) {
				t.Errorf("Setup wrote %v\ngolden has %v", got, want.Healthy)
			}
		})
	}
}
