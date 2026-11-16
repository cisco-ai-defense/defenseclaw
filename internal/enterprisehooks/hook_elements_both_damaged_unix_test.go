// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// GAP-0754: a hook script and the hook entry damaged in the same change are two
// broken elements. The registration check runs the hook, so a broken script made
// it read the entry as unjudged, and the repair that put both back counted one
// restore. The entry is read from the agent config alone.
func TestProbeHookElementsNamesTheEntryAndTheScriptDamagedTogether(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("install: %v", err)
	}
	config := filepath.Join(home, ".hermes", "config.yaml")
	script := filepath.Join(home, ".defenseclaw", "hooks", "hermes-hook.sh")
	installedConfig, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	installedScript, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	scriptElement := hookRuntimeFileElement(script)
	probe := func(step string) HookElements {
		t.Helper()
		got, err := ProbeHookElements(context.Background(), opts)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		return got
	}
	for _, tc := range []struct {
		name   string
		tamper func(t *testing.T)
		want   []string
	}{
		{"script appended to and entry removed", func(t *testing.T) {
			write(t, script, append(slices.Clone(installedScript), "# edited\n"...), 0o700)
			write(t, config, []byte("{}\n"), 0o600)
		}, []string{HookElementEntry, scriptElement}},
		{"script deleted and entry edited", func(t *testing.T) {
			if err := os.Remove(script); err != nil {
				t.Fatal(err)
			}
			write(t, config, []byte(strings.ReplaceAll(string(installedConfig), "hermes-hook.sh", "hermes-hook.sh.bak")), 0o600)
		}, []string{HookElementEntry, scriptElement}},
		// The twins: one element damaged names that element alone.
		{"script appended to only", func(t *testing.T) {
			write(t, script, append(slices.Clone(installedScript), "# edited\n"...), 0o700)
		}, []string{scriptElement}},
		{"entry removed only", func(t *testing.T) {
			write(t, config, []byte("{}\n"), 0o600)
		}, []string{HookElementEntry}},
		{"nothing damaged", func(t *testing.T) {}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(t, script, installedScript, 0o700)
			write(t, config, installedConfig, 0o600)
			tc.tamper(t)
			got := probe(tc.name)
			if !slices.Equal(got.Broken(), tc.want) {
				t.Fatalf("broken elements = %v, want %v", got.Broken(), tc.want)
			}
			for element, paths := range map[string][]string{HookElementEntry: {config}, scriptElement: {script}} {
				if slices.Contains(tc.want, element) && !slices.Equal(got.Files[element], paths) {
					t.Fatalf("files of %q = %v, want %v", element, got.Files[element], paths)
				}
			}
		})
	}
	// After one install both elements match again.
	write(t, script, append(slices.Clone(installedScript), "# edited\n"...), 0o700)
	write(t, config, []byte("{}\n"), 0o600)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if got := probe("after the repair"); len(got.Broken()) != 0 {
		t.Fatalf("broken after the repair = %v", got.Broken())
	}
	if body, err := os.ReadFile(config); err != nil || string(body) != string(installedConfig) {
		t.Fatalf("the config entry was not put back exactly (err %v)", err)
	}
}

func write(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
}

// The change to a restored element is read from its content before and after:
// absent or missing lines were deleted, extra bytes or lines were appended,
// anything else was edited.
func TestClassifyHookElementChangeNamesDeleteAppendAndEdit(t *testing.T) {
	const rendered = "#!/bin/sh\nexec defenseclaw-hook\n"
	for _, tc := range []struct {
		name    string
		before  string
		existed bool
		after   string
		want    string
	}{
		{"file missing", "", false, rendered, HookChangeDeleted},
		{"file emptied", "", true, rendered, HookChangeDeleted},
		{"lines removed", "#!/bin/sh\n", true, rendered, HookChangeDeleted},
		{"a line removed from the middle", "a\nc\n", true, "a\nb\nc\n", HookChangeDeleted},
		{"one byte appended", rendered + "#", true, rendered, HookChangeAppended},
		{"a line appended", rendered + "extra\n", true, rendered, HookChangeAppended},
		{"a line added in the middle", "a\nx\nb\n", true, "a\nb\n", HookChangeAppended},
		{"a line edited", "a\nx\nc\n", true, "a\nb\nc\n", HookChangeEdited},
		{"a command path edited", "cmd /tmp/a\n", true, "cmd /tmp/b\n", HookChangeEdited},
		{"a config reset to a stub", "{}\n", true, "a\nb\nc\nd\n", HookChangeDeleted},
		{"many lines added to a config", "a\nb\nc\nd\nx\ny\nz\n", true, "a\n", HookChangeAppended},
		{"same content", rendered, true, rendered, HookChangeEdited},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyHookElementChange([]byte(tc.before), tc.existed, []byte(tc.after)); got != tc.want {
				t.Fatalf("change = %q, want %q", got, tc.want)
			}
		})
	}
	if !KnownHookChange(HookChangeAppended) || KnownHookChange("overwritten") || KnownHookChange("") {
		t.Fatal("KnownHookChange accepts only deleted, appended and edited")
	}
}
