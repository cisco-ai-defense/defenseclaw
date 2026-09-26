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

//go:build !windows

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// hostHookGoldenPath pins the exact bytes and modes the host hook writers lay
// down. The sandbox variants share these templates, so every template change
// must leave this manifest untouched unless the host output is meant to move.
// Regenerate deliberately with DEFENSECLAW_UPDATE_GOLDEN=1.
const hostHookGoldenPath = "testdata/hook_render_host.golden.json"

type hostHookGoldenFile struct {
	Mode   string `json:"mode"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

type hostHookGoldenCase struct {
	name  string
	write func(t *testing.T, dir string)
}

func hostHookGoldenCases() []hostHookGoldenCase {
	const apiAddr = "127.0.0.1:18970"
	const token = "golden-token-0123456789abcdef"
	var cases []hostHookGoldenCase
	add := func(name string, write func(t *testing.T, dir string)) {
		cases = append(cases, hostHookGoldenCase{name: name, write: write})
	}

	// Every connector-owned lifecycle script with the setup-time options that
	// change template data: fail mode, managed mode and scoped tokens.
	connectors := make([]string, 0, len(connectorHookScripts))
	for name := range connectorHookScripts {
		connectors = append(connectors, name)
	}
	sort.Strings(connectors)
	type variant struct {
		managed, scoped bool
		failMode        string
	}
	fullMatrix := []variant{}
	for _, managed := range []bool{false, true} {
		for _, scoped := range []bool{true, false} {
			for _, failMode := range []string{"closed", "open"} {
				fullMatrix = append(fullMatrix, variant{managed, scoped, failMode})
			}
		}
	}
	// The sandbox render shares the claudecode, codex and inspect templates,
	// so those take the full option matrix; the remaining connectors pin the
	// two production shapes (user setup and guardian-managed).
	reduced := []variant{{false, true, "closed"}, {true, true, "open"}}
	for _, name := range connectors {
		extras := connectorHookScripts[name]
		variants := reduced
		if name == "claudecode" || name == "codex" {
			variants = fullMatrix
		}
		for _, v := range variants {
			name, extras, v := name, extras, v
			label := name + "/managed=" + boolLabel(v.managed) + "/scoped=" + boolLabel(v.scoped) + "/fail=" + v.failMode
			add(label, func(t *testing.T, dir string) {
				if err := writeHookScriptsCommonWithOptions(dir, apiAddr, token, v.failMode, extras, v.managed, name, v.scoped); err != nil {
					t.Fatalf("write %s: %v", label, err)
				}
			})
		}
	}

	// Generic-only and legacy all-script writers.
	add("generic/common", func(t *testing.T, dir string) {
		if err := writeHookScriptsCommon(dir, apiAddr, token, nil); err != nil {
			t.Fatal(err)
		}
	})
	add("legacy/all-scripts", func(t *testing.T, dir string) {
		if err := WriteHookScriptsWithToken(dir, apiAddr, token); err != nil {
			t.Fatal(err)
		}
	})
	add("legacy/all-scripts-no-token", func(t *testing.T, dir string) {
		if err := WriteAllHookScripts(dir, "127.0.0.1:18999"); err != nil {
			t.Fatal(err)
		}
	})
	add("helpers/unmanaged", func(t *testing.T, dir string) {
		if err := writeHookHelpersForMode(dir, false); err != nil {
			t.Fatal(err)
		}
	})
	add("helpers/managed", func(t *testing.T, dir string) {
		if err := writeHookHelpersForMode(dir, true); err != nil {
			t.Fatal(err)
		}
	})
	return cases
}

func boolLabel(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func snapshotHookDir(t *testing.T, dir string) map[string]hostHookGoldenFile {
	t.Helper()
	out := map[string]hostHookGoldenFile{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		out[filepath.ToSlash(rel)] = hostHookGoldenFile{
			Mode:   info.Mode().Perm().String(),
			Size:   len(data),
			SHA256: hex.EncodeToString(sum[:]),
		}
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	return out
}

// TestHostHookScriptBytesGolden proves that the host hook writers keep
// producing byte-identical scripts, helpers and sidecars.
func TestHostHookScriptBytesGolden(t *testing.T) {
	got := map[string]map[string]hostHookGoldenFile{}
	for _, tc := range hostHookGoldenCases() {
		dir := t.TempDir()
		tc.write(t, dir)
		got[tc.name] = snapshotHookDir(t, dir)
	}
	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(hostHookGoldenPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(hostHookGoldenPath)
	if err != nil {
		t.Fatalf("read golden (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1): %v", err)
	}
	if bytes.Equal(want, encoded) {
		return
	}
	var wantCases map[string]map[string]hostHookGoldenFile
	if err := json.Unmarshal(want, &wantCases); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	var diffs []string
	for name, files := range got {
		for file, entry := range files {
			if wantCases[name][file] != entry {
				diffs = append(diffs, name+" "+file)
			}
		}
		for file := range wantCases[name] {
			if _, ok := files[file]; !ok {
				diffs = append(diffs, name+" "+file+" (missing)")
			}
		}
	}
	for name := range wantCases {
		if _, ok := got[name]; !ok {
			diffs = append(diffs, name+" (case missing)")
		}
	}
	sort.Strings(diffs)
	if len(diffs) > 20 {
		diffs = append(diffs[:20], "...")
	}
	t.Fatalf("host hook output drifted from %s:\n  %s", hostHookGoldenPath, strings.Join(diffs, "\n  "))
}
