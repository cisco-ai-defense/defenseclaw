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

package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The upgrade fixtures are data homes under testdata/upgrade/<release>/home,
// each with a same-name provider overlay, a skill-scanner policy named custom
// and a custom rule pack. config.yaml names its home @HOME@.
//   - 0.8.10-v8: a 0.8.10 home after its own config v8 upgrade.
//   - 1.0.0, 1.0.1: the config_version 9 home that release's upgrade left
//     (config.yaml is the output of that release's MigrateV9 on the 0.8.10
//     home, with the policy file at an absolute path, since neither could
//     upgrade one named custom), plus a hand-written overlay added later.
//
// Each home is upgraded, rolled back the way the installer does it (its copy
// of the data home is put back), then upgraded again. Both upgrades must leave
// config.yaml equal to config.golden.yaml, and the rollback must leave the
// home exactly as it was. DEFENSECLAW_UPDATE_GOLDEN=1 rewrites the goldens.
func TestUpgradeFixturesMigrateRollBackAndReUpgrade(t *testing.T) {
	for _, release := range []string{"0.8.10-v8", "1.0.0", "1.0.1"} {
		t.Run(release, func(t *testing.T) {
			fixture, err := filepath.Abs(filepath.Join("testdata", "upgrade", release))
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			// 0.8.x read a relative policy file from the working directory.
			t.Chdir(home)
			copyUpgradeFixture(t, filepath.Join(fixture, "home"), home)
			before := upgradeFixtureTree(t, home)
			configPath := filepath.Join(home, "config.yaml")
			in := MigrateV9Input{ConfigPath: configPath, RulePackDigest: upgradeFixtureDigest}
			upgrade := func(stage string) {
				t.Helper()
				if _, err := MigrateV9(context.Background(), in); err != nil {
					t.Fatalf("%s: MigrateV9: %v", stage, err)
				}
				raw, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := ValidateCandidate(configPath, raw); err != nil {
					t.Fatalf("%s: this release refuses the upgraded config: %v", stage, err)
				}
				compareUpgradeGolden(t, stage, filepath.Join(fixture, "config.golden.yaml"), home, raw)
			}
			upgrade("upgrade")
			restoreUpgradeFixture(t, home, before)
			if after := upgradeFixtureTree(t, home); !maps.Equal(before, after) {
				t.Fatalf("rollback: the home differs from the copy taken before the upgrade:\nbefore %v\nafter  %v",
					slices.Sorted(maps.Keys(before)), slices.Sorted(maps.Keys(after)))
			}
			upgrade("re-upgrade")
		})
	}
}

// upgradeFixtureDigest pins a rule pack by its files (guardrail.RulePackDigest
// is not importable here; the fixtures need only a stable digest).
func upgradeFixtureDigest(dir string) (string, error) {
	sum := sha256.New()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		sum.Write([]byte(filepath.ToSlash(rel) + "\x00"))
		sum.Write(raw)
		return nil
	})
	return hex.EncodeToString(sum.Sum(nil)), err
}

func copyUpgradeFixture(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// The goldens pin the fixtures' LF bytes; a CRLF checkout must not
		// change a digest.
		text := strings.ReplaceAll(string(raw), "\r\n", "\n")
		if rel == "config.yaml" {
			text = strings.ReplaceAll(text, "@HOME@", dst)
		}
		return os.WriteFile(target, []byte(text), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// upgradeFixtureTree maps each path under root to its content ("/" for a
// folder).
func upgradeFixtureTree(t *testing.T, root string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == root {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			tree[filepath.ToSlash(rel)] = "/"
			return nil
		}
		raw, err := os.ReadFile(path)
		tree[filepath.ToSlash(rel)] = string(raw)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func restoreUpgradeFixture(t *testing.T, root string, tree map[string]string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range slices.Sorted(maps.Keys(tree)) {
		target := filepath.Join(root, filepath.FromSlash(rel))
		if tree[rel] == "/" {
			err = os.MkdirAll(target, 0o700)
		} else if err = os.MkdirAll(filepath.Dir(target), 0o700); err == nil {
			err = os.WriteFile(target, []byte(tree[rel]), 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// compareUpgradeGolden compares config.yaml, with its home written @HOME@
// and forward slashes, to the golden file.
func compareUpgradeGolden(t *testing.T, stage, golden, home string, raw []byte) {
	t.Helper()
	got := string(raw)
	homes := []string{home}
	if cwd, err := os.Getwd(); err == nil && cwd != home {
		homes = append(homes, cwd)
	}
	if real, err := filepath.EvalSymlinks(home); err == nil && real != home {
		homes = append(homes, real)
	}
	slices.SortFunc(homes, func(a, b string) int { return len(b) - len(a) })
	for _, h := range homes {
		got = strings.ReplaceAll(got, h, "@HOME@")
	}
	got = strings.ReplaceAll(got, `\`, "/")
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" && stage == "upgrade" {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	wantRaw, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%s: %v (DEFENSECLAW_UPDATE_GOLDEN=1 writes it)", stage, err)
	}
	// A CRLF checkout (core.autocrlf on Windows) must not fail the compare,
	// as copyUpgradeFixture keeps the fixtures LF.
	want := strings.ReplaceAll(string(wantRaw), "\r\n", "\n")
	if got != want {
		t.Fatalf("%s: config.yaml differs from %s:\n--- got\n%s\n--- want\n%s", stage, golden, got, want)
	}
}
