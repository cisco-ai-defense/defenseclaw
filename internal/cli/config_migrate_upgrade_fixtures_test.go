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

package cli

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The upgrade fixtures of internal/config pin their rule pack with a stand-in
// for guardrail.RulePackDigest. `defenseclaw migrate` runs the real loader and
// digest: each fixture home must still upgrade to its golden, from a working
// directory that is not the data home, and its pack must load (GAP-0004).
func TestConfigMigrateUpgradeFixturesWithTheRealRulePackLoader(t *testing.T) {
	for _, release := range []string{"0.8.10-v8", "1.0.0", "1.0.1"} {
		t.Run(release, func(t *testing.T) {
			fixture, err := filepath.Abs(filepath.Join("..", "config", "testdata", "upgrade", release))
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("USERPROFILE", os.Getenv("HOME"))
			copyFixtureHome(t, filepath.Join(fixture, "home"), home)
			t.Chdir(t.TempDir())

			path := filepath.Join(home, "config.yaml")
			input, err := configMigrateV9Input(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := config.MigrateV9(context.Background(), input); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			if _, err := guardrail.LoadRulePack(filepath.Join(home, "policies", "guardrail", "team")); err != nil {
				t.Fatalf("the fixture's rule pack does not load: %v", err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got := string(raw)
			if real, err := filepath.EvalSymlinks(home); err == nil && real != home {
				got = strings.ReplaceAll(got, real, "@HOME@")
			}
			got = strings.ReplaceAll(strings.ReplaceAll(got, home, "@HOME@"), `\`, "/")
			want, err := os.ReadFile(filepath.Join(fixture, "config.golden.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
				t.Fatalf("config.yaml differs from the golden:\n--- got\n%s\n--- want\n%s", got, want)
			}
		})
	}
}

func copyFixtureHome(t *testing.T, src, dst string) {
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
