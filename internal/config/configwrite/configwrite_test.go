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

package configwrite

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func writeTestConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := "config_version: 8\ndata_dir: " + dir + "\n" + body
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyPatchesValidatesAndAdvancesGeneration(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	path := writeTestConfig(t, "# operator note\nguardrail:\n  mode: observe # keep\nobservability: {}\n")
	opt := Options{Actor: "cli:test", Reason: "test"}

	first, err := Apply(context.Background(), path, []Change{{Path: "guardrail.mode", Value: "action"}}, opt)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if first.Generation != 1 || len(first.Changed) != 1 || first.Changed[0] != "guardrail.mode" {
		t.Fatalf("first result = %+v", first)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "# operator note") || !strings.Contains(string(raw), "mode: action # keep") {
		t.Fatalf("comments were not kept:\n%s", raw)
	}
	state, err := ReadGenerationState(path)
	if err != nil || state.Generation != 1 || state.ConfigSHA256 != first.SHA256 || state.Actor != "cli:test" {
		t.Fatalf("generation state = %+v, %v", state, err)
	}

	// Compare-and-swap: a stale digest is refused.
	if _, err := Apply(context.Background(), path, []Change{{Path: "guardrail.mode", Value: "observe"}},
		Options{Actor: "cli:test", ExpectSHA256: strings.Repeat("0", 64)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale ExpectSHA256 error = %v, want ErrConflict", err)
	}
	// Validation runs before the write: the file and generation stay put.
	if _, err := Apply(context.Background(), path, []Change{{Path: "guardrail.mode", Value: "bogus"}}, opt); err == nil {
		t.Fatal("an invalid value was accepted")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(raw) {
		t.Fatal("a rejected change modified config.yaml")
	}
	second, err := Apply(context.Background(), path,
		[]Change{{Path: "guardrail.mode", Unset: true}, {Path: "gateway.api_port", Value: 18971}},
		Options{Actor: "cli:test", ExpectSHA256: first.SHA256})
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if second.Generation != 2 || len(second.RestartRequired) != 1 || second.RestartRequired[0] != "gateway.api_port" {
		t.Fatalf("second result = %+v", second)
	}

	// A truncated state file keeps its counter: the next write resumes past
	// it instead of resetting to 1.
	if err := os.WriteFile(GenerationPath(path), []byte(`{"generation": 41, "config_sha`), 0o600); err != nil {
		t.Fatal(err)
	}
	third, err := Apply(context.Background(), path, []Change{{Path: "guardrail.mode", Value: "action"}}, opt)
	if err != nil {
		t.Fatalf("third Apply: %v", err)
	}
	if state, err := ReadGenerationState(path); err != nil || third.Generation != 42 || !state.GenerationReset {
		t.Fatalf("after a corrupt state file: result %+v, state %+v, %v", third, state, err)
	}
}

func TestApplyRefusesLocalActorsOnStandaloneManagedHosts(t *testing.T) {
	path := writeTestConfig(t, "observability: {}\n")
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "standalone")
	change := []Change{{Path: "guardrail.mode", Value: "action"}}
	if _, err := Apply(context.Background(), path, change, Options{Actor: "cli:test"}); !errors.Is(err, ErrManaged) {
		t.Fatalf("local actor error = %v, want ErrManaged", err)
	}
	if _, err := ReadGenerationState(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused write recorded a generation: %v", err)
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused write took the writer lock: %v", err)
	}
}

func TestParsePath(t *testing.T) {
	parts, err := parsePath(`asset_policy.skill.denied[2]["a.b"].name`)
	if err != nil || len(parts) != 6 || !parts[3].isIdx || parts[3].index != 2 || parts[4].key != "a.b" {
		t.Fatalf("parsePath = %+v, %v", parts, err)
	}
	for _, bad := range []string{"", "a..b", "[0].a", "a[x]", "a.", "a[1"} {
		if _, err := parsePath(bad); err == nil {
			t.Fatalf("parsePath(%q) accepted", bad)
		}
	}
}

// TestOnlyTheWriterWritesConfigYAML is the spec section 3 guard: config.yaml
// is written only by this package (and the config package beneath it) and
// by the managed lifecycle, which takes config.yaml.lock and records the
// generation itself. Any other write would skip the lock, the canonical
// validation and config.generation.json.
func TestOnlyTheWriterWritesConfigYAML(t *testing.T) {
	write := regexp.MustCompile(`(os\.WriteFile|os\.Create|os\.OpenFile|os\.Rename|WriteFileDurable|[wW]riteFileAtomic)\([^)\n]*(ConfigPath\b|cfgPath\b|configPath\b|ConfigFilePath\b|"config\.yaml")`)
	allowed := []string{"internal/config/", "internal/enterpriseunix/"}
	_, thisFile, _, _ := runtime.Caller(0)
	root, _ := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	for _, dir := range []string{"internal", "cmd"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			for _, prefix := range allowed {
				if strings.HasPrefix(rel, prefix) {
					return nil
				}
			}
			raw, readErr := os.ReadFile(path)
			if readErr == nil {
				if hit := write.Find(raw); hit != nil {
					t.Errorf("%s writes config.yaml directly (%s); use configwrite.Apply or ReplaceDocument", rel, hit)
				}
			}
			return nil
		})
	}
}
