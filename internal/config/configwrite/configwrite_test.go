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

func TestApplyKeepsCommentsOnRetainedListItems(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	path := writeTestConfig(t, "asset_policy:\n  skill:\n    denied:\n      - name: first # first operator note\n      - name: second # second operator note\n")
	_, err := Apply(context.Background(), path, []Change{{
		Path: "asset_policy.skill.denied",
		Value: []map[string]string{
			{"name": "second"},
			{"name": "first"},
			{"name": "third"},
		},
	}}, Options{Actor: "cli:test"})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"name: first # first operator note", "name: second # second operator note"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("retained list item lost %q:\n%s", want, raw)
		}
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

func TestApplyPutsTheOldConfigBackWhenTheGenerationRecordFails(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	path := writeTestConfig(t, "guardrail:\n  mode: observe\n")
	before, _ := os.ReadFile(path)
	// A directory where config.generation.json goes makes the second write
	// of the transaction fail after config.yaml was replaced.
	if err := os.Mkdir(GenerationPath(path), 0o700); err != nil {
		t.Fatal(err)
	}
	change := []Change{{Path: "guardrail.mode", Value: "action"}}
	if _, err := Apply(context.Background(), path, change, Options{Actor: "cli:test"}); err == nil {
		t.Fatal("Apply succeeded although the generation file could not be written")
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("a failed write left the new config in place:\n%s", after)
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

// A managed host restarts for the enterprise block outside
// enterprise.inspection, which the gateway reads once at start (GAP-0135).
func TestManagedRestartRequiredCountsTheEnterpriseBlockOutsideInspection(t *testing.T) {
	got := ManagedRestartRequired([]string{
		"guardrail.mode", "enterprise.inspection.mode", "enterprise.enrollment.home_roots", "gateway.api_port",
	})
	if want := "gateway.api_port,enterprise.enrollment.home_roots"; strings.Join(got, ",") != want {
		t.Fatalf("ManagedRestartRequired = %v, want %s", got, want)
	}
}

// A block added or removed whole names its leaves, so the Windows hot path
// sees an enrollment list and not an unknown enterprise key: the first
// enterprise.enrollment block took the restart transaction (GAP-0887).
func TestChangedPathsNamesTheLeavesOfABlockAddedOrRemovedWhole(t *testing.T) {
	base := []byte("config_version: 9\nguardrail:\n  mode: action\n")
	added := []byte("config_version: 9\nguardrail:\n  mode: action\nenterprise:\n  enrollment:\n    exclude_users: [svc]\n")
	for _, tc := range []struct {
		name          string
		before, after []byte
	}{
		{"added", base, added}, {"removed", added, base},
	} {
		got, err := ChangedPaths(tc.before, tc.after)
		if err != nil || strings.Join(got, ",") != "enterprise.enrollment.exclude_users" {
			t.Fatalf("%s: ChangedPaths = %v, %v", tc.name, got, err)
		}
	}
	// An empty block has no leaf: it is still a change, of the block.
	got, err := ChangedPaths(base, append(append([]byte(nil), base...), []byte("  connectors:\n    cursor: {}\n")...))
	if err != nil || strings.Join(got, ",") != "guardrail.connectors.cursor" {
		t.Fatalf("empty block: ChangedPaths = %v, %v", got, err)
	}
}
