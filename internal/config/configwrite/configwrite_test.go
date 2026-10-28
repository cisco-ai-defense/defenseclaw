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
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
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

func TestCurrentOSActorIdentifiesExecutingAccount(t *testing.T) {
	actor := CurrentOSActor()
	current, err := user.Current()
	if err != nil {
		t.Skipf("OS account lookup unavailable: %v", err)
	}
	if runtime.GOOS == "windows" {
		if !strings.HasPrefix(actor, "os:sid:"+current.Uid+":") {
			t.Fatalf("actor %q does not identify Windows account %q", actor, current.Uid)
		}
	} else if !strings.HasPrefix(actor, "os:uid:"+strconv.Itoa(os.Getuid())+":") || !strings.Contains(actor, current.Username) {
		t.Fatalf("actor %q does not identify Unix account %q", actor, current.Username)
	}
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

// yaml.Unmarshal decodes only the first document; a write must not delete a
// second one an operator appended (GAP-1400).
func TestApplyRefusesASecondYAMLDocument(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	path := writeTestConfig(t, "guardrail:\n  mode: observe\n---\nguardrail:\n  mode: action\n")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Apply(context.Background(), path, []Change{{Path: "gateway.api_port", Value: 18971}}, Options{Actor: "cli:test"})
	if !errors.Is(err, ErrMultipleDocuments) {
		t.Fatalf("Apply error = %v, want ErrMultipleDocuments", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("a refused write changed config.yaml:\n%s", after)
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

// Bundle principals are accepted only from the lifecycle (Options.Lifecycle)
// and are then recorded with the bundle fields in config.generation.json; a
// CLI, TUI or API caller naming one is refused before anything is written.
func TestBundlePrincipalActorsOnlyFromTheLifecycle(t *testing.T) {
	// A managed standalone config declares its profile: on Windows an unset
	// profile resolves to secure_client without the service pin, so the
	// accepted writes below would fail validation.
	path := writeTestConfig(t, "enterprise:\n  profile: standalone\nobservability: {}\n")
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "standalone")
	change := []Change{{Path: "guardrail.mode", Value: "action"}}
	bundle := BundleRef{ID: "b-01J9ZZZZZZZZZZZZZZZZZZZZZZ", Version: 7, SignerKeyID: "k1"}
	for _, opt := range []Options{
		{Actor: "control-plane:t1/alice"},
		{Actor: "operator:root"},
		{Actor: ActorLifecycle, Bundle: bundle},
		{Actor: "cli:alice", Lifecycle: true},
	} {
		if _, err := Apply(context.Background(), path, change, opt); err == nil {
			t.Fatalf("%+v was accepted", opt)
		}
	}
	for _, actor := range []string{"control-plane:t1", "control-plane:/alice", "control-plane:t1/a/b", "operator:", "operator:a\nb"} {
		if _, err := Apply(context.Background(), path, change, Options{Actor: actor, Lifecycle: true}); err == nil {
			t.Fatalf("malformed principal %q was accepted", actor)
		}
	}
	if _, err := ReadGenerationState(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused write recorded a generation: %v", err)
	}
	res, err := Apply(context.Background(), path, change, Options{Actor: "control-plane:t1/alice", Reason: "tighten", Lifecycle: true, Bundle: bundle})
	if err != nil {
		t.Fatalf("lifecycle principal write: %v", err)
	}
	state, err := ReadGenerationState(path)
	if err != nil || state.Generation != res.Generation || state.Actor != "control-plane:t1/alice" ||
		state.BundleID != bundle.ID || state.BundleVersion != 7 || state.SignerKeyID != "k1" || state.Reason != "tighten" {
		t.Fatalf("generation state = %+v, %v", state, err)
	}
	if _, err := Apply(context.Background(), path, []Change{{Path: "guardrail.mode", Value: "observe"}}, Options{Actor: "operator:root", Lifecycle: true}); err != nil {
		t.Fatalf("lifecycle operator write: %v", err)
	}
	if state, _ := ReadGenerationState(path); state.BundleID != "" || state.Actor != "operator:root" {
		t.Fatalf("bundle fields leaked into the next generation: %+v", state)
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

func TestManagedConfigRestartRequiredClassifiesBundleChanges(t *testing.T) {
	before := []byte("config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 500\n")
	restart := []byte("config_version: 9\nguardrail:\n  block_at: MEDIUM\n  hook_self_heal_debounce_ms: 600\n")
	for _, level := range []string{"CRITICAL", "HIGH", "LOW"} {
		hot := []byte("config_version: 9\nguardrail:\n  block_at: " + level + "\n  hook_self_heal_debounce_ms: 500\n")
		if keys, err := ManagedConfigRestartRequired(before, hot, ManagedDefaults{}); err != nil || len(keys) != 0 {
			t.Fatalf("MEDIUM to %s = %v, %v; want hot", level, keys, err)
		}
	}
	if keys, err := ManagedConfigRestartRequired(before, restart, ManagedDefaults{}); err != nil || strings.Join(keys, ",") != "guardrail.hook_self_heal_debounce_ms" {
		t.Fatalf("debounce change = %v, %v; want restart", keys, err)
	}
}

// enterprise.openshell is lifecycle and restart-required on every host;
// openshell.* (the sandbox floor included) stays hot.
func TestEnterpriseOpenShellRestartsAndSandboxFloorStaysHot(t *testing.T) {
	changed := []string{"enterprise.openshell.install", "enterprise.openshell.gateway_port", "openshell.admin.required_for",
		"guardrail.profiles.contractors.sandbox.allowed"}
	want := "enterprise.openshell.install,enterprise.openshell.gateway_port"
	if got := RestartRequired(changed); strings.Join(got, ",") != want {
		t.Fatalf("RestartRequired = %v, want %s", got, want)
	}
	if got := ManagedRestartRequired(changed); strings.Join(got, ",") != want {
		t.Fatalf("ManagedRestartRequired = %v, want %s", got, want)
	}
}

// GAP-0617: bytes written outside the writer (an administrator's content
// write on Windows, which the gateway hot reloads) are recorded as the next
// generation, once, and only while they are still the bytes on disk.
func TestRecordUnrecordedAdvancesTheGenerationForAnUnrecordedWrite(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	path := writeTestConfig(t, "guardrail:\n  mode: observe\n")
	opt := Options{Actor: ActorUnattributedHandEdit, Reason: "edited outside the lifecycle"}
	ctx := context.Background()

	// No state file yet: the first write is generation 1.
	raw, _ := os.ReadFile(path)
	recorded, err := RecordUnrecorded(ctx, path, raw, opt)
	state, stateErr := ReadGenerationState(path)
	if err != nil || !recorded || stateErr != nil || state.Generation != 1 || state.ConfigSHA256 != SHA256Hex(raw) ||
		state.Actor != ActorUnattributedHandEdit || !IsHandEditActor(state.Actor) {
		t.Fatalf("first record: recorded=%t err=%v state=%+v (%v)", recorded, err, state, stateErr)
	}
	// The same bytes again: already recorded, the generation stays.
	if recorded, err = RecordUnrecorded(ctx, path, raw, opt); err != nil || recorded {
		t.Fatalf("a recorded write was recorded again: recorded=%t err=%v", recorded, err)
	}
	// A writer's own generation is not a hand edit.
	if _, err := Apply(ctx, path, []Change{{Path: "guardrail.mode", Value: "action"}}, Options{Actor: "cli:test"}); err != nil {
		t.Fatal(err)
	}
	if state, _ = ReadGenerationState(path); state.Generation != 2 || IsHandEditActor(state.Actor) {
		t.Fatalf("writer generation = %+v", state)
	}
	// An edit in an editor is the next generation.
	edited := []byte(strings.Replace(string(raw), "observe", "action\n  block_at: HIGH", 1))
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if recorded, err = RecordUnrecorded(ctx, path, edited, opt); err != nil || !recorded {
		t.Fatalf("edit: recorded=%t err=%v", recorded, err)
	}
	if state, _ = ReadGenerationState(path); state.Generation != 3 || state.ConfigSHA256 != SHA256Hex(edited) {
		t.Fatalf("edit generation = %+v", state)
	}
	// Bytes that are no longer on disk are left to the next reload.
	if recorded, err = RecordUnrecorded(ctx, path, raw, opt); err != nil || recorded {
		t.Fatalf("stale bytes were recorded: recorded=%t err=%v", recorded, err)
	}
	if state, _ = ReadGenerationState(path); state.Generation != 3 {
		t.Fatalf("stale bytes advanced the generation: %+v", state)
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

func TestLifecycleGenerationRepairKeepsTheProvenCounter(t *testing.T) {
	path := writeTestConfig(t, "guardrail:\n  mode: observe\n")
	if err := os.WriteFile(GenerationPath(path), []byte("broken record"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Locked(context.Background(), path, Options{Actor: ActorLifecycle, GenerationFloor: 10}, func() (bool, error) { return true, nil })
	if err != nil || got.Generation != 11 {
		t.Fatalf("repaired generation = %+v, %v; want 11", got, err)
	}
	before, err := os.ReadFile(GenerationPath(path))
	if err != nil {
		t.Fatal(err)
	}
	approved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Locked(context.Background(), path, Options{Actor: ActorLifecycle, GenerationFloor: 11, RecordSHA256: SHA256Hex(approved)}, func() (bool, error) {
		return true, os.WriteFile(path, append(approved, []byte("\n# concurrent edit\n")...), 0o600)
	})
	after, readErr := os.ReadFile(GenerationPath(path))
	if !errors.Is(err, ErrConflict) || readErr != nil || string(before) != string(after) {
		t.Fatalf("unapproved concurrent bytes were recorded: error=%v, record changed=%v", err, string(before) != string(after))
	}

}
