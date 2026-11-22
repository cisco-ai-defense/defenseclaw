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

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// An observability.local edit that the compiled plan folds away (the row cap
// of the rejected-record store while keep_rejected_records is off, an
// explicit default) still changes the effective policy digest, which digests
// the section as written (GAP-0007). The reload must rebuild the generation
// for it: it took the unchanged branch, so the gateway kept the old digest
// and doctor reported FAIL Policy (stale) until an unrelated change
// (rel-1-0-10 GAP-1220).
func TestConfigManagerReloadAppliesObservabilityEditThePlanFolds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	base := "config_version: 8\ndata_dir: " + dir + "\nobservability:\n  local:\n    keep_rejected_records: false\n"
	withRows := []byte(base + "    rejected_records_max_rows: 1000\n")
	withoutRows := []byte(base)
	explicitDefault := []byte(base + "    retention_days: 7\n")

	digest := func(raw []byte) string {
		t.Helper()
		g, err := buildGeneration(context.Background(), generationInputs{cfg: &config.Config{DataDir: dir}, raw: raw})
		if err != nil {
			t.Fatal(err)
		}
		return g.Digest
	}
	if digest(withRows) == digest(withoutRows) {
		t.Fatal("precondition: rejected_records_max_rows does not change the effective digest")
	}

	if err := os.WriteFile(path, withRows, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := config.ParseCompileObservabilityV8(
		path, withRows, config.ObservabilityV8CompileOptions{DefaultDataDir: dir},
	)
	if err != nil {
		t.Fatal(err)
	}
	var applied [][]string
	mgr := newConfigManagerWithSnapshot(
		path, initial, nil, nil, compiled.Plan.Digest(),
		func(_ context.Context, _, _ *config.Config, diff ConfigDiff, _ configReloadSource) error {
			applied = append(applied, diff.Changed)
			return nil
		},
	)
	mgr.bindInitialObservabilityV8Plan(compiled.Plan)
	reload := func(raw []byte) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := mgr.Reload(context.Background(), "test"); err != nil {
			t.Fatal(err)
		}
	}

	// The running bytes again: nothing to rebuild.
	reload(withRows)
	if len(applied) != 0 {
		t.Fatalf("an unchanged config rebuilt the generation: %v", applied)
	}
	steps := []struct {
		name string
		raw  []byte
	}{
		{"unset rejected_records_max_rows while the store is off", withoutRows},
		{"set rejected_records_max_rows while the store is off", withRows},
		{"unset it again", withoutRows},
		{"write a default retention_days explicitly", explicitDefault},
	}
	for index, step := range steps {
		reload(step.raw)
		if len(applied) != index+1 || !slices.Contains(applied[index], "observability") {
			t.Fatalf("%s: the reload did not rebuild the generation (apply calls %v); "+
				"the gateway keeps the old effective digest", step.name, applied)
		}
		if got := mgr.gen.Load(); got != uint64(index+1) {
			t.Fatalf("%s: generation = %d, want %d", step.name, got, index+1)
		}
	}
	// The same bytes once more: still nothing to rebuild.
	reload(explicitDefault)
	if len(applied) != len(steps) {
		t.Fatalf("a repeated reload of the applied bytes rebuilt the generation: %v", applied)
	}
}

// The same edits through the sidecar apply boundary: each one swaps in a
// generation whose observability component is the one `defenseclaw-gateway
// policy digest` (doctor's Policy row) computes from the file, so the
// published effective digest moves with every edit.
func TestSidecarReloadPublishesDigestOfObservabilityEditThePlanFolds(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	base := "config_version: 8\ndata_dir: " + fixture.dataDir + "\nobservability:\n  local:\n    keep_rejected_records: false\n"
	withRows := []byte(base + "    rejected_records_max_rows: 1000\n")
	withoutRows := []byte(base)
	if err := os.WriteFile(fixture.configPath, withRows, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.publishConfig(initial)
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, withRows); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	mgr := newConfigManagerWithSnapshot(
		fixture.configPath, initial, nil, nil,
		fixture.sidecar.observabilityV8ActivePlanDigest(),
		fixture.sidecar.applyConfigReloadSnapshot,
	)
	if err := mgr.Reload(t.Context(), "startup_reconcile"); err != nil {
		t.Fatal(err)
	}
	previous := ""
	for index, raw := range [][]byte{withoutRows, withRows, withoutRows} {
		if err := os.WriteFile(fixture.configPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := mgr.Reload(t.Context(), "test"); err != nil {
			t.Fatal(err)
		}
		loaded, err := config.LoadRuntimeV8File(fixture.configPath)
		if err != nil {
			t.Fatal(err)
		}
		want, err := ComputeEffectivePolicyFor(t.Context(), loaded, EffectivePolicyOptions{Raw: raw})
		if err != nil {
			t.Fatal(err)
		}
		live := fixture.sidecar.Generation()
		if live == nil {
			t.Fatalf("edit %d: the reload published no generation", index)
		}
		if got, wantObs := live.Components["observability"], want.Components["observability"]; got == "" || got != wantObs {
			t.Fatalf("edit %d: the gateway applies observability %s, config.yaml computes %s", index, got, wantObs)
		}
		if live.Digest == previous {
			t.Fatalf("edit %d: the effective digest %s did not move", index, live.Digest)
		}
		previous = live.Digest
	}
}
