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

package guardrail

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

// Path of the committed JSON snapshot consumed by
// docs-site/scripts/build-policy-assets.ts. We resolve it relative
// to this source file so the test passes regardless of where `go
// test` was invoked from.
func ruleAxesSnapshotPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed — can't locate the snapshot file relative to the test")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	return filepath.Join(repoRoot, "docs-site", "data", "rule-axes.json")
}

// TestRuleAxesSnapshotMatchesCommittedJSON is the source-of-truth
// guard for axes.go ↔ docs-site/data/rule-axes.json. The TS build at
// docs-site/scripts/build-policy-assets.ts reads this JSON to label
// recipes with their data axes / tool capability classes. If this
// test fails, axes.go has been updated but the committed JSON is
// stale. Re-run with UPDATE_RULE_AXES_JSON=1 to regenerate.
//
// We intentionally compare against the *committed* file (not just
// regenerate every time) so reviewers see a diff in PRs when the
// mapping changes — that diff is the audit trail.
func TestRuleAxesSnapshotMatchesCommittedJSON(t *testing.T) {
	t.Parallel()

	snap := DumpRuleAxesSnapshot()

	// Stable serialization: sort exact-map keys so JSON output is
	// byte-deterministic across Go versions and map iteration
	// orders. Prefix slices are already ordered by source code so
	// they don't need re-sorting.
	rendered, err := marshalSnapshotDeterministic(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}

	snapshotPath := ruleAxesSnapshotPath(t)

	if os.Getenv("UPDATE_RULE_AXES_JSON") == "1" {
		// Regeneration mode — write the committed file and exit ok.
		// Used when intentionally updating the mapping; CI never
		// runs with this env var so it can't accidentally pass a
		// drifting test.
		if err := os.WriteFile(snapshotPath, rendered, 0o644); err != nil {
			t.Fatalf("write %s: %v", snapshotPath, err)
		}
		t.Logf("regenerated %s", snapshotPath)
		return
	}

	committed, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatalf("read %s (commit it after running with UPDATE_RULE_AXES_JSON=1): %v", snapshotPath, err)
	}

	committed = bytes.ReplaceAll(committed, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(rendered, committed) {
		t.Errorf(
			"axes.go and %s have diverged.\n"+
				"To fix: review the diff below and either reconcile axes.go OR run\n"+
				"  UPDATE_RULE_AXES_JSON=1 go test ./internal/guardrail -run TestRuleAxesSnapshotMatchesCommittedJSON\n"+
				"to regenerate the snapshot. Commit both files together so docs-site builds stay in sync.\n\n"+
				"---- expected (regenerated from axes.go) ----\n%s\n"+
				"---- got (committed in repo) ----\n%s",
			snapshotPath,
			rendered,
			committed,
		)
	}
}

func marshalSnapshotDeterministic(snap RuleAxesSnapshot) ([]byte, error) {
	// Use a sidecar type with a sorted slice in place of the map so
	// JSON output is stable. We can't json.Marshal the raw map
	// because Go's encoder doesn't promise key order for maps.
	type ruleAxisEntry struct {
		ID   string     `json:"id"`
		Axes []DataAxis `json:"axes"`
	}
	type stableSnapshot struct {
		ExactSorted        []ruleAxisEntry        `json:"exact_rule_axes"`
		PrefixAxes         []PrefixAxisRule       `json:"prefix_axes"`
		PrefixCapabilities []PrefixCapabilityRule `json:"prefix_capabilities"`
	}

	sorted := make([]ruleAxisEntry, 0, len(snap.Exact))
	for id, axes := range snap.Exact {
		sorted = append(sorted, ruleAxisEntry{ID: id, Axes: axes})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	out, err := json.MarshalIndent(stableSnapshot{
		ExactSorted:        sorted,
		PrefixAxes:         snap.PrefixAxes,
		PrefixCapabilities: snap.PrefixCapabilities,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	// Trailing newline so the file is POSIX-friendly and `git diff`
	// doesn't complain about no-newline-at-end markers.
	return append(out, '\n'), nil
}
