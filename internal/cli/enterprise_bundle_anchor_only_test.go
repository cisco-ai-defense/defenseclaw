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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The live1 P-3 anchor-only Setup /ensure TRUSTANCHORS= replaced
// bundle-anchors.json and still reported noop:true, noop_reason "compliant".
func TestAnchorOnlyEnsureThatChangedTheAnchorsIsNotANoop(t *testing.T) {
	const path = `C:\ProgramData\Cisco\DefenseClaw\etc\trust\bundle-anchors.json`
	compliant := func() *enterprisestatus.Result {
		return &enterprisestatus.Result{Action: "ensure", Noop: true, NoopReason: "compliant"}
	}
	revoked := []byte(`{"schema_version":1,"keys":[{"id":"k1","status":"revoked"}]}`)
	for _, tc := range []struct {
		name      string
		existed   bool
		previous  []byte
		confirmed bool
		want      string
	}{
		{"replaced under a confirmed bundle", true, []byte(`{"schema_version":1,"keys":[{"id":"k1","status":"active"}]}`), true,
			"replaced the trust anchors in " + path + anchorOnlyConfirmedClause},
		// A base-only device, or one whose bundle never confirmed: no
		// bundle keeps enforcing, so the line does not say one does.
		{"replaced without a confirmed bundle", true, []byte(`{"schema_version":1}`), false, "replaced the trust anchors in " + path},
		{"first install", false, nil, false, "installed trust anchors in " + path},
		// An existing file the run could not read first is replaced as
		// before and counts as changed.
		{"unreadable before", true, nil, true, "replaced the trust anchors in " + path + anchorOnlyConfirmedClause},
	} {
		result := compliant()
		settleAnchorOnlyEnsure(result, &anchorOnlyChange{path: path, existed: tc.existed, previous: tc.previous, installed: revoked}, tc.confirmed)
		if result.Noop || result.NoopReason != "" || len(result.Changes) != 1 || result.Changes[0] != tc.want {
			t.Fatalf("%s: noop=%v reason=%q changes=%q", tc.name, result.Noop, result.NoopReason, result.Changes)
		}
	}

	same := []byte(`{"schema_version":1}`)
	unchanged := compliant()
	settleAnchorOnlyEnsure(unchanged, &anchorOnlyChange{path: path, existed: true, previous: same, installed: append([]byte(nil), same...)}, true)
	if !unchanged.Noop || unchanged.NoopReason != "compliant" || len(unchanged.Changes) != 0 {
		t.Fatalf("byte-identical anchors: %+v", unchanged)
	}

	failed := compliant()
	failed.AddError("lifecycle_busy", "busy")
	settleAnchorOnlyEnsure(failed, &anchorOnlyChange{path: path, installed: same}, true)
	if len(failed.Changes) != 0 {
		t.Fatalf("a failed run reported changes: %q", failed.Changes)
	}

	// GAP-0034: BUNDLE= TRUSTANCHORS= that repeats the confirmed bundle but
	// commits other anchors (key A only -> A and B) changed the device, so
	// it is not an already_applied no-op; the same anchors again still are.
	keyA := []byte(`{"schema_version":1,"keys":[{"id":"a","status":"active"}]}`)
	keyAB := []byte(`{"schema_version":1,"keys":[{"id":"a","status":"active"},{"id":"b","status":"active"}]}`)
	alreadyApplied := func() *enterprisestatus.Result {
		return &enterprisestatus.Result{Action: "ensure", Noop: true, NoopReason: "already_applied"}
	}
	rotated := alreadyApplied()
	settleAnchorOnlyEnsure(rotated, &anchorOnlyChange{path: path, existed: true, previous: keyA, installed: keyAB}, false)
	if rotated.Noop || rotated.NoopReason != "" || len(rotated.Changes) != 1 || rotated.Changes[0] != "replaced the trust anchors in "+path {
		t.Fatalf("repeat bundle with new anchors: noop=%v reason=%q changes=%q", rotated.Noop, rotated.NoopReason, rotated.Changes)
	}
	repeated := alreadyApplied()
	settleAnchorOnlyEnsure(repeated, &anchorOnlyChange{path: path, existed: true, previous: keyAB, installed: append([]byte(nil), keyAB...)}, false)
	if !repeated.Noop || repeated.NoopReason != "already_applied" || len(repeated.Changes) != 0 {
		t.Fatalf("repeat bundle with the same anchors: %+v", repeated)
	}

	bundleRun := compliant()
	settleAnchorOnlyEnsure(bundleRun, nil, true)
	if !bundleRun.Noop || len(bundleRun.Changes) != 0 {
		t.Fatalf("a run without TRUSTANCHORS= alone changed: %+v", bundleRun)
	}
}
