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
	"strings"
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
	for _, tc := range []struct {
		name     string
		previous []byte
		want     string
	}{
		{"replaced", []byte(`{"schema_version":1,"keys":[{"id":"k1","status":"active"}]}`), "replaced the trust anchors in " + path},
		{"first", nil, "installed trust anchors in " + path},
	} {
		result := compliant()
		settleAnchorOnlyEnsure(result, &anchorOnlyChange{path: path, previous: tc.previous,
			installed: []byte(`{"schema_version":1,"keys":[{"id":"k1","status":"revoked"}]}`)})
		if result.Noop || result.NoopReason != "" || len(result.Changes) != 1 || !strings.HasPrefix(result.Changes[0], tc.want) {
			t.Fatalf("%s: noop=%v reason=%q changes=%q", tc.name, result.Noop, result.NoopReason, result.Changes)
		}
	}

	same := []byte(`{"schema_version":1}`)
	unchanged := compliant()
	settleAnchorOnlyEnsure(unchanged, &anchorOnlyChange{path: path, previous: same, installed: append([]byte(nil), same...)})
	if !unchanged.Noop || unchanged.NoopReason != "compliant" || len(unchanged.Changes) != 0 {
		t.Fatalf("byte-identical anchors: %+v", unchanged)
	}

	failed := compliant()
	failed.AddError("lifecycle_busy", "busy")
	settleAnchorOnlyEnsure(failed, &anchorOnlyChange{path: path, installed: same})
	if len(failed.Changes) != 0 {
		t.Fatalf("a failed run reported changes: %q", failed.Changes)
	}

	bundleRun := compliant()
	settleAnchorOnlyEnsure(bundleRun, nil)
	if !bundleRun.Noop || len(bundleRun.Changes) != 0 {
		t.Fatalf("a run without TRUSTANCHORS= alone changed: %+v", bundleRun)
	}
}
