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
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestTierGateReadsThePackTierAndTable (DET111 D4 step 1): a tier gate reads
// the cell of the request's own tier in its pack's table. A permissive pack
// whose tiered-strict row enforces in its permissive column enforces for a
// permissive request, and the default column still alerts; with no table the
// built-in cells hold, and StrictPolicy reads the strict column.
func TestTierGateReadsThePackTierAndTable(t *testing.T) {
	dir := t.TempDir()
	column := "version: 1\ntier: permissive\nrows:\n  - id: tiered-strict\n    per_user:\n      floor: allow\n    managed:\n      floor: allow\n"
	if err := os.WriteFile(filepath.Join(dir, decide.TiersFile), []byte(column), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packTableFallback.Delete(dir) })
	table := packTable(dir)
	if table == decide.Builtin() {
		t.Fatal("a column that changes a cell decided with the built-in table")
	}
	for _, tc := range []struct {
		name    string
		request trustedActionRequest
		enforce bool
	}{
		{"pack table, permissive request", trustedActionRequest{PolicyTier: decide.TierPermissive, Tiers: table}, true},
		{"pack table, default request", trustedActionRequest{PolicyTier: decide.TierDefault, Tiers: table}, false},
		{"pack table, strict request", trustedActionRequest{PolicyTier: decide.TierPermissive, StrictPolicy: true, Tiers: table}, true},
		{"built-in, permissive request", trustedActionRequest{PolicyTier: decide.TierPermissive}, false},
		{"built-in, strict", trustedActionRequest{StrictPolicy: true}, true},
	} {
		if got := tc.request.tierEnforces(tierGateStrict); got != tc.enforce {
			t.Errorf("%s: enforces %v, want %v", tc.name, got, tc.enforce)
		}
	}
	// A shipped pack's tiers.yaml is the built-in table itself.
	for _, tier := range []string{"default", "permissive", "strict"} {
		shipped := filepath.Join(guardrailPoliciesRoot(t), tier)
		t.Cleanup(func() { packTableFallback.Delete(shipped) })
		if packTable(shipped) != decide.Builtin() {
			t.Errorf("shipped %s pack: its table is not decide.Builtin()", tier)
		}
	}
}
