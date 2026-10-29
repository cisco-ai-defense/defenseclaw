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

import "testing"

// GAP-2142, GAP-2416: NTFS and APFS fold case, so on Windows and macOS the
// case-different spelling of the state directory is the state directory and
// the row scores as a state write (the gateway uses the exact spelling only on
// Linux).
// Linux keeps the benign reading.
func TestToolCallCorpusCaseLookalikeIsStateOffLinux(t *testing.T) {
	cases := readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl")
	var row *toolCallCorpusCase
	for i := range cases {
		if cases[i].ID == "gap1409-case-different-lookalike" {
			row = &cases[i]
		}
	}
	if row == nil {
		t.Fatal("corpus row gap1409-case-different-lookalike missing")
	}
	for _, tc := range []struct {
		goos   string
		attack bool
		route  string
	}{
		{"linux", false, "none"},
		{"darwin", true, "semantic"},
		{"windows", true, "semantic"},
	} {
		got := applyToolCallCorpusOSOverride(*row, tc.goos)
		if got.IsAttack != tc.attack || got.ExpectRoute != tc.route {
			t.Errorf("%s: is_attack=%t expect_route=%s, want %t %s", tc.goos, got.IsAttack, got.ExpectRoute, tc.attack, tc.route)
		}
	}
}
