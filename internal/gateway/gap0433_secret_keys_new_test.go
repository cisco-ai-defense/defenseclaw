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
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// TestGAP0433ShippedPacksCarryTheBuiltinKeys: each shipped pack's
// SEC-SECRET-ASSIGN carries the built-in key vocabulary exactly (the
// generated catalog's, from the default pack), so the shipped packs give the
// verdicts they gave when the words were a Go map.
func TestGAP0433ShippedPacksCarryTheBuiltinKeys(t *testing.T) {
	builtin := builtinSecretAssignmentKeys()
	if len(builtin.words) == 0 || len(builtin.prefixes) == 0 || len(builtin.suffixes) == 0 {
		t.Fatalf("built-in key vocabulary is incomplete: %d words, %d prefixes, %d suffixes",
			len(builtin.words), len(builtin.prefixes), len(builtin.suffixes))
	}
	for _, tier := range []string{"default", "strict", "permissive"} {
		rp, err := guardrail.LoadRulePack(filepath.Join(guardrailPoliciesRoot(t), tier))
		if err != nil {
			t.Fatal(err)
		}
		var keys *guardrail.RuleKeysYAML
		for _, file := range rp.RuleFiles {
			for index := range file.Rules {
				if file.Rules[index].ID == secretAssignmentRuleID {
					keys = file.Rules[index].Keys
				}
			}
		}
		if keys == nil {
			t.Fatalf("%s: SEC-SECRET-ASSIGN has no keys block", tier)
		}
		got := compileSecretAssignmentKeys(keys)
		for _, set := range []struct {
			name      string
			got, want map[string]bool
		}{{"words", got.words, builtin.words}, {"prefixes", got.prefixes, builtin.prefixes}, {"suffixes", got.suffixes, builtin.suffixes}} {
			if len(set.got) != len(set.want) {
				t.Fatalf("%s: %s has %d entries, built-in %d", tier, set.name, len(set.got), len(set.want))
			}
			for word := range set.want {
				if !set.got[word] {
					t.Fatalf("%s: %s lacks %q", tier, set.name, word)
				}
			}
		}
	}
}
