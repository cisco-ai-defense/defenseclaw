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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// Each shipped pack loads its tiers.yaml (DET111 D4): the column names the
// pack's own tier, and a pack without one keeps the built-in column.
func TestShippedPacksLoadTheirTiers(t *testing.T) {
	for _, name := range []string{"default", "permissive", "strict"} {
		rp, err := LoadRulePack(filepath.Join("..", "..", "policies", "guardrail", name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rp.Tiers == nil {
			t.Fatalf("%s: no tiers.yaml loaded", name)
		}
		if got := rp.Tiers.Tier.String(); got != name {
			t.Fatalf("%s: tiers.yaml names tier %s", name, got)
		}
	}
}

// A tiers.yaml that does not pass decide's schema check refuses the pack
// with invalid_tiers; a pack without one loads with no column.
func TestRulePackTiersAreChecked(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pack")
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("..", "..", "policies", "guardrail", "default"))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, decide.TiersFile)); err != nil {
		t.Fatal(err)
	}
	write := func(rel, text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rp, err := LoadRulePack(dir)
	if err != nil {
		t.Fatalf("pack without tiers.yaml: %v", err)
	}
	if rp.Tiers != nil {
		t.Fatal("pack without tiers.yaml got a column")
	}
	write(decide.TiersFile, "version: 1\ntier: default\nrows:\n  - id: truncated\n    per_user: {floor: allow, levels: false}\n    managed: {floor: alert, levels: false}\n")
	_, err = LoadRulePack(dir)
	var packErr *RulePackError
	if !errors.As(err, &packErr) || packErr.Code != "invalid_tiers" {
		t.Fatalf("silent-allow tiers.yaml: err = %v, want invalid_tiers", err)
	}
}
