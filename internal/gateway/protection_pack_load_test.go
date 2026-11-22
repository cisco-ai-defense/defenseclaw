// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// TestProtectionPacksComposeOnEveryBase composes every shipped opt-in
// protection pack over each of the three base packs through the product path
// (guardrail.Compose + protectionPackSource), the exact compose a running
// gateway performs on reload. A pack that exceeds the semantic rule-cost limit
// on a large base (rel-1-0-10:GAP-0050, GAP-0055) fails here instead of being
// saved by `protection enable` and then rejected at reload.
func TestProtectionPacksComposeOnEveryBase(t *testing.T) {
	root := filepath.Join("..", "..", "policies")
	useCases := filepath.Join(root, "guardrail-use-cases")
	entries, err := os.ReadDir(useCases)
	if err != nil {
		t.Fatalf("read use-cases: %v", err)
	}
	var packs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Only selectable packs (a rules/ directory with at least one YAML)
		// are composable; a staged pack such as ssh-authorized-keys-protection
		// ships no rules and `protection enable` refuses it.
		rules, rerr := os.ReadDir(filepath.Join(useCases, e.Name(), "rules"))
		if rerr != nil {
			continue
		}
		hasYAML := false
		for _, r := range rules {
			if !r.IsDir() && filepath.Ext(r.Name()) == ".yaml" {
				hasYAML = true
				break
			}
		}
		if hasYAML {
			packs = append(packs, e.Name())
		}
	}
	if len(packs) == 0 {
		t.Fatal("no protection packs found")
	}
	for _, base := range []string{"default", "strict", "permissive"} {
		baseDir := filepath.Join(root, "guardrail", base)
		rp, err := guardrail.LoadRulePack(baseDir)
		if err != nil {
			t.Fatalf("load base %s: %v", base, err)
		}
		for _, pack := range packs {
			t.Run(base+"+"+pack, func(t *testing.T) {
				if _, err := guardrail.Compose(rp, protectionPackSource, guardrail.Customization{Protections: []string{pack}}); err != nil {
					t.Fatalf("compose %s over %s failed: %v", pack, base, err)
				}
			})
		}
	}
}
