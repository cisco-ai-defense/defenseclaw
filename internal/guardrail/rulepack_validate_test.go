// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import "testing"

// A cached pack is validated once, however many profiles and connectors
// resolve to it.
func TestRulePackCacheValidatesEachPackOnce(t *testing.T) {
	prev := validateRulePack
	t.Cleanup(func() { validateRulePack = prev })
	runs := 0
	validateRulePack = func(*RulePack) error { runs++; return nil }

	cache := NewRulePackCache()
	a, b := &RulePack{}, &RulePack{}
	for i := 0; i < 5; i++ {
		if err := cache.Validate(a); err != nil {
			t.Fatalf("Validate(a): %v", err)
		}
	}
	if err := cache.Validate(b); err != nil {
		t.Fatalf("Validate(b): %v", err)
	}
	if runs != 2 {
		t.Fatalf("validated %d times for 2 packs, want 2", runs)
	}
}
