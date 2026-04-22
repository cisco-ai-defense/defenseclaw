// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import "testing"

func TestAllActionsUnique(t *testing.T) {
	seen := make(map[Action]bool)
	for _, a := range AllActions() {
		if seen[a] {
			t.Errorf("duplicate action in AllActions(): %q", a)
		}
		seen[a] = true
	}
}

func TestAllActionsNonEmpty(t *testing.T) {
	for _, a := range AllActions() {
		if a == "" {
			t.Errorf("empty action string in AllActions()")
		}
	}
}

func TestIsKnownAction(t *testing.T) {
	for _, a := range AllActions() {
		if !IsKnownAction(string(a)) {
			t.Errorf("IsKnownAction(%q) = false, want true", a)
		}
	}
	for _, bad := range []string{"", "not-a-real-action", "SCAN", "unknown"} {
		if IsKnownAction(bad) {
			t.Errorf("IsKnownAction(%q) = true, want false", bad)
		}
	}
}
