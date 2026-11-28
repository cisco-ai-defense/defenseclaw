// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// GAP-1801 (b), (c), RV-W111D2: a merging HKLM value is admitted, but two
// things it leaves to chance were silent while status was green: an
// explicit allowManagedHooksOnly: false (it can override the drop-in's lock
// under merge) and no requiredMinimumVersion of 2.1.242 or later (Claude
// Code 2.1.154 to 2.1.241 that a user runs reads only HKLM and runs no
// DefenseClaw hooks). Status names both.
func TestGAP1801MergeCaveatsNameTheUnlockAndTheClientFloor(t *testing.T) {
	source := func(settings map[string]interface{}) *claudeCodeSettingsSource {
		return &claudeCodeSettingsSource{name: "MDM/OS managed settings", path: `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`, settings: settings}
	}
	got := claudeCodeOSAdminMergeCaveats(source(map[string]interface{}{"managedSourcesBehavior": "merge", "allowManagedHooksOnly": false}))
	if len(got) != 2 || !strings.Contains(got[0], "allowManagedHooksOnly: false") || !strings.Contains(got[1], `"requiredMinimumVersion": "2.1.242"`) {
		t.Fatalf("caveats %q", got)
	}
	got = claudeCodeOSAdminMergeCaveats(source(map[string]interface{}{"managedSourcesBehavior": "merge", "requiredMinimumVersion": "2.1.200"}))
	if len(got) != 1 || !strings.Contains(got[0], "2.1.154 to 2.1.241") {
		t.Fatalf("a floor below 2.1.242: %q", got)
	}
	for _, settings := range []map[string]interface{}{
		{"managedSourcesBehavior": "merge", "requiredMinimumVersion": "2.1.242"},
		{"managedSourcesBehavior": "merge", "requiredMinimumVersion": "2.2.0", "allowManagedHooksOnly": true},
	} {
		if got := claudeCodeOSAdminMergeCaveats(source(settings)); len(got) != 0 {
			t.Fatalf("%v: caveats %q, want none", settings, got)
		}
	}
}
