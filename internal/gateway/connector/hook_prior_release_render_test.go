// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// GAP-0980: the render of releases up to 1.0.6 is the current render with the
// Constrained Language fallback end of legacyWindowsAwaitedHookCommand; the
// Windows enterprise guardian's read-only verify accepts it as such, and
// nothing else.
func TestPriorReleaseHookRenderIsTheLegacyFallbackEndOfEveryBridge(t *testing.T) {
	const hookScript = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	current := antigravityOwnedHookKeys("windows", hookScript, true)
	if len(current) != len(antigravityLifecycleEvents) {
		t.Fatalf("rendered %d keys", len(current))
	}
	for key, rendered := range current {
		prior := priorReleaseHookRender(rendered)
		if sameHookJSON(rendered, prior) {
			t.Fatalf("%s: the earlier release's render equals the current one", key)
		}
		if !sameHookJSON(priorReleaseHookRender(rendered), prior) {
			t.Fatalf("%s: the transformation is not stable", key)
		}
		// Rendering the same document again, event by event, with the legacy
		// end of the managed bridge is what the transformation must give.
		for _, event := range antigravityLifecycleEvents {
			command := antigravityHookCommandForEvent("windows", event, hookScript, true)
			legacy, ok := legacyWindowsAwaitedHookCommand(command)
			if !ok || legacy == command {
				t.Fatalf("%s: no legacy form of the %s bridge", key, event)
			}
		}
	}
	// A command that is not a bridge, and every other value, is kept.
	unix := antigravityOwnedHookKeys("linux", "/opt/defenseclaw/hooks/antigravity-hook.sh", true)
	for key, rendered := range unix {
		if !sameHookJSON(rendered, priorReleaseHookRender(rendered)) {
			t.Fatalf("%s: a non-bridge command changed", key)
		}
	}
	if got := priorReleaseHookRender(float64(30)); got != float64(30) {
		t.Fatalf("number changed: %v", got)
	}
}
