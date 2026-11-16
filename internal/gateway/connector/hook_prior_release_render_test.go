// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

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

// The needle comparison of a generic hook config (Kiro and the connectors that
// are matched by their native hook flag) accepts the earlier release's bridge
// only when asked, and only as the legacy fallback end of the same command.
func TestHookCommandMatchesPriorReleaseAcceptsOnlyTheLegacyFallbackEnd(t *testing.T) {
	for _, name := range []string{"kiro", "devin", "antigravity", "copilot"} {
		needle := nativeHookFlag + name
		current := hookInvocationCommandFor("windows", name, "")
		legacy, ok := legacyWindowsAwaitedHookCommand(current)
		if !ok {
			// A connector whose command is not an awaited bridge has no earlier render.
			if hookCommandMatchesPriorRelease(current+" x", needle) {
				t.Fatalf("%s: a different command matched", name)
			}
			continue
		}
		if !hookCommandMatches(current, needle) || hookCommandMatches(legacy, needle) {
			t.Fatalf("%s: the exact comparison must take only the current command", name)
		}
		if !hookCommandMatchesPriorRelease(current, needle) || !hookCommandMatchesPriorRelease(legacy, needle) {
			t.Fatalf("%s: the prior-release comparison must take the current and the legacy command", name)
		}
		if hookCommandMatchesPriorRelease(legacy+" ", needle) || hookCommandMatchesPriorRelease(strings.Replace(legacy, "powershell", "pwsh", 1), needle) {
			t.Fatalf("%s: an edited legacy command matched", name)
		}
	}
	if hookCommandMatchesPriorRelease("anything", "/opt/defenseclaw/hooks/kiro-hook.sh") {
		t.Fatal("a script needle matched a stranger")
	}
}
