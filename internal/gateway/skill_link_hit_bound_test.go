// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A shell call that names more links into skill folders than are read is
// refused, with the text that asks for fewer, while a skill is denied: the
// held link in it is judged, not the outage the reading would end in. The
// same call is allowed when no skill is held or denied.
func TestCallNamingMoreSkillLinksThanAreReadIsRefusedWhileASkillIsDenied(t *testing.T) {
	f := newOperandContextFixture(t, "held")
	if err := os.Symlink(f.held, filepath.Join(f.proj, "lnk-held")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(f.proj, "w4"), 0o755); err != nil {
		t.Fatal(err)
	}
	var names []string
	for i := 0; i < 1100; i++ {
		dir := filepath.Join(filepath.Dir(f.held), fmt.Sprintf("ordinary%04d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("w4/l%04d", i)
		if err := os.Symlink(dir, filepath.Join(f.proj, name)); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	command := "ls -d " + strings.Join(names, " ") + " lnk-held"
	request := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash", CWD: f.proj, ToolInput: map[string]interface{}{"command": command}}
	d, matched := f.api.claudeCodeSkillAssetDecision(f.ctx, request)
	if !matched || d.Action != "block" || d.Source != "skill-links-truncated" || !strings.Contains(d.Reason, "name fewer skill folders") {
		t.Errorf("denied skill: matched = %t, action = %q, source = %q, want the block that names fewer skill folders", matched, d.Action, d.Source)
	}
	f.api.scannerCfg.AssetPolicy.Skill.Denied = nil
	if d, matched := f.api.claudeCodeSkillAssetDecision(f.ctx, request); matched && d.Action == "block" {
		t.Errorf("no skill denied: blocked (%q), want the call allowed", d.Source)
	}
}
