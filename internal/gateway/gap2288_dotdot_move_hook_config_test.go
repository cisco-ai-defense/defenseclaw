// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2288: on the laptop, a move, install or sync into a Claude settings file
// spelled through x/.. is the hook config write its plain spelling is.
func TestGAP2288DotDotMoveIntoClaudeSettingsIsAHookConfigWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	cwd := filepath.Join(home, "app")
	if err := os.MkdirAll(filepath.Join(cwd, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	ruled := func(command string) bool {
		request := trustedActionRequest{Connector: "claudecode", EnforcementCapable: true, Input: actionfacts.Input{
			Tool: "Bash", Command: command, ActiveHome: home, CWD: cwd,
		}}
		for _, finding := range agentHookConfigFindingsAs(context.Background(), request, nil) {
			if finding.RuleID == agentHookConfigWriteRuleID {
				return true
			}
		}
		return false
	}
	for _, writer := range []string{"mv /tmp/s", "install /tmp/s", "rsync /tmp/s"} {
		if !ruled(writer + " .claude/settings.json") {
			t.Fatalf("%s: the plain spelling is no hook config write", writer)
		}
		for _, dest := range []string{"x/../.claude/settings.json", cwd + "/x/../.claude/settings.json"} {
			if !ruled(writer + " " + dest) {
				t.Errorf("%s %s: no %s, the plain spelling has it", writer, dest, agentHookConfigWriteRuleID)
			}
		}
	}
	for _, command := range []string{"mv /tmp/s x/../notes.json", "rsync -a src/ x/../backup/"} {
		if ruled(command) {
			t.Errorf("%s: an ordinary file is no hook config write", command)
		}
	}
}
