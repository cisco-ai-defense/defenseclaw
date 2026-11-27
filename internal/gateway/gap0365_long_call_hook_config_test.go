// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP0365LongCallNamesHookConfigWrite (substrate-1 GAP-0365): a shell
// call over the guards' 8192-byte placement bound, padded by a data word in
// its own statement, still names tamper.agent_hook_config_write for a
// settings write after a cd, on the laptop and in a copy-mode actor, with
// the same verdict and rules on both, in the default and strict packs. A
// long call that writes no hook file names none.
func TestGAP0365LongCallNamesHookConfigWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged only")
	}
	big := strings.Repeat("A", 9000)
	shapes := []struct {
		name, command string
		write         bool
	}{
		{"settings-first", "cd .cache && echo '{}' > ../.claude/settings.json && echo " + big, true},
		{"settings-last", "cd .cache && echo " + big + " && echo '{}' > ../.claude/settings.json", true},
		{"settings-no-cd", "echo " + big + "; echo '{}' > .claude/settings.json", true},
		{"settings-8000", "cd .cache && echo '{}' > ../.claude/settings.json && echo " + strings.Repeat("A", 8000), true},
		{"benign-long", "cd .cache && echo " + big + " && ls", false},
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", pack)
			home := filepath.Join(t.TempDir(), "home", "alice")
			for _, d := range []string{".cache", ".claude"} {
				if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePack = pack
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			binding := sandboxTestBinding("claudecode")
			actor := withProfilePath(withAuthenticatedHookConnector(sandboxauth.WithRequest(context.Background(), binding, nil), binding.Connector), profilePathHook)
			for _, shape := range shapes {
				la, lr := gap0304Verdict(t, api, context.Background(), home, shape.command)
				ca, cr := gap0304Verdict(t, api, actor, sandboxauth.SandboxHome, shape.command)
				t.Logf("GAP0365 pack=%s %s len=%d laptop=%s %v actor=%s %v", pack, shape.name, len(shape.command), la, lr, ca, cr)
				named := slices.Contains(lr, agentHookConfigWriteRuleID)
				if named != shape.write || slices.Contains(cr, agentHookConfigWriteRuleID) != shape.write {
					t.Errorf("%s: write rule named laptop=%v actor=%v, want %v", shape.name, lr, cr, shape.write)
				}
				if shape.write && (la == "allow" || ca == "allow") {
					t.Errorf("%s: a named settings write is allowed: laptop=%s actor=%s", shape.name, la, ca)
				}
				if la != ca || !slices.Equal(lr, cr) {
					t.Errorf("%s: actor %s %v != laptop %s %v", shape.name, ca, cr, la, lr)
				}
			}
		})
	}
}

// TestGAP0365LongCallStatementsBounded: the long-call reading keeps at
// most agentHookConfigLongCallStatementCap statements, each within the
// placement bound, and reads nothing past the analyzer's command bound.
func TestGAP0365LongCallStatementsBounded(t *testing.T) {
	var parts []string
	for i := 0; i < 200; i++ {
		parts = append(parts, "echo '{}' > .claude/settings.json")
	}
	parts = append(parts, "echo "+strings.Repeat("A", 9000))
	command := strings.Join(parts, "; ")
	got := agentHookConfigLongCallStatements(command, "/home/alice", "/home/alice")
	if len(got) != agentHookConfigLongCallStatementCap {
		t.Fatalf("kept %d statements", len(got))
	}
	for _, statement := range got {
		if len(statement.Command) > agentHookConfigMaxPlacedBytes {
			t.Fatalf("kept a statement over the bound: %d bytes", len(statement.Command))
		}
	}
	if got := agentHookConfigLongCallStatements("echo '{}' > .claude/settings.json; echo "+strings.Repeat("A", agentHookConfigLongCallMaxBytes), "/home/alice", "/home/alice"); got != nil {
		t.Fatalf("read a call over the analyzer bound: %d", len(got))
	}
	if got := agentHookConfigLongCallStatements("cd .cache && echo "+strings.Repeat("A", 9000)+" && ls", "/home/alice", "/home/alice"); len(got) != 0 {
		t.Fatalf("kept statements that name no hook file: %+v", got)
	}
}
