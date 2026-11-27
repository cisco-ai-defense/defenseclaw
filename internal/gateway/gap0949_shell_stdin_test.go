// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP0949ShellStdinAndAliasHookConfigWrite: a hook-config write in a
// here-document a shell runs as its script, or after an alias for a cd,
// gets the verdict and rule of the same lines as a call (refers), on the
// laptop and in a copy-mode actor; a here-document fed to a script or to
// cat, and an alias for another folder, stay allowed (substrate-1 GAP-0949,
// RV-SEC10B rows E16, E09).
func TestGAP0949ShellStdinAndAliasHookConfigWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	const write = "echo \x27{}\x27 > settings.json"
	refers := "$CMD; cd .claude; " + write
	rows := []struct {
		name, command string
		write         bool
	}{
		{"E16 heredoc", "$CMD; bash <<EOF\ncd .claude\n" + write + "\nEOF", true},
		{"heredoc no unread", "bash <<EOF\ncd .claude\n" + write + "\nEOF", true},
		{"quoted heredoc", "$CMD; bash <<\x27EOF\x27\ncd .claude\n" + write + "\nEOF", true},
		{"sh -s heredoc", "$CMD; sh -s x <<EOF\ncd .claude\n" + write + "\nEOF", true},
		{"heredoc path", "$CMD; bash <<EOF\necho \x27{}\x27 > .claude/settings.json\nEOF", true},
		{"heredoc after cd", "$CMD; cd .claude && bash <<EOF\n" + write + "\nEOF", true},
		{"E09 alias", "shopt -s expand_aliases\nalias g=\x27cd .claude\x27\n$CMD\ng\n" + write, true},
		{"alias no unread", "shopt -s expand_aliases\nalias g=\x27cd .claude\x27\ng\n" + write, true},
		{"heredoc other folder", "$CMD; bash <<EOF\ncd src\n" + write + "\nEOF", false},
		{"alias other folder", "shopt -s expand_aliases\nalias g=\x27cd src\x27\n$CMD\ng\n" + write, false},
		{"cat heredoc data", "$CMD; cat <<EOF\ncd .claude\n" + write + "\nEOF", false},
		{"script heredoc data", "$CMD; bash run.sh <<EOF\ncd .claude\n" + write + "\nEOF", false},
		{"bash -c heredoc data", "$CMD; bash -c true <<EOF\ncd .claude\n" + write + "\nEOF", false},
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", pack)
			home := filepath.Join(t.TempDir(), "home", "alice")
			for _, dir := range []string{"src", ".claude"} {
				if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
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
			wa, wr := gap0304Verdict(t, api, context.Background(), home, refers)
			if wa == "allow" || !slices.Contains(wr, agentHookConfigWriteRuleID) {
				t.Fatalf("reference: laptop %s %v; want the hook-config write rule", wa, wr)
			}
			for _, row := range rows {
				la, lr := gap0304Verdict(t, api, context.Background(), home, row.command)
				ca, cr := gap0304Verdict(t, api, actor, sandboxauth.SandboxHome, row.command)
				if row.write {
					if la != wa || !slices.Equal(lr, wr) || ca != wa || !slices.Equal(cr, wr) {
						t.Errorf("%s: laptop %s %v, actor %s %v; want %s %v", row.name, la, lr, ca, cr, wa, wr)
					}
					continue
				}
				if la != "allow" || ca != "allow" {
					t.Errorf("%s: laptop %s %v, actor %s %v; want allow", row.name, la, lr, ca, cr)
				}
			}
		})
	}
}
