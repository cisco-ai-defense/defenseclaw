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

// TestGAP0668StateWriteAfterGroupedCdIsJudgedInTheMovedFolder: a cd in a
// time-prefixed group, a cd before a process substitution and a cd in the
// last stage of a pipeline (zsh, Bash with lastpipe) leave the shell in the
// DefenseClaw state folder, and a relative write after it is a state write
// there: the laptop names tamper.detector_state_write as it does for the
// plain spelling, and the copy-mode actor gives the same verdict and rules.
// The same shapes that move to /tmp stay an allow (substrate-1 GAP-0668).
func TestGAP0668StateWriteAfterGroupedCdIsJudgedInTheMovedFolder(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	stateWrites := []string{
		`time { cd ~/.defenseclaw && ls; }; echo m > config.yaml`,
		`cd ~/.defenseclaw; ls; cat <(cd /tmp; ls); echo m > config.yaml`,
		`shopt -s lastpipe; true | { cd ~/.defenseclaw && ls; }; echo m > config.yaml`,
		`bash -O lastpipe -c 'true | { cd ~/.defenseclaw && ls; }; echo m > config.yaml'`,
		`true | { cd ~/.defenseclaw && ls; }; echo m > config.yaml`,
		`cd ~/.defenseclaw && ls; echo m > config.yaml`,
	}
	benign := []string{
		`time { cd /tmp && ls; }; echo m > config.yaml`,
		`cd /tmp; ls; cat <(cd ~/.defenseclaw; ls); echo m > config.yaml`,
		`true | { cd /tmp && ls; }; echo m > config.yaml`,
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", pack)
			home := filepath.Join(t.TempDir(), "home", "alice")
			for _, dir := range []string{"src", ".claude", ".defenseclaw"} {
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
			judge := func(command string) (string, []string, string, []string) {
				la, lr := gap0304Verdict(t, api, context.Background(), home, command)
				ca, cr := gap0304Verdict(t, api, actor, sandboxauth.SandboxHome, command)
				if ca != la || !slices.Equal(cr, lr) {
					t.Errorf("%q: actor %s %v, laptop %s %v", command, ca, cr, la, lr)
				}
				return la, lr, ca, cr
			}
			for _, command := range stateWrites {
				la, lr, _, _ := judge(command)
				if la == "allow" || !slices.Contains(lr, "tamper.detector_state_write") {
					t.Errorf("%q: laptop %s %v; want tamper.detector_state_write", command, la, lr)
				}
			}
			for _, command := range benign {
				if la, lr, _, _ := judge(command); la != "allow" {
					t.Errorf("%q: laptop %s %v; want allow", command, la, lr)
				}
			}
		})
	}
}
