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

// substrate-1 GAP-0648: a cd inside a ( ... ) group, a pipeline stage or a
// command substitution ends with it. The copy-mode actor kept the group's
// folder as one the later commands run in, so
// (cd ~/.defenseclaw && ls); echo m > config.yaml read the write in
// ~/.defenseclaw and blocked with tamper.detector_state_write where the
// laptop allows. The actor must give the laptop's verdict and rules for the
// benign rows, and keep the laptop's block where the write does land in the
// state folder (the cd outside a group, a cd again after the group, the
// write inside the group, a here-string call).
//
// A group in the last stage of a pipeline or in an & list does not end its
// folder for the laptop (zsh and Bash with lastpipe run the last stage in
// the shell itself): a hook-config write after it keeps the laptop's
// tamper.agent_hook_config_write alert on the actor (GAP-0648 review P2-1).
func TestGAP0648SubshellCdFolderEndsWithTheGroup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	type probe struct {
		command string
		allow   bool // the laptop allows it (benign); otherwise it judges it
	}
	probes := []probe{
		{"(cd ~/.defenseclaw && ls); echo m > config.yaml", true},
		{"echo m > config.yaml; (cd ~/.defenseclaw && ls); echo m > config.yaml", true},
		{"(cd ~/.defenseclaw && ls) && echo m > config.yaml", true},
		{"cd ~/.defenseclaw | true; echo m > config.yaml", true},
		{"x=$(cd ~/.defenseclaw && ls); echo m > config.yaml", true},
		{"(cd ~/.defenseclaw && ls); (cd ~/.cache && ls); echo m > config.yaml", true},
		// The write lands in the state folder: the laptop's finding on both
		// sides.
		{"cd ~/.defenseclaw && ls; echo m > config.yaml", false},
		{"cd ~/.defenseclaw && (ls); echo m > config.yaml", false},
		{"(cd ~/.defenseclaw; echo m > config.yaml)", false},
		{"(cd ~/.defenseclaw && ls); cd ~/.defenseclaw; echo m > config.yaml", false},
		{"{ cd ~/.defenseclaw && ls; }; echo m > config.yaml", false},
		{"cat <<< x; cd ~/.defenseclaw && ls; echo m > config.yaml", false},
		{"cat <<< x; (cd ~/.defenseclaw; ls; echo m > config.yaml)", false},
		// A hook-config write after a group the laptop does not end: the
		// last stage of a pipeline (lastpipe, zsh) and an & list.
		{"shopt -s lastpipe; true | { cd ~/.claude && ls; }; echo x > settings.json", false},
		{"true | { cd ~/.claude && ls; }; echo x > settings.json", false},
		{"cd ~/.claude && ls &\nwait; echo x > settings.json", false},
		{"zsh -c 'true | { cd ~/.claude && ls; }; echo x > settings.json'", false},
		{"{ cd ~/.claude && ls; } & wait; echo x > settings.json", false},
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", pack)
			home := filepath.Join(t.TempDir(), "home", "alice")
			for _, dir := range []string{".defenseclaw", ".cache", ".claude"} {
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
			for _, p := range probes {
				la, lr := gap0304Verdict(t, api, context.Background(), home, p.command)
				ca, cr := gap0304Verdict(t, api, actor, sandboxauth.SandboxHome, p.command)
				if p.allow && la != "allow" {
					t.Errorf("%q: test setup: the laptop judges a benign call %s %v", p.command, la, lr)
					continue
				}
				if !p.allow && la == "allow" {
					t.Errorf("%q: test setup: the laptop gives %s %v for a state write", p.command, la, lr)
					continue
				}
				if ca != la || !slices.Equal(cr, lr) {
					t.Errorf("%q: copy-mode actor %s %v, laptop %s %v", p.command, ca, cr, la, lr)
				}
			}
		})
	}
}
