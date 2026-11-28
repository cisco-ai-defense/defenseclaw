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

// substrate-1 GAP-0645 (reopened by the live row TST-5823): a Substrate actor
// whose project is a folder outside its home (/work/<project>, the shape of
// every actor's working copy) and whose ~/.defenseclaw/config.yaml is a real
// file. Every route to that file must reach the verdict and the rule the
// laptop gives: the default tier alerts (tamper.detector_state_write is HIGH,
// stateWriteSeverityFor) and strict blocks. An alert does not stop the call,
// so the actor's own transcript shows no refusal in the default tier; the
// verdict is in the gateway's audit row, which names the rule.
//
// TestGAP0377SandboxGuestPlacementKeepsS7CandidateMatrix judges the
// matrix from the guest's home as the working folder; the live actor's working
// folder is its project, so this test gives the binding the way
// substrateActorScope does (route list, copy-mode workdir, profile) and the
// facts the live call has: the project as the working folder, a literal write,
// the three variable forms of the gap and the benign control.
func TestGAP0645CopyModeActorNamesStateWriteFromProjectFolder(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	const projectCWD = "/work/proj645"
	rank := func(action string) int {
		switch action {
		case "allow":
			return 0
		case "block", "deny":
			return 2
		}
		return 1
	}
	const stateRule = "tamper.detector_state_write"
	type row struct {
		name, command string
		benign        bool
	}
	rows := []row{
		{name: "literal", command: "echo m > ~/.defenseclaw/config.yaml"},
		{name: "plain", command: "cd ~/.defenseclaw; x=config.yaml; echo m > $x"},
		{name: "bash-c", command: "bash -c 'cd ~/.defenseclaw; x=config.yaml; echo m > $x'"},
		{name: "sh-c", command: "sh -c 'cd ~/.defenseclaw; x=config.yaml; echo m > $x'"},
		{name: "and-chain", command: "cd ~/.defenseclaw && x=config.yaml && echo m > $x"},
		{name: "or-chain-sh-c", command: "cd ~/.defenseclaw || cd /tmp && sh -c 'x=config.yaml; echo m > $x'"},
		{name: "or-chain-bash-c", command: "cd ~/.defenseclaw || cd /tmp && bash -c 'x=config.yaml; echo m > $x'"},
		{name: "or-chain-func", command: "cd ~/.defenseclaw || cd /tmp && f() { x=config.yaml; echo m > $x; }; f"},
		{name: "func-first", command: "f() { x=config.yaml; echo m > $x; }; cd ~/.defenseclaw || cd /tmp && f"},
		{name: "herestring-wrap", command: "cat <<< ok; cd ~/.defenseclaw || cd /tmp && sh -c 'x=config.yaml; echo m > $x'"},
		{name: "relative-literal", command: "cd ~/.defenseclaw; echo m > config.yaml"},
		{name: "benign-tmp", command: "cd /tmp; x=notes645.txt; echo m > $x", benign: true},
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", pack)
			home := filepath.Join(t.TempDir(), "home", "alice")
			for _, dir := range []string{"project", ".defenseclaw", ".ssh"} {
				if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			// The real file the live actor writes first.
			if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "config.yaml"), []byte("dc: real\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePack = pack
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			// The binding substrateActorScope puts on a Substrate actor's call.
			binding := sandboxauth.Binding{
				ID: "sb_000000000000000000000000000000e3", SandboxName: "dc-eng/svl3-c645a", Connector: "claudecode",
				PolicyProfile: "eng",
				Routes:        []sandboxauth.Route{sandboxauth.RouteHook, sandboxauth.RouteNotify, sandboxauth.RouteInspect, sandboxauth.RouteOTLP},
				Workdir:       sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
			}
			actor := withProfilePath(withAuthenticatedHookConnector(sandboxauth.WithRequest(context.Background(), binding, nil), binding.Connector), profilePathHook)
			for _, r := range rows {
				laptopAction, laptopRules := gap0304Verdict(t, api, context.Background(), filepath.Join(home, "project"),
					strings.ReplaceAll(r.command, "~", home))
				actorAction, actorRules := gap0304Verdict(t, api, actor, projectCWD, r.command)
				if r.benign {
					if actorAction != "allow" || len(actorRules) != 0 || laptopAction != "allow" {
						t.Errorf("%s: benign control: actor %s %v, laptop %s %v", r.name, actorAction, actorRules, laptopAction, laptopRules)
					}
					continue
				}
				if !slices.Contains(laptopRules, stateRule) {
					t.Errorf("%s: the laptop does not name %s (%s %v): the row models nothing", r.name, stateRule, laptopAction, laptopRules)
				}
				if !slices.Contains(actorRules, stateRule) {
					t.Errorf("%s: copy-mode actor %s %v does not name %s (laptop %s %v)", r.name, actorAction, actorRules, stateRule, laptopAction, laptopRules)
				}
				if rank(actorAction) < rank(laptopAction) || actorAction == "allow" {
					t.Errorf("%s: copy-mode actor %s %v is weaker than the laptop's %s %v", r.name, actorAction, actorRules, laptopAction, laptopRules)
				}
				if pack == "strict" && actorAction != "block" {
					t.Errorf("%s: strict tier: copy-mode actor %s, want block", r.name, actorAction)
				}
			}
		})
	}
}
