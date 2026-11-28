// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// gap0304Verdict is the hook's action and every rule id of its answer,
// ACTION-COMPOUND-LIMIT included.
func gap0304Verdict(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) (string, []string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0304", "cwd": cwd,
		"tool_name": "Bash", "tool_input": map[string]any{"command": command}, "tool_use_id": t.Name()})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("hook status=%d: %.500s", rec.Code, rec.Body.String())
	}
	var out struct {
		Action  string   `json:"action"`
		RuleIDs []string `json:"rule_ids"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	slices.Sort(out.RuleIDs)
	return out.Action, slices.Compact(out.RuleIDs)
}

// substrate-1 GAP-0304: a command padded with static cd steps, run in the
// home, writes ../.claude/settings.json or removes ../.bash_history from
// .cache. The copy-mode actor (every Substrate actor) must reach the laptop's
// verdict and rules in that home: a chain of repeated cd steps reads as the
// short chain, the hook-config guard places the write past the analysis
// bound as the laptop guard does, and a chain with more distinct placed
// commands than the guest reading takes is truncated (ACTION-COMPOUND-LIMIT),
// never a silent allow.
//
// substrate-1 GAP-0359: the guest reading takes the call's own statement
// budget, so a cd followed by 17 to 100 benign commands, joined by newlines
// or by &&, gets the laptop's verdict in every pack (an allow, and the
// laptop's own limit for 32 or more && steps), padding keeps PATH-HISTORY,
// and past the statement budget the actor still names the hook-config write.
func TestGAP0304SandboxCdChainKeepsLaptopParity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	repeat := func(n int, unit func(int) string) string {
		var b strings.Builder
		for i := range n {
			b.WriteString(unit(i))
		}
		return b.String()
	}
	same := func(int) string { return "cd .cache && cd .. && " }
	distinct := func(i int) string { return fmt.Sprintf("cd .cache && touch f%d && cd .. && ", i) }
	touch := func(i int) string { return fmt.Sprintf("touch f%d && ", i) }
	mkdirLine := func(i int) string { return fmt.Sprintf("mkdir -p d%d\n", i) }
	trueStep := func(i int) string { return fmt.Sprintf("true %d; ", i) }
	settings, history := "cd .cache && echo '{}' > ../.claude/settings.json", "cd .cache && rm ../.bash_history"
	type probe struct {
		name, command string
		// benign: the actor must give the laptop's answer, an allow when
		// laptopAllows (otherwise the laptop's own limit).
		benign, laptopAllows bool
		// allPacks: also run in the permissive and strict packs.
		allPacks bool
	}
	var probes []probe
	for _, n := range []int{0, 2, 15, 16, 17, 40} {
		probes = append(probes,
			probe{name: fmt.Sprintf("same-cd-%d settings", n), command: repeat(n, same) + settings},
			probe{name: fmt.Sprintf("same-cd-%d history", n), command: repeat(n, same) + history})
	}
	for _, n := range []int{2, 8, 14} {
		probes = append(probes,
			probe{name: fmt.Sprintf("distinct-cd-%d settings", n), command: repeat(n, distinct) + settings},
			probe{name: fmt.Sprintf("distinct-cd-%d history", n), command: repeat(n, distinct) + history, allPacks: n == 8})
	}
	probes = append(probes,
		// 17 and 100 distinct placed commands before the delete, under the
		// call's statement budget: read in full, the laptop's PATH-HISTORY.
		probe{name: "distinct-placed-17 history", command: "cd .cache && " + repeat(17, touch) + "rm ../.bash_history"},
		probe{name: "script-100 history", command: "cd .cache\n" + repeat(100, mkdirLine) + "rm ../.bash_history", allPacks: true},
		// The same text in two directories: the second rm is the harmful one.
		probe{name: "same-text-diff-cwd", command: "cd .cache/sub && rm ../.bash_history && cd .. && rm ../.bash_history"},
		probe{name: "same-text-diff-cwd-padded14", command: "cd .cache/sub && " + repeat(14, touch) + "rm ../.bash_history && cd .. && rm ../.bash_history", allPacks: true},
		// A cd .. that moves each time it runs.
		probe{name: "cd-dotdot-moves", command: "cd .cache/a/b && cd .. && cd .. && rm ../.bash_history"},
		probe{name: "cd-dotdot-moves-settings", command: "cd .cache/a/b && cd .. && cd .. && echo '{}' > ../.claude/settings.json"},
		// The hook-config guard under and past the statement budget: past
		// it, both sides carry the limit and name the write.
		probe{name: "guard-126-settings", command: repeat(126, trueStep) + settings},
		probe{name: "guard-130-settings", command: repeat(130, trueStep) + settings, allPacks: true},
		// More distinct placed commands than the guest reading takes: 141
		// simple commands are over the call's statement budget too (it
		// counts pipeline stages), so both sides give the limit.
		probe{name: "placed-140-pipes history", command: "cd .cache\n" +
			repeat(70, func(i int) string { return fmt.Sprintf("touch a%d | touch b%d\n", i, i) }) + "rm ../.bash_history",
			allPacks: true},
	)
	for _, sep := range []string{"\n", " && "} {
		for _, n := range []int{17, 28, 32, 100} {
			parts := []string{"cd .cache"}
			for i := range n {
				parts = append(parts, fmt.Sprintf("mkdir -p d%d", i))
			}
			probes = append(probes, probe{name: fmt.Sprintf("benign-mkdir-%d sep=%q", n, sep),
				command: strings.Join(parts, sep), benign: true, laptopAllows: sep == "\n" || n < 32, allPacks: true})
		}
	}

	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", pack)
			home := filepath.Join(t.TempDir(), "home", "alice")
			for _, dir := range []string{".cache/sub", ".cache/a/b"} {
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
				if pack != "default" && !p.allPacks {
					continue
				}
				la, lr := gap0304Verdict(t, api, context.Background(), home, p.command)
				ca, cr := gap0304Verdict(t, api, actor, sandboxauth.SandboxHome, p.command)
				switch {
				case p.benign:
					if p.laptopAllows && la != "allow" {
						t.Fatalf("%s: test setup: the laptop judges a benign script %s %v", p.name, la, lr)
					}
				case la == "allow":
					t.Fatalf("%s: test setup: the laptop allows %q", p.name, p.command)
				case ca == "allow":
					t.Fatalf("%s: copy-mode actor allows (silently) what the laptop judges %s %v", p.name, la, lr)
				case ca == la && slices.Contains(lr, evaluationLimitRuleID) && gap0304RulesCover(cr, lr):
					// Past its own && list bound the laptop's reading loses
					// the cd for its semantic rules; the actor keeps it
					// (substrate-1 GAP-0363), so it may name more, never
					// fewer, with the same verdict.
					continue
				}
				if ca != la || !slices.Equal(cr, lr) {
					t.Fatalf("%s: copy-mode actor %s %v, laptop %s %v", p.name, ca, cr, la, lr)
				}
			}
		})
	}
}

// gap0304RulesCover reports whether rules names every rule of sub.
func gap0304RulesCover(rules, sub []string) bool {
	for _, rule := range sub {
		if !slices.Contains(rules, rule) {
			return false
		}
	}
	return true
}
