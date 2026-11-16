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
func TestGAP0304SandboxCdChainKeepsLaptopParity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	packDir := installDefaultRulePackForDataDir(t, t.TempDir())
	pack := mustLoadRulePack(t, packDir)
	installDefaultProfileConnector(t, "claudecode")
	if err := ApplyConnectorRulePackOverrides("claudecode", pack); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(t.TempDir(), "home", "alice")
	if err := os.MkdirAll(filepath.Join(home, ".cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = packDir
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	binding := sandboxTestBinding("claudecode")
	actor := withProfilePath(withAuthenticatedHookConnector(sandboxauth.WithRequest(context.Background(), binding, nil), binding.Connector), profilePathHook)

	repeat := func(n int, unit func(int) string) string {
		var b strings.Builder
		for i := range n {
			b.WriteString(unit(i))
		}
		return b.String()
	}
	same := func(int) string { return "cd .cache && cd .. && " }
	distinct := func(i int) string { return fmt.Sprintf("cd .cache && touch f%d && cd .. && ", i) }
	settings, history := "cd .cache && echo '{}' > ../.claude/settings.json", "cd .cache && rm ../.bash_history"
	type probe struct {
		name, command string
		// limited: the actor's own reading is truncated where the laptop's
		// is not, so it alerts with the limit instead of the laptop's rules.
		limited bool
	}
	var probes []probe
	for _, n := range []int{0, 2, 15, 16, 17, 40} {
		probes = append(probes,
			probe{fmt.Sprintf("same-cd-%d settings", n), repeat(n, same) + settings, false},
			probe{fmt.Sprintf("same-cd-%d history", n), repeat(n, same) + history, false})
	}
	for _, n := range []int{2, 8, 14} {
		probes = append(probes,
			probe{fmt.Sprintf("distinct-cd-%d settings", n), repeat(n, distinct) + settings, false},
			probe{fmt.Sprintf("distinct-cd-%d history", n), repeat(n, distinct) + history, false})
	}
	// 17 distinct placed commands before the write, under the call's own
	// statement budget: past the guest reading's cap.
	probes = append(probes, probe{"distinct-placed-17 history",
		"cd .cache && " + repeat(17, func(i int) string { return fmt.Sprintf("touch f%d && ", i) }) + "rm ../.bash_history", true})

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			la, lr := gap0304Verdict(t, api, context.Background(), home, p.command)
			ca, cr := gap0304Verdict(t, api, actor, sandboxauth.SandboxHome, p.command)
			if la == "allow" {
				t.Fatalf("test setup: the laptop allows %q", p.command)
			}
			if ca == "allow" {
				t.Fatalf("copy-mode actor allows (silently) what the laptop judges %s %v", la, lr)
			}
			if p.limited {
				if !slices.Contains(cr, evaluationLimitRuleID) {
					t.Fatalf("copy-mode actor %s %v: want the evaluation-limit finding past the placement cap", ca, cr)
				}
				return
			}
			if ca != la || !slices.Equal(cr, lr) {
				t.Fatalf("copy-mode actor %s %v, laptop %s %v", ca, cr, la, lr)
			}
		})
	}
}
