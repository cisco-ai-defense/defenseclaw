// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"gopkg.in/yaml.v3"
)

// GAP-0286: a required sandbox pack of the applied config edited in place
// into one that does not load (an unbuildable network mode, an unknown key)
// is a policy that does not build, not a config to refuse: ensure, from the
// installed config and with the same config passed by --config, exits with
// config_refused, noop true and noop_reason policy_refused, names the pack
// and the reason, says nothing was applied and the running gateway keeps
// the last good policy, and leaves the generation and the gateway alone.
func TestEnsureReportsAnInPlaceEditOfARequiredSandboxPackAsPolicyRefused(t *testing.T) {
	// The profile form (a guardrail profile's own required pack, which the
	// config load refuses before the plan's pack check) resolves its pack by
	// the real path, which the rooted fixture does not map: it is the live
	// cell's (evidence/rel-1-0-6/fc-fix/sbx2/dc-ent-mac).
	for _, tc := range []struct{ goos, where string }{{"darwin", "admin"}, {"linux", "admin"}} {
		goos := tc.goos
		t.Run(goos+" "+tc.where, func(t *testing.T) {
			h := newOSHost(t, goos)
			base := sandboxConfig(t, goos, true, map[string]any{"install": "prerequisite", "driver": "docker"})
			requireOK(t, h.ensure(base))
			var doc map[string]any
			if err := yaml.Unmarshal(base, &doc); err != nil {
				t.Fatal(err)
			}
			policyDir := doc["policy_dir"].(string)
			pack := filepath.Join(policyDir, "sandbox", "r-pack", "pack.yaml")
			group := h.accounts.accounts[h.env.Layout.ServiceUser].GID
			if err := os.Chmod(h.env.P(policyDir), 0o755); err != nil {
				t.Fatal(err)
			}
			for parent := policyDir; parent != "/"; parent = filepath.Dir(parent) {
				h.owners[h.env.P(parent)] = [2]int{0, group}
			}
			for _, dir := range []string{filepath.Dir(filepath.Dir(pack)), filepath.Dir(pack)} {
				if err := os.MkdirAll(h.env.P(dir), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(h.env.P(dir), 0o750); err != nil {
					t.Fatal(err)
				}
				h.owners[h.env.P(dir)] = [2]int{0, group}
			}
			good := "version: 1\nname: r-pack\nextends: balanced\nworkspace:\n  mode: copy\nnetwork:\n  mode: allowlist\n"
			if err := os.WriteFile(h.env.P(pack), []byte(good), 0o640); err != nil {
				t.Fatal(err)
			}
			h.owners[h.env.P(pack)] = [2]int{0, group}
			doc["openshell"].(map[string]any)["pack_dir"] = filepath.Join(policyDir, "sandbox")
			if tc.where == "admin" {
				doc["openshell"].(map[string]any)["admin"] = map[string]any{"required_pack": "r-pack"}
			} else {
				// A profile's own required pack, as the live cell used: the
				// config load refuses it, not the plan's pack check.
				guard, _ := doc["guardrail"].(map[string]any)
				if guard == nil {
					guard = map[string]any{}
					doc["guardrail"] = guard
				}
				guard["profiles"] = map[string]any{"r-prof": map[string]any{"mode": "observe", "sandbox": map[string]any{"required_pack": "r-pack"}}}
			}
			window, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(h.env.P(policyDir), 0o755); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.ensure(window))
			state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct{ name, content, reason string }{
				{"unbuildable network mode", strings.Replace(good, "mode: allowlist", "mode: unbuildable", 1), "network.mode"},
				{"unknown key", good + "network_invalid_key: true\n", "network_invalid_key"},
			} {
				if err := os.WriteFile(h.env.P(pack), []byte(tc.content), 0o640); err != nil {
					t.Fatal(err)
				}
				for _, run := range []struct {
					name string
					run  func() *enterprisestatus.Result
				}{
					{"installed config", func() *enterprisestatus.Result { return h.run(Options{Action: ActionEnsure}) }},
					{"--config", func() *enterprisestatus.Result { return h.ensure(window) }},
				} {
					// As in the GAP-0546 test: the fixture's owners map gives the
					// folder the mode the service group needs.
					if err := os.Chmod(h.env.P(policyDir), 0o755); err != nil {
						t.Fatal(err)
					}
					mark := len(h.services.calls)
					r := run.run()
					requireError(t, r, codeConfigRefused)
					got := messagesOf(r.Errors, codeConfigRefused)
					for _, want := range []string{"r-pack", tc.reason, "nothing was applied", "keeps the last good policy"} {
						if !strings.Contains(got, want) {
							t.Fatalf("%s, %s: refusal %q lacks %q", tc.name, run.name, got, want)
						}
					}
					if msg := messagesOf(r.Errors, codeConfig); msg != "" {
						t.Fatalf("%s, %s: also config_invalid: %q", tc.name, run.name, msg)
					}
					if !r.Noop || r.NoopReason != "policy_refused" {
						t.Fatalf("%s, %s: noop %v (%q), want true (policy_refused)", tc.name, run.name, r.Noop, r.NoopReason)
					}
					if got, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath)); err != nil || got.Generation != state.Generation {
						t.Fatalf("%s, %s: generation moved: %+v, %v", tc.name, run.name, got, err)
					}
					for _, call := range h.services.calls[mark:] {
						if strings.Contains(call, "gateway") && (strings.HasPrefix(call, "restart ") || strings.HasPrefix(call, "stop ")) {
							t.Fatalf("%s, %s: touched the gateway: %s", tc.name, run.name, call)
						}
					}
				}
			}
			// Restored, the next ensure succeeds again.
			if err := os.WriteFile(h.env.P(pack), []byte(good), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(h.env.P(policyDir), 0o755); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionEnsure}))
		})
	}
}
