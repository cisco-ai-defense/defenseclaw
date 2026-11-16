// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"gopkg.in/yaml.v3"
)

// GAP-0546: a required pack that the gateway cannot load is a bad candidate,
// not a config to commit and then recover from after a gateway restart.
func TestEnsureRefusesUnloadableRequiredSandboxPackBeforeActivation(t *testing.T) {
	h := newOSHost(t, "darwin")
	base := sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite", "driver": "docker"})
	requireOK(t, h.ensure(base))
	state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(base, &doc); err != nil {
		t.Fatal(err)
	}
	policyDir := doc["policy_dir"].(string)
	pack := filepath.Join(policyDir, "sandbox", "t6-pack", "pack.yaml")
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
	for _, tc := range []struct{ name, content, field, ref string }{
		{"missing version by path", "name: t6-pack\nextends: balanced\n", "version", pack},
		{"missing name by path", "version: 1\nextends: balanced\n", "name", pack},
		{"missing version by name", "name: t6-pack\nextends: balanced\n", "version", "t6-pack"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc["openshell"].(map[string]any)["pack_dir"] = filepath.Join(policyDir, "sandbox")
			doc["openshell"].(map[string]any)["admin"] = map[string]any{"required_pack": tc.ref}
			candidate, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(h.env.P(policyDir), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(pack), []byte(tc.content), 0o640); err != nil {
				t.Fatal(err)
			}
			h.owners[h.env.P(pack)] = [2]int{0, group}
			mark := len(h.services.calls)
			r := h.ensure(candidate)
			requireError(t, r, codeConfig)
			if got := messagesOf(r.Errors, codeConfig); !strings.Contains(got, "required sandbox pack") || !strings.Contains(got, tc.field) {
				t.Fatalf("config refusal = %q", got)
			}
			if got, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath)); err != nil || got.Generation != state.Generation {
				t.Fatalf("failed ensure changed generation: %+v, %v", got, err)
			}
			for _, call := range h.services.calls[mark:] {
				if strings.Contains(call, "gateway") && (strings.HasPrefix(call, "restart ") || strings.HasPrefix(call, "stop ")) {
					t.Errorf("failed ensure touched the gateway: %s", call)
				}
			}
		})
	}
	// A repaired pack is accepted on the next ensure.
	if err := os.WriteFile(h.env.P(pack), []byte("version: 1\nname: t6-pack\nextends: balanced\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.env.P(policyDir), 0o755); err != nil {
		t.Fatal(err)
	}
	doc["openshell"].(map[string]any)["admin"] = map[string]any{"required_pack": "t6-pack"}
	candidate, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.ensure(candidate))
}

// A pack required only by a profile still becomes the floor for that account.
// Planning must load it even when the base administrator floor has no pack.
func TestEnsurePreflightLoadsProfileRequiredSandboxPacks(t *testing.T) {
	e := &Env{Root: t.TempDir()}
	packDir := "/var/lib/defenseclaw/policies/sandbox"
	pack := filepath.Join(e.P(packDir), "broken", "pack.yaml")
	if err := os.MkdirAll(filepath.Dir(pack), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pack, []byte("name: broken\nextends: balanced\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		OpenShell: config.OpenShellConfig{PackDir: packDir},
		Guardrail: config.GuardrailConfig{Profiles: map[string]config.GuardrailProfile{
			"restricted": {Sandbox: &config.OpenShellAdminConfig{RequiredPack: "broken"}},
		}},
	}
	if err := e.checkRequiredSandboxPacks(cfg); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("profile pack preflight = %v, want malformed-pack refusal", err)
	}
}
