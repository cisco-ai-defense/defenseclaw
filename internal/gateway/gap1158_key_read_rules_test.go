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

// TestGAP1158KeyReadAfterCdNamesTheLaptopRules: a private-key read after a
// cd, a pushd or a function that cds into ~/.ssh blocks on PATH-SSH-KEY on
// the laptop; the copy-mode actor gives the same verdict with the same
// rules, without an extra ACTION-COMPOUND-LIMIT (substrate-1 GAP-1158, rows
// G503a-G503c of SUB-GUEST-A).
func TestGAP1158KeyReadAfterCdNamesTheLaptopRules(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	rows := []string{
		"cd ~/.ssh && cat id_ed25519",
		"cd ~/.ssh; cat id_ed25519",
		"pushd ~/.ssh; cat id_ed25519",
		"pushd ~/.ssh && cat id_ed25519 && popd",
		"f() { cd ~/.ssh; }; f; cat id_ed25519",
		"f() { cd ~/.ssh; }; f && cat id_ed25519",
		"g() { cd ~/.ssh && cat id_ed25519; }; g",
		"cd .cache; cd ../.ssh && cat id_ed25519",
		"$CMD; cd ~/.ssh && cat id_ed25519",
		"$CMD; pushd ~/.ssh; cat id_ed25519",
		"$CMD; f() { cd ~/.ssh; }; f; cat id_ed25519",
		"cd ~/.ssh\ncat id_ed25519",
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", pack)
			home := filepath.Join(t.TempDir(), "home", "alice")
			for _, dir := range []string{".cache/sub/x", ".ssh", ".claude", ".defenseclaw"} {
				if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"),
				[]byte("-----BEGIN OPENSSH PRIVATE KEY-----\ngap1158-synthetic\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
				t.Fatal(err)
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
			for _, command := range rows {
				la, lr := gap0304Verdict(t, api, context.Background(), home, command)
				ca, cr := gap0304Verdict(t, api, actor, sandboxauth.SandboxHome, command)
				t.Logf("GAP1158 %s %q: laptop %s %v actor %s %v", pack, command, la, lr, ca, cr)
				if la == "allow" || !slices.Contains(lr, "PATH-SSH-KEY") {
					t.Errorf("%q: laptop %s %v; want a PATH-SSH-KEY block", command, la, lr)
				}
				if ca != la || !slices.Equal(cr, lr) {
					t.Errorf("%q: actor %s %v, laptop %s %v", command, ca, cr, la, lr)
				}
			}
		})
	}
}
