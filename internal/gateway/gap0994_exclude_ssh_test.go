// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP0994ExcludedSSHAndStatusInSSHAllow: an --exclude value names what
// an archive or a copy leaves out, and git status in ~/.ssh writes nothing,
// so tar --exclude=.ssh, rsync --exclude .ssh and cd ~/.ssh && git status
// allow on the laptop and in a copy-mode actor, where both blocked
// persistence.ssh_authorized_keys_command (substrate-1 GAP-0994, RV-0922
// rows n13, n14, n20). The attack twins keep their block.
func TestGAP0994ExcludedSSHAndStatusInSSHAllow(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	rows := []struct {
		name, command string
		allow         bool
	}{
		{"n13 tar exclude eq", "tar czf /tmp/proj.tgz --exclude=.ssh src", true},
		{"n14 rsync exclude", "rsync -a --exclude .ssh src/ /tmp/b/", true},
		{"n20 cd ssh git status", "cd ~/.ssh && git status", true},
		{"tar exclude eq quoted", "tar czf /tmp/proj.tgz --exclude=\x27.ssh\x27 src", true},
		{"rsync exclude eq", "rsync -a --exclude=.ssh src/ /tmp/b/", true},
		{"a01 tar ssh", "tar czf /tmp/k.tgz .ssh", false},
		{"a02 tar exclude other ssh", "tar czf /tmp/k.tgz --exclude=.git .ssh", false},
		{"a03 rsync ssh", "rsync -a ~/.ssh/ /tmp/b/", false},
		{"a04 rsync exclude other ssh", "rsync -a --exclude .git ~/.ssh/ /tmp/b/", false},
		{"a05 cd ssh append keys", "cd ~/.ssh && echo k >> authorized_keys", false},
		{"a06 cd ssh git add", "cd ~/.ssh && git init && git add . && git commit -m k", false},
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", pack)
			home := filepath.Join(t.TempDir(), "home", "alice")
			for _, dir := range []string{"src", ".ssh"} {
				if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"),
				[]byte("-----BEGIN OPENSSH PRIVATE KEY-----\ngap0994-synthetic\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
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
			for _, row := range rows {
				la, lr := gap0304Verdict(t, api, context.Background(), home, row.command)
				ca, cr := gap0304Verdict(t, api, actor, sandboxauth.SandboxHome, row.command)
				t.Logf("GAP0994 %s %s: laptop %s %v actor %s %v", pack, row.name, la, lr, ca, cr)
				if row.allow {
					if la != "allow" || ca != "allow" {
						t.Errorf("%s: laptop %s %v, actor %s %v; want allow", row.name, la, lr, ca, cr)
					}
					continue
				}
				if la == "allow" || ca == "allow" || !strings.Contains(strings.Join(lr, " "), "persistence.") && !strings.Contains(strings.Join(lr, " "), "PATH-SSH") {
					t.Errorf("%s: laptop %s %v, actor %s %v; want both to keep the block", row.name, la, lr, ca, cr)
				}
			}
		})
	}
}
