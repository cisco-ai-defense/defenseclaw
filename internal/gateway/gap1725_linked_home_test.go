// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-1725 on the gateway route: a home below a linked directory with no
// ~/.ssh yet. Creating ~/.ssh/authorized_keys is the SSH rule in action mode.
func TestR105LinkedHomeKeyFileBeforeItExists(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(real, "h", "project"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "link", "h")
	cwd := filepath.Join(home, "project")
	for command, want := range map[string]bool{
		"echo k >> ~/.ssh/authorized_keys":                    true,
		"mkdir -p ~/.ssh && echo k >> ~/.ssh/authorized_keys": true,
		"echo k >> notes.txt":                                 false,
	} {
		args, _ := json.Marshal(map[string]string{"command": command})
		input := actionfacts.Input{Tool: "Bash", Args: args, Command: command, CWD: cwd, ActiveHome: home}
		findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
			Input: input, LegacyText: string(args), Connector: "claudecode", EnforcementCapable: true,
		})
		got := false
		for _, finding := range findings {
			if finding.RuleID == "persistence.ssh_authorized_keys_command" && finding.contributesToEnforcement() {
				got = true
			}
		}
		if got != want {
			t.Errorf("%q: SSH rule = %t, want %t (%v)", command, got, want, findingIDs(findings))
		}
	}
}
