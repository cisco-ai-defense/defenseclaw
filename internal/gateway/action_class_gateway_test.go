// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestR104ActionClassWrappedProtectedTargets(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(cwd, "dirlink")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		blocked       bool
	}{
		{"busybox tee", `busybox tee -a alias`, true},
		{"time cp", `time cp payload alias`, true},
		{"tar into protected directory", `tar -C dirlink -xf keys.tar authorized_keys`, true},
		{"ln into protected directory", `ln -sf report.txt dirlink/authorized_keys`, true},
		{"busybox ordinary", `busybox tee -a report.txt`, false},
		{"time ordinary", `time cp payload report.txt`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, got := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if got != tc.blocked {
					t.Fatalf("route %d blocked=%t, want %t", i, got, tc.blocked)
				}
			}
		})
	}
}

func TestR104LeadGap0531HomePrivateKeyRead(t *testing.T) {
	const connector = "r104-gap-0531"
	installToolCallCorpusProfileConnector(t, connector, "default")
	home, cwd := r104ReviewHome(t)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`cat "$HOME/.ssh/id_ed25519"`,
		`cat ${HOME}/.ssh/id_ed25519`,
		`cat ~/.ssh/id_ed25519; echo done`,
		`head -c 0 ~/.ssh/id_ed25519; echo done`,
		`echo hi; cat "$HOME/.ssh/id_ed25519"`,
	} {
		t.Run(command, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"command": command})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: "Bash", Args: args, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, LegacyText: string(args), Connector: connector, EnforcementCapable: true})
			if buildVerdict(findings, "tool_call").Action != guardrailActionBlock {
				t.Fatalf("GAP-0531 private-key read allowed: %v", findingIDs(findings))
			}
		})
	}
}
