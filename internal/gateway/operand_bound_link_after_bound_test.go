// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestNamedProtectedLinkPastTheOperandBoundBlocks(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	ordinary := strings.Repeat("f ", 1024)
	for _, row := range []struct{ name, command string }{
		{"within bound", "echo " + strings.Repeat("f ", 1023) + ">> alias"},
		{"redirect past bound", "echo " + ordinary + ">> alias"},
		{"descriptor then redirect", "echo " + ordinary + "2>/dev/null >> alias"},
		{"write operand past bound", "tee " + ordinary + "alias"},
		{"later statement", "touch " + ordinary + "; echo x >> alias"},
	} {
		t.Run(row.name, func(t *testing.T) {
			defer hookpaths.HookCall()()
			request := trustedActionRequest{
				Input: actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home,
					DialectHint: actionfacts.DialectPOSIX},
				Connector: "claudecode", EnforcementCapable: true,
			}
			findings := dispatchTrustedAction(withShareBodyStrict(t.Context(), func() bool { return false }), request)
			if got := buildVerdict(findings, "tool_call").Action; got != "block" {
				t.Errorf("named protected link: %s; findings: %v", got, findings)
			}
		})
	}
}

func TestShellEscapedProtectedNamePastTheOperandBoundBlocks(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	// Bash removes each backslash, so this is ../.ssh/authorized_keys.
	escaped := `\.\./.\s\s\h/\a\u\t\h\o\r\i\z\e\d_\k\e\y\s`
	for _, row := range []struct{ name, command string }{
		{"within bound", "echo x " + strings.Repeat("f ", 900) + ">> " + escaped},
		{"past bound", "echo x " + strings.Repeat("f ", 1024) + ">> " + escaped},
		{"past bound as operand", "tee " + strings.Repeat("f ", 1024) + escaped},
	} {
		t.Run(row.name, func(t *testing.T) {
			defer hookpaths.HookCall()()
			request := trustedActionRequest{
				Input: actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home,
					DialectHint: actionfacts.DialectPOSIX},
				Connector: "claudecode", EnforcementCapable: true,
			}
			findings := dispatchTrustedAction(withShareBodyStrict(t.Context(), func() bool { return false }), request)
			if got := buildVerdict(findings, "tool_call").Action; got != "block" {
				t.Errorf("escaped direct protected path: %s; findings: %v", got, findings)
			}
		})
	}
}
