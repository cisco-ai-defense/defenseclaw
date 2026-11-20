// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A plain name past the operand bound that is another name of a protected
// file, a hard link to the keys file, is read as before the bound: it blocks
// in every tier, below the bound and above it (GAP-0943). An ordinary name in
// an ordinary folder stays the unresolved remainder that the tier decides.
func TestSecondNameOfAProtectedFilePastTheOperandBoundBlocks(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	if err := os.Link(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "hl")); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	over, within := operandWords(1100), operandWords(900)
	rows := []struct {
		name, command string
		want          string
		bound         bool // the call is past the operand bound
	}{
		{"hard link within the bound", "echo " + within + " >> hl", "block", false},
		{"hard link past the bound as a redirect", "echo " + over + " >> hl", "block", true},
		{"hard link past the bound as an operand", "tee " + over + " hl", "block", true},
		{"ordinary folder past the bound", "touch " + over + " sub/f1 sub/f2", "alert", true},
		{"missing folder past the bound", "touch " + over + " none/f1", "alert", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			defer hookpaths.HookCall()()
			request := trustedActionRequest{
				Input: actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home,
					DialectHint: actionfacts.DialectPOSIX},
				Connector: "claudecode", EnforcementCapable: true,
			}
			findings := dispatchTrustedAction(withShareBodyStrict(t.Context(), func() bool { return false }), request)
			if got := operandBoundTierAction(findings, false); got != row.want {
				t.Errorf("%s, want %s; findings %v", got, row.want, findings)
			}
			alert := slices.ContainsFunc(findings, operandBoundTruncated)
			if alert != row.bound {
				t.Errorf("bound alert %v, want %v", alert, row.bound)
			}
		})
	}
}
