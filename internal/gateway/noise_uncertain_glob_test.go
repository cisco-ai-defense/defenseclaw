// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/testenv/hlinkmatrix"
)

// A write operand that the one shell word resolver reports UNCERTAIN (a glob
// form it does not model, a glob option the call may have changed) is never a
// plain allow: the default pack alerts on it and the strict pack blocks it,
// and a form the resolver proves protected blocks in both
// (rel-1-0-10:GAP-0350, GAP-0378, GAP-0379, GAP-0380).
func TestUncertainGlobFormsAreNeverAPlainAllow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "project")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(keys), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	names := hlinkmatrix.DefaultNames()
	hlinkmatrix.Rev2Setup(t, project, keys, names, "L3")
	t.Setenv("HOME", home)
	installDefaultProfileConnector(t, "claudecode")
	checked := 0
	for _, variant := range hlinkmatrix.Rev2ClassVariants(names) {
		for name, value := range variant.Env {
			t.Setenv(name, value)
		}
		uncertain := hookpaths.NewTargetMemo().UncertainGlobWriteReason(variant.Command, project, home, nil) != ""
		if uncertain {
			checked++
			for _, strict := range []bool{false, true} {
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input:     actionfacts.Input{Tool: "Bash", Command: variant.Command, CWD: project, ActiveHome: home},
					Connector: "claudecode", EnforcementCapable: true, StrictPolicy: strict,
				})
				verdict := buildVerdict(findings, "tool_call").Action
				switch {
				case verdict == "allow":
					t.Errorf("%s strict=%v: an UNCERTAIN operand is a plain allow", variant.ID, strict)
				case strict && verdict != "block":
					t.Errorf("%s: strict pack answered %s, want block", variant.ID, verdict)
				}
			}
		}
		for name := range variant.Env {
			os.Unsetenv(name)
		}
	}
	if checked < 100 {
		t.Fatalf("only %d UNCERTAIN variants checked", checked)
	}
}
