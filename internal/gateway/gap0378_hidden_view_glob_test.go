// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A glob operand of a writer in a folder this gateway cannot see (the working
// folder is not there for it: a cd target, a replayed session) is judged by
// the protected-target readers as on rel/1.0.10, not as an unproven
// authorized-keys write: reading every such word as uncertain blocked plain
// builds and edits in the default pack (rel-1-0-10:GAP-0378, the owner A/B of
// s7/hlinkport-r2 bf8dc50428: +135 default blocks on the held-out set). A
// pattern that names a key file is still never a plain allow. In a folder the
// gateway sees, a word the resolver cannot expand exactly (a sourced file
// that may change the glob options, an extglob search pattern) is no
// unproven write when a reading wider than any bash may take names no
// protected file (the A/B round 2 of d062b88bd2: +8 / +5), and stays never a
// plain allow when it names a hard link to the keys.
func TestGAP0378HiddenViewGlobOperandIsNoAuthorizedKeysWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX glob walk")
	}
	home := filepath.Join(t.TempDir(), "home")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	installDefaultProfileConnector(t, "claudecode")
	gone := filepath.Join(home, "work", "not-here")
	seen := filepath.Join(home, "work", "here")
	linked := filepath.Join(home, "work", "linked")
	for _, dir := range []string{seen, linked} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(keys, filepath.Join(linked, "notes.txt")); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	for _, row := range []struct {
		command, cwd string
		ak           bool
	}{
		{"rm -f build/*.o", gone, false},
		{"chmod 644 docs/*.md", gone, false},
		{"mv notes/*.txt archive/", gone, false},
		{"rm -f [[:alpha:]]*.o", gone, false},
		{"cp key.pub ../../.ssh/authorized_k*", gone, true},
		{"source ./env.sh; chmod 644 cfg/*", seen, false},
		{"rg -n abc.*(x|y) logs | tail -3", seen, false},
		{"source ./env.sh; chmod 644 *.txt", linked, true},
		{"list=[3-m,x-y] true", seen, false},
	} {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:     actionfacts.Input{Tool: "Bash", Command: row.command, CWD: row.cwd, ActiveHome: home},
			Connector: "claudecode", EnforcementCapable: true,
		})
		ak := false
		for _, finding := range findings {
			ak = ak || finding.RuleID == "persistence.ssh_authorized_keys_command"
		}
		verdict := buildVerdict(findings, "tool_call").Action
		switch {
		case !row.ak && ak:
			t.Errorf("%q in %s: authorized-keys finding (%s), want none", row.command, filepath.Base(row.cwd), verdict)
		case row.ak && verdict == "allow":
			t.Errorf("%q: a pattern that may name a key file is a plain allow", row.command)
		}
	}
}
