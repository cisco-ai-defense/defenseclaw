// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"
)

// TestDET111MetadataOnlyProgramsCarryNoContentRead (DET111 ruling 3a; the
// sweep T17 stat row of GAP-1825/1826): stat, du, df, file, readlink,
// realpath and find report metadata or names, never a file's bytes, so a
// credential operand is accounted (the command stays fully known) but no
// read effect names it. The controls keep their effects: cat still reads,
// and find -delete still deletes below its root.
func TestDET111MetadataOnlyProgramsCarryNoContentRead(t *testing.T) {
	o := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj"}
	run := func(cmd string) Result {
		return Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: cmd, Workdir: o.CWD}, o)
	}
	has := func(r Result, k Kind, sub string) bool {
		for _, e := range r.Effects {
			if e.Kind == k && strings.Contains(e.Target.Path, sub) {
				return true
			}
		}
		return false
	}
	for _, cmd := range []string{
		"stat /home/u/.docker/config.json",
		"stat -c %s /home/u/.ssh/id_ed25519",
		"du -sh /home/u/.aws/credentials",
		"df /home/u/.ssh",
		"file /home/u/.ssh/id_ed25519",
		"readlink -f /home/u/.ssh/id_ed25519",
		"realpath /home/u/.aws/credentials",
		"find /home/u/.ssh -name id_ed25519",
		"ls -l /home/u/.ssh/id_ed25519",
		"test -f /home/u/.ssh/id_ed25519",
		"[ -r /home/u/.aws/credentials ]",
	} {
		r := run(cmd)
		for _, e := range r.Effects {
			if e.Kind == KindRead {
				t.Errorf("%q: read effect on %q, want none (metadata only)\n%s", cmd, e.Target.Path, fmtRes(r))
			}
		}
	}
	for _, c := range []struct {
		cmd  string
		kind Kind
		sub  string
	}{
		{"cat /home/u/.docker/config.json", KindRead, "/.docker/config.json"},
		{"find /home/u/.ssh -name id_ed25519 -delete", KindDelete, "/.ssh"},
	} {
		if r := run(c.cmd); !has(r, c.kind, c.sub) {
			t.Errorf("%q: no %s effect on %q (control)\n%s", c.cmd, c.kind, c.sub, fmtRes(r))
		}
	}
	if r := run("stat /home/u/.docker/config.json"); !r.FullyKnown() {
		t.Errorf("stat of a static path is not fully known (the operand must stay accounted)\n%s", fmtRes(r))
	}
}
