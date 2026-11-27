// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// DET111 S4-R3 INODE follow-ups (DET111 ruling 02:5xZ). The identity is read
// with os.Stat on the resolver's answer: a symbolic link to a hard link of a
// protected member is that member, known only when the file it lands on has a
// second link; a link to a plain project file is no member.
func TestDET111R3SymlinkToHardLinkOnDisk(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home layout; the Windows reader is covered by the native Resolver run")
	}
	home := t.TempDir()
	linked, err := WriteHardLinkHome(home, []string{".ssh/authorized_keys", "proj/copy.txt"},
		map[string]string{"proj/keya": ".ssh/authorized_keys"})
	if err != nil {
		t.Fatal(err)
	}
	if !linked {
		t.Skip("no hard links here")
	}
	proj := filepath.Join(home, "proj")
	for name, target := range map[string]string{"s": "keya", "s2": "copy.txt"} {
		if err := os.Symlink(target, filepath.Join(proj, name)); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
	}
	o := effects.Options{Flavor: effects.FlavorPOSIX, Home: home, CWD: proj, Env: map[string]string{"HOME": home}}
	protected := func(cmd string) map[string]Protection {
		res := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: cmd}, o)
		best := map[string]Protection{}
		for _, f := range Project(res, Env{Home: home, Flavor: o.Flavor}) { // the disk resolver and DiskIdentity
			for _, p := range Protected(f.Target) {
				if cur, ok := best[p.Set]; !ok || (cur.Certainty != "known" && p.Certainty == "known") {
					best[p.Set] = p
				}
			}
		}
		return best
	}
	if p := protected(`echo k >> s`)[SetSSHAuthorizedKeys]; p.Certainty != "known" || p.Basis != "inode" {
		t.Fatalf("symlink to a hard link of the keys: %+v, want authorized_keys known by inode", p)
	}
	if got := protected(`echo k >> s2`); len(got) != 0 {
		t.Fatalf("symlink to a one-link project file: %v, want none", got)
	}
}

// A call past maxIdentityStats path targets leaves the rest unread, counts
// it, and hits bounded.Paths on the call's Truncated; a call at the cap does not.
func TestDET111R3IdentityBudgetHitsTruncated(t *testing.T) {
	o := effects.Options{Flavor: effects.FlavorPOSIX, Home: "/home/dcku", CWD: "/home/dcku/proj",
		Env: map[string]string{"HOME": "/home/dcku"}}
	touch := func(n int) string {
		var b strings.Builder
		b.WriteString("touch")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, " f%d", i)
		}
		return b.String()
	}
	for _, tc := range []struct {
		n   int
		hit bool
	}{{maxIdentityStats, false}, {maxIdentityStats + 1, true}} {
		fx := NewHardLinkFixture()
		var tr bounded.Truncated
		_, _, over := IdentityCounts()
		res := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: touch(tc.n)}, o)
		Project(res, Env{Home: o.Home, Flavor: o.Flavor, Identity: fx.Identity, Truncated: &tr,
			Resolve: func(p string) (string, bool) { return p, true }})
		if fx.Calls > maxIdentityStats {
			t.Fatalf("%d targets: %d identity reads, cap %d", tc.n, fx.Calls, maxIdentityStats)
		}
		_, _, over2 := IdentityCounts()
		if got := tr.Set().Has(bounded.Paths); got != tc.hit || (over2 > over) != tc.hit {
			t.Fatalf("%d targets: Truncated paths=%v over-budget +%d, want hit=%v", tc.n, got, over2-over, tc.hit)
		}
	}
}
