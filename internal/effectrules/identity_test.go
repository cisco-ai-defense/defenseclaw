// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// DET111 S4-R3 INODE: a hard link of a protected member is the member under
// another name (rel-1-0-10:GAP-1288/1289/1317/1318). The classifier reads one
// identity per resolved target and the member identities only for a target
// with a second link. Red at a64bfdb931 (names only), green with identity.

func identityProtected(t *testing.T, cmd string, o effects.Options, fn IdentityFunc) map[string]Protection {
	t.Helper()
	res := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: cmd}, o)
	facts := Project(res, Env{Home: o.Home, Flavor: o.Flavor, Identity: fn,
		Resolve: func(p string) (string, bool) { return p, true }})
	best := map[string]Protection{}
	for _, f := range facts {
		for _, p := range Protected(f.Target) {
			if cur, ok := best[p.Set]; !ok || (cur.Certainty != "known" && p.Certainty == "known") {
				best[p.Set] = p
			}
		}
	}
	return best
}

func TestDET111R3HardLinkIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-host fixture: the authorized_keys members come from the host key reader (hookpaths.ProtectedAuthorizedKeysPaths, host separators), so a POSIX path names none of them on a Windows host, and a Windows host reads every hook call with Windows paths (gateway effectWindowsCall)")
	}
	px := effects.Options{Flavor: effects.FlavorPOSIX, Home: "/home/dcku", CWD: "/home/dcku/proj", Login: "dcku",
		Env: map[string]string{"HOME": "/home/dcku"}}
	ak, idrsa, hook := "/home/dcku/.ssh/authorized_keys", "/home/dcku/.ssh/id_rsa", "/home/dcku/.claude/settings.json"
	cases := []struct {
		name, cmd string
		fix       func() *HardLinkFixture
		set       string
		certainty string // known, maybe, or "" (no match in any set)
		reach     string
	}{
		{"GAP-1317 append to a hard link of the keys", `echo k >> keya`,
			func() *HardLinkFixture { return NewHardLinkFixture().Link("/home/dcku/proj/keya", ak) },
			SetSSHAuthorizedKeys, "known", ""},
		{"GAP-1318 copy onto a hard link of the keys", `cp x ordinary/keya`,
			func() *HardLinkFixture { return NewHardLinkFixture().Link("/home/dcku/proj/ordinary/keya", ak) },
			SetSSHAuthorizedKeys, "known", ""},
		{"GAP-1288 glob-bracket literal hard link", `cp x key[9]`,
			func() *HardLinkFixture { return NewHardLinkFixture().Link("/home/dcku/proj/key[9]", ak) },
			SetSSHAuthorizedKeys, "maybe", "R-NAME"},
		{"GAP-1288 glob-bracket literal, redirect", `echo k > key[9]`,
			func() *HardLinkFixture { return NewHardLinkFixture().Link("/home/dcku/proj/key[9]", ak) },
			SetSSHAuthorizedKeys, "maybe", "R-NAME"},
		{"GAP-1289 dd of=./key[9]", `dd if=x of=./key[9]`,
			func() *HardLinkFixture { return NewHardLinkFixture().Link("/home/dcku/proj/key[9]", ak) },
			SetSSHAuthorizedKeys, "maybe", "R-NAME"},
		{"hard link of a private key read", `cat ida`,
			func() *HardLinkFixture { return NewHardLinkFixture().Link("/home/dcku/proj/ida", idrsa) },
			SetCredentials, "known", ""},
		{"hard link of a hook config", `echo '{}' > s.json`,
			func() *HardLinkFixture { return NewHardLinkFixture().Link("/home/dcku/proj/s.json", hook) },
			SetAgentHookConfig, "known", ""},
		{"fp: hard link of another project file", `echo k >> notes.txt`,
			func() *HardLinkFixture {
				return NewHardLinkFixture().Link("/home/dcku/proj/notes.txt", "/home/dcku/proj/b.txt").File(ak)
			},
			"", "", ""},
		{"fp: glob with no literal file", `cp x key[9]`,
			func() *HardLinkFixture { return NewHardLinkFixture().File(ak) },
			"", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := identityProtected(t, c.cmd, px, c.fix().Identity)
			if c.set == "" {
				if len(got) != 0 {
					t.Fatalf("%q: %v, want no protected match", c.cmd, got)
				}
				return
			}
			p, ok := got[c.set]
			if !ok || p.Certainty != c.certainty || (c.reach != "" && p.Reach != c.reach) {
				t.Fatalf("%q: set %s = %+v (all %v), want %s %s", c.cmd, c.set, p, got, c.certainty, c.reach)
			}
		})
	}
}

// One stat per resolved target: a target with a single link never reads the
// member identities.
func TestDET111R3HardLinkSingleLinkReadsOnlyTheTarget(t *testing.T) {
	px := effects.Options{Flavor: effects.FlavorPOSIX, Home: "/home/dcku", CWD: "/home/dcku/proj",
		Env: map[string]string{"HOME": "/home/dcku"}}
	fix := NewHardLinkFixture().File("/home/dcku/proj/notes.txt", "/home/dcku/.ssh/authorized_keys")
	if got := identityProtected(t, `echo k >> notes.txt`, px, fix.Identity); len(got) != 0 {
		t.Fatalf("protected %v, want none", got)
	}
	if fix.Calls != 1 {
		t.Fatalf("identity reads %d, want 1 (the target only)", fix.Calls)
	}
}

// The default reader is the disk: a real hard link of the keys file.
func TestDET111R3HardLinkOnDisk(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home layout; the Windows reader is covered by the native Resolver run")
	}
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	ak := filepath.Join(home, ".ssh", "authorized_keys")
	for _, d := range []string{proj, filepath.Dir(ak)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(ak, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(ak, filepath.Join(proj, "keya")); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	o := effects.Options{Flavor: effects.FlavorPOSIX, Home: home, CWD: proj, Env: map[string]string{"HOME": home}}
	got := identityProtected(t, `echo k >> keya`, o, nil)
	if p := got[SetSSHAuthorizedKeys]; p.Certainty != "known" || p.Basis != "inode" {
		t.Fatalf("protected %v, want authorized_keys known by inode", got)
	}
	if got := identityProtected(t, `echo k >> other.txt`, o, nil); len(got) != 0 {
		t.Fatalf("protected %v for a new file, want none", got)
	}
}

func TestDET111R3InodeProofSurvivesSameTargetNameMaybe(t *testing.T) {
	target := func(match *semanticpb.ProtectedMatch) *semanticpb.EffectTarget {
		return &semanticpb.EffectTarget{Key: "/home/alice/project/keya", Protected: []*semanticpb.ProtectedMatch{match}}
	}
	facts := []*semanticpb.EffectFact{
		{Kind: string(effects.KindWrite), TargetState: string(effects.TargetStateKnown), RoleState: string(effects.RoleStateKnown),
			Target: target(&semanticpb.ProtectedMatch{Set: SetSSHAuthorizedKeys, State: string(gradeKnown), Reason: "inode"})},
		{Kind: string(effects.KindWrite), TargetState: string(effects.TargetStateKnown), RoleState: string(effects.RoleStateKnown),
			Target: target(&semanticpb.ProtectedMatch{Set: SetSSHAuthorizedKeys, State: string(gradeUnknown), Reason: "exact"})},
	}
	holdKnownOnNameMaybe(facts)
	if got := facts[0].GetTarget().GetProtected()[0]; got.GetState() != string(gradeKnown) || got.GetReason() != "inode" {
		t.Fatalf("resolver-proven hard-link identity was downgraded by a same-name Maybe: %+v", got)
	}
	if got := facts[1].GetTarget().GetProtected()[0]; got.GetState() != string(gradeUnknown) {
		t.Fatalf("bare-name match lost its Maybe grade beside inode proof: %+v", got)
	}
}
