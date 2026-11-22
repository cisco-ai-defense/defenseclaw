// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// restrictedSpecPrograms are the programs testdata/flagspec_restricted.tsv must
// cover per platform (rel-1-0-10 GAP-0219): the restricted-tier POSIX programs and
// the siblings that shared a row with them.
var restrictedSpecPrograms = map[string][]string{
	"gnu": {"cp", "install", "mv", "ln", "rm", "unlink", "shred", "tee"},
	"bsd": {"cp", "install", "mv", "ln", "rm", "unlink", "tee", "sed"},
}

type restrictedSpecFlag struct {
	arity    int
	optional bool // arity "opt" (GAP-0216)
	effect   string
}

func loadRestrictedFlagSpec(t *testing.T) map[string]map[string]map[string]restrictedSpecFlag {
	t.Helper()
	f, err := os.Open("testdata/flagspec_restricted.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	spec := map[string]map[string]map[string]restrictedSpecFlag{"gnu": {}, "bsd": {}}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 5 {
			t.Fatalf("line %d: %d columns, want 5", n, len(cols))
		}
		prog, plat, flag, eff := cols[0], cols[1], cols[2], cols[4]
		opt := cols[3] == "opt"
		ar, err := strconv.Atoi(cols[3])
		if opt {
			ar, err = 0, nil
		}
		if err != nil || (ar != 0 && ar != 1) {
			t.Fatalf("line %d: arity %q", n, cols[3])
		}
		if spec[plat] == nil {
			t.Fatalf("line %d: platform %q", n, plat)
		}
		if spec[plat][prog] == nil {
			spec[plat][prog] = map[string]restrictedSpecFlag{}
		}
		if _, dup := spec[plat][prog][flag]; dup {
			t.Fatalf("line %d: %s %s %s listed twice", n, plat, prog, flag)
		}
		spec[plat][prog][flag] = restrictedSpecFlag{arity: ar, optional: opt, effect: eff}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return spec
}

func restrictedFlagEffect(fl Flag) string {
	switch fl.Role {
	case RoleWrite, RoleOutput:
		return "output"
	case RoleLink:
		return "link"
	case RoleNone, RoleIgnore:
		return "inert"
	}
	return "role:" + string(fl.Role)
}

func TestRestrictedFlagSpecMatchesTables(t *testing.T) {
	spec := loadRestrictedFlagSpec(t)
	for plat, progs := range restrictedSpecPrograms {
		for _, prog := range progs {
			p, ok := lookupProgram(prog, FlavorPOSIX, DialectPOSIX, plat == "bsd")
			if !ok {
				t.Errorf("%s %s: no table row", plat, prog)
				continue
			}
			if len(p.Names) != 1 || p.Names[0] != prog {
				t.Errorf("%s %s: row shared with %v (one row per program)", plat, prog, p.Names)
			}
			want := spec[plat][prog]
			for name, sf := range want {
				fl, ok := p.Flags[name]
				if !ok {
					t.Errorf("%s %s %s: reviewed in the spec but missing from the table", plat, prog, name)
					continue
				}
				ar := 0
				if fl.Value {
					ar = 1
				}
				if ar != sf.arity || fl.Optional != sf.optional || restrictedFlagEffect(fl) != sf.effect {
					t.Errorf("%s %s %s: table arity %d optional=%v effect %s, spec %d optional=%v %s", plat, prog, name, ar, fl.Optional, restrictedFlagEffect(fl), sf.arity, sf.optional, sf.effect)
				}
			}
			for name := range p.Flags {
				if _, ok := want[name]; !ok {
					t.Errorf("%s %s %s: in the table but not reviewed in testdata/flagspec_restricted.tsv", plat, prog, name)
				}
			}
		}
		for prog := range spec[plat] {
			found := false
			for _, q := range progs {
				found = found || q == prog
			}
			if !found {
				t.Errorf("%s %s: in the spec but not a covered program", plat, prog)
			}
		}
	}
	// Every BSD row is one of the covered programs, and the BSD rows are used
	// only when the caller says the host runs the BSD tools.
	for name := range bsdTable {
		found := false
		for _, q := range restrictedSpecPrograms["bsd"] {
			found = found || q == name
		}
		if !found {
			t.Errorf("bsd row %s is not covered by the spec", name)
		}
	}
	if p, _ := lookupProgram("cp", FlavorPOSIX, DialectPOSIX, false); p.Flags["-t"].Role != RoleWrite {
		t.Errorf("GNU cp lost -t")
	}
	if p, _ := lookupProgram("cp", FlavorWindows, DialectPOSIX, true); p.Flags["-t"].Role != RoleWrite {
		t.Errorf("Git Bash (Windows flavor) must use GNU cp")
	}
}
