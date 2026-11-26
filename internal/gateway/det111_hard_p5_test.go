// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hardP5Home is a test home holding the protected members and a project.
func hardP5Home(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for _, f := range []string{".aws/credentials", ".claude/settings.json", ".codex/config.toml",
		".defenseclaw/config.yaml", "proj/notes.txt", "proj/data.txt"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	return home
}

// hardP5Parity checks that each variant of each plain control has the
// control's action at a severity never below the control's (the effect
// lane's raise stands where no 1.0.10 reader reads the spelling, R-NOLOSS),
// and that each benign call allows, in all five tiers on both POSIX routes.
// The DefenseClaw state rule's severity is the tier's (HIGH or CRITICAL,
// GAP-0747), so a state variant may be HIGH where the control is CRITICAL.
func hardP5Parity(t *testing.T, home string, cases map[string][]string, benign []string) {
	t.Helper()
	useDefaultEffectsLane(t)
	for _, tier := range boundedTestTiers {
		for _, route := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, route, tier.posture, tier.managed, tier.tier)
			for control, variants := range cases {
				wantAction, wantSev := hardP2Verdict(t, api, route, home, control)
				if wantAction == "allow" {
					t.Fatalf("%s %s: control %q allows: the control is void", tier.name, route, control)
				}
				for _, v := range variants {
					action, sev := hardP2Verdict(t, api, route, home, v)
					if action != wantAction || hardP5SevRank(sev) < hardP5SevRank(wantSev) && (!strings.Contains(control, "/.defenseclaw/") || sev != "HIGH") {
						t.Errorf("%s %s %q: %s/%s, plain spelling %q %s/%s", tier.name, route, v, action, sev, control, wantAction, wantSev)
					}
				}
			}
			for _, command := range benign {
				if action, _ := hardP2Verdict(t, api, route, filepath.Join(home, "proj"), command); action != "allow" {
					t.Errorf("%s %s benign %q: %s, want allow", tier.name, route, command, action)
				}
			}
		}
	}
}

func hardP5SevRank(s string) int {
	return map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[strings.ToUpper(s)]
}

// TestDET111KnownProtectedDeleteIsThePlainSpelling (GAP-1478): a Python
// delete call (os.remove, os.unlink, pathlib unlink, through
// os.path.expanduser or sys.argv) on an exact member of a restricted set is
// the delete rm FILE is, and gets its verdict in all five tiers on both
// routes. At a2d6245be7 every variant was allowed: the call lowered to an
// opaque path literal. A delete of a project or temp file stays allowed.
func TestDET111KnownProtectedDeleteIsThePlainSpelling(t *testing.T) {
	home := hardP5Home(t)
	py := func(code string) string { return `python3 -c '` + code + `'` }
	cases := map[string][]string{}
	for _, target := range []string{".codex/config.toml", ".claude/settings.json", ".defenseclaw/config.yaml", ".aws/credentials"} {
		member := filepath.Join(home, target)
		cases["rm "+member] = []string{
			py(`import os;os.remove("` + member + `")`),
			py(`import os;os.unlink("` + member + `")`),
			py(`import os;os.remove(os.path.expanduser("~/` + target + `"))`),
			py(`import pathlib;pathlib.Path("` + member + `").unlink()`),
			py(`import os,sys;os.remove(sys.argv[1])`) + " " + member,
		}
	}
	benign := []string{
		py(`import os;os.remove("/tmp/x")`),
		py(`import os;os.remove("` + filepath.Join(home, "proj", "notes.txt") + `")`),
		py(`import pathlib;pathlib.Path("out.txt").unlink()`),
		py(`import os,sys;os.remove(sys.argv[1])`) + " /tmp/x",
		py(`import shutil;shutil.rmtree("/tmp/build")`),
	}
	hardP5Parity(t, home, cases, benign)
}

// TestDET111SedExecCommandIsTheCommand (GAP-1500): sed's e COMMAND runs
// COMMAND with /bin/sh, so sed '1e CMD' FILE gets the verdict of CMD alone
// in all five tiers on both routes. At a2d6245be7 a hook config write inside
// it was allowed: the command text was opaque code. A sed e command that
// changes no protected file stays allowed.
func TestDET111SedExecCommandIsTheCommand(t *testing.T) {
	home := hardP5Home(t)
	notes := filepath.Join(home, "proj", "notes.txt")
	settings := filepath.Join(home, ".claude", "settings.json")
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	cases := map[string][]string{
		"echo x > " + settings: {"sed '1e echo x > " + settings + "' " + notes, "sed -n '1e echo x > " + settings + "' " + notes},
		"touch " + settings:    {"sed '1e touch " + settings + "' " + notes},
		"cp /tmp/x " + state:   {"sed -e '1e cp /tmp/x " + state + "' " + notes},
	}
	benign := []string{
		"sed '1e echo hi' " + notes,
		"sed -n '1e date' " + notes,
		"sed '1e touch /tmp/x' " + notes,
		"sed '$e echo done > /tmp/out.txt' " + notes,
	}
	hardP5Parity(t, home, cases, benign)
}

// TestDET111BSDSedInPlaceIsSedI (GAP-1500): on a macOS host /usr/bin/sed is
// BSD sed, whose -I SUFFIX edits the file in place as GNU sed -i does: the
// in-place edit of a hook config gets the verdict of sed -i on it.
func TestDET111BSDSedInPlaceIsSedI(t *testing.T) {
	defer func(g string) { effectHostGOOS = g }(effectHostGOOS)
	effectHostGOOS = "darwin"
	home := hardP5Home(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	cases := map[string][]string{
		"sed -i s/a/b/ " + settings: {"/usr/bin/sed -I .bak p " + settings, "/usr/bin/sed -I .bak -e s/a/b/ " + settings},
	}
	benign := []string{"/usr/bin/sed -I .bak s/a/b/ " + filepath.Join(home, "proj", "notes.txt")}
	hardP5Parity(t, home, cases, benign)
}

// TestDET111UnlistedWritersAreThePlainSpelling (GAP-0506 writer half): a
// sqlite3 call that changes a DefenseClaw state database and git config
// --file or an ed script on a hook config are the writes cp onto those
// files is, and get
// its verdict in all five tiers on both routes. At a2d6245be7 both were
// allowed (sqlite3 an unknown program, git config --file unaccounted).
// Reads by the same programs and their writes of project files stay
// allowed.
func TestDET111UnlistedWritersAreThePlainSpelling(t *testing.T) {
	home := hardP5Home(t)
	audit := filepath.Join(home, ".defenseclaw", "audit.db")
	if err := os.WriteFile(audit, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	proj := filepath.Join(home, "proj")
	cases := map[string][]string{
		"cp /tmp/x " + audit: {
			"sqlite3 " + audit + " 'delete from audit_events'",
			"sqlite3 -batch " + audit + ` "insert into audit_events values('x')"`,
		},
		"cp /tmp/x " + settings: {
			"git config --file " + settings + " core.x y",
			"git config -f " + settings + " --add a.b c",
			"ed -s " + settings + " <<< $'1d\\nw\\nq'",
		},
	}
	benign := []string{
		"sqlite3 " + filepath.Join(proj, "app.db") + " 'insert into t values (1)'",
		"sqlite3 " + filepath.Join(proj, "app.db") + " 'select count(*) from t'",
		"git config --file " + filepath.Join(proj, ".gitmodules") + " submodule.x.url https://example.invalid/x",
		"git config --file " + filepath.Join(proj, ".gitmodules") + " --get submodule.x.url",
		"ed -s " + filepath.Join(proj, "notes.txt") + " <<< $'1d\\nw\\nq'",
		"ed -s " + settings + " <<< $',p\\nq'",
	}
	hardP5Parity(t, home, cases, benign)
}
