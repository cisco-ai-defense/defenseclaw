// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cdFoldRoute is one way a Bash call reaches the gateway: the Claude Code
// hook, the Codex hook (with the folder evidence its client sends) and
// /api/v1/inspect/tool (the OpenClaw exec tool).
type cdFoldRoute struct {
	name, connector string
	verdict         func(t *testing.T, a *APIServer, session, cwd, command string) string
}

var cdFoldRoutes = []cdFoldRoute{
	{"claudecode", "claudecode", func(t *testing.T, a *APIServer, session, cwd, command string) string {
		return tdOrUnknown(cdFirstVerdict(t, a, session, cwd, command))
	}},
	{"codex", "codex", func(t *testing.T, a *APIServer, session, cwd, command string) string {
		return tdOrUnknown(tdCodexVerdict(t, a, session, cwd, command))
	}},
	{"inspect", "openclaw", func(t *testing.T, a *APIServer, _, cwd, command string) string {
		action, _ := gap0437Inspect(t, a, cwd, command)["action"].(string)
		return tdOrUnknown(map[string]string{"allow": "A", "alert": "L", "block": "B"}[action])
	}},
}

// cdFoldDynamicSteps are the statements after a cd that the walk cannot
// follow (rel-1-0-10:GAP-1083, substrate-1:GAP-0367): a dynamic command
// word, eval of a variable, a shell body made at run time, here-strings
// (a syntax error to the POSIX analysis) and a cd fed one. Each may run
// anywhere; none of them moves the shell when it runs as it reads.
var cdFoldDynamicSteps = map[string]string{
	"dynamic-word": "$CMD",
	"eval-var":     `eval "$X"`,
	"bash-c-var":   `bash -c "$X"`,
	"here-string":  "bash <<< 'true'",
	"cat-here":     "cat <<< 'x'",
}

// cdFoldChain is n steps of an && chain, past the 32 steps a folder carries.
func cdFoldChain(n int) string {
	return strings.Repeat("true && ", n)
}

// TestCDFolderJudgesTheStatementsAfterADynamicStep* are rel-1-0-10:GAP-1083
// (the rel twin of substrate-1:GAP-0367). After a cd into a target's folder,
// a statement behind a dynamic step (cdFoldDynamicSteps) or past a long &&
// chain may still run in that folder, so the semantic rules judge it there
// too, as the working-folder tracking of the path facts reads it: in the 5
// tiers, on the three routes, every such form gets at least the verdict of
// the target's one-step form (the oracle, read at run time). The same holds
// for a ../ operand after a cd into a folder of the home (cd ~/.cache/d;
// ...; rm ../../.defenseclaw/...). Controls (a cd into an ordinary folder, an
// ordinary write) keep the verdict of the dynamic step alone.
func TestCDFolderJudgesTheStatementsAfterADynamicStepClaudeCode(t *testing.T) {
	cdFoldDynamicStepRows(t, cdFoldRoutes[0])
}

func TestCDFolderJudgesTheStatementsAfterADynamicStepCodex(t *testing.T) {
	cdFoldDynamicStepRows(t, cdFoldRoutes[1])
}

func TestCDFolderJudgesTheStatementsAfterADynamicStepInspect(t *testing.T) {
	cdFoldDynamicStepRows(t, cdFoldRoutes[2])
}

// cdFoldDynamicStepRows are the rows of the dynamic-step tests on one route
// (one test per route keeps each within a CI shard under -race).
func cdFoldDynamicStepRows(t *testing.T, r cdFoldRoute) {
	t.Helper()
	home, project := cdFirstFixture(t)
	for _, dir := range []string{filepath.Join(home, ".cache", "d"), filepath.Join(project, "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, r.connector, "action")
		session := "td-cdfold-" + r.name + "-" + p.name
		verdict := func(command string) string { return r.verdict(t, a, session, project, command) }
		for _, tg := range cdFirstTargets {
			oracle := verdict(tg.one)
			forms := map[string]string{"chain-33": "cd " + tg.dir + " && " + cdFoldChain(33) + tg.inner}
			for name, step := range cdFoldDynamicSteps {
				forms[name+"-newline"] = "cd " + tg.dir + "\n" + step + "\n" + tg.inner
				forms[name+"-and"] = "cd " + tg.dir + " && " + step + " && " + tg.inner
				if strings.Contains(tg.one, "~/") {
					// The same file named from a folder two below the home,
					// where the hook folder names another file.
					forms[name+"-dotdot"] = "cd ~/.cache/d\n" + step + "\n" + strings.Replace(tg.one, "~/", "../../", 1)
				}
			}
			forms["cd-here-string"] = "cd " + tg.dir + " <<< 'x'\n" + tg.inner
			for name, command := range forms {
				if got := verdict(command); cdFirstRank[got] < cdFirstRank[oracle] {
					t.Errorf("%s %s %s (%s): %q is %s, the one-step form %q is %s",
						r.name, p.name, tg.name, name, command, got, tg.one, oracle)
				}
			}
		}
		for name, step := range cdFoldDynamicSteps {
			alone := verdict(step)
			for _, control := range []string{
				"cd src\n" + step + "\necho ok > out.txt", "cd src && " + step + " && cat README.md",
				"cd ~/.cache\n" + step + "\nrm -f ../proj/build.log",
			} {
				if got := verdict(control); got != alone {
					t.Errorf("%s %s control (%s) %q is %s, the step alone is %s", r.name, p.name, name, control, got, alone)
				}
			}
		}
	}
}

// TestCDPATHFolderCurrentFolderHeadIsThePlainOne* are rel-1-0-10:GAP-1063, the
// CDPATH residual of GAP-1042: after CDPATH=<a folder the call does not
// give> cd <name>, the shell may be anywhere, so a current-folder head
// ($PWD/, ${PWD}/, "$PWD"/, $(pwd)/, `pwd`/, ~+/) before a protected
// relative operand is the plain spelling of that operand there: at least
// its verdict, which is the unknown tier (an alert in default, permissive
// and managed, a block in strict and managed-strict), in the 5 tiers and on
// the three routes. A static CDPATH reads the same way.
func TestCDPATHFolderCurrentFolderHeadIsThePlainOneClaudeCode(t *testing.T) {
	cdPathHeadRows(t, cdFoldRoutes[0])
}

func TestCDPATHFolderCurrentFolderHeadIsThePlainOneCodex(t *testing.T) {
	cdPathHeadRows(t, cdFoldRoutes[1])
}

func TestCDPATHFolderCurrentFolderHeadIsThePlainOneInspect(t *testing.T) {
	cdPathHeadRows(t, cdFoldRoutes[2])
}

// cdPathHeadRows are the rows of the CDPATH tests on one route.
func cdPathHeadRows(t *testing.T, r cdFoldRoute) {
	t.Helper()
	_, project := cdFirstFixture(t)
	dot := "."
	operands := []string{dot + "ssh/id_rsa", dot + "aws/credentials"}
	forms := []string{"cat %s", "cp %s /tmp/staged"}
	cds := []string{`CDPATH="$TD327_UNSET" cd sub && `, `CDPATH="$TD327_UNSET" cd sub; `, "CDPATH=/nonexistent-td327 cd sub && "}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, r.connector, "action")
		session := "td-cdpath-" + r.name + "-" + p.name
		tier := "L"
		if strings.Contains(p.name, "strict") {
			tier = "B"
		}
		for _, cd := range cds {
			for _, form := range forms {
				for _, operand := range operands {
					plainCommand := cd + strings.Replace(form, "%s", operand, 1)
					plain := r.verdict(t, a, session, project, plainCommand)
					if cdFirstRank[plain] < cdFirstRank[tier] {
						t.Errorf("%s %s: the plain %q is %s, want at least %s", r.name, p.name, plainCommand, plain, tier)
					}
					for _, head := range tdCurrentFolderHeads() {
						spelled := cd + strings.Replace(form, "%s", head+"/"+operand, 1)
						if got := r.verdict(t, a, session, project, spelled); cdFirstRank[got] < cdFirstRank[plain] {
							t.Errorf("%s %s: %q is %s, the plain spelling is %s", r.name, p.name, spelled, got, plain)
						}
					}
				}
			}
		}
	}
}
