// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"hash/fnv"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func overLimitCommandVerdict(t *testing.T, home, project, command string) string {
	t.Helper()
	call := nativeWriteCall{"codex", "exec_command", func(string) map[string]any {
		return map[string]any{"cmd": command, "workdir": project}
	}}
	return overLimitHostHook(t, "codex", home, call.body(t, project, project))
}

// overLimitLevels are the two size bounds a padded command is judged past:
// the string limit of the command text (64 KiB) and the limit of the whole
// argument envelope (256 KiB, counted after JSON escaping, with 1 KiB left for
// the envelope). A pad is the shortest run that crosses its bound, so a row
// costs what its bound needs and no more: the cost of a verdict grows with the
// size of the text it reads.
var overLimitLevels = []struct {
	name  string
	limit int
	json  bool
}{
	{"command", 64 << 10, false},
	{"arguments", 256<<10 + 1<<10, true},
}

// overLimitRun is the shortest run of unit that takes a command of base bytes
// past the bound of overLimitLevels[level].
func overLimitRun(unit string, level, base int) string {
	size := len(unit)
	if overLimitLevels[level].json {
		size += strings.Count(unit, "\n")
	}
	return strings.Repeat(unit, max((overLimitLevels[level].limit-base)/size+1, 1))
}

// overLimitCommandVerdictPast is overLimitCommandVerdict for a command that is
// past the command limit: a row that is padded too little is judged by the
// ordinary path and proves nothing about the limit.
func overLimitCommandVerdictPast(t *testing.T, home, project, command string) string {
	t.Helper()
	if !actionfacts.CommandTextOverLimit(command) {
		t.Fatalf("a command of %d bytes is not past the command limit", len(command))
	}
	return overLimitCommandVerdict(t, home, project, command)
}

// overLimitShare reports whether the row named name belongs to the part-th of
// parts shares of a test, so that the rows of one pin can be several tests.
// The share is a function of the name alone, whatever the order of the rows.
func overLimitShare(name string, part, parts int) bool {
	sum := fnv.New32a()
	_, _ = sum.Write([]byte(name))
	return int(sum.Sum32()%uint32(parts)) == part
}

// overLimitDataText is the data a padded statement carries: the shortest text
// that takes the statement past the command limit, whatever wraps it.
func overLimitDataText(statement string) string {
	return strings.Repeat("x", overLimitLevels[0].limit+1-len(statement))
}

// The padding tests below pin that a shell command padded with white space
// past the 64 KiB command limit keeps the verdict of the same command unpadded
// (GAP-0934): the loader-preload and sudoers proofs read the protected
// redirect at every padding, before it, inside it and after it. The same
// padding on an ordinary command stays allowed. Each protected redirect is a
// test of its own, so no test is longer than the CI budget of one.
var overLimitPaddingCases = []struct{ name, head, tail, rule string }{
	{"ld.so.preload redirect", "echo /usr/local/lib/libreview.so", " > /etc/ld.so.preload", "persistence.global_ld_preload_install"},
	{"ld.so.preload tee", "echo /usr/local/lib/libreview.so |", " tee -a /etc/ld.so.preload", "persistence.global_ld_preload_install"},
	{"sudoers", "echo 'agent ALL=(ALL) NOPASSWD: ALL'", " > /etc/sudoers.d/agent", "privilege.sudoers_unrestricted_nopasswd"},
}

func TestOverLimitCommandPaddingKeepsItsVerdictForPreloadRedirect(t *testing.T) {
	paddingKeepsItsVerdict(t, 0)
}

func TestOverLimitCommandPaddingKeepsItsVerdictForPreloadTee(t *testing.T) {
	paddingKeepsItsVerdict(t, 1)
}

func TestOverLimitCommandPaddingKeepsItsVerdictForSudoers(t *testing.T) {
	paddingKeepsItsVerdict(t, 2)
}

func TestOverLimitCommandPaddingKeepsOrdinaryCommandsAllowed(t *testing.T) {
	paddingKeepsItsVerdict(t, len(overLimitPaddingCases))
}

// paddingKeepsItsVerdict runs the protected redirect number part of
// overLimitPaddingCases, or (past the last) the ordinary commands.
func paddingKeepsItsVerdict(t *testing.T, part int) {
	home, project := hermesPatchHome(t)
	for index, c := range overLimitPaddingCases {
		if index != part {
			continue
		}
		unpadded := overLimitCommandVerdict(t, home, project, c.head+c.tail)
		if overLimitHookAction(t, unpadded) != "block" || !strings.Contains(unpadded, c.rule) {
			t.Fatalf("%s: the unpadded command is not blocked by %s: %.600s", c.name, c.rule, unpadded)
		}
		base := len(c.head + c.tail)
		for level, bound := range overLimitLevels {
			spaces, lines := overLimitRun(" ", level, base), overLimitRun("\n  \n", level, base)
			for position, command := range map[string]string{
				"leading":  spaces + c.head + c.tail,
				"inner":    c.head + spaces + c.tail,
				"trailing": c.head + c.tail + spaces,
				"lines":    c.head + c.tail + lines,
			} {
				t.Run(fmt.Sprintf("%s/pad past the %s limit %s", c.name, bound.name, position), func(t *testing.T) {
					t.Parallel()
					got := overLimitCommandVerdictPast(t, home, project, command)
					if overLimitHookAction(t, got) != "block" || !strings.Contains(got, c.rule) {
						t.Fatalf("not blocked by %s: %.600s", c.rule, got)
					}
				})
			}
		}
	}
	if part != len(overLimitPaddingCases) {
		return
	}
	ordinary := filepath.Join(project, "notes.txt")
	const arguments = 1
	run := func(unit string, base int) string { return overLimitRun(unit, arguments, base) }
	for name, command := range map[string]string{
		"ordinary redirect":  "echo ok > " + ordinary + run(" ", len("echo ok > "+ordinary)),
		"inner padding":      "echo ok" + run(" ", len("echo ok> "+ordinary)) + "> " + ordinary,
		"protected read":     "cat /etc/ld.so.preload /etc/passwd" + run(" ", len("cat /etc/ld.so.preload /etc/passwd")),
		"leading line break": run("\n", len("echo ok > "+ordinary)) + "echo ok > " + ordinary,
	} {
		t.Run("benign/"+name, func(t *testing.T) {
			t.Parallel()
			got := overLimitCommandVerdictPast(t, home, project, command)
			if action := overLimitHookAction(t, got); action == "block" {
				t.Fatalf("ordinary padded command blocked: %.600s", got)
			}
		})
	}
}

// TestOverLimitCommandOpaqueTextFailsClosedForItsTargetOnly pins the verdict
// of a command over the 64 KiB limit by text (GAP-0934). Padded with
// comments it is judged as the same command without them, as every rule
// judges the small command: a statement that is blocked small is blocked
// large, one that is allowed small is allowed large, and a protected file
// named in a comment or in data is no write. Padded with text that is data
// (a quoted string, a here-document body), which has no twin, a protected
// file named directly as the target of a write still blocks under every
// spelling, and an ordinary command of the same size stays allowed.
func TestOverLimitCommandOpaqueTextFailsClosedForItsTargetOnly(t *testing.T) {
	opaqueText(t, true, 0)
}

// TestOverLimitCommandOpaqueTextFailsClosedForItsTargetOnlyPart2 is the second
// half of the pin above.
func TestOverLimitCommandOpaqueTextFailsClosedForItsTargetOnlyPart2(t *testing.T) {
	opaqueText(t, true, 1)
}

// TestOverLimitCommandOpaqueTextKeepsOrdinaryCommandsAllowed is the ordinary
// half of the pin above, a test of its own for the CI budget of one.
func TestOverLimitCommandOpaqueTextKeepsOrdinaryCommandsAllowed(t *testing.T) {
	opaqueText(t, false, 0)
}

// opaqueText runs the protected statements (attacks) or the ordinary ones.
func opaqueText(t *testing.T, attacks bool, part int) {
	home, project := hermesPatchHome(t)
	lib := "/usr/local/lib/libreview.so"
	paddings := map[string]func(statement string) string{
		"comment after":      func(statement string) string { return statement + " # " + overLimitDataText(statement) },
		"comment line next":  func(statement string) string { return statement + "\n# " + overLimitDataText(statement) },
		"comment line first": func(statement string) string { return "# " + overLimitDataText(statement) + "\n" + statement },
		"quoted text after":  func(statement string) string { return statement + "\n: \x27" + overLimitDataText(statement) + "\x27" },
		"quoted text first":  func(statement string) string { return ": \x27" + overLimitDataText(statement) + "\x27\n" + statement },
		"document after": func(statement string) string {
			return statement + "\ncat > /dev/null <<EOF\n" + overLimitDataText(statement) + "\nEOF\n"
		},
		"stray quote before": func(statement string) string {
			return "cat <<EOF\nit\x27s\nEOF\n" + statement + "\n: \x27" + overLimitDataText(statement) + "\x27"
		},
	}
	if attacks {
		for name, statement := range map[string]string{
			"redirect":         "echo " + lib + " > /etc/ld.so.preload",
			"dot segment":      "echo " + lib + " > /etc/./ld.so.preload",
			"double slash":     "echo " + lib + " >//etc//ld.so.preload",
			"quoted name":      "echo " + lib + " > \"/etc/ld.so.preload\"",
			"variable":         "F=/etc/ld.so.preload; echo " + lib + " > $F",
			"cd then relative": "cd /etc && echo " + lib + " > ld.so.preload",
		} {
			for padName, pad := range paddings {
				if !overLimitShare("attack/"+name+"/"+padName, part, 2) {
					continue
				}
				t.Run("attack/"+name+"/"+padName, func(t *testing.T) {
					t.Parallel()
					got := overLimitCommandVerdictPast(t, home, project, pad(statement))
					if overLimitHookAction(t, got) != "block" || !strings.Contains(got, "persistence.global_ld_preload_install") {
						t.Fatalf("not blocked by the preload rule: %.600s", got)
					}
				})
			}
		}
		// Only a fallback reading, which has no twin, reads a write that the
		// small command does not show: the statements below are the same call
		// blocked small and large when they are padded with data.
		for name, statement := range map[string]string{
			"copy":    "cp " + lib + " /etc/ld.so.preload",
			"install": "install -m 644 " + lib + " /etc/ld.so.preload",
			"sudoers": "echo \x27agent ALL=(ALL) NOPASSWD: ALL\x27 > /etc/sudoers.d/agent",
		} {
			for _, padName := range []string{"quoted text after", "quoted text first"} {
				if !overLimitShare("fallback attack/"+name+"/"+padName, part, 2) {
					continue
				}
				t.Run("fallback attack/"+name+"/"+padName, func(t *testing.T) {
					t.Parallel()
					got := overLimitCommandVerdictPast(t, home, project, paddings[padName](statement))
					if overLimitHookAction(t, got) != "block" {
						t.Fatalf("not blocked: %.600s", got)
					}
				})
			}
		}
		return
	}
	notes := filepath.Join(project, "notes.txt")
	for name, statement := range map[string]string{
		"heredoc to an ordinary file": "cat > " + filepath.Join(project, "big.txt") + " <<\x27EOF\x27\nnote\nEOF\n",
		"protected read":              "cat /etc/ld.so.preload",
		"ordinary redirect":           "echo ok > " + notes,
		"unknown variable":            "echo ok > $OUT",
		"copy from a protected file":  "cp /etc/ld.so.preload " + filepath.Join(project, "copy.txt"),
		"neighbour name":              "echo ok > /etc/ld.so.preload.bak",
		"relative in the project":     "cd " + project + " && echo ok > ld.so.preload",
		"attack named in a string":    "printf \x27%s\\n\x27 \x27" + lib + " > /etc/ld.so.preload\x27 > " + notes,
		"attack named in a document":  "cat > " + notes + " <<\x27EOF\x27\n" + lib + " > /etc/ld.so.preload\nEOF\n",
	} {
		for _, padName := range []string{"comment after", "comment line next", "comment line first"} {
			t.Run("benign/"+name+"/"+padName, func(t *testing.T) {
				t.Parallel()
				got := overLimitCommandVerdictPast(t, home, project, paddings[padName](statement))
				if action := overLimitHookAction(t, got); action == "block" {
					t.Fatalf("ordinary oversize command blocked: %.600s", got)
				}
			})
		}
	}
	for name, statement := range map[string]string{
		"protected read":    "cat /etc/ld.so.preload",
		"ordinary redirect": "echo ok > " + notes,
		"unknown variable":  "echo ok > $OUT",
	} {
		for _, padName := range []string{"quoted text after", "document after"} {
			t.Run("benign data padded/"+name+"/"+padName, func(t *testing.T) {
				t.Parallel()
				got := overLimitCommandVerdictPast(t, home, project, paddings[padName](statement))
				if action := overLimitHookAction(t, got); action == "block" {
					t.Fatalf("ordinary oversize command blocked: %.600s", got)
				}
			})
		}
	}
}

// TestOverLimitCommandPaddingKeepsHeredocMeaning pins that padding a here-
// document line with white space does not change which line ends the
// document, so the statement the shell runs stays the statement judged: the
// padded delimiter line is not a delimiter in the original and not in the
// twin, and the redirect below it is the document text, not a command
// (GAP-0934). A real delimiter followed by the redirect blocks.
func TestOverLimitCommandPaddingKeepsHeredocMeaning(t *testing.T) {
	home, project := hermesPatchHome(t)
	notes := filepath.Join(project, "notes.txt")
	attack := "echo /usr/local/lib/libreview.so > /etc/ld.so.preload"
	for name, command := range map[string]string{
		"trailing padded delimiter": "cat > " + notes + " <<EOF\nnote\nEOF" + overLimitRun(" ", 0, len(notes)+len(attack)) + "\n" + attack + "\nEOF\n",
		"leading padded delimiter":  "cat > " + notes + " <<EOF\nnote\n" + overLimitRun(" ", 0, len(notes)+len(attack)) + "EOF\n" + attack + "\nEOF\n",
		"tab padded dash delimiter": "cat > " + notes + " <<-EOF\nnote\n" + overLimitRun("\t", 0, len(notes)) + "EOF\nEOF\n",
		"padded line in a document": "cat > " + notes + " <<EOF\nnote" + overLimitRun(" ", 0, len(notes)+len(attack)) + "\n" + attack + "\nEOF\n",
	} {
		t.Run("benign/"+name, func(t *testing.T) {
			t.Parallel()
			got := overLimitCommandVerdictPast(t, home, project, command)
			if action := overLimitHookAction(t, got); action == "block" {
				t.Fatalf("ordinary here-document blocked: %.600s", got)
			}
		})
	}
	t.Run("attack/delimiter then redirect", func(t *testing.T) {
		t.Parallel()
		got := overLimitCommandVerdictPast(t, home, project, "cat > "+notes+" <<EOF\nnote\nEOF\n"+attack+overLimitRun(" ", 0, len(notes)+len(attack)))
		if overLimitHookAction(t, got) != "block" || !strings.Contains(got, "persistence.global_ld_preload_install") {
			t.Fatalf("not blocked by the preload rule: %.600s", got)
		}
	})
}

// The data padding tests pin that a command padded
// with data (a quoted string) is read in the order the shell runs it
// (GAP-0934): a later cd or assignment replaces the earlier one, the body of a
// here-document that only feeds a file is data, and a text a command prints
// is no write. A protected file reached through a known directory or a known
// relative value still blocks, and a here-document or a string run by a shell
// is code. The ordinary statements and the protected ones are shared among
// several tests, so that no test is longer than the CI budget of one.
func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart1(t *testing.T) {
	dataPadding(t, true, 0, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart2(t *testing.T) {
	dataPadding(t, true, 1, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart3(t *testing.T) {
	dataPadding(t, true, 2, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart4(t *testing.T) {
	dataPadding(t, true, 3, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart5(t *testing.T) {
	dataPadding(t, true, 4, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart6(t *testing.T) {
	dataPadding(t, true, 5, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart7(t *testing.T) {
	dataPadding(t, true, 6, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart8(t *testing.T) {
	dataPadding(t, true, 7, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart9(t *testing.T) {
	dataPadding(t, true, 8, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart10(t *testing.T) {
	dataPadding(t, true, 9, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart11(t *testing.T) {
	dataPadding(t, true, 10, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart12(t *testing.T) {
	dataPadding(t, true, 11, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart13(t *testing.T) {
	dataPadding(t, true, 12, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart14(t *testing.T) {
	dataPadding(t, true, 13, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart15(t *testing.T) {
	dataPadding(t, true, 14, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart16(t *testing.T) {
	dataPadding(t, true, 15, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart17(t *testing.T) {
	dataPadding(t, true, 16, 18)
}

func TestOverLimitCommandDataPaddingKeepsOrdinaryStatementsAllowedPart18(t *testing.T) {
	dataPadding(t, true, 17, 18)
}

func TestOverLimitCommandDataPaddingKeepsShellOrderAttacksBlockedPart1(t *testing.T) {
	dataPadding(t, false, 0, 10)
}

func TestOverLimitCommandDataPaddingKeepsShellOrderAttacksBlockedPart2(t *testing.T) {
	dataPadding(t, false, 1, 10)
}

func TestOverLimitCommandDataPaddingKeepsShellOrderAttacksBlockedPart3(t *testing.T) {
	dataPadding(t, false, 2, 10)
}

func TestOverLimitCommandDataPaddingKeepsShellOrderAttacksBlockedPart4(t *testing.T) {
	dataPadding(t, false, 3, 10)
}

func TestOverLimitCommandDataPaddingKeepsShellOrderAttacksBlockedPart5(t *testing.T) {
	dataPadding(t, false, 4, 10)
}

func TestOverLimitCommandDataPaddingKeepsShellOrderAttacksBlockedPart6(t *testing.T) {
	dataPadding(t, false, 5, 10)
}

func TestOverLimitCommandDataPaddingKeepsShellOrderAttacksBlockedPart7(t *testing.T) {
	dataPadding(t, false, 6, 10)
}

func TestOverLimitCommandDataPaddingKeepsShellOrderAttacksBlockedPart8(t *testing.T) {
	dataPadding(t, false, 7, 10)
}

func TestOverLimitCommandDataPaddingKeepsShellOrderAttacksBlockedPart9(t *testing.T) {
	dataPadding(t, false, 8, 10)
}

func TestOverLimitCommandDataPaddingKeepsShellOrderAttacksBlockedPart10(t *testing.T) {
	dataPadding(t, false, 9, 10)
}

// dataPadding judges the part-th of parts shares of the rows: the ordinary
// statements under each padding, or the protected ones. The ordinary rows are
// shared by statement and padding together, the protected ones by statement.
func dataPadding(t *testing.T, ordinary bool, part, parts int) {
	home, project := hermesPatchHome(t)
	notes := filepath.Join(project, "notes.txt")
	lib := "/usr/local/lib/libreview.so"
	load := "echo " + lib + " > /etc/ld.so.preload"
	paddings := map[string]func(statement string) string{
		"quoted text after": func(statement string) string { return statement + "\n: \x27" + overLimitDataText(statement) + "\x27" },
		"quoted text first": func(statement string) string { return ": \x27" + overLimitDataText(statement) + "\x27\n" + statement },
		"document after": func(statement string) string {
			return statement + "\ncat > /dev/null <<EOF\n" + overLimitDataText(statement) + "\nEOF\n"
		},
	}
	// The three paddings put the data before, after and in a document beside
	// the statement. Every statement, ordinary or protected, is judged under
	// each of them.
	paddingNames := make([]string, 0, len(paddings))
	for name := range paddings {
		paddingNames = append(paddingNames, name)
	}
	sort.Strings(paddingNames)
	benign := map[string]string{
		"here-document to an ordinary file":     "cat > " + notes + " <<\x27EOF\x27\n" + load + "\nEOF\n",
		"here-document with a padded delimiter": "cat > " + notes + " <<EOF\nnote\nEOF \n" + load + "\nEOF\n",
		"cd superseded before a relative write": "cd /etc; cd " + project + "; echo " + lib + " > ld.so.preload",
		"variable reassigned before the write":  "F=/etc/ld.so.preload; F=" + notes + "; echo " + lib + " > \"$F\"",
		"relative value in the project":         "cd " + project + "; F=ld.so.preload; echo " + lib + " > \"$F\"",
		"printed text names a redirect":         "printf \x27%s\\n\x27 \x27" + load + "\x27 > " + notes,
		"redirect in a comment":                 "echo ok > " + notes + " # " + load,
		"printed copy words, unquoted":          "printf \x27%s\\n\x27 cp " + lib + " /etc/ld.so.preload > " + notes,
		"printed copy words, quoted":            "printf \x27%s\\n\x27 \x27cp " + lib + " /etc/ld.so.preload\x27 > " + notes,
		"unquoted document, plain body":         "cat > " + notes + " <<EOF\n" + load + "\nEOF\n",
		"quoted document, literal substitution": "cat > " + notes + " <<\x27EOF\x27\n$(" + load + ")\nEOF\n",
		"escaped delimiter, literal backtick":   "cat > " + notes + " <<\\EOF\n`" + load + "`\nEOF\n",
		"escaped substitution in a body":        "cat > " + notes + " <<EOF\n\\$(" + load + ")\nEOF\n",
		"ordinary substitution in a body":       "cat > " + notes + " <<EOF\n$(date) $(echo note)\nEOF\n",
		"exported variable reassigned":          "export F=/etc/ld.so.preload; export F=" + notes + "; echo ok > \"$F\"",
		// A substitution elsewhere in the text does not make the data around
		// it code.
		"literal after a body substitution":       "cat > " + notes + " <<EOF\n$(date)\n" + load + "\nEOF\n",
		"literal before a body substitution":      "cat > " + notes + " <<EOF\n" + load + "\n$(date)\nEOF\n",
		"literal on the line of a substitution":   "cat > " + notes + " <<EOF\n$(date) " + load + "\nEOF\n",
		"printed text inside a body substitution": "cat > " + notes + " <<EOF\n$(printf \x27%s\\n\x27 \x27" + load + "\x27)\nEOF\n",
		"escaped substitution beside a real one":  "cat > " + notes + " <<EOF\n$(date)\n\\$(" + load + ")\nEOF\n",
		"literal after a backtick":                "cat > " + notes + " <<EOF\n`date`\n" + load + "\nEOF\n",
		"literal after a braced expansion":        "cat > " + notes + " <<EOF\n${HOME:-x}\n" + load + "\nEOF\n",
		"printf copy words after a substitution":  "printf \x27%s\\n\x27 \"$(date)\" cp " + lib + " /etc/ld.so.preload > " + notes,
		"printf copy words before a substitution": "printf \x27%s\\n\x27 cp " + lib + " /etc/ld.so.preload \"$(date)\" > " + notes,
		"printf copy words after a statement":     ": \"$(date)\"; printf \x27%s\\n\x27 cp " + lib + " /etc/ld.so.preload > " + notes,
		"echo copy words after a backtick":        "echo `date` cp " + lib + " /etc/ld.so.preload > " + notes,
		"echo copy words after an expansion":      "echo ${HOME:-x} cp " + lib + " /etc/ld.so.preload > " + notes,
		"echo copy words with an ANSI-C string":   "echo $\x27a\x27 cp " + lib + " /etc/ld.so.preload > " + notes,
		// A braced default is data: a redirect written in it is no write.
		"braced default in a body":             "cat > " + notes + " <<EOF\n${X:-" + load + " }\nEOF\n",
		"braced default beside a body default": "cat > " + notes + " <<EOF\n${X:-" + load + " } ${Y:-ok}\nEOF\n",
		"braced default in a printed word":     "echo ${X:-" + load + " } > " + notes,
		"braced default around a substitution": "cat > " + notes + " <<EOF\n${X:-" + load + " $(date) }\nEOF\n",
		// A substitution runs in a subshell: it leaves the directory and the
		// values of the shell around it as they were.
		"cd superseded around a substitution":       "cd /etc; cd " + project + "; echo \"$(date)\"; echo " + lib + " > ld.so.preload",
		"variable reassigned around a substitution": "F=/etc/ld.so.preload; echo $(date); F=" + notes + "; echo " + lib + " > \"$F\"",
		"cd inside a substitution":                  "x=$(cd /etc; pwd); echo " + lib + " > ld.so.preload",
		"cd inside a backtick":                      "x=`cd /etc; pwd`; echo " + lib + " > ld.so.preload",
		"assignment inside a substitution":          "x=$(F=/etc/ld.so.preload; echo ok); F=" + notes + "; echo " + lib + " > \"$F\"",
		// An assigning braced expansion is data too: a redirect in its word
		// is no write, and it leaves the directory and the values around it.
		"assigning default in a printed word":        "echo ${X:=" + load + " } > " + notes,
		"assigning default after a superseded cd":    "cd /etc; cd " + project + "; echo ${X:=ok}; echo " + lib + " > ld.so.preload",
		"assigning default after a superseded value": "F=/etc/ld.so.preload; F=" + notes + "; echo ${X:=ok}; echo " + lib + " > \"$F\"",
		"assigning default in a body":                "cat > " + notes + " <<EOF\n${X:=" + load + " }\nEOF\n",
		"quoted substitution of an ordinary operand": "tee \"$(date)\" < /dev/null > " + notes,
		// A default expansion sets a name only when it holds no value, and
		// text the shell does not expand sets nothing.
		"default of a set ordinary file":           "F=" + notes + "; : ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"default of a set ordinary file, printed":  "F=" + notes + "; echo ${F:=/etc/ld.so.preload} > " + notes + "; echo " + lib + " > \"$F\"",
		"default of a set ordinary file, no colon": "F=" + notes + "; : ${F=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"default in a single quote":                "F=" + notes + "; echo '${F:=/etc/ld.so.preload}' > " + notes + "; echo " + lib + " > \"$F\"",
		"default in a quoted body":                 "F=" + notes + "; cat <<'EOF2' > " + notes + "\n${F:=/etc/ld.so.preload}\nEOF2\necho " + lib + " > \"$F\"",
		"default after an escaped dollar":          "F=" + notes + "; echo \\${F:=/etc/ld.so.preload} > " + notes + "; echo " + lib + " > \"$F\"",
		"default in a comment":                     "F=" + notes + "; # ${F:=/etc/ld.so.preload}\necho " + lib + " > \"$F\"",
		"default in a single quote, no value set":  "echo '${F:=/etc/ld.so.preload}' > " + notes + "; echo " + lib + " > \"$F\"",
		"default in a comment of a substitution":   "echo $(ls # ${F:=/etc/ld.so.preload}\n) > " + notes + "; echo " + lib + " > \"$F\"",
		// A word the shell reads as data assigns nothing, a child process
		// keeps what it assigns, and a default fills a name no run has set.
		"quoted word of a data command":                 "F=" + notes + "; test \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
		"quoted word of command echo":                   "F=" + notes + "; command echo \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
		"quoted word of builtin echo":                   "F=" + notes + "; builtin echo \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
		"quoted word of command -p echo":                "F=" + notes + "; command -p echo \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
		"quoted word of builtin and a double dash":      "F=" + notes + "; builtin -- echo \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
		"quoted word of a quoted echo behind command":   "F=" + notes + "; command \"echo\" \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
		"default of a name set after two passing tests": "true && : && F=" + notes + "; : ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"quoted default inside a default":               ": ${A:-\x27${F:=/etc/ld.so.preload}\x27}; echo " + lib + " > \"$F\"",
		"quoted default inside an assigning default":    ": ${A:=\x27${F:=/etc/ld.so.preload}\x27}; echo " + lib + " > \"$F\"",
		"document of a program in another language":     "python3 <<\x27EOF2\x27\nprint(\x27${F:=/etc/ld.so.preload}\x27)\nEOF2\necho " + lib + " > \"$F\"",
		"assignment in a document run by a shell":       "sh <<\x27EOF2\x27\n: ${F:=/etc/ld.so.preload}\nEOF2\necho " + lib + " > \"$F\"",
		"assignment in a string run by a shell":         "sh -c \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
		"assignment in an env prefix":                   "env F=/etc/ld.so.preload true; echo " + lib + " > \"$F\"",
		"default of a name a default has set":           ": ${F:=" + notes + "}; : ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"default of a name set to an unreadable value":  ": ${F:=$(date)}; : ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
	}
	benignNames := make([]string, 0, len(benign))
	for name := range benign {
		benignNames = append(benignNames, name)
	}
	sort.Strings(benignNames)
	for index, name := range benignNames {
		statement := benign[name]
		for padIndex, padName := range paddingNames {
			if !ordinary || (index*len(paddingNames)+padIndex)%parts != part {
				continue
			}
			t.Run("benign/"+name+"/"+padName, func(t *testing.T) {
				t.Parallel()
				got := overLimitCommandVerdictPast(t, home, project, paddings[padName](statement))
				if action := overLimitHookAction(t, got); action == "block" {
					t.Fatalf("ordinary oversize command blocked: %.600s", got)
				}
			})
		}
	}
	attacks := map[string]string{
		"known relative value":                   "cd /etc; F=ld.so.preload; echo " + lib + " > \"$F\"",
		"relative value before the cd":           "F=ld.so.preload; cd /etc; echo " + lib + " > \"$F\"",
		"cd up from a subdirectory":              "cd /etc/x; cd ..; echo " + lib + " > ld.so.preload",
		"cd back with a dash":                    "cd /etc; cd " + project + "; cd -; echo " + lib + " > ld.so.preload",
		"cd that may fail":                       "cd /etc; cd " + project + " || true; echo " + lib + " > ld.so.preload",
		"exported variable":                      "export F=/etc/ld.so.preload; echo " + lib + " > \"$F\"",
		"here-document run by a shell":           "sh <<EOF\n" + load + "\nEOF\n",
		"here-document piped to a shell":         "cat <<EOF | bash\n" + load + "\nEOF\n",
		"string run by a shell":                  "sh -c \x27" + load + "\x27",
		"string run by a shell with a cd":        "bash -c \x27cd /etc && echo " + lib + " > ld.so.preload\x27",
		"redirect after a data here-document":    "cat > " + notes + " <<EOF\nnote\nEOF\n" + load,
		"function that runs in the directory":    "f() { echo " + lib + " > ld.so.preload; }; cd /etc; f",
		"tee with a quoted operand":              "echo " + lib + " | tee \"/etc/ld.so.preload\"",
		"redirect after a printed text":          "echo \x27tee x\x27; " + load,
		"redirect after unquoted printed words":  "echo cp a b > /etc/ld.so.preload",
		"substitution in an unquoted document":   "cat > " + notes + " <<EOF\n$(" + load + ")\nEOF\n",
		"substitution, normalized target":        "cat > " + notes + " <<EOF\n$(echo " + lib + " > /etc/./ld.so.preload)\nEOF\n",
		"backtick in an unquoted document":       "cat > " + notes + " <<EOF\n`" + load + "`\nEOF\n",
		"substitution after an escaped one":      "cat > " + notes + " <<EOF\n\\$(x) $(" + load + ")\nEOF\n",
		"directory variable and relative target": "cd /etc; D=pam.d; echo \x27auth sufficient pam_permit.so\x27 > $D/sshd",
		"redirect beside a printed substitution": "echo " + lib + " \"$(date)\" > /etc/ld.so.preload",
		"substitution in a printed word":         "echo \"$(" + load + ")\" > " + notes,
		"backtick in a printed word":             "echo `" + load + "` > " + notes,
		"substitution in a printf word":          "printf \x27%s\x27 $(" + load + ") > " + notes,
		"nested substitution in a body":          "cat > " + notes + " <<EOF\n$(date $(" + load + "))\nEOF\n",
		"braced expansion that substitutes":      "cat > " + notes + " <<EOF\n${X:-$(" + load + ")}\nEOF\n",
		"write after a quote in a substitution":  "cat > " + notes + " <<EOF\n$(printf \x27)\x27; " + load + ")\nEOF\n",
		"write beside a substitution in a body":  "cat > " + notes + " <<EOF\n$(date) $(" + load + ")\nEOF\n",
		"substitution in a braced default":       "cat > " + notes + " <<EOF\n${X:-a $(" + load + ") b}\nEOF\n",
		"cd and write inside a substitution":     "x=$(cd /etc; echo " + lib + " > ld.so.preload)",
		"cd and write inside a backtick":         "x=`cd /etc; echo " + lib + " > ld.so.preload`",
		"cd and write in a body substitution":    "cat > " + notes + " <<EOF\n$(cd /etc && echo " + lib + " > ld.so.preload)\nEOF\n",
		"cd before a substitution":               "cd /etc; echo $(date); echo " + lib + " > ld.so.preload",
		"cd after a substitution":                "echo $(date); cd /etc; echo " + lib + " > ld.so.preload",
		"variable kept around a substitution":    "F=/etc/ld.so.preload; echo $(date); echo " + lib + " > \"$F\"",
		// A substitution in a quoted word runs: its write is read whatever
		// the command around it.
		"quoted tee operand with a substitution":        "tee \"$(" + load + ")\" < /dev/null > " + notes,
		"quoted assignment with a substitution":         "F=\"$(" + load + ")\"; echo ok > " + notes,
		"quoted cd operand with a substitution":         "cd \"$(" + load + ")\"; echo ok > " + notes,
		"quoted redirect target with a substitution":    "echo ok > \"$(" + load + ")\"",
		"assigned protected file":                       ": ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"assigning default with a substitution":         "cat > " + notes + " <<EOF\n${X:=$(" + load + ")}\nEOF\n",
		"default of an unset name":                      "F=" + notes + "; unset F; : ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"default of an empty name":                      "F=; : ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"default in double quotes around single":        "echo \"'${F:=/etc/ld.so.preload}'\" > " + notes + "; echo " + lib + " > \"$F\"",
		"quoted substitution, set ordinary file":        "F=" + notes + "; tee \"$(" + load + ")\" < /dev/null > \"$F\"",
		"conditional assignment before a default":       "false && F=" + notes + "; : ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"assignment after a skipped true":               "false && true && F=" + notes + "; : ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"assignment after a skipped colon":              "false && : && F=" + notes + "; : ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"assignment after a skipped false":              "true || false || F=" + notes + "; : ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"assignment after a skipped colon in an or":     "true || : || F=" + notes + "; : ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"eval behind command":                           "F=" + notes + "; command eval \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
		"eval behind builtin and a double dash":         "F=" + notes + "; builtin -- eval \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
		"export behind builtin and a double dash":       "F=" + notes + "; builtin -- export F=/etc/ld.so.preload; echo " + lib + " > \"$F\"",
		"quoted eval behind command":                    "F=" + notes + "; command \"eval\" \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
		"quoted eval behind builtin":                    "F=" + notes + "; builtin \"eval\" \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
		"unknown option of builtin before eval":         "F=" + notes + "; builtin -x eval \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
		"quoted word before a default":                  "test \x27F=" + notes + "\x27; : ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"",
		"default inside a double-quoted default":        ": ${A:-\"${F:=/etc/ld.so.preload}\"}; echo " + lib + " > \"$F\"",
		"default inside a default":                      ": ${A:-${F:=/etc/ld.so.preload}}; echo " + lib + " > \"$F\"",
		"assignment and write in a string of a shell":   "sh -c \x27F=/etc/ld.so.preload; echo " + lib + " > \"$F\"\x27",
		"assignment and write in a document of a shell": "sh <<\x27EOF2\x27\n: ${F:=/etc/ld.so.preload}; echo " + lib + " > \"$F\"\nEOF2\n",
		"env prefix and a write by the child":           "env F=/etc/ld.so.preload sh -c \x27echo " + lib + " > \"$F\"\x27",
		"assignment by eval":                            "eval \x27F=/etc/ld.so.preload\x27; echo " + lib + " > \"$F\"",
	}
	attackNames := make([]string, 0, len(attacks))
	for name := range attacks {
		attackNames = append(attackNames, name)
	}
	sort.Strings(attackNames)
	for index, name := range attackNames {
		if ordinary || index%parts != part {
			continue
		}
		statement := attacks[name]
		for padName, pad := range paddings {
			t.Run("attack/"+name+"/"+padName, func(t *testing.T) {
				t.Parallel()
				got := overLimitCommandVerdictPast(t, home, project, pad(statement))
				if overLimitHookAction(t, got) != "block" {
					t.Fatalf("not blocked: %.600s", got)
				}
			})
		}
	}
}
