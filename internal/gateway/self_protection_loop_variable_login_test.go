// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0880, GAP-0885: a loop variable takes the values of its word
// list, or the one word a static echo or printf stage hands a while read loop.
// When the list expands USER or LOGNAME, the variable holds the login for
// the iteration that has it, so an edit or a redirect that reaches
// DefenseClaw state through the variable blocks in every profile, as the
// assignment form does. A list of other names, or a body that does not
// reach DefenseClaw state, keeps the verdict it has without the loop.
func TestLoopVariableFromLoginReachesState(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	active := filepath.Base(home)
	type row struct {
		name, command string
		protected     bool
	}
	var rows []row
	for _, list := range []string{"$USER", "${USER}", `"$USER"`, "$LOGNAME", "${LOGNAME}", `"${LOGNAME}"`, "ordinary $USER", "$USER ordinary", "ordinary $LOGNAME", active} {
		head := "for u in " + list + "; do "
		rows = append(rows,
			row{"editor-" + list, head + `sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml; done`, true},
			row{"printf-" + list, head + `printf "$X" > ` + parent + `$u/.defenseclaw/config.yaml; done`, true},
			row{"break-" + list, head + `sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml; break; done`, true},
		)
	}
	rows = append(rows,
		row{"control-assign-login", `u=$USER; sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml`, true},
		row{"control-assign-literal", `u=` + active + `; sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml`, true},
		row{"control-literal", `sed -i s/a/b/ ` + parent + active + `/.defenseclaw/config.yaml`, true},
		row{"while-read-echo", `echo $USER | while read u; do sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml; done`, true},
		row{"while-read-printf", `printf '%s\n' ${LOGNAME} | while read -r u; do printf "$X" > ` + parent + `$u/.defenseclaw/config.yaml; done`, true},
		row{"while-read-sibling", `echo ordinary | while read u; do sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml; done`, false},
		row{"while-read-unreadable-input", `ls | while read u; do sed -i s/a/b/ ` + parent + `$u/notes.txt; done`, false},
		row{"nested", `for a in $USER; do for u in $a; do sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml; done; done`, true},
		row{"nested-same-list", `for a in ordinary; do for u in $a $USER; do sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml; done; done`, true},
		row{"body-rebinds-to-login", `for u in ordinary; do u=$USER; sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml; done`, true},
		row{"body-rebinds-to-sibling", `for u in $USER; do u=ordinary; sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml; done`, false},
		row{"long-list-of-others", `for u in a b c d e f g h i j k l; do sed -i s/a/b/ ` + parent + `$u/notes.txt; done`, false},
		row{"other-names", `for u in alice bob; do sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml; done`, false},
		row{"other-names-ordinary-file", `for u in alice bob; do sed -i s/a/b/ ` + parent + `$u/notes.txt; done`, false},
		row{"login-ordinary-file", `for u in $USER; do sed -i s/a/b/ ` + parent + `$u/notes.txt; done`, false},
		row{"sibling-only", `for u in ordinary; do sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml; done`, false},
		row{"bound-other-first", `USER=ordinary; for u in $USER; do sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml; done`, false},
	)
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "strict", "permissive"} {
				for _, row := range rows {
					if !row.protected && pack == "strict" {
						continue
					}
					got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
					block := strings.HasPrefix(got, `{"action":"block"`)
					if row.protected && (!block || !strings.Contains(got, "tamper.detector_state_write")) {
						t.Errorf("%s %s managed=%t pack=%s: %s = %.200s, want protected block", row.name, connector, managed, pack, row.command, got)
					}
					if !row.protected && block {
						t.Errorf("%s %s managed=%t pack=%s: %s = %.200s, want ordinary allow", row.name, connector, managed, pack, row.command, got)
					}
				}
			}
		}
	}
}

// rel-1-0-6:GAP-0880, GAP-0885 review 1: the reading of a loop does not depend
// on how long its list is, on a function the action only declares, on an IFS
// the read sets for itself, on another loop that ends before the write, or on
// a link: a state write through the variable, or through a link the variable
// reaches, blocks in every profile and both connectors, as the literal path
// does. Ordinary files keep their verdict.
func TestLoopVariableNearFormsReachState(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	active := filepath.Base(home)
	write := `sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml`
	ordinary := `sed -i s/a/b/ ` + parent + `$u/notes.txt`
	filler := func(count int) string {
		list := ""
		for index := 0; index < count; index++ {
			list += "w" + string(rune('a'+index%26)) + string(rune('a'+index/26)) + " "
		}
		return list
	}
	rows := []struct {
		name, command string
		protected     bool
	}{
		{"nine-words", `for u in a b c d e f g h $USER; do ` + write + `; done`, true},
		{"thirty-words", `for u in ` + filler(29) + `$USER; do ` + write + `; done`, true},
		{"hundred-words", `for u in ` + filler(100) + `$USER; do ` + write + `; done`, true},
		{"function-after", `for u in $USER; do ` + write + `; done; f() { :; }`, true},
		{"function-before", `f() { :; }; for u in $USER; do ` + write + `; done`, true},
		{"while-ifs-empty", `echo $USER | while IFS= read -r u; do ` + write + `; done`, true},
		{"while-printf-ifs-empty", `printf '%s\n' "$USER" | while IFS= read -r u; do ` + write + `; done`, true},
		{"while-ifs-set", `echo $USER | while IFS=: read -r u; do ` + write + `; done`, true},
		{"while-ifs-text", `x=IFS; echo $USER | while read u; do ` + write + `; done`, true},
		{"prior-binding-survives-other-loop", `u=$USER; for a in x; do :; done; ` + write + `; for u in x; do :; done`, true},
		{"prior-binding-survives-read-loop", `u=$USER; echo x | while read a; do :; done; ` + write, true},
		{"for-file-link", `for u in $USER; do sed -i s/a/b/ ` + parent + `$u/statealias; done`, true},
		{"for-directory-link", `for u in $USER; do sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml; done`, true},
		{"while-file-link", `echo $USER | while read u; do sed -i s/a/b/ ` + parent + `$u/statealias; done`, true},
		{"literal-link-name", `for d in ordinary aliasdir; do sed -i s/a/b/ ` + parent + active + `/$d/config.yaml; done`, true},
		{"assigned-file-link", `u=$USER; sed -i s/a/b/ ` + parent + `$u/statealias`, true},
		{"assigned-directory-link", `u=$USER; sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml`, true},
		{"literal-file-link", `sed -i s/a/b/ ` + parent + active + `/statealias`, true},
		{"nine-ordinary", `for u in a b c d e f g h ordinary; do ` + ordinary + `; done`, false},
		{"thirty-ordinary", `for u in ` + filler(29) + `ordinary; do ` + ordinary + `; done`, false},
		{"login-ordinary", `for u in $USER; do ` + ordinary + `; done`, false},
		{"sibling-ordinary", `for u in alice bob; do ` + ordinary + `; done`, false},
		{"function-called-rebinds-sibling", `f() { u=ordinary; }; for u in $USER; do f; sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml; done`, false},
		{"while-ifs-empty-ordinary", `echo $USER | while IFS= read -r u; do ` + ordinary + `; done`, false},
		{"later-loop-rebinds-sibling", `u=ordinary; for u in $USER; do :; done; sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml`, false},
		{"over-bound-ordinary", `for u in ` + filler(40) + `ordinary; do ` + ordinary + `; done`, false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "permissive", "strict"} {
				for _, row := range rows {
					if !row.protected && pack == "strict" {
						continue
					}
					got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
					block := strings.HasPrefix(got, `{"action":"block"`)
					if row.protected && (!block || !strings.Contains(got, "tamper.detector_state_write")) {
						t.Errorf("%s %s managed=%t pack=%q: %.120s = %.200s, want protected block", row.name, connector, managed, pack, row.command, got)
					}
					if !row.protected && block {
						t.Errorf("%s %s managed=%t pack=%q: %.120s = %.200s, want ordinary allow", row.name, connector, managed, pack, row.command, got)
					}
				}
			}
		}
	}
}

// rel-1-0-6:GAP-0880, GAP-0885 review 2: every distinct word of a list is read
// (a link named in a late position, the login after many path words), the
// readings of the statements before a rebinding of the variable stay, a
// comment names no evidence, and a read that drops a trailing delimiter reads
// the value it drops it from. Ordinary commands keep their verdict.
func TestLoopVariableOrderLinksAndDelimiters(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	active := filepath.Base(home)
	ordinaryDir := filepath.Join(home, "aliasdi")
	if err := os.MkdirAll(ordinaryDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(ordinaryDir, "config.yaml"), filepath.Join(home, "statealia")} {
		if err := os.WriteFile(name, []byte("ordinary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	paths := func(count int) string {
		var words []string
		for index := 0; index < count; index++ {
			words = append(words, fmt.Sprintf("x%02d.txt", index))
		}
		return strings.Join(words, " ") + " "
	}
	write := `sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml`
	ordinary := `sed -i s/a/b/ ` + parent + `$u/notes.txt`
	fileBody := `sed -i s/a/b/ ` + parent + `$u/statealias`
	fileReading := `sed -i s/a/b/ '` + parent + active + `/statealias'`
	redirectBody := `printf x > ` + parent + `$u/statealias`
	redirectReading := `printf x > '` + parent + active + `/statealias'`
	dirBody := `sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml`
	dirReading := `sed -i s/a/b/ '` + parent + active + `/aliasdir/config.yaml'`
	rows := []struct {
		name, command string
		protected     bool
	}{
		{"fifth-plain-directory-link", `for d in a b c d aliasdir; do sed -i s/a/b/ ` + home + `/$d/config.yaml; done`, true},
		{"fifth-plain-file-link", `for f in a b c d statealias; do sed -i s/a/b/ ` + home + `/$f; done`, true},
		{"fiftieth-plain-directory-link", `for d in ` + paths(0) + strings.Repeat("p ", 49) + `aliasdir; do sed -i s/a/b/ ` + home + `/$d/config.yaml; done`, true},
		{"login-after-forty-seven-path-words", `for u in ` + paths(47) + `$USER; do ` + write + `; done`, true},
		{"login-after-forty-eight-path-words", `for u in ` + paths(48) + `$USER; do ` + write + `; done`, true},
		{"fifth-plain-ordinary", `for d in a b c d ordinary; do sed -i s/a/b/ ` + home + `/$d/notes.txt; done`, false},
		{"for-rebind-after-write", `for u in $USER; do ` + write + `; u=ordinary; done`, true},
		{"for-export-after-write", `for u in $USER; do ` + write + `; export u=ordinary; done`, true},
		{"for-read-after-write", `for u in $USER; do ` + write + `; read u; done`, true},
		{"for-function-after-write", `f() { u=ordinary; }; for u in $USER; do ` + write + `; f; done`, true},
		{"for-declared-function-in-body", `for u in $USER; do f() { u=ordinary; }; ` + write + `; done`, true},
		{"for-prefix-assignment-before", `for u in $USER; do u=ordinary true; ` + write + `; done`, true},
		{"while-rebind-after-write", `echo $USER | while read u; do ` + write + `; u=ordinary; done`, true},
		{"while-ifs-after-loop", `echo $USER | while read u; do ` + write + `; done; IFS=x`, true},
		{"while-inert-ifs-function", `f() { IFS=x; }; echo $USER | while read u; do ` + write + `; done`, true},
		{"for-rebind-before-ordinary", `for u in $USER; do u=ordinary; ` + ordinary + `; done`, false},
		{"for-read-before-ordinary", `for u in $USER; do read u; ` + ordinary + `; done`, false},
		{"while-ordinary", `echo $USER | while read u; do ` + ordinary + `; done`, false},
		{"comment-file-link-control", `for u in $USER; do ` + fileBody + `; done`, true},
		{"comment-file-link", `for u in $USER; do ` + fileBody + `; done # ` + fileReading, true},
		{"comment-redirect-link", `for u in $USER; do ` + redirectBody + `; done # ` + redirectReading, true},
		{"comment-directory-link", `for u in $USER; do ` + dirBody + `; done # ` + dirReading, true},
		{"trailing-delimiter-ordinary-directory", `echo aliasdir | while IFS=r read -r d; do sed -i s/a/b/ ` + home + `/$d/config.yaml; done`, false},
		{"second-delimiter-keeps-file-link", `echo statealias | while IFS=s read -r f; do sed -i s/a/b/ ` + home + `/$f; done`, true},
		{"trailing-delimiter-ordinary-file", `echo statealiax | while IFS=x read -r f; do sed -i s/a/b/ ` + home + `/$f; done`, false},
		{"empty-delimiter-directory-link", `echo aliasdir | while IFS= read -r d; do sed -i s/a/b/ ` + home + `/$d/config.yaml; done`, true},
		{"other-delimiter-directory-link", `echo aliasdir | while IFS=: read -r d; do sed -i s/a/b/ ` + home + `/$d/config.yaml; done`, true},
		{"trailing-delimiter-state-name", `echo .defenseclawx | while IFS=x read -r d; do sed -i s/a/b/ ` + home + `/$d/config.yaml; done`, true},
		// review 3: select takes the words of its list as for does.
		{"select-login", `select u in $USER; do ` + write + `; break; done`, true},
		{"select-redirect", `select u in $USER; do ` + redirectBody + `; break; done`, true},
		{"select-directory-link", `select u in a aliasdir; do sed -i s/a/b/ ` + home + `/$u/config.yaml; break; done`, true},
		{"select-ordinary", `select u in alice bob; do ` + ordinary + `; break; done`, false},
		{"select-login-ordinary-file", `select u in $USER; do ` + ordinary + `; break; done`, false},
		// review 3: code that may not run does not end the word of the loop.
		{"if-false-assign", `for u in $USER; do if false; then u=ordinary; fi; ` + write + `; done`, true},
		{"and-false-assign", `for u in $USER; do false && u=ordinary; ` + write + `; done`, true},
		{"or-true-assign", `for u in $USER; do true || u=ordinary; ` + write + `; done`, true},
		{"case-nonmatch-assign", `for u in $USER; do case x in y) u=ordinary;; esac; ` + write + `; done`, true},
		{"if-false-read", `for u in $USER; do if false; then read u; fi; ` + write + `; done`, true},
		{"subshell-assign", `for u in $USER; do (u=ordinary); ` + write + `; done`, true},
		{"while-if-false-assign", `echo $USER | while read u; do if false; then u=ordinary; fi; ` + write + `; done`, true},
		{"link-if-false-assign", `for u in a aliasdir; do if false; then u=ordinary; fi; sed -i s/a/b/ ` + home + `/$u/config.yaml; done`, true},
		{"link-and-false-assign", `for u in a aliasdir; do false && u=ordinary; sed -i s/a/b/ ` + home + `/$u/config.yaml; done`, true},
		{"if-true-ordinary", `for u in $USER; do if true; then u=ordinary; fi; ` + ordinary + `; done`, false},
		{"or-true-ordinary", `for u in $USER; do true || u=ordinary; ` + ordinary + `; done`, false},
		// review 3: IFS code that may not run does not stop the read of the loop,
		// and a delimiter of more than one byte is dropped whole.
		{"while-if-false-ifs-before", `if false; then IFS=x; fi; echo $USER | while read u; do ` + write + `; done`, true},
		{"while-ifs-before-state-name", `IFS=x; echo $USER | while read u; do ` + write + `; done`, true},
		{"while-utf8-ifs-link", `echo aliasdiré | while IFS=é read -r u; do sed -i s/a/b/ ` + home + `/$u/config.yaml; done`, true},
		{"here-string-login", `while read u; do ` + write + `; done <<< $USER`, true},
		{"here-string-quoted-login", `while read -r u; do ` + write + `; done <<< "$USER"`, true},
		{"here-string-directory-link", `while read -r d; do sed -i s/a/b/ ` + home + `/$d/config.yaml; done <<< aliasdir`, true},
		{"here-string-ordinary", `while read u; do ` + ordinary + `; done <<< $USER`, false},
		{"here-string-ordinary-name", `while read -r d; do sed -i s/a/b/ ` + home + `/$d/config.yaml; done <<< ordinary`, false},
		{"while-utf8-ifs-ordinary", `echo notesé | while IFS=é read -r u; do sed -i s/a/b/ ` + home + `/$u/notes.txt; done`, false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "permissive", "strict"} {
				for _, row := range rows {
					if !row.protected && pack == "strict" {
						continue
					}
					got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
					block := strings.HasPrefix(got, `{"action":"block"`)
					if row.protected && (!block || !strings.Contains(got, "tamper.detector_state_write")) {
						t.Errorf("%s %s managed=%t pack=%q: = %.200s, want protected block", row.name, connector, managed, pack, got)
					}
					if !row.protected && block {
						t.Errorf("%s %s managed=%t pack=%q: = %.200s, want ordinary allow", row.name, connector, managed, pack, got)
					}
				}
			}
		}
	}
}

// rel-1-0-6:GAP-0880, GAP-0885 review 4: a binding that certainly runs ends
// the word of the loop (a true condition, an if or case whose every branch
// binds it, printf -v, a true &&), a function named like the builtin it
// shadows binds nothing, and the IFS of a read is the one that reaches it: a
// known variable gave it, code after the loop did not. Protected writes keep
// their block, ordinary ones their verdict.
func TestLoopVariableCertainBindingsAndReachingIFS(t *testing.T) {
	home, project, parent := g235bBinderFixture(t)
	write := `sed -i s/a/b/ ` + parent + `$u/aliasdir/config.yaml`
	direct := `sed -i s/a/b/ ` + parent + `$u/.defenseclaw/config.yaml`
	readWrite := `echo aliasdirx | while read -r d; do sed -i s/a/b/ ` + home + `/$d/config.yaml; done`
	missing := project + `/missing/out`
	rows := []struct {
		name, command string
		protected     bool
	}{
		{"read-shadowed-by-function", `read() { :; }; for u in $USER; do read u; ` + direct + `; done`, true},
		{"read-shadowed-link", `read() { :; }; for u in $USER; do read u; ` + write + `; done`, true},
		{"printf-shadowed-by-function", `printf() { :; }; for u in $USER; do printf -v u ordinary; ` + direct + `; done`, true},
		{"true-shadowed-by-function", `true() { return 1; }; for u in $USER; do true && u=ordinary; ` + direct + `; done`, true},
		{"if-true-unknown-condition", `for u in $USER; do if test -f /nonexistent; then u=ordinary; fi; ` + write + `; done`, true},
		{"if-one-branch-only", `for u in $USER; do if test -f /nonexistent; then u=ordinary; else :; fi; ` + write + `; done`, true},
		{"case-without-default", `for u in $USER; do case x in y) u=ordinary;; esac; ` + write + `; done`, true},
		{"and-unknown-condition", `for u in $USER; do test -f /nonexistent && u=ordinary; ` + write + `; done`, true},
		{"ifs-from-known-variable", `sep=x; IFS=$sep; ` + readWrite, true},
		{"ifs-from-known-variable-declared", `sep=x; export IFS=$sep; ` + readWrite, true},
		{"ifs-static", `IFS=x; ` + readWrite, true},
		{"ifs-in-a-branch", `if test -f /nonexistent; then IFS=x; fi; ` + readWrite, true},
		{"ifs-in-a-loop-that-runs-again", `while test -f /nonexistent; do ` + readWrite + `; IFS=x; done`, true},
		{"read-redirection-fails", `for u in $USER; do read u < ` + missing + `; ` + direct + `; done`, true},
		{"printf-redirection-fails", `for u in $USER; do printf -v u ordinary > ` + missing + `; ` + direct + `; done`, true},
		{"printf-missing-format", `for u in $USER; do printf -v u; ` + direct + `; done`, true},
		{"read-with-timeout", `for u in $USER; do read -t 1 u <<< ordinary; ` + direct + `; done`, true},
		{"local-outside-a-function", `for u in $USER; do local u=ordinary; ` + direct + `; done`, true},
		{"read-shadowed-before-the-call", `read() { :; }; for u in $USER; do read u <<< ordinary; ` + write + `; done`, true},
		{"read-declared-in-a-loop-that-runs-again", `for i in 1 2; do for u in $USER; do read u <<< ordinary; ` + write + `; done; read() { :; }; done`, true},
		{"ifs-in-a-function-the-loop-calls", `f() { IFS=x; }; for i in 1 2; do ` + readWrite + `; f; done`, true},
		{"read-here-string-binds-and-function-declared-after", `for u in $USER; do read u <<< ordinary; ` + write + `; done; read() { :; }`, false},
		{"printf-v-binds-and-function-declared-after", `for u in $USER; do printf -v u ordinary; ` + write + `; done; printf() { :; }`, false},
		{"if-true-binds-and-function-declared-after", `for u in $USER; do if true; then u=ordinary; fi; ` + write + `; done; true() { :; }`, false},
		{"or-false-binds-and-function-declared-after", `for u in $USER; do false || u=ordinary; ` + write + `; done; false() { :; }`, false},
		{"ifs-in-an-uncalled-function-and-an-outer-loop", `f() { IFS=x; }; for i in 1 2; do ` + readWrite + `; done`, false},
		{"ifs-in-a-function-declared-after-an-outer-loop", `for i in 1 2; do ` + readWrite + `; done; f() { IFS=x; }`, false},
		{"if-true-binds", `for u in $USER; do if true; then u=ordinary; fi; ` + write + `; done`, false},
		{"and-true-binds", `for u in $USER; do true && u=ordinary; ` + write + `; done`, false},
		{"printf-v-binds", `for u in $USER; do printf -v u ordinary; ` + write + `; done`, false},
		{"or-false-binds", `for u in $USER; do false || u=ordinary; ` + write + `; done`, false},
		{"both-branches-bind", `for u in $USER; do if test -f /nonexistent; then u=ordinary; else u=ordinary; fi; ` + write + `; done`, false},
		{"every-arm-binds", `for u in $USER; do case x in y) u=ordinary;; *) u=ordinary;; esac; ` + write + `; done`, false},
		{"ifs-after-the-loop", readWrite + `; IFS=x`, false},
		{"ifs-after-the-write", `echo aliasdirx | while read -r d; do sed -i s/a/b/ ` + home + `/$d/config.yaml; IFS=x; done`, false},
		{"ifs-in-a-function-declared-after", readWrite + `; f() { IFS=x; }`, false},
		{"ifs-in-a-function-declared-before", `f() { IFS=x; }; ` + readWrite, false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "permissive", "strict"} {
				for _, row := range rows {
					if !row.protected && pack == "strict" {
						continue
					}
					got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
					block := strings.HasPrefix(got, `{"action":"block"`)
					if row.protected && (!block || !strings.Contains(got, "tamper.detector_state_write")) {
						t.Errorf("%s %s managed=%t pack=%q: = %.200s, want protected block", row.name, connector, managed, pack, got)
					}
					if !row.protected && block {
						t.Errorf("%s %s managed=%t pack=%q: = %.200s, want ordinary allow", row.name, connector, managed, pack, got)
					}
				}
			}
		}
	}
}
