// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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
