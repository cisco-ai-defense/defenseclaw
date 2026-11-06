// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func TestG235BalancedCopyWordBindingControls(t *testing.T) {
	const home = "/home/u"
	rows := []struct {
		command, want string
	}{
		{`f=out.txt; printf -- %s hello; cp a.txt $f`, "out.txt"},
		{`f=out.txt; printf -- '%%n' hello; cp a.txt $f`, "out.txt"},
		{`f=out.txt; printf '%s\n' hello; cp a.txt $f`, "out.txt"},
		{`g() { printf -- %s hello; cp a.txt $f; }; f=out.txt; g`, "out.txt"},
		{`f=out.txt; read -r unrelated; cp a.txt $f`, "out.txt"},
		{`other=old.txt; read -r other; f=out.txt; cp a.txt $f`, "out.txt"},
		{`one=old.txt; read -r one two; f=out.txt; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -r f; cp a.txt $f`, ""},
		{`f=out.txt; read -r other f; cp a.txt $f`, ""},
		{`f=out.txt; printf -- '%n' f; cp a.txt $f`, ""},
		{`f=out.txt; printf -- '%10n' f; cp a.txt $f`, ""},
		{`f=out.txt; printf -v f disklink; cp a.txt $f`, ""},
	}
	for _, row := range rows {
		t.Run(row.command, func(t *testing.T) {
			file, ok := parseShell(row.command)
			if !ok {
				t.Fatal("command did not parse")
			}
			var dest *syntax.Word
			syntax.Walk(file, func(node syntax.Node) bool {
				call, ok := node.(*syntax.CallExpr)
				if !ok || len(call.Args) != 3 {
					return true
				}
				if program, known := StaticWord(call.Args[0], home); known && program == "cp" {
					dest = call.Args[2]
				}
				return true
			})
			if dest == nil {
				t.Fatal("copy destination not found")
			}
			_, values := knownWordParameters(row.command, file, home, nil, nil, true)
			if got := values[dest]; got != row.want {
				t.Errorf("destination value %q, want %q", got, row.want)
			}
		})
	}
}
