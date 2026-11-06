// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os/exec"
	"strings"
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
		{`f=out.txt; printf ''; cp a.txt $f`, "out.txt"},
		{`f=out.txt; printf -- ''; cp a.txt $f`, "out.txt"},
		{`g() { printf -- %s hello; cp a.txt $f; }; f=out.txt; g`, "out.txt"},
		{`g() { printf ''; cp a.txt $f; }; f=out.txt; g`, "out.txt"},
		{`f=out.txt; read -r unrelated; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -- unrelated; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -r -- unrelated; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -rs unrelated; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -sr -- unrelated; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -p prompt unrelated; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -r -a unrelated; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -r; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -r --; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -rs; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -p prompt; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -a unrelated f; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -aunrelated f; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -a f unrelated; cp a.txt $f`, ""},
		{`f=out.txt; pwd; cp a.txt $f`, "out.txt"},
		{`f=out.txt; builtin read -r <<< data; cp a.txt $f`, "out.txt"},
		{`f=out.txt; command read -r <<< data; cp a.txt $f`, "out.txt"},
		{`f=out.txt; builtin read -r other <<< data; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -rp prompt other <<< data; cp a.txt $f`, "out.txt"},
		{`f=out.txt; printf -v other %s plain; cp a.txt $f`, "out.txt"},
		{`f=out.txt; printf -vother %s plain; cp a.txt $f`, "out.txt"},
		{`f=out.txt; mapfile -t other <<< data; cp a.txt $f`, "out.txt"},
		{`f=out.txt; readarray -t other <<< data; cp a.txt $f`, "out.txt"},
		{`f=out.txt; wait -p other; cp a.txt $f`, "out.txt"},
		{`f=out.txt; getopts x other; cp a.txt $f`, "out.txt"},
		{`f=out.txt; declare other; cp a.txt $f`, "out.txt"},
		{`f=out.txt; typeset other; cp a.txt $f`, "out.txt"},
		{`f=out.txt; export other; cp a.txt $f`, "out.txt"},
		{`f=out.txt; readonly other; cp a.txt $f`, "out.txt"},
		{`f=out.txt; builtin read -r f <<< disklink; cp a.txt $f`, ""},
		{`f=out.txt; command read -r f <<< disklink; cp a.txt $f`, ""},
		{`f=out.txt; printf -v f %s disklink; cp a.txt $f`, ""},
		{`f=out.txt; printf -v other '%n' f; cp a.txt $f`, ""},
		{`f=out.txt; mapfile -t f <<< disklink; cp a.txt $f`, ""},
		{`f=out.txt; readarray -t f <<< disklink; cp a.txt $f`, ""},
		{`f=out.txt; mapfile -C 'f=disklink' -c 1 other <<< data; cp a.txt $f`, ""},
		{`f=out.txt; wait -p f; cp a.txt $f`, ""},
		{`f=out.txt; getopts x f; cp a.txt $f`, ""},
		{`f=out.txt; declare f; cp a.txt $f`, ""},
		{`f=out.txt; declare -n other=f; cp a.txt $f`, ""},
		{`f=out.txt; export f; cp a.txt $f`, ""},
		{`g() { local other; cp a.txt $f; }; f=out.txt; g`, "out.txt"},
		{`g() { declare other=plain; cp a.txt $f; }; f=out.txt; g`, "out.txt"},
		{`g() { local f=disklink; cp a.txt $f; }; f=out.txt; g`, ""},
		{`other=old.txt; read -r other; f=out.txt; cp a.txt $f`, "out.txt"},
		{`one=old.txt; read -r one two; f=out.txt; cp a.txt $f`, "out.txt"},
		{`f=out.txt; read -r f; cp a.txt $f`, ""},
		{`f=out.txt; read -r other f; cp a.txt $f`, ""},
		{`f=out.txt; read -- f; cp a.txt $f`, ""},
		{`f=out.txt; read -rs f; cp a.txt $f`, ""},
		{`f=out.txt; read -a f; cp a.txt $f`, ""},
		{`f=out.txt; read -p prompt f; cp a.txt $f`, ""},
		{`f=out.txt; read -a 'f[x=1]'; cp a.txt $f`, ""},
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

func TestG235BinderOperandRolesMatchBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is unavailable")
	}
	forms := []string{
		"pwd", "pwd -P",
		"read -r other", "read -rs other", "read -rp prompt other",
		"read -r -a other", "read -raother", "read -d: other",
		"read -n1 other", "read -N1 other", "read -t1 other", "read -u0 other",
		"read -r f", "read -a f", "read -af",
		"builtin read -r other", "command read -r other",
		"builtin read -r f", "command read -r f",
		"mapfile -t other", "readarray -t other", "mapfile -t f", "readarray -t f",
		"printf -v other %s disklink", "printf -vother %s disklink",
		"printf -v f %s disklink", "printf -vf %s disklink",
		"printf -v other '%n' f",
		"getopts x other -x", "getopts x f -x",
		"declare other=disklink", "typeset other=disklink", "export other=disklink", "readonly other=disklink",
		"declare f=disklink", "typeset f=disklink", "export f=disklink", "readonly f=disklink",
	}
	for _, form := range forms {
		t.Run(form, func(t *testing.T) {
			command := "f=out.txt; " + form + " <<< disklink; cp a.txt $f"
			file, ok := parseShell(command)
			if !ok {
				t.Fatal("command did not parse")
			}
			var destination *syntax.Word
			syntax.Walk(file, func(node syntax.Node) bool {
				if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) == 3 {
					if program, fixed := StaticWord(call.Args[0], "/home/u"); fixed && program == "cp" {
						destination = call.Args[2]
					}
				}
				return true
			})
			if destination == nil {
				t.Fatal("copy destination not found")
			}
			_, values := knownWordParameters(command, file, "/home/u", nil, nil, true)
			got := values[destination]
			oracle := exec.Command("bash", "-c", "f=out.txt; "+form+" <<< disklink; printf '\\n__F__%s\\n' \"$f\"")
			output, err := oracle.CombinedOutput()
			if err != nil {
				t.Fatalf("bash oracle: %v: %s", err, output)
			}
			marker := strings.LastIndex(string(output), "__F__")
			if marker < 0 {
				t.Fatalf("bash oracle omitted result: %s", output)
			}
			unchanged := strings.TrimSpace(string(output[marker+5:])) == "out.txt"
			if unchanged && got != "out.txt" || !unchanged && got != "" {
				t.Errorf("known value %q disagrees with Bash unchanged=%t", got, unchanged)
			}
		})
	}
}
