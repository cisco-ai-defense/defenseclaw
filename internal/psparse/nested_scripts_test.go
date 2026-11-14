// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

func TestExtractNestedScripts(t *testing.T) {
	cases := []struct {
		src     string
		kind    string
		dialect string
		text    string
		static  bool
	}{
		{`powershell -Command "whoami"`, KindPowerShellCommand, "powershell", "whoami", true},
		{`pwsh -c 'Get-Date'`, KindPowerShellCommand, "powershell", "Get-Date", true},
		{`powershell.exe -ExecutionPolicy Bypass -Command "Remove-Item x"`, KindPowerShellCommand, "powershell", "Remove-Item x", true},
		{`powershell -EncodedCommand ZQBjAGgAbwAgAGgAaQA=`, KindEncodedCommand, "powershell", "echo hi", true},
		{`iex 'whoami'`, KindIEXLiteral, "powershell", "whoami", true},
		{`Invoke-Expression "hostname"`, KindIEXLiteral, "powershell", "hostname", true},
		{`[scriptblock]::Create('calc.exe')`, KindScriptBlockCreate, "powershell", "calc.exe", true},
		{`cmd /c "dir C:\"`, KindCmdC, "cmd", "", false}, // a payload word with a quote is NotStatic (review 9 R9-2)
		{`cmd /c dir C:\`, KindCmdC, "cmd", `dir C:\`, true},
		// review 5: Start-Process argv is not modelled -> always opaque (ps_child_argv)
		{`Start-Process powershell -ArgumentList '-Command','calc.exe'`, KindStartProcessArgs, "powershell", "", false},
	}
	for _, c := range cases {
		sc, _ := Parse(c.src, Options{})
		got := ExtractNestedScripts(sc)
		if len(got) == 0 {
			t.Errorf("%q: no nested script extracted", c.src)
			continue
		}
		ns := got[0]
		if ns.Kind != c.kind || ns.Dialect != c.dialect || ns.Static != c.static || ns.Text != c.text {
			t.Errorf("%q:\n got  kind=%s dialect=%s static=%v text=%q\n want kind=%s dialect=%s static=%v text=%q",
				c.src, ns.Kind, ns.Dialect, ns.Static, ns.Text, c.kind, c.dialect, c.static, c.text)
		}
	}
}

func TestExtractNestedScriptsDynamicNotDropped(t *testing.T) {
	// A non-literal payload must be reported, not dropped, with a reason.
	for _, src := range []string{`iex $cmd`, `powershell -Command $payload`, `[scriptblock]::Create($x)`} {
		sc, _ := Parse(src, Options{})
		got := ExtractNestedScripts(sc)
		if len(got) == 0 {
			t.Errorf("%q: dynamic payload dropped", src)
			continue
		}
		if got[0].Static || got[0].Reason == "" {
			t.Errorf("%q: expected Static=false with a Reason, got %+v", src, got[0])
		}
	}
}

func TestLiteralStringConcat(t *testing.T) {
	// A parenthesised argument is a ParenExpression on the reference side, so
	// LiteralString must report it non-static (not evaluate the concatenation).
	sc, _ := Parse(`x ('a' + 'b' + 'c')`, Options{})
	WalkCommands(sc, func(c *Command) {
		if n, _ := LiteralString(c.Name); n != "x" {
			return
		}
		for _, el := range c.Elements {
			if a, ok := el.(*Arg); ok {
				if v, ok := LiteralString(a.Value); ok {
					t.Errorf("parenthesised arg resolved static %q; want non-static", v)
				}
			}
		}
	})
	// A + concatenation of string literals passed directly (no parens) is also
	// a binary expression -> non-static.
	if v, ok := LiteralString(&Binary{Op: "+", LHS: &StringLit{Static: true, Value: "a"}, RHS: &StringLit{Static: true, Value: "b"}}); ok {
		t.Errorf("binary + resolved static %q; want non-static", v)
	}
}
