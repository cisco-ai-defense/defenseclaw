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
		{`cmd /c "dir C:\"`, KindCmdC, "cmd", `dir C:\`, true},
		{`Start-Process powershell -ArgumentList '-Command','calc.exe'`, KindStartProcessArgs, "powershell", "calc.exe", true},
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
	sc, _ := Parse(`x ('a' + 'b' + 'c')`, Options{})
	var got string
	WalkCommands(sc, func(c *Command) {
		if n, _ := LiteralString(c.Name); n == "x" {
			for _, el := range c.Elements {
				if a, ok := el.(*Arg); ok {
					if s, ok := LiteralString(a.Value); ok {
						got = s
					}
				}
			}
		}
	})
	if got != "abc" {
		t.Errorf("literal concat: got %q want abc", got)
	}
}
