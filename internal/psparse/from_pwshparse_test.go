// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"bufio"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// adapterView is the part of a Script the effects frontend reads: every command
// (operator, name, parameters, argument kinds, redirections, --%), the literal
// value of every name and argument, and the nested scripts.
func adapterView(sc *Script) string {
	var b strings.Builder
	inv := Project(sc)
	j, _ := json.Marshal(inv)
	b.Write(j)
	WalkCommands(sc, func(c *Command) {
		v, ok := LiteralString(c.Name)
		fmt.Fprintf(&b, "\n[%s %q %v]", c.InvokeOp, v, ok)
		for _, el := range c.Elements {
			switch e := el.(type) {
			case *Parameter:
				cv, cok := "", false
				if e.Colon != nil {
					cv, cok = LiteralString(e.Colon)
				}
				fmt.Fprintf(&b, " P(%s %q %v %q %v)", e.Name, e.Raw, e.HasColon, cv, cok)
			case *Arg:
				av, aok := LiteralString(e.Value)
				fmt.Fprintf(&b, " A(%q %v)", av, aok)
			}
		}
		for _, r := range c.Redirs {
			tv, tok := "", false
			if r.Target != nil {
				tv, tok = LiteralString(r.Target)
			}
			fmt.Fprintf(&b, " R(%s %s %q %v)", r.Op, r.Merge, tv, tok)
		}
		if c.StopParsing != "" {
			fmt.Fprintf(&b, " S(%q)", c.StopParsing)
		}
	})
	for _, ns := range ExtractNestedScripts(sc) {
		fmt.Fprintf(&b, "\nN(%s %s %v %q %s)", ns.Kind, ns.Dialect, ns.Static, ns.Text, ns.Reason)
	}
	return b.String()
}

// TestFromPwshparseMatchesParse: on inputs where psparse.Parse reads the same
// commands as pwsh, the adapter builds the same view field by field.
func TestFromPwshparseMatchesParse(t *testing.T) {
	cases := []string{
		`Remove-Item -Path C:\tmp\x -Recurse -Force`,
		`Get-ChildItem C:\work | Remove-Item -Force`,
		`del C:\x.txt; rm -r -fo .\build`,
		`& 'C:\tools\x.exe' --flag value`,
		`. .\setup.ps1`,
		`& $cmd arg`,
		`Set-Content -Path:out.txt -Value 'a''b'`,
		`Write-Output "hello $env:USERNAME" > out.txt 2>&1`,
		`Get-Process *>> all.log`,
		`cmd /c del C:\x`,
		`powershell -NoProfile -Command "Remove-Item C:\x -Recurse"`,
		`pwsh -c 'Remove-Item C:\y'`,
		`Invoke-Expression 'Remove-Item C:\z'`,
		`iex "rm C:\q"`,
		`icacls C:\x --% /grant Everyone:F`,
		`if ($a) { Remove-Item a } else { Remove-Item b }`,
		`foreach ($f in Get-ChildItem) { Remove-Item $f }`,
		`function Clean { param($p) Remove-Item $p -Recurse }; Clean C:\x`,
		`$x = Get-Item C:\x; $x | Remove-Item`,
		`Start-Process cmd -ArgumentList '/c','del C:\x'`,
		`[scriptblock]::Create('Remove-Item C:\x').Invoke()`,
		`Copy-Item a,b,c -Destination D:\out`,
		`git push && Remove-Item x || Write-Output fail`,
		`Get-Content x | ForEach-Object { Remove-Item $_ }`,
		`Remove-Item (Join-Path $env:TEMP x) -Force`,
		`New-Item -ItemType Directory -Path @("a","b")`,
		`Set-ItemProperty -Path HKCU:\Software\X -Name y -Value 1`,
		`$h = @{ Path = 'C:\x'; Force = $true }; Remove-Item @h`,
		"Remove-Item `\n  -Path C:\\x",
		`Write-Host héllo > C:\tmp\é.txt`,
	}
	for _, src := range cases {
		ps, _ := Parse(src, Options{Dialect: DialectUnknown})
		pw, ok := FromPwshparse(src, Options{Dialect: DialectUnknown})
		if !ok {
			t.Errorf("FromPwshparse declined %q", src)
			continue
		}
		if a, b := adapterView(ps), adapterView(pw); a != b {
			t.Errorf("view differs for %q\npsparse: %s\nadapter: %s", src, a, b)
		}
	}
}

// TestFromPwshparseShapes pins the conventions the adapter keeps from Parse.
func TestFromPwshparseShapes(t *testing.T) {
	sc, ok := FromPwshparse("Write-Output x >> a.log 2>&1; icacls y --% /grant E:F", Options{Dialect: DialectUnknown})
	if !ok {
		t.Fatal("declined")
	}
	var cmds []*Command
	WalkCommands(sc, func(c *Command) { cmds = append(cmds, c) })
	if len(cmds) != 2 {
		t.Fatalf("commands = %d, want 2", len(cmds))
	}
	r := cmds[0].Redirs
	if len(r) != 2 || r[0].Op != ">>" || r[1].Op != "2>" || r[1].Merge != "1" {
		t.Errorf("redirections = %+v", r)
	}
	if cmds[1].StopParsing != " /grant E:F" && cmds[1].StopParsing != "/grant E:F" {
		t.Errorf("stop-parsing tail = %q", cmds[1].StopParsing)
	}
	// a backtick-e under DialectUnknown is not static, in a name and in an argument
	sc, _ = FromPwshparse("Remove-It`em x`e", Options{Dialect: DialectUnknown})
	WalkCommands(sc, func(c *Command) {
		if _, ok := LiteralString(c.Elements[0].(*Arg).Value); ok {
			t.Error("backtick-e argument resolved static under DialectUnknown")
		}
	})
	// offsets are byte offsets with non-ASCII text before the command
	src := "'é' | Out-Null; Remove-Item C:\\x"
	sc, _ = FromPwshparse(src, Options{Dialect: DialectUnknown})
	WalkCommands(sc, func(c *Command) {
		if v, _ := LiteralString(c.Name); v == "Remove-Item" {
			if s, _ := c.Span(); !strings.HasPrefix(src[s:], "Remove-Item") {
				t.Errorf("command span starts at %d: %q", s, src[s:])
			}
		}
	})
}

// TestFromPwshparseFixture reads every public oracle row with both parsers and
// reports, per view field, the rows where they differ. psparse is wrong on some
// rows (scripts/pwshoracle compare reports), so this counts and never fails on
// a difference; it fails on a panic or a decline outside the depth budget.
func TestFromPwshparseFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("fixture sweep")
	}
	f, err := os.Open(filepath.Join("..", "..", "scripts", "pwshoracle", "fixture", "pub.b64.gz"))
	if err != nil {
		t.Skip(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	rows, declined, same, projDiff, litDiff, nestDiff := 0, 0, 0, 0, 0, 0
	for sc.Scan() {
		raw, err := base64.StdEncoding.DecodeString(sc.Text())
		if err != nil {
			continue
		}
		rows++
		src := string(raw)
		pw, ok := FromPwshparse(src, Options{Dialect: DialectUnknown})
		if !ok {
			declined++
			continue
		}
		ps, _ := Parse(src, Options{Dialect: DialectUnknown})
		a, b := adapterView(ps), adapterView(pw)
		if a == b {
			same++
			continue
		}
		ja, jb, _ := strings.Cut(a, "\n")
		_ = jb
		ka, _, _ := strings.Cut(b, "\n")
		if ja != ka {
			projDiff++
		}
		na, nb := strings.Count(a, "\nN("), strings.Count(b, "\nN(")
		if na != nb || nestedPart(a) != nestedPart(b) {
			nestDiff++
		}
		if ja == ka {
			litDiff++
		}
	}
	t.Logf("rows %d declined %d same %d differ %d (projection %d, literal values only %d, nested %d)",
		rows, declined, same, rows-declined-same, projDiff, litDiff, nestDiff)
	if declined > 20 {
		t.Errorf("declined %d rows (depth budget declines are expected on ~11)", declined)
	}
}

func nestedPart(v string) string {
	if i := strings.Index(v, "\nN("); i >= 0 {
		return v[i:]
	}
	return ""
}

// TestFromPwshparseWordQuotes: an expandable bareword drops its inner quote
// delimiters as pwsh does. Oracle (pwsh 7.6.6 ExpandableStringExpressionAst
// .Value, BareWord): $HOME'\x' -> $HOME\x, a"$v"x -> a$vx.
// The adapter kept the quotes in the literal atoms, so Remove-Item $HOME'\x'
// deleted a "C:\Users\alice'\x'" target instead of the home subfolder.
func TestFromPwshparseWordQuotes(t *testing.T) {
	cases := []struct{ src, want string }{
		{`Remove-Item $HOME'\x'`, `${HOME}\x`},
		{`tool a"$v"x`, `a${v}x`},
		{`tool $env:TEMP"\y z"`, `${env:TEMP}\y z`},
		{`tool $a'it''s'`, `${a}it's`},
		{`tool $a"q""t"`, `${a}q"t`},
		{`tool $a'"'`, `${a}"`},
		{`tool $a"'"`, `${a}'`},
		{`tool $a\b`, `${a}\b`},
	}
	for _, c := range cases {
		sc, ok := FromPwshparse(c.src, Options{Dialect: DialectPwsh7})
		if !ok {
			t.Fatalf("declined %q", c.src)
		}
		var got string
		WalkCommands(sc, func(cm *Command) {
			for _, el := range cm.Elements {
				arg, ok := el.(*Arg)
				if !ok {
					continue
				}
				sl, ok := arg.Value.(*StringLit)
				if !ok || sl.Static {
					continue
				}
				var b strings.Builder
				for _, p := range sl.Parts {
					if v, ok := p.Expr.(*Variable); ok {
						n := v.Name
						if v.Scope != "" {
							n = v.Scope + ":" + n
						}
						b.WriteString("${" + n + "}")
					} else if s, ok := LiteralString(p.Expr); ok {
						b.WriteString(s)
					} else {
						fmt.Fprintf(&b, "<%T>", p.Expr)
					}
				}
				got = b.String()
			}
		})
		if got != c.want {
			t.Errorf("%q: word = %q, want %q", c.src, got, c.want)
		}
	}
}
