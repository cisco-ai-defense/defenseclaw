package psparse

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// review2: new valid-PowerShell lines. § = backtick, ¶ = CRLF, ↵ = LF.
var rev2Lines = []string{
	// A fused arguments
	`Remove-Item C:\a\'b c'\d`, `Remove-Item "C:\a"\b`, `Remove-Item 'C:\a'b`, `Remove-Item C:\a"$env:X"\b`,
	`Remove-Item C:\a'$env:X'\b`, `Remove-Item a'b'"c"d`, `Remove-Item $env:TEMP\x`, `Remove-Item $HOME'\x'`,
	`Remove-Item ${env:TEMP}\x`, `Remove-Item $(Get-Location)\x`, `Remove-Item C:\x,C:\y'z'`, `Remove-Item -Path C:\a'b'`,
	`Remove-Item -Path:C:\a'b c'`, `Remove-Item *'.ps1'`, `Remove-Item .\'a b'`, `Remove-Item ~\'a b'\c`,
	`Remove-Item C:\x\[ab]'c'`, `Write-Output a[0]`, `Write-Output $x[0]b`, `Write-Output $x.y'z'`, `Write-Output a=$x`,
	`Write-Output --foo=bar'baz'`, `Write-Output a,b'c'`, `Write-Output a"b"'c'd"e"`, `Write-Output 1-2-3`, `Write-Output 1.2.3`,
	`Write-Output 1+2`, `Write-Output 1*2`, `Write-Output -1-2`, `Write-Output 0x10-1`, `Write-Output a\[b]`, `Write-Output [a]`,
	`Write-Output [int]`, `Write-Output C:\x\[a]\b`, `Write-Output a(b)`, `Write-Output a$(1)`, `Write-Output $(1)$(2)`,
	`Write-Output "a"$x`, `Write-Output (1)a`, `Write-Output a{b}c`, `Write-Output a@b`, `Write-Output a@(1)`,
	`Write-Output user@host:/path`, `Write-Output a!b`, `Write-Output 'a'#b`, `Write-Output "a"#b`, `Write-Output $x#b`,
	`Write-Output (1)#x`, `Write-Output a<#c#>b`, `Write-Output 'a'<#c#>'b'`, `Remove-Item C:\a\§'b`, `Write-Output 'a'"b"`,
	`Write-Output $x'b'c`, `Write-Output a$x'b'`, `Write-Output ${x}y`, `Write-Output $x:y`, `Write-Output $env:X'y'`,
	`Write-Output a,'b'c,d`, `Write-Output C:\x\*\y`, `Write-Output -a'b'`, `Write-Output -a"b"`, `Write-Output -a$x`,
	`Remove-Item 'C:\x'§'y`, `Write-Output .5x`, `Write-Output 5.x`,
	// B backtick escapes in names / args
	`Rem§ove-Item C:\x`, `R§e§m§o§v§e§-§I§t§e§m C:\x`, `§Remove-Item C:\x`, `Remove-Ite§m C:\x`, `i§ex 'Remove-Item C:\x'`,
	`I§nvoke-Expression 'Remove-Item C:\x'`, `Invoke-Ex§pression 'Remove-Item C:\x'`, `ie§x 'Remove-Item C:\x'`,
	`po§wershell -c Remove-Item C:\x`, `c§md /c del C:\x`, `Remove-Item C:\a§\b`, `Remove-Item C:\a§tb`, `Remove-Item C:\a§0b`,
	`Remove-Item C:\a§ab`, `Remove-Item C:\a§fb`, `Remove-Item C:\a§vb`, `Remove-Item C:\a§rb`, `Write-Output §u{41}`,
	`Write-Output a§u{41}b`, `Write-Output a§e`, `Write-Output §$env:X`, `Write-Output §$(Remove-Item C:\x)`,
	`§$(Remove-Item C:\x)`, `§$x`, `Write-Output §@x`, `Write-Output a§§b`, `Write-Output a§;b`, `Write-Output a§|b`,
	`Write-Output a§#b`, `Write-Output §-Recurse`, `Remove-Item C:\x §-Recurse`, `Write-Output a§ b`, `& Re§move-Item C:\x`,
	`. Re§move-Item C:\x`, `& "Re§move-Item" C:\x`, `Write-Output "a§u{110000}b"`, `Write-Output "a§u{}b"`, `Write-Output "a§u{d800}b"`,
	`Write-Output "a§u{1F600}b"`, `Write-Output §{a}`, `Write-Output §(1)`, `Write-Output a§`, `§u{72}m C:\x`,
	`Write-Output "§$(Remove-Item C:\x)"`, `Remove-Item C:\x§,C:\y`, `Write-Output §'a'`, `Write-Output §§`,
	// C smart quotes and dashes
	`Remove-Item ‘C:\a b’`, `Remove-Item ‚C:\a b‛`, `Remove-Item “C:\$env:X”`, `Remove-Item “C:\a”\b`, `Write-Output ‘a’‘b’`,
	`Write-Output “a“`, `Write-Output 'a’`, `Write-Output ‘a'`, `Write-Output “a"`, `Write-Output "a“`, `Write-Output ‘a’’b’`,
	`Write-Output “a””b”`, `Write-Output “a§”b”`, `Remove-Item –Recurse C:\x`, `Remove-Item —Force C:\x`, `Remove-Item ―Force C:\x`,
	`Write-Output a–b`, `Get-ChildItem –Path:C:\x`, "Write-Output @“↵x $y↵”@", "Write-Output @‘↵x↵’@", `‘Remove-Item C:\x’ | iex`,
	`iex “Remove-Item C:\x”`, `Write-Output “$(Remove-Item C:\x)”`, `Write-Output ”a“`, `Write-Output ‛a‛`, `Write-Output „a"`,
	`Write-Output ‘a’b`, `Write-Output a‘b c’`, `Write-Output 5–3`, `Write-Output ––x`, `Get-Item –Path –x`,
	// D --%
	`Write-Output --% a b`, `Write-Output --% "a b"`, `Write-Output --% a | Remove-Item C:\x`, `Write-Output --% a ; Remove-Item C:\x`,
	`Write-Output --% a "|" b`, `Write-Output --% %TEMP%`, `cmd /c --% del %TEMP%\x`, `Write-Output a --% b`, `Write-Output --%`,
	`Write-Output --%a`, `Write-Output '--%' a`, `Write-Output §--% a`, `Write-Output -- --% a`, `Write-Output --% a && Remove-Item C:\x`,
	"Write-Output --% a↵Remove-Item C:\\x", `Write-Output --% a 2>&1`, `Write-Output --% 'a | b'`, `Write-Output --% a || Remove-Item C:\x`,
	// E nested-script hosts (node level)
	`powershell -ep bypass -c Remove-Item C:\x`, `powershell -c "Remove-Item C:\x"`, `pwsh -nop -c Remove-Item C:\x`,
	`powershell -c - `, `'Remove-Item C:\x' | powershell -`, `Start-Process powershell '-c Remove-Item C:\x'`,
	`Start-Process powershell -Arg '-c Remove-Item C:\x'`, `cmd /c"del C:\x"`, `cmd /cdel C:\x`, `cmd /d /s /c "del C:\x"`,
	`cmd /c git log -n 1`, `& $env:ComSpec /c del C:\x`, `C:\Windows\System32\cmd.exe /c del C:\x & del C:\y`,
	// F param / attributes
	`param($a = (Remove-Item C:\x))`, `param([ValidateScript({Remove-Item C:\x})]$a)`, `function f { param([string]$p = $(Remove-Item C:\x)) }`,
	`function f { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$p) Remove-Item $p }`,
	`param([int]$a = 1, [switch]$b) Remove-Item C:\x`, `& { param($p) Remove-Item $p } C:\x`, `[CmdletBinding()] param() Remove-Item C:\x`,
	`function f([string]$a = (Get-Item C:\x)) { }`, `filter f { param($x) Remove-Item $x }`,
	`param([Alias('p')][string]$Path = "C:\$(Remove-Item C:\y)")`, `[OutputType([string])] param()`,
	`param([ArgumentCompleter({ Remove-Item C:\x })]$a)`, `param($a = @{ k = (Remove-Item C:\x) })`,
	`using namespace System.IO; Remove-Item C:\x`, "#requires -Version 5↵Remove-Item C:\\x",
	`class C { [void] M() { Remove-Item C:\x } }`, `class C { [string] $p = (Remove-Item C:\x) }`, `enum E { A; B }; Remove-Item C:\x`,
	`trap { Remove-Item C:\x }; Get-Item y`, `try { Remove-Item C:\x } catch [System.Exception] { Remove-Item C:\y } finally { Remove-Item C:\z }`,
	`function f { begin { Remove-Item a } process { Remove-Item b } end { Remove-Item c } }`, `function f { dynamicparam { Remove-Item C:\x } }`,
	`function f { clean { Remove-Item C:\x } }`, `function f { param([Parameter(ValueFromPipeline)]$i) process { Remove-Item $i } }`,
	`param([ValidateScript({ $_ -and (Remove-Item C:\x) })][string[]]$a, [System.IO.FileInfo]$b = 'C:\y')`,
	`data { 'x' }; Remove-Item C:\x`, `param([Parameter()][ValidateRange(1,(Get-Random))]$a)`,
	// G numbers
	`Write-Output 0xFFFFFFFF`, `Write-Output 0x80000000`, `Write-Output 12345678901234567`, `Write-Output 9223372036854775808`,
	`Write-Output 1e6`, `Write-Output 1.5mb`, `Write-Output 1.0d`, `Write-Output 1.50d`, `Write-Output 1l`, `Write-Output 1u`,
	`Write-Output 0b101`, `Write-Output 1n`, `Write-Output 1y`, `Write-Output 1uy`, `Write-Output 1s`, `Write-Output 1us`,
	`Write-Output 1ul`, `Write-Output 0x1kb`, `Write-Output 1e-5`, `Write-Output 1e20`, `Write-Output .5`, `Write-Output 5.`,
	`Write-Output 1d`, `Write-Output 0x10L`, `Write-Output 1tb`, `Write-Output 1pb`, `Write-Output 1e309`, `Write-Output 0x`,
	`Write-Output 1kbx`, `Write-Output 1.2e3kb`, `Write-Output 07`, `Write-Output +5`, `Write-Output 1..3`, `Get-Process -Id 0x10`,
	`Write-Output 0xFFFFFFFFFFFFFFFF`, `Write-Output 0xFFFFFFFFu`, `Write-Output 2147483648`, `Write-Output 1e15`, `Write-Output 123456789.123`,
	`Write-Output 0.1`, `Write-Output 1.5e-7`, `Write-Output 1KB`, `Write-Output 0x7fffffffffffffffn`, `Write-Output 1.5n`,
	// H switch
	`switch -Wildcard ('a') { 'a*' { Remove-Item C:\x } }`, `switch -Regex -CaseSensitive ($x) { '^a' { Remove-Item C:\x } default { Remove-Item C:\y } }`,
	`switch -File C:\x.txt { 'a' { Remove-Item C:\y } }`, `switch ($x) { {$_ -gt 1} { Remove-Item C:\x } }`, `switch -w ('a') { a { Remove-Item C:\x } }`,
	`switch -regex -file C:\x { 'a' { break } }`, `switch (Get-ChildItem) { default { Remove-Item $_ } }`,
	`switch ('a','b') { a { Remove-Item C:\x; continue } b { Remove-Item C:\y } }`, `switch ($x) { (Remove-Item C:\x) { 1 } }`,
	`switch -file:C:\x { a { Remove-Item C:\y } }`, `switch -exact -casesensitive ($x) { 'a' { Remove-Item C:\x } }`,
	"switch ($x)↵{↵  'a' { Remove-Item C:\\x }↵}", `switch -regex ($x) { "a$(Remove-Item C:\x)" { 1 } }`,
	// I here-strings CRLF
	"Write-Output @'¶abc¶'@", "Write-Output @\"¶abc $x¶\"@", "Write-Output @'¶a¶b¶'@", "Write-Output @'¶'@", "Write-Output @'¶¶'@",
	"$s = @'¶Remove-Item C:\\x¶'@; iex $s", "@'¶Remove-Item C:\\x¶'@ | iex", "iex @'¶Remove-Item C:\\x¶'@",
	"Write-Output @\"¶$(Remove-Item C:\\x)¶\"@", "Write-Output @'  ¶abc¶'@", "Write-Output @'↵abc¶'@", "Write-Output @'¶a'@b¶'@",
	"Write-Output @\"¶abc\"¶\"@", "Write-Output @'¶abc¶'@; Remove-Item C:\\x", "Write-Output @\"¶§$x¶\"@", "Write-Output @\"¶a\"\"b¶\"@",
	// J pipeline into iex
	`'Remove-Item C:\x' | Invoke-Expression`, `"Remove-Item C:\x" | iex`, `@('Remove-Item C:\x') | iex`, `('Remove-Item C:\x') | iex`,
	`'Remove-Item C:\x' | Out-String | iex`, `Write-Output 'Remove-Item C:\x' | iex`, `Get-Content C:\x.ps1 | iex`,
	`'Remove-Item C:\x' | & iex`, `'Remove-Item C:\x' | Microsoft.PowerShell.Utility\Invoke-Expression`, `iex -C 'Remove-Item C:\x'`,
	// K cmd /c
	`cmd /c "del C:\x"`, `cmd.exe /c del C:\x & del C:\y`, `cmd /V:ON /c del C:\x`, `cmd /k del C:\x`, `& cmd /c del C:\x`,
	`cmd /c del C:\x 2>&1`, `cmd /C del "C:\a b"`, `cmd /r del C:\x`, `CMD /C DEL C:\x`,
}

func rev2Expand(s string) string {
	s = strings.ReplaceAll(s, "§", "`")
	s = strings.ReplaceAll(s, "¶", "\r\n")
	return strings.ReplaceAll(s, "↵", "\n")
}

func TestRev2ValueOracle(t *testing.T) {
	pwsh := os.Getenv("PSPARSE_ORACLE")
	if pwsh == "" {
		t.Skip("PSPARSE_ORACLE unset")
	}
	var texts []string
	for _, s := range rev2Lines {
		texts = append(texts, rev2Expand(s))
	}
	t.Logf("rev2 lines: %d", len(texts))
	in, _ := os.CreateTemp("", "rev2-in-*.b64")
	defer os.Remove(in.Name())
	for _, s := range texts {
		in.WriteString(base64.StdEncoding.EncodeToString([]byte(s)) + "\n")
	}
	in.Close()
	ps1, _ := os.CreateTemp("", "rev2-oracle-*.ps1")
	defer os.Remove(ps1.Name())
	ps1.WriteString(valueOracleScript)
	ps1.Close()
	out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", ps1.Name(), in.Name()).Output()
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	oracle := map[int]ovLine{}
	osc := bufio.NewScanner(strings.NewReader(string(out)))
	osc.Buffer(make([]byte, 1<<20), 1<<24)
	for osc.Scan() {
		var ol ovLine
		if json.Unmarshal([]byte(osc.Text()), &ol) == nil {
			oracle[ol.I] = ol
		}
	}
	cnt := map[string]int{}
	var rep strings.Builder
	desc := func(c *Command) string {
		n, ok := LiteralString(c.Name)
		var b strings.Builder
		fmt.Fprintf(&b, "%q/%v[", n, ok)
		for _, el := range c.Elements {
			switch e := el.(type) {
			case *Parameter:
				fmt.Fprintf(&b, " -%s", strings.ToLower(e.Name))
				if e.Colon != nil {
					v, ok := LiteralString(e.Colon)
					fmt.Fprintf(&b, ":%q/%v", v, ok)
				}
			case *Arg:
				v, ok := LiteralString(e.Value)
				fmt.Fprintf(&b, " %q/%v", v, ok)
			case Expr:
				v, ok := LiteralString(e)
				fmt.Fprintf(&b, " E%q/%v", v, ok)
			}
		}
		b.WriteString(" ]")
		return b.String()
	}
	odesc := func(c ovCmd) string {
		var b strings.Builder
		fmt.Fprintf(&b, "%q/%v[", c.Name.V, c.Name.S)
		for _, e := range c.Els {
			if e.P != "" {
				fmt.Fprintf(&b, " -%s", e.P)
				if e.C != nil {
					fmt.Fprintf(&b, ":%q/%v", e.C.V, e.C.S)
				}
			} else {
				fmt.Fprintf(&b, " %q/%v", e.V, e.S)
			}
		}
		b.WriteString(" ]")
		return b.String()
	}
	for i, s := range texts {
		ol, ok := oracle[i]
		if !ok {
			cnt["oracle-missing"]++
			fmt.Fprintf(&rep, "MISSING #%d %q\n", i, s)
			continue
		}
		tag := "clean"
		if ol.Err {
			tag = "oracle-err"
		}
		cnt["lines "+tag]++
		var mine []*Command
		sc, _ := Parse(s, Options{})
		WalkCommands(sc, func(c *Command) { mine = append(mine, c) })
		var md, od []string
		for _, c := range mine {
			md = append(md, desc(c))
		}
		for _, c := range ol.Cmds {
			od = append(od, odesc(c))
		}
		if strings.Join(md, " ; ") == strings.Join(od, " ; ") {
			cnt["exact "+tag]++
			continue
		}
		kind := "DIFF"
		if len(mine) != len(ol.Cmds) {
			kind = "COUNT"
		}
		cnt[kind+" "+tag]++
		fmt.Fprintf(&rep, "%s %s #%d %q\n   mine:   %s\n   oracle: %s\n", kind, tag, i, s, strings.Join(md, " ; "), strings.Join(od, " ; "))
	}
	var keys []string
	for k := range cnt {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var sum strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&sum, "%-30s %d\n", k, cnt[k])
	}
	if p := os.Getenv("REV2_REPORT"); p != "" {
		os.WriteFile(p, []byte(sum.String()+"\n"+rep.String()), 0o644)
	}
	t.Logf("\n%s", sum.String())
}
