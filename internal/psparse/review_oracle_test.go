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

// Extra valid-PowerShell lines covering the grammar areas of the review (§ = backtick).
var revExtraLines = []string{
	`Remove-Item C:\Users\$env:USERNAME\x`, `Remove-Item C:\a\$(Get-Date)\b`, `Remove-Item C:\a\${env:X}\b`,
	`Remove-Item C:\fo§o`, `Re§move-Item C:\x`, `Write-Output a§nb`, `Write-Output a§$b`, `Write-Output "§u{72}m"`, `Write-Output "§e[0m"`,
	`Write-Output "C:\$1\x"`, `Write-Output "a$?b"`, `Write-Output "cost: $5"`, `Write-Output "$"`, `Write-Output "a$ b"`,
	`Write-Output "${env:TEMP}\x"`, `Write-Output "a""b"`, `Write-Output 'a''b'`, `Write-Output "a§"b"`, `Write-Output "a§§b"`,
	`Write-Output "a$:b"`, `Write-Output "$x:y"`, `Write-Output "a$_b"`, `Write-Output "a$^b"`, `Write-Output "x$$"`,
	`Remove-Item “C:\x y”`, `Remove-Item ‘C:\x y’`, `Remove-Item „C:\x y“`, `Write-Host "a”; Remove-Item C:\x; "b"`,
	`Write-Host 'a’; Remove-Item C:\x; 'b'`, `Write-Output ‘it’’s’`, `Write-Output “say ””hi”””`,
	`Remove-Item C:\Users\'x y'\f`, `Remove-Item *.ps1`, `Remove-Item C:\x\*`, `Remove-Item */*`, `Remove-Item a"b c"d`,
	`Write-Output 0x10`, `Write-Output 1kb`, `Write-Output 1e3`, `Write-Output 1.5`, `Write-Output 10.0.0.1`, `Write-Output -1`,
	`Write-Output - 1`, `Get-Process -Id -1`, `Write-Output (1+2)`, `Write-Output ('a'+'b')`, `Write-Output 'a'+'b'`,
	`Write-Output a-b`, `Write-Output a -b`, `Write-Output -a:b`, `Write-Output -a: b`, `New-Item -Path: C:\x`,
	`New-Item -Path: -Name:child.txt`, `Get-ChildItem -Path:C:\x -Recurse`, `Get-ChildItem -Path:'C:\x y'`,
	`Get-ChildItem -Path:$env:TEMP\x`, `Get-ChildItem . -Recurse`, `git add .`, `git commit -m "msg" -- .`,
	`7z a out.zip C:\secret`, `7z.exe a out.zip C:\secret`, `cmd /c --% echo hi | Remove-Item C:\x`,
	`icacls --% C:\x /grant Everyone:F`, `cmd /c dir 2>&1 >> C:\out.txt`, `Get-Process *> C:\all.txt`,
	`Get-Process 3>&1 2>&1 > out.txt`, "ls §\n  -Recurse", `Get-Item x # comment ; Remove-Item y`, `Get-Item x <# c #> -Force`,
	`Get-Item a#b`, `Get-Item a<#b#>c`, `Get-Item --name x`, `Get-Item -- -x`, `& { Remove-Item C:\x }`, `. { Remove-Item C:\x }`,
	`& 'C:\Program Files\x.exe' -a`, `& $env:ComSpec /c del C:\x`, `switch -regex (Get-Item x) { 'a' { Remove-Item y } }`,
	`$h = @{ Path = 'C:\x' }; Remove-Item @h`, `Remove-Item -Path C:\x,C:\y`, `Remove-Item C:\x, C:\y`,
	`powershell -enc ZQBjAGgAbwA=`, `powershell -NoP -NonI -W Hidden -Exec Bypass -Enc ZQBjAGgAbwA=`, `powershell /c Remove-Item C:\x`,
	`powershell –Command Remove-Item C:\x`, `Get-Item —Path C:\x`, `'Remove-Item C:\x' | iex`, `Write-Output $x.y`, `Write-Output $x[0]`,
	`Write-Output $x-1`, `Write-Output a$x`, `Write-Output "a"b`, `Write-Output a"b"`, `Write-Output a'b'`, `Write-Output $x"a"`,
	`Write-Output $x'a'`, `Write-Output (Get-Date).Year`, `Write-Output $(1)x`, `Get-Content -Raw:$true x`,
	`Get-Content x | Out-File -FilePath C:\y -Encoding utf8`, `$x = Get-Item C:\x; Remove-Item $x`,
	`foreach ($f in Get-ChildItem) { Remove-Item $f }`, "Write-Output @'\nliteral $x\n'@", "Write-Output @\"\nexp $x\n\"@",
	"Write-Output @\"\nnot \"@ end\n\"@", "Write-Output @'\r\nabc\r\n'@", `Write-Output C:\x\[a]`, `Write-Output [a]b`,
	`Write-Output %USERPROFILE%\x`, `Write-Output a=b`, `Write-Output a,b`, `Write-Output @(1,2)`, `Write-Output !x`,
	`Write-Output ~\x`, `Write-Output ..\x`, `Write-Output .\x`, `Write-Output $true`, `Write-Output a:b`, `Write-Output :a`,
	`Write-Output \\server\share`, `Write-Output http://h/a?b=c&d`, `Write-Output a&b`, `Write-Output 'a' 'b'`,
	`Write-Output a{b}`, `Write-Output {a}`, `Write-Output a}b`, `Write-Output 1.txt`, `Write-Output 1-2`, `Write-Output 2>x`,
	`Remove-Item C:\x 2>$null`, `Write-Output a2>x`, `Copy-Item -Path:C:\a -Destination:C:\b`, `Copy-Item C:\a -Destination C:\b`,
	`iex "Remove-Item C:\x"`, `iex 'Remove-Item C:\x'`, `pwsh -c 'Remove-Item C:\x'`, `pwsh -Command "Remove-Item $env:TEMP"`,
	`Write-Output "a$(1)b"`, `Write-Output "a$($x.y)b"`, `Write-Output "a$x.y"`, `Write-Output "a$x[0]"`, `Write-Output "$($x)"`,
	`Write-Output "a§$(1)"`, `Write-Output "a§§$(1)"`, `Write-Output 'a$(1)'`, `Write-Output "a§u{0}b"`, `Write-Output "§0"`,
	`Write-Output a§ b`, `Write-Output "a§`, `Write-Output §"a§"`, `Write-Output §'a§'`, `Write-Output a§'b`,
	`Write-Output -Name:"x y"`, `Write-Output -Name:'x'`, `Write-Output -Name:$x`, `Write-Output -Name:(1)`, `Write-Output -Name:a,b`,
	// review 4 R4-2: comma/array arguments split element by element
	`Remove-Item C:\tmp\a,C:\Windows`, `Remove-Item -Path C:\tmp\a, C:\Windows -Recurse`,
	`Remove-Item -Path:C:\a,C:\b`, `Write-Output 'C:\tmp\a','C:\Windows'`,
	`Write-Output C:\a, 'C:\b', "C:\c"`, `Copy-Item C:\a,C:\Windows\System32\x.dll C:\dst`,
}

func bq2(s string) string { return strings.ReplaceAll(s, "§", "`") }

type ovVal struct {
	S bool    `json:"s"`
	V string  `json:"v"`
	P string  `json:"p"`
	C *ovVal  `json:"c"`
	L []ovVal `json:"l"` // elements of a comma/array argument (review 4 R4-2)
}
type ovCmd struct {
	Name ovVal   `json:"name"`
	Els  []ovVal `json:"els"`
}
type ovLine struct {
	I    int     `json:"i"`
	Err  bool    `json:"err"`
	Cmds []ovCmd `json:"cmds"`
}

func TestRevValueOracle(t *testing.T) {
	pwsh := os.Getenv("PSPARSE_ORACLE")
	if pwsh == "" {
		t.Skip("PSPARSE_ORACLE unset")
	}
	var texts []string
	seen := map[string]bool{}
	add := func(s string) {
		if strings.TrimSpace(s) != "" && !seen[s] {
			seen[s] = true
			texts = append(texts, s)
		}
	}
	for _, p := range strings.Split(os.Getenv("PSPARSE_CORPUS"), ":") {
		if p == "" {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<22)
		for sc.Scan() {
			var row struct {
				Text string `json:"text"`
			}
			if json.Unmarshal(sc.Bytes(), &row) == nil {
				add(row.Text)
			}
		}
		f.Close()
	}
	nCorpus := len(texts)
	for _, s := range revExtraLines {
		add(bq2(s))
	}
	in, _ := os.CreateTemp("", "rev-in-*.b64")
	defer os.Remove(in.Name())
	for _, s := range texts {
		in.WriteString(base64.StdEncoding.EncodeToString([]byte(s)) + "\n")
	}
	in.Close()
	ps1, err := os.CreateTemp("", "rev-oracle-*.ps1")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(ps1.Name())
	ps1.WriteString(valueOracleScript)
	ps1.Close()
	out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", ps1.Name(), in.Name()).Output()
	if err != nil {
		t.Fatalf("oracle: %v %s", err, tailStderr(err))
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
	type mineEl struct {
		param   string
		ok      bool
		v       string
		colon   bool
		colonOK bool
		colonV  string
	}
	cnt := map[string]int{}
	var report strings.Builder
	for i, s := range texts {
		ol, ok := oracle[i]
		if !ok {
			cnt["oracle-missing"]++
			continue
		}
		src := "corpus"
		if i >= nCorpus {
			src = "extra"
		}
		tag := src
		if ol.Err {
			tag += "/oracle-err"
		}
		cnt["lines "+tag]++
		var mine []*Command
		psc, _ := Parse(s, Options{})
		WalkCommands(psc, func(c *Command) { mine = append(mine, c) })
		if len(mine) != len(ol.Cmds) {
			cnt["count-mismatch "+tag]++
			fmt.Fprintf(&report, "COUNT %s #%d mine=%d oracle=%d: %q\n", tag, i, len(mine), len(ol.Cmds), s)
			continue
		}
		for ci, c := range mine {
			oc := ol.Cmds[ci]
			if v, ok := LiteralString(c.Name); ok && (!oc.Name.S || v != oc.Name.V) {
				cnt["WRONG-STATIC-name "+tag]++
				fmt.Fprintf(&report, "WRONGNAME %s #%d mine=%q oracle(s=%v,%q): %q\n", tag, i, v, oc.Name.S, oc.Name.V, s)
			}
			var els []mineEl
			for _, el := range c.Elements {
				switch e := el.(type) {
				case *Parameter:
					me := mineEl{param: strings.ToLower(e.Name), colon: e.Colon != nil}
					if e.Colon != nil {
						me.colonV, me.colonOK = LiteralString(e.Colon)
					}
					els = append(els, me)
				case *Arg:
					v, ok := LiteralString(e.Value)
					els = append(els, mineEl{ok: ok, v: v})
				case Expr:
					v, ok := LiteralString(e)
					els = append(els, mineEl{ok: ok, v: v})
				}
			}
			if len(els) != len(oc.Els) {
				cnt["element-count-mismatch "+tag]++
				fmt.Fprintf(&report, "ELS %s #%d cmd%d mine=%d oracle=%d: %q\n", tag, i, ci, len(els), len(oc.Els), s)
				continue
			}
			for k, me := range els {
				o := oc.Els[k]
				if me.param != "" || o.P != "" {
					if me.param != o.P {
						cnt["param-mismatch "+tag]++
						fmt.Fprintf(&report, "PARAM %s #%d mine=%q oracle=%q: %q\n", tag, i, me.param, o.P, s)
						continue
					}
					if me.colon && me.colonOK && (o.C == nil || !o.C.S || o.C.V != me.colonV) {
						cnt["WRONG-STATIC-colon "+tag]++
						fmt.Fprintf(&report, "WRONGCOLON %s #%d mine=%q oracle=%+v: %q\n", tag, i, me.colonV, o.C, s)
					}
					continue
				}
				if me.ok && (!o.S || o.V != me.v) {
					cnt["WRONG-STATIC-arg "+tag]++
					fmt.Fprintf(&report, "WRONGARG %s #%d el%d mine=%q oracle(s=%v,%q): %q\n", tag, i, k, me.v, o.S, o.V, s)
				} else if !me.ok && o.S {
					cnt["under-static(ok) "+tag]++
				} else {
					cnt["agree "+tag]++
				}
			}
		}
	}
	var keys []string
	for k := range cnt {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var sum strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&sum, "%-45s %d\n", k, cnt[k])
	}
	if p := os.Getenv("REV_REPORT"); p != "" {
		os.WriteFile(p, []byte(sum.String()+"\n"+report.String()), 0o644)
	}
	t.Logf("\n%s", sum.String())
	// Value gate: no WRONG-STATIC result is allowed on an oracle-clean line
	// (LiteralString must never report a static value PowerShell disagrees
	// with). count/element mismatches are reported but not gated here (the
	// --% verbatim tail legitimately differs in element shape).
	wrong := cnt["WRONG-STATIC-arg corpus"] + cnt["WRONG-STATIC-name corpus"] + cnt["WRONG-STATIC-colon corpus"] +
		cnt["WRONG-STATIC-arg extra"] + cnt["WRONG-STATIC-name extra"] + cnt["WRONG-STATIC-colon extra"]
	if wrong > 0 {
		t.Errorf("value gate: %d WRONG-STATIC result(s) on oracle-clean lines (floor is 0); set REV_REPORT to see them", wrong)
	}
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

const valueOracleScript = `
param([string]$InFile)
$ErrorActionPreference = 'Stop'
function V($el) {
  if ($null -eq $el) { return [ordered]@{ s = $false; v = '' } }
  $tn = $el.GetType().Name
  if ($tn -eq 'StringConstantExpressionAst' -or $tn -eq 'ConstantExpressionAst') { return [ordered]@{ s = $true; v = [string]$el.Value } }
  if ($tn -eq 'ArrayLiteralAst') {
    $parts = New-Object System.Collections.ArrayList
    foreach ($x in $el.Elements) { [void]$parts.Add((V $x)) }
    return [ordered]@{ s = $false; v = ''; l = $parts }
  }
  return [ordered]@{ s = $false; v = '' }
}
$lines = [System.IO.File]::ReadAllLines($InFile)
$i = -1
foreach ($line in $lines) {
  $i++
  $text = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($line))
  $errs = $null; $toks = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$toks, [ref]$errs)
  $hadErr = ($errs -ne $null -and $errs.Count -gt 0)
  $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
  $out = New-Object System.Collections.ArrayList
  foreach ($c in $cmds) {
    $els = $c.CommandElements
    $name = V $els[0]
    $ea = New-Object System.Collections.ArrayList
    for ($k = 1; $k -lt $els.Count; $k++) {
      $el = $els[$k]
      if ($el.GetType().Name -eq 'CommandParameterAst') {
        $cv = $null; if ($el.Argument -ne $null) { $cv = V $el.Argument }
        [void]$ea.Add([ordered]@{ p = ([string]$el.ParameterName).ToLower(); c = $cv })
      } else { [void]$ea.Add((V $el)) }
    }
    [void]$out.Add([ordered]@{ name = $name; els = $ea })
  }
  Write-Output ([ordered]@{ i = $i; err = $hadErr; cmds = $out } | ConvertTo-Json -Compress -Depth 20)
}
`
