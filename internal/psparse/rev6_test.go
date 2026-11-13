// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"
)

// r6enc encodes a string as PowerShell -EncodedCommand (base64 of UTF-16LE).
func r6enc(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// rev6Lines is the delta-review-6 probe corpus (reviewer
// claude:d4a4f3ed/s7-pwsh-review6, 2026-11-13): host CLI spellings and forms,
// the stdin `-` forms (R6-1), cmd payload forms (R6-2), legacy trailing-
// backslash quoting (R6-3), launchers, splatting, here-strings, iex pipelines,
// and -EncodedCommand variants. Folded into goldenCorpus so the pwsh 7.7 value
// golden gate covers them permanently. (§ = backtick, ↵ = LF.)
func rev6Lines() []string {
	E := r6enc
	l := []string{
		// A host CLI spellings and forms
		`powershell -c 'Remove-Item C:\x'`, `powershell.exe -c 'Remove-Item C:\x'`, `PowerShell.EXE -Command 'Remove-Item C:\x'`,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c 'Remove-Item C:\x'`, `& powershell -c 'Remove-Item C:\x'`,
		`& 'powershell.exe' -c 'Remove-Item C:\x'`, `& "C:\Program Files\PowerShell\7\pwsh.exe" -c 'Remove-Item C:\x'`, `. pwsh -c 'Remove-Item C:\x'`,
		`pwsh --command 'Remove-Item C:\x'`, `pwsh --c 'Remove-Item C:\x'`, `pwsh /c 'Remove-Item C:\x'`, `powershell /Command 'Remove-Item C:\x'`,
		"pwsh \u2013c 'Remove-Item C:\\x'", "pwsh \u2014Command 'Remove-Item C:\\x'", "pwsh \u2015c 'Remove-Item C:\\x'",
		`pwsh -co 'Remove-Item C:\x'`, `pwsh -comm 'Remove-Item C:\x'`, `pwsh -nop -noni -w hidden -ep bypass -c 'Remove-Item C:\x'`,
		`powershell 'Remove-Item C:\x'`, `powershell Remove-Item C:\x`, `pwsh -c Remove-Item C:\x`, `pwsh -nop 'Remove-Item C:\x'`,
		`pwsh -cwa 'Remove-Item $args[0]' C:\x`, `pwsh -CommandWithArgs 'Remove-Item C:\x'`, `pwsh -f C:\x.ps1`, `pwsh C:\x.ps1`,
		`pwsh -File C:\x.ps1 -c 'Remove-Item C:\y'`, `pwsh -c 'Remove-Item C:\x' -nop`, `pwsh -c Remove-Item 'C:\x'`, `pwsh -c 'Remove-Item' 'C:\x'`,
		`pwsh -c {Remove-Item C:\x}`, `powershell {Remove-Item C:\x}`, `pwsh -nop -c {Remove-Item C:\x} -args a`, `pwsh -c $cmd`,
		`pwsh -c "Remove-Item $env:X"`, `pwsh -Version 5.1 -c 'Remove-Item C:\x'`, `powershell -Version 2 -c 'Remove-Item C:\x'`,
		`pwsh -wd C:\ -c 'Remove-Item C:\x'`, `pwsh -WorkingDirectory C:\ -c 'Remove-Item C:\x'`, `pwsh -o xml -c 'Remove-Item C:\x'`,
		`pwsh -if text -c 'Remove-Item C:\x'`, `pwsh -sta -c 'Remove-Item C:\x'`, `pwsh -login -c 'Remove-Item C:\x'`, `pwsh -l -c 'Remove-Item C:\x'`,
		`pwsh -c:'Remove-Item C:\x'`, `pwsh -Command:'Remove-Item C:\x'`, `pwsh -nop:$true -c 'Remove-Item C:\x'`, `pwsh -c 'Get-Date' -c 'Remove-Item C:\x'`,
		`pwsh -nop -File -`, `pwsh -File - extra`, `pwsh -File:-`, `pwsh -File '-'`, `pwsh --% -`, `pwsh --% -c -`, `pwsh --% -File -`, `pwsh -nop --% -`,
		`pwsh -c - `, `pwsh -c -`, `pwsh -File -`, `pwsh -`, `pwsh -c ''`, `pwsh -c ' '`, `pwsh -c`, `pwsh`,
		`pwsh -c Write-Output --% ; Remove-Item C:\x`, `pwsh --% -c Remove-Item C:\x`, `powershell -c 'Write-Output' --% "a;Remove-Item C:\x"`,
		`pwsh -c Write-Output a,b`, `pwsh -c 'Write-Output',"a;Remove-Item C:\x"`, `pwsh -c @('Remove-Item','C:\x')`, `pwsh -c ('Remove-Item C:\x')`,
		`pwsh -c "Remove-Item C:\x"`, `pwsh -c "Remove-Item 'C:\x'"`, `pwsh -c 'Remove-Item C:\x' 2>&1`, `pwsh -c 'Remove-Item C:\x' > out.txt`,
		`pwsh -c 'Remove-Item C:\x' | Out-Null`, `$r = pwsh -c 'Remove-Item C:\x'`, `pwsh -c 'Remove-Item C:\x' && Get-Date`, `if (1) { pwsh -c 'Remove-Item C:\x' }`,
		`pwsh -c 'Write-Output a' 'b' 'c;Remove-Item C:\x'`, `pwsh -c 'Write-Output a#' 'Remove-Item C:\x'`, `pwsh -c 'Write-Output <#' '#> ; Remove-Item C:\x'`,
		// legacy (5.1) quoting without a double quote in the text: trailing backslash before an added quote
		`powershell -c 'Write-Output x\' '''$(Remove-Item(''C:\Windows''))''' 'a b\'`,
		`powershell -c 'Write-Output x\' '$(Remove-Item(''C:\Windows''))' 'a b\'`,
		`powershell -c 'Write-Output a\' 'b'`, `powershell -c 'Remove-Item C:\x\'`, `powershell -c 'Write-Output C:\a b\\'`,
		`powershell -c 'Write-Output x\' '''$(Remove-Item(''C:\Windows''))''#' 'a b\'`,
		`cmd /c 'echo x\' 'a b\'`,
		// B cmd
		`cmd /c del C:\x`, `cmd.exe /c 'del C:\x'`, `cmd /k del C:\x`, `cmd /r del C:\x`, `cmd /C del C:\x`, `cmd /s /c 'del C:\x'`, `cmd /q /c del C:\x`,
		`cmd /v:on /c 'del !x!'`, `cmd /cdel C:\x`, `cmd /d/c del C:\x`, `cmd "/c del C:\x"`, `C:\Windows\System32\cmd.exe /c del C:\x`, `& cmd /c del C:\x`,
		`cmd /c start powershell -c Remove-Item C:\x`, `cmd /c powershell -c 'Remove-Item C:\x'`, `cmd /c 'del %SystemRoot%\x'`, `cmd /c del C:\x ^& del C:\y`,
		`cmd /c del C:\x '&' del C:\y`, `cmd /c --% del C:\x & del C:\y`, `cmd /c 'del "C:\x"'`, `cmd /u /c del C:\x`, `cmd /e:on /c del C:\x`, `cmd /c`, `cmd`,
		`cmd /c $x`, `cmd /c @a`, `cmd @a`, `cmd -c del C:\x`,
		// C other launchers
		`Invoke-Command -ScriptBlock {Remove-Item C:\x}`, `icm {Remove-Item C:\x}`, `Invoke-Command -ComputerName h -ScriptBlock {Remove-Item C:\x}`,
		`Invoke-Command -FilePath C:\x.ps1`, `Invoke-Command -ScriptBlock ([scriptblock]::Create('Remove-Item C:\x'))`, `Invoke-Command ([scriptblock]::Create('Remove-Item C:\x'))`,
		`[Diagnostics.Process]::Start('powershell','-c Remove-Item C:\x')`, `[System.Diagnostics.Process]::Start('cmd','/c del C:\x')`,
		`[Diagnostics.ProcessStartInfo]::new('cmd','/c del C:\x')`, `(New-Object Diagnostics.Process).Start()`,
		`Start-Job {Remove-Item C:\x}`, `Start-Job -ScriptBlock {Remove-Item C:\x}`, `Start-ThreadJob {Remove-Item C:\x}`, `Start-Job -InitializationScript {Remove-Item C:\x} {1}`,
		`Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='cmd /c del C:\x'}`,
		`Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'cmd /c del C:\x'`, `([wmiclass]'Win32_Process').Create('cmd /c del C:\x')`,
		`wmic process call create 'cmd /c del C:\x'`, `$ExecutionContext.InvokeCommand.InvokeScript('Remove-Item C:\x')`,
		`[powershell]::Create().AddScript('Remove-Item C:\x').Invoke()`, `& ([scriptblock]::Create('Remove-Item C:\x'))`, `. ([scriptblock]::Create('Remove-Item C:\x'))`,
		`Invoke-Expression -Command 'Remove-Item C:\x'`, `iex -Command:'Remove-Item C:\x'`, `Invoke-Expression('Remove-Item C:\x')`, `iex('Remove-Item C:\x')`,
		`iex -c 'Remove-Item C:\x'`, `iex -Co 'Remove-Item C:\x'`, `iex 'Remove-Item C:\x' -Verbose`, `Microsoft.PowerShell.Utility\Invoke-Expression 'Remove-Item C:\x'`,
		`Start-Process -FilePath powershell -ArgumentList '-c Remove-Item C:\x'`, `start powershell '-c Remove-Item C:\x'`, `saps pwsh '-c','Remove-Item C:\x'`,
		`Start-Process -Verb RunAs powershell '-c Remove-Item C:\x'`, `Start-Process wt 'powershell -c Remove-Item C:\x'`, `Start-Process conhost 'powershell -c Remove-Item C:\x'`,
		`Start-Process C:\x.bat`, `Start-Process @p`, `Start-Process (Get-Command powershell).Source '-c Remove-Item C:\x'`, `Start-Process powershell`,
		`Start-Process -FilePath:'pwsh' -ArgumentList:'-c','Remove-Item C:\x'`, `Start-Process -Fi pwsh -Ar '-c Remove-Item C:\x'`, `Start-Process pwsh.exe -NoNewWindow -Wait -Args '-c Remove-Item C:\x'`,
		`& $env:ComSpec /c del C:\x`, `& (gcm powershell) -c 'Remove-Item C:\x'`, `& (Get-Command pwsh) -c 'Remove-Item C:\x'`, `Invoke-Item C:\x.bat`,
		// D splatting into host calls
		`$a='-c','Remove-Item C:\x'; powershell @a`, `powershell @a`, `powershell -c @a`, `pwsh -nop @a`, `& powershell @args`, `pwsh -c 'Get-Date' @a`,
		`$p=@{c='Remove-Item C:\x'}; powershell @p`, `iex @a`, `Invoke-Expression @p`, `$a=@('/c','del C:\x'); cmd @a`, `pwsh @a -c 'Get-Date'`, `pwsh -c @a 'x'`,
		// E here-strings to -Command / iex
		"powershell -c @'↵Remove-Item C:\\x↵'@", "powershell -c @\"↵Remove-Item C:\\x↵\"@", "iex @'↵Remove-Item C:\\x↵'@", "pwsh -c @'↵Write-Output \"a;Remove-Item C:\\x\"↵'@",
		"@'↵Remove-Item C:\\x↵'@ | iex", "@'↵Remove-Item C:\\x↵'@ | pwsh -c -",
		// F pipeline input to iex / host stdin
		`'Remove-Item C:\x' | iex`, `'Remove-Item C:\x' | Invoke-Expression`, `'Remove-Item C:\x' | & iex`, `'Remove-Item C:\x' | . iex`, `'Remove-Item C:\x' | iex -Verbose`,
		`'Remove-Item C:\x' | Microsoft.PowerShell.Utility\Invoke-Expression`, `'Remove-Item C:\x' | iex | Out-Null`, `Get-Content x | iex`, `gc x | iex`,
		`'Remove-Item C:\x' | Write-Output | iex`, `'Remove-Item C:\x' | % {$_} | iex`, `'Remove-Item C:\x' | ForEach-Object { iex $_ }`, `$c | iex`,
		`"Remove-Item $x" | iex`, `'Remove-Item C:\x'|iex`, `'Remove-Item C:\x' | IEX`, `'Remove-Item C:\x' 2>&1 | iex`, `'Remove-Item C:\x' | iex 2>&1`,
		`-join ('Remove-','Item C:\x') | iex`, `'Write-Output a' | iex; Remove-Item C:\x`, `'Remove-Item C:\x' | Tee-Object -Variable t | iex`, `'Remove-Item C:\x' | & 'iex'`,
		`'Remove-Item C:\x' | pwsh -c -`, `'Remove-Item C:\x' | powershell -`, `'Remove-Item C:\x' | pwsh -nop -`, `'Remove-Item C:\x' | pwsh`, `'Remove-Item C:\x' | pwsh -nop`,
		`'del C:\x' | cmd`, `'del C:\x' | cmd /q`, `'Remove-Item C:\x' | pwsh -File -`, `'Remove-Item C:\x' | pwsh -c 'Get-Date'`, `'Remove-Item C:\x' | pwsh -c '$input | iex'`,
		`'Remove-Item C:\x' | powershell -c -`, `'Remove-Item C:\x' | & powershell -c -`, `'Remove-Item C:\x' | pwsh -nop -c '-'`,
		`'Remove-Item C:\x' | iex 'Get-Date'`, `'a' | iex -Command 'Remove-Item C:\x'`,
	}
	// M -EncodedCommand variants
	rm := E("Remove-Item C:\\x")
	l = append(l,
		"pwsh -e "+rm, "pwsh -enc "+rm, "pwsh -ec "+rm, "pwsh -en "+rm, "pwsh -encod "+rm, "pwsh -EncodedCommand "+rm, "pwsh -ENC "+rm,
		"pwsh --encodedcommand "+rm, "pwsh /e "+rm, "pwsh -e:"+rm, "pwsh -EncodedCommand:"+rm, "pwsh -e '"+rm+"'", "pwsh -e \""+rm+"\"",
		"pwsh -ec "+E("Write-Output A")+" -ec "+rm, "pwsh -ec "+E("Write-Output A")+" -c 'Remove-Item C:\\x'", "pwsh -c 'Get-Date' -ec "+rm,
		"pwsh -ec "+rm+" -nop", "pwsh -ec "+rm+" extra", "pwsh -nop -w hidden -ec "+rm, "pwsh -ec "+E("Write-Output \"a;Remove-Item C:\\x\""),
		"pwsh -ec "+rm[:len(rm)-2], "pwsh -ec "+strings.TrimRight(rm, "="), "pwsh -ec "+rm[:8]+" "+rm[8:], "pwsh -ec "+base64.StdEncoding.EncodeToString([]byte("Remove-Item C:\\x")),
		"pwsh -ec "+E("Remove-Item C:\\x\x00; Remove-Item C:\\y"), "pwsh -ec "+E("iex 'Remove-Item C:\\x'"), "pwsh -ec "+E("powershell -c 'Remove-Item C:\\x'"),
		"pwsh -ec "+E("Write-Output x\\")+" "+E("y"), "powershell -ec "+rm+" -c 'Get-Date'", "cmd /c powershell -ec "+rm,
		"pwsh -ea "+rm+" -ec "+E("Write-Output a"), "pwsh -EncodedArguments "+rm, "Start-Process pwsh -ArgumentList '-ec','"+rm+"'",
		"$e='"+rm+"'; pwsh -ec $e", "pwsh -ec "+"('"+rm+"')", "pwsh -ec @e", "& pwsh -ec "+rm, "powershell.exe -ec "+rm,
		"pwsh -ec "+E("Remove-Item ~\\x"), "pwsh -ec "+E("Remove-Item C:\\W*"),
	)
	return l
}

// firstNestedOfKind parses src under dialect d and returns the first nested
// script of the given kind.
func firstNestedOfKind(src string, d Dialect, kind string) (NestedScript, bool) {
	sc, _ := Parse(src, Options{Dialect: d})
	for _, n := range ExtractNestedScripts(sc) {
		if n.Kind == kind {
			return n, true
		}
	}
	return NestedScript{}, false
}

// TestRev6StdinDash is the review-6 R6-1 regression: a PowerShell host whose
// -Command / positional command value is exactly "-" reads the script from
// stdin, so the argv holds no script and the nested entry is non-static with
// ps_stdin -- never a static nested script "-".
func TestRev6StdinDash(t *testing.T) {
	for _, src := range []string{
		`pwsh -c -`,
		`pwsh -c - `,
		`pwsh -nop -c -`,
		`pwsh -nop -c '-'`,
		`powershell -`,
		`pwsh -nop -`,
		`powershell -NoProfile -Command -`,
	} {
		ns, ok := firstNestedOfKind(src, DialectUnknown, KindPowerShellCommand)
		if !ok {
			t.Errorf("%q: no powershell-command nested script", src)
			continue
		}
		if ns.Static || ns.Reason != ReasonStdin {
			t.Errorf("%q: got static=%v reason=%q text=%q; want static=false reason=%q",
				src, ns.Static, ns.Reason, ns.Text, ReasonStdin)
		}
	}
}

// TestRev6CmdHiddenPayload is the review-6 R6-2 regression: a cmd invocation
// that hides its command line in a splat, a dynamic word, or a fused/combined
// /c-style switch gives a non-static cmd script (ps_cmd_argv) so the effects
// lane is opaque rather than fully known.
func TestRev6CmdHiddenPayload(t *testing.T) {
	for _, src := range []string{
		`cmd @a`,
		`$a=@('/c','rd /s /q C:\Windows'); cmd @a`,
		`cmd /crd /s /q C:\Windows`,
		`cmd /cdel C:\x`,
		`cmd /d/c rd /s /q C:\Windows`,
		`cmd "/c rd /s /q C:\Windows"`,
		`cmd /C:rd /s /q C:\Windows`,
	} {
		ns, ok := firstNestedOfKind(src, DialectUnknown, KindCmdC)
		if !ok {
			t.Errorf("%q: no cmd-c nested script", src)
			continue
		}
		if ns.Static || ns.Reason != ReasonCmdArgv {
			t.Errorf("%q: got static=%v reason=%q text=%q; want static=false reason=%q",
				src, ns.Static, ns.Reason, ns.Text, ReasonCmdArgv)
		}
	}
}

// TestRev6FileStdinAndStopParse covers the Sonnet-probe residuals: `-File -`
// reads the script from stdin (PS-FILE-STDIN), and a --% stop-parse token
// before a stdin dash is the same stdin form (PS-STOPPARSE-DASH).
func TestRev6FileStdinAndStopParse(t *testing.T) {
	rows := []struct {
		src   string
		stdin bool // want a non-static ps_stdin powershell-command
	}{
		{`pwsh -File -`, true},
		{`pwsh -f -`, true},
		{`pwsh -nop -File -`, true},
		{`powershell -File -`, true},
		{`pwsh -File - extra`, true},
		{`pwsh -File:-`, true},
		{`pwsh -File '-'`, true},
		{`pwsh --% -`, true},
		{`pwsh --% -c -`, true},
		{`pwsh --% -File -`, true},
		{`pwsh -nop --% -`, true},
		{`pwsh -c --% -`, true},
		{`powershell -Command --% -`, true},
		{`pwsh -File x.ps1`, false},
		{`pwsh -File`, false},
	}
	for _, r := range rows {
		for _, d := range []Dialect{DialectUnknown, DialectWindowsPS51, DialectPwsh7} {
			sc, _ := Parse(r.src, Options{Dialect: d})
			got := false
			for _, n := range ExtractNestedScripts(sc) {
				if !n.Static && n.Reason == ReasonStdin {
					got = true
				}
				if r.stdin && n.Static {
					t.Errorf("%q d=%d: static nested %q; want ps_stdin", r.src, d, n.Text)
				}
			}
			if got != r.stdin {
				t.Errorf("%q d=%d: ps_stdin=%v want %v", r.src, d, got, r.stdin)
			}
		}
	}
}

// TestRev6CmdCleanStillStatic guards against R6-2 over-reaching: a bare
// /c|/k|/r switch with a literal payload stays static with the exact text.
func TestRev6CmdCleanStillStatic(t *testing.T) {
	cases := []struct {
		src  string
		text string
	}{
		{`cmd /c del C:\x`, `del C:\x`},
		{`cmd /k dir`, `dir`},
		{`cmd /C del C:\x`, `del C:\x`},
		{`cmd.exe /c "del C:\x"`, `del C:\x`},
	}
	for _, c := range cases {
		ns, ok := firstNestedOfKind(c.src, DialectPwsh7, KindCmdC)
		if !ok {
			t.Errorf("%q: no cmd-c nested script", c.src)
			continue
		}
		if !ns.Static || ns.Text != c.text {
			t.Errorf("%q: got static=%v text=%q; want static=true text=%q", c.src, ns.Static, ns.Text, c.text)
		}
	}
}

// TestRev6LegacyTrailingBackslash is the review-6 R6-3 regression: under
// Windows PowerShell 5.1 / an unknown dialect, a host word that contains
// whitespace and ends in a backslash is mis-quoted by legacy native argument
// passing, so the resolved payload is opaque (ps_legacy_quoting). Under a
// proven pwsh 7 the text is kept.
func TestRev6LegacyTrailingBackslash(t *testing.T) {
	for _, src := range []string{
		`powershell -c 'Write-Output a\' 'b'`,
		`powershell -c 'Remove-Item C:\x y\'`,
	} {
		for _, d := range []Dialect{DialectUnknown, DialectWindowsPS51} {
			ns, ok := firstNestedOfKind(src, d, KindPowerShellCommand)
			if !ok {
				t.Errorf("%q d=%d: no powershell-command nested script", src, d)
				continue
			}
			if ns.Static || ns.Reason != ReasonLegacyQuoting {
				t.Errorf("%q d=%d: got static=%v reason=%q; want static=false reason=%q",
					src, d, ns.Static, ns.Reason, ReasonLegacyQuoting)
			}
		}
		if ns, ok := firstNestedOfKind(src, DialectPwsh7, KindPowerShellCommand); !ok || !ns.Static {
			t.Errorf("%q pwsh7: want a static nested script, got ok=%v %+v", src, ok, ns)
		}
	}
}
