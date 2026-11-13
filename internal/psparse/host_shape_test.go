// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"bytes"
	"context"
	"encoding/base64"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// ---------------------------------------------------------------------------
// Tested shapes: rows, oracle differential, NotStatic reasons.
// ---------------------------------------------------------------------------

// hostShapeRows are the tested powershell shapes (host_shapes.go). Every row is
// Static under every dialect and, with the oracle, runs identically as host
// argv and as the extracted text (TestHostShapeCLIOracle).
var hostShapeRows = []struct {
	id   string
	argv []string
}{
	{"ps-command/c", []string{"-c", "Write-Output a"}},
	{"ps-command/Command", []string{"-Command", "Write-Output a b"}},
	{"ps-command/COMMAND-case", []string{"-COMMAND", "Write-Output A"}},
	{"ps-command/multiword", []string{"-c", "Write-Output", "a", "b"}},
	{"ps-command/quotes", []string{"-c", "Write-Output 'x y'"}},
	{"ps-command/semicolon", []string{"-c", "Write-Output a; Write-Output b"}},
	{"ps-command/nop", []string{"-nop", "-c", "Write-Output a"}},
	{"ps-command/NoProfile-NonInteractive-NoLogo", []string{"-NoProfile", "-NonInteractive", "-NoLogo", "-Command", "Write-Output a"}},
	{"ps-command/noni-nol", []string{"-NoP", "-noni", "-nol", "-c", "Write-Output a"}},
	{"ps-command/ep", []string{"-ep", "Bypass", "-c", "Write-Output a"}},
	{"ps-command/ExecutionPolicy", []string{"-ExecutionPolicy", "Bypass", "-c", "Write-Output a"}},
	{"ps-command/exec", []string{"-Exec", "Bypass", "-c", "Write-Output a"}},
	{"ps-command/w", []string{"-w", "hidden", "-c", "Write-Output a"}},
	{"ps-command/WindowStyle", []string{"-WindowStyle", "Hidden", "-c", "Write-Output a"}},
	{"ps-command/wd", []string{"-wd", "/tmp", "-c", "Write-Output a"}},
	{"ps-command/if-of", []string{"-if", "text", "-of", "text", "-c", "Write-Output a"}},
	{"ps-command/all-opts", []string{"-NoProfile", "-nologo", "-noni", "-ep", "Bypass", "-w", "hidden", "-c", "Write-Output a"}},
	{"ps-encoded/e", []string{"-e", r6enc("Write-Output a")}},
	{"ps-encoded/ec", []string{"-ec", r6enc("Write-Output a")}},
	{"ps-encoded/enc", []string{"-enc", r6enc("Write-Output a b")}},
	{"ps-encoded/EncodedCommand", []string{"-EncodedCommand", r6enc("Write-Output 'x y'")}},
	{"ps-encoded/nop-enc", []string{"-nop", "-noni", "-enc", r6enc("Write-Output a")}},
	{"ps-encoded/ep-w-enc", []string{"-ep", "Bypass", "-w", "hidden", "-enc", r6enc("Write-Output a")}},
}

// hostShapeSource renders a host argv as PowerShell source with every word in
// single quotes, so the parser sees exactly those words.
func hostShapeSource(host string, argv []string) string {
	var b strings.Builder
	b.WriteString(host)
	for _, w := range argv {
		b.WriteString(" '" + strings.ReplaceAll(w, "'", "''") + "'")
	}
	return b.String()
}

func firstHostNested(src string, d Dialect) (NestedScript, bool) {
	sc, _ := Parse(src, Options{Dialect: d})
	for _, n := range ExtractNestedScripts(sc) {
		if n.Kind == KindPowerShellCommand || n.Kind == KindEncodedCommand || n.Kind == KindCmdC {
			return n, true
		}
	}
	return NestedScript{}, false
}

// expectedShapeText is the script text a tested shape resolves to.
func expectedShapeText(argv []string) string {
	for i, w := range argv {
		l := strings.ToLower(w)
		if psCommandSwitches[l] {
			return strings.Join(argv[i+1:], " ")
		}
		if psEncodedSwitches[l] {
			return decodeUTF16LEBase64(argv[i+1])
		}
	}
	return ""
}

func decodeUTF16LEBase64(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

func TestHostShapeRowsStatic(t *testing.T) {
	for _, r := range hostShapeRows {
		for _, host := range []string{"pwsh", "powershell", "PowerShell.EXE"} {
			for _, d := range []Dialect{DialectUnknown, DialectWindowsPS51, DialectPwsh7} {
				ns, ok := firstHostNested(hostShapeSource(host, r.argv), d)
				if !ok || !ns.Static {
					t.Errorf("%s host=%s d=%d: want Static, got %+v", r.id, host, d, ns)
					continue
				}
				if want := expectedShapeText(r.argv); ns.Text != want {
					t.Errorf("%s host=%s d=%d: text %q want %q", r.id, host, d, ns.Text, want)
				}
			}
		}
	}
}

// TestHostShapeCLIOracle is the differential: with PSPARSE_ORACLE (pwsh 7.7) the
// real host argv and the extracted static text must produce the same output and
// exit code. A row that disagrees does not belong in the table.
func TestHostShapeCLIOracle(t *testing.T) {
	pwsh := os.Getenv("PSPARSE_ORACLE")
	if pwsh == "" {
		t.Skip("PSPARSE_ORACLE unset")
	}
	run := func(args ...string) (string, int) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, pwsh, args...)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			code = -1
		}
		return strings.TrimSpace(out.String()), code
	}
	for _, r := range hostShapeRows {
		ns, ok := firstHostNested(hostShapeSource("pwsh", r.argv), DialectPwsh7)
		if !ok || !ns.Static {
			t.Errorf("%s: not static", r.id)
			continue
		}
		// -WindowStyle is Windows-only: the Linux oracle rejects it ("not
		// implemented on this platform") and it cannot change which script runs, so
		// the differential runs the row without that pair.
		argv := r.argv[:0:0]
		for i := 0; i < len(r.argv); i++ {
			if l := strings.ToLower(r.argv[i]); (l == "-w" || l == "-windowstyle") && i+1 < len(r.argv) {
				i++
				continue
			}
			argv = append(argv, r.argv[i])
		}
		outA, codeA := run(argv...)
		outB, codeB := run("-NoProfile", "-EncodedCommand", r6enc(ns.Text))
		if outA != outB || codeA != codeB {
			t.Errorf("%s: oracle disagrees\n host argv %q -> %d %q\n static text %q -> %d %q", r.id, r.argv, codeA, outA, ns.Text, codeB, outB)
		}
		if codeA != 0 {
			t.Errorf("%s: host argv failed under pwsh 7.7 (exit %d): %q", r.id, codeA, outA)
		}
	}
}

// hostShapeNotStatic are inputs outside the table. Each is NotStatic under every
// dialect with the named reason (cases are named by the review probe id when one
// exists).
var hostShapeNotStatic = []struct {
	id     string
	src    string
	reason string
}{
	// padding and empty words (N01..N09, A13, A14)
	{"N01", `pwsh '' -c 'Get-Date'`, ReasonHostOption},
	{"N03", `pwsh ' -c' 'Get-Date'`, ReasonHostOption},
	{"N04", `pwsh '-c ' 'Get-Date'`, ReasonHostOption},
	{"N07", `pwsh ' -nop' -c 'Get-Date'`, ReasonHostOption},
	{"pad-value", `pwsh -ep ' Bypass' -c 'Get-Date'`, ReasonHostOption},
	// --% tails (S01..S12, C11, cmd)
	{"S04", `pwsh -c Write-Output --% %DCV%`, ReasonStopParsing},
	{"S09", `pwsh -c --% Write-Output -`, ReasonStopParsing},
	{"stop-before-c", `pwsh -nop --% -c Get-Date`, ReasonStopParsing},
	{"stop-cmd", `cmd /c --% del %TEMP%\x`, ReasonStopParsing},
	// colon forms (COLC, A06)
	{"COLC", `pwsh -c:'Get-Date'`, ReasonHostOption},
	{"colon-opt", `pwsh -nop:'x' -c 'Get-Date'`, ReasonHostOption},
	{"colon-enc", `pwsh -e:` + "ZQBjAGgAbwA=", ReasonHostOption},
	// splats and dynamic words
	{"splat", `pwsh @a`, ReasonNonLiteral},
	{"splat-c", `pwsh -c @a`, ReasonNonLiteral},
	{"var-c", `pwsh -c $x`, ReasonNonLiteral},
	{"var-before", `pwsh $x -c 'Get-Date'`, ReasonNonLiteral},
	{"splat-cmd", `cmd @a`, ReasonCmdArgv},
	// stdin
	{"A01", `pwsh -c -`, ReasonStdin},
	{"A04", `pwsh -nop -`, ReasonStdin},
	{"B01", `pwsh -File -`, ReasonStdin},
	// switch spellings and abbreviations outside the table
	{"abbrev-com", `pwsh -com 'Get-Date'`, ReasonHostOption},
	{"abbrev-comm", `pwsh -comm 'Get-Date'`, ReasonHostOption},
	{"slash-c", `pwsh /c 'Get-Date'`, ReasonHostOption},
	{"long-command", `pwsh --command 'Get-Date'`, ReasonHostOption},
	{"en-dash-c", "pwsh \u2013c 'Get-Date'", ReasonHostOption},
	{"unknown-switch", `pwsh -foo -c 'Get-Date'`, ReasonHostOption},
	{"version", `pwsh -Version 2 -c 'Get-Date'`, ReasonHostOption},
	{"noexit", `pwsh -noexit -c 'Get-Date'`, ReasonHostOption},
	{"abbrev-enc", `pwsh -encod ` + "ZQBjAGgAbwA=", ReasonHostOption},
	{"slash-enc", `pwsh /enc ` + "ZQBjAGgAbwA=", ReasonHostOption},
	// positional commands
	{"positional", `pwsh 'Get-Date'`, ReasonHostShape},
	{"positional-bare", `powershell Get-Date`, ReasonHostShape},
	{"opts-only-then-pos", `pwsh -nop 'Get-Date'`, ReasonHostShape},
	// encoded-command shape violations
	{"enc-extra", `pwsh -enc ` + "ZQBjAGgAbwA= extra", ReasonHostShape},
	{"enc-invalid", `pwsh -enc abc`, ReasonNonLiteral},
	{"enc-missing", `pwsh -enc`, ReasonHostShape},
	// value-taking option without a value
	{"ep-missing", `pwsh -ep`, ReasonHostShape},
	// cmd shapes outside the table (R7-2, R8-4)
	{"D01", `cmd /crd /s /q C:\Windows`, ReasonCmdArgv},
	{"D14", `cmd ' /c' 'rd /s /q C:\Windows'`, ReasonCmdArgv},
	{"D08", `cmd -x:'/c rd /s /q C:\Windows'`, ReasonCmdArgv},
	{"cmd-word-before", `cmd foo /c ver`, ReasonCmdArgv},
	{"cmd-unknown-opt", `cmd /z /c ver`, ReasonCmdArgv},
}

func TestHostShapeNotStatic(t *testing.T) {
	for _, r := range hostShapeNotStatic {
		for _, d := range []Dialect{DialectUnknown, DialectWindowsPS51, DialectPwsh7} {
			ns, ok := firstHostNested(r.src, d)
			if !ok {
				// a file/no-script form is fine only if the row expects no nested script
				t.Errorf("%s d=%d %q: no nested script", r.id, d, r.src)
				continue
			}
			if ns.Static || ns.Reason != r.reason {
				t.Errorf("%s d=%d %q: static=%v reason=%q text=%q; want NotStatic reason=%q", r.id, d, r.src, ns.Static, ns.Reason, ns.Text, r.reason)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Property: Static=true implies the argv is in the table.
// ---------------------------------------------------------------------------

// refWord is a host word as the property checker sees it.
type refWord struct {
	text   string
	static bool
	colon  bool
}

// The reference matcher below is an independent statement of the table in
// host_shapes.go: it shares no code and no data with it, so a Static result that
// the gate lets through by mistake (or a new Static path that bypasses the gate)
// is caught here.
var (
	refNoVal   = []string{"-noprofile", "-nop", "-noninteractive", "-noni", "-nologo", "-nol", "-sta", "-mta"}
	refWithVal = []string{"-executionpolicy", "-ep", "-exec", "-windowstyle", "-w", "-inputformat", "-if", "-outputformat", "-of", "-workingdirectory", "-wd"}
	refCmdSw   = []string{"-c", "-command"}
	refEncSw   = []string{"-e", "-ec", "-enc", "-encodedcommand"}
	refCmdOpts = []string{"/q", "/d", "/s", "/a", "/u", "/x", "/y", "/e:on", "/e:off", "/v:on", "/v:off", "/f:on", "/f:off"}
)

func refIn(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// refPS returns the script text a tested powershell shape resolves to, or ok=false.
func refPS(words []refWord, stop bool) (text string, ok bool) {
	if stop {
		return "", false
	}
	for _, w := range words {
		if !w.static || w.colon || w.text == "--%" {
			return "", false
		}
	}
	i := 0
	for i < len(words) {
		w := words[i].text
		if w == "" || strings.TrimSpace(w) != w {
			return "", false
		}
		l := strings.ToLower(w)
		switch {
		case refIn(refNoVal, l):
			i++
		case refIn(refWithVal, l):
			if i+1 >= len(words) {
				return "", false
			}
			v := words[i+1].text
			if v == "" || strings.TrimSpace(v) != v || strings.HasPrefix(v, "-") {
				return "", false
			}
			i += 2
		case refIn(refCmdSw, l):
			rest := words[i+1:]
			if len(rest) == 0 || (len(rest) == 1 && rest[0].text == "-") {
				return "", false
			}
			parts := make([]string, len(rest))
			for k, r := range rest {
				parts[k] = r.text
			}
			return strings.Join(parts, " "), true
		case refIn(refEncSw, l):
			if i+2 != len(words) {
				return "", false
			}
			dec := decodeUTF16LEBase64(words[i+1].text)
			if dec == "" {
				return "", false
			}
			return dec, true
		default:
			return "", false
		}
	}
	return "", false
}

// refCmd returns the script text of the tested cmd-run shape, or ok=false.
func refCmd(c *Command) (text string, ok bool) {
	var words []string
	for _, el := range c.Elements {
		a, isArg := el.(*Arg)
		if !isArg {
			return "", false
		}
		v, isLit := LiteralString(a.Value)
		if !isLit {
			return "", false
		}
		words = append(words, v)
	}
	if c.StopParsing != "" {
		return "", false
	}
	for i, w := range words {
		if w == "--%" || w == "" || strings.TrimSpace(w) != w {
			return "", false
		}
		l := strings.ToLower(w)
		if l == "/c" || l == "/k" || l == "/r" {
			rest := words[i+1:]
			if len(rest) == 0 {
				return "", false
			}
			for _, r := range rest {
				if r == "--%" {
					return "", false
				}
			}
			return strings.Join(rest, " "), true
		}
		if !refIn(refCmdOpts, l) {
			return "", false
		}
	}
	return "", false
}

// checkStaticImpliesShape asserts the property for every host nested script of
// src under dialect d.
func checkStaticImpliesShape(t testing.TB, src string, d Dialect) {
	t.Helper()
	sc, _ := Parse(src, Options{Dialect: d})
	for _, n := range ExtractNestedScripts(sc) {
		if !n.Static {
			continue
		}
		if n.Kind != KindPowerShellCommand && n.Kind != KindEncodedCommand && n.Kind != KindCmdC {
			continue
		}
		cmd, ok := n.Source.(*Command)
		if !ok {
			t.Fatalf("d=%d %q: static %s nested script without a command source", d, src, n.Kind)
		}
		name, _ := LiteralString(cmd.Name)
		var want string
		var in bool
		if isPSHost(name) {
			var ws []refWord
			for _, w := range hostWords(cmd) {
				ws = append(ws, refWord(w))
			}
			stop := cmd.StopParsing != ""
			want, in = refPS(ws, stop)
		} else if baseName(name) == "cmd" {
			want, in = refCmd(cmd)
		} else {
			t.Fatalf("d=%d %q: static %s from a non-host command %q", d, src, n.Kind, name)
		}
		if !in {
			t.Fatalf("d=%d %q: Static %s script %q is not a tested host-call shape", d, src, n.Kind, n.Text)
		}
		if n.Text != want {
			t.Fatalf("d=%d %q: static text %q, table says %q", d, src, n.Text, want)
		}
	}
}

// hostGen builds host invocations from switch, padding, quoting and order
// variants, a fixed seed making the run reproducible.
type hostGen struct{ r *rand.Rand }

func (g *hostGen) pick(ss []string) string { return ss[g.r.Intn(len(ss))] }
func (g *hostGen) coin(pct int) bool       { return g.r.Intn(100) < pct }

type genWord struct {
	text string
	raw  bool // render as-is (variable, splat, --%)
}

var (
	genHosts   = []string{"pwsh", "powershell", "PowerShell.EXE", "pwsh.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "& pwsh", "& 'powershell.exe'"}
	genNoVal   = []string{"-NoProfile", "-nop", "-NOP", "-noni", "-NonInteractive", "-NoLogo", "-nol", "-sta", "-mta", "-noexit", "-login", "-l", "-nop:", "-foo", "/nop", "--nop", "\u2013nop"}
	genWithVal = [][]string{{"-ep", "Bypass"}, {"-ExecutionPolicy", "Bypass"}, {"-w", "hidden"}, {"-WindowStyle", "Hidden"}, {"-Version", "2"}, {"-wd", "/tmp"}, {"-if", "text"}, {"-of", "xml"}, {"-File", "x.ps1"}, {"-foo", "bar"}, {"-ep", ""}, {"-ep", " Bypass"}, {"-ep"}}
	genCmdSw   = []string{"-c", "-Command", "-command", "-C", "-comm", "-co", "/c", "--command", "\u2013c", "-cwa", "-c:"}
	genEncSw   = []string{"-e", "-ec", "-enc", "-EncodedCommand", "-en", "-encodedc", "/e", "-e:", "-ea"}
	genPayload = []string{"Get-Date", `Remove-Item C:\x`, "Write-Output 'a b'", `Write-Output "x"`, "-", "--%", "", " ", `a\ b\`, "$x", "x;y", "Write-Output a", "-nop"}
	genB64     = []string{r6enc("Write-Output a"), r6enc("Remove-Item C:\\x"), r6enc(""), "abc", " " + r6enc("x"), r6enc("x") + " ", "@@@@", r6enc("Write-Output a")[:8]}
	genCmdOpts = []string{"/q", "/d", "/s", "/a", "/u", "/x", "/y", "/e:on", "/V:OFF", "/f:on", "/z", "foo", " /q", "/c"}
	genCmdSw2  = []string{"/c", "/C", "/k", "/K", "/r", "/crd", "/d/c", " /c", "/c "}
)

func (g *hostGen) argv() (host string, words []genWord, isCmd bool) {
	if g.coin(15) {
		host, isCmd = "cmd", true
		for k := g.r.Intn(3); k > 0; k-- {
			words = append(words, genWord{text: g.pick(genCmdOpts)})
		}
		words = append(words, genWord{text: g.pick(genCmdSw2)})
		for k := g.r.Intn(3); k > 0; k-- {
			words = append(words, genWord{text: g.pick(genPayload)})
		}
	} else {
		host = g.pick(genHosts)
		for k := g.r.Intn(4); k > 0; k-- {
			if g.coin(50) {
				words = append(words, genWord{text: g.pick(genNoVal)})
			} else {
				for _, w := range genWithVal[g.r.Intn(len(genWithVal))] {
					words = append(words, genWord{text: w})
				}
			}
		}
		switch g.r.Intn(5) {
		case 0, 1, 2:
			words = append(words, genWord{text: g.pick(genCmdSw)})
			for k := 1 + g.r.Intn(3); k > 0; k-- {
				words = append(words, genWord{text: g.pick(genPayload)})
			}
		case 3:
			words = append(words, genWord{text: g.pick(genEncSw)}, genWord{text: g.pick(genB64)})
			if g.coin(20) {
				words = append(words, genWord{text: g.pick(genPayload)})
			}
		default:
			words = append(words, genWord{text: g.pick(genPayload)}) // positional
		}
	}
	// order / structure mutations
	if len(words) > 1 && g.coin(8) {
		i, j := g.r.Intn(len(words)), g.r.Intn(len(words))
		words[i], words[j] = words[j], words[i]
	}
	if g.coin(5) {
		i := g.r.Intn(len(words) + 1)
		words = append(words[:i], append([]genWord{{text: "--%", raw: true}}, words[i:]...)...)
	}
	if g.coin(4) {
		i := g.r.Intn(len(words) + 1)
		words = append(words[:i], append([]genWord{{text: g.pick([]string{"@a", "@args", "$x", "$env:P"}), raw: true}}, words[i:]...)...)
	}
	return host, words, isCmd
}

func genBare(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		isWordRune := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(`_.\:/-`, r)
		if !isWordRune {
			return false
		}
	}
	return true
}

func (g *hostGen) render(host string, words []genWord) string {
	var b strings.Builder
	b.WriteString(host)
	for i := 0; i < len(words); i++ {
		w := words[i]
		b.WriteByte(' ')
		if w.raw {
			b.WriteString(w.text)
			continue
		}
		tok := ""
		switch {
		case genBare(w.text) && g.coin(40):
			tok = w.text
		case !strings.ContainsAny(w.text, "$`\"\n") && g.coin(15):
			tok = `"` + w.text + `"`
		default:
			tok = "'" + strings.ReplaceAll(w.text, "'", "''") + "'"
		}
		// colon fuse: a switch word glued to its value (-c:'x')
		if strings.HasPrefix(w.text, "-") && i+1 < len(words) && !words[i+1].raw && g.coin(6) {
			next := "'" + strings.ReplaceAll(words[i+1].text, "'", "''") + "'"
			b.WriteString(w.text + ":" + next)
			i++
			continue
		}
		b.WriteString(tok)
	}
	return b.String()
}

func TestHostShapeProperty(t *testing.T) {
	g := &hostGen{r: rand.New(rand.NewSource(1))}
	static, total := 0, 0
	for n := 0; n < 40000; n++ {
		host, words, _ := g.argv()
		src := g.render(host, words)
		for _, d := range []Dialect{DialectUnknown, DialectWindowsPS51, DialectPwsh7} {
			total++
			sc, _ := Parse(src, Options{Dialect: d})
			for _, ns := range ExtractNestedScripts(sc) {
				if ns.Static {
					static++
				}
			}
			checkStaticImpliesShape(t, src, d)
		}
	}
	if static == 0 {
		t.Fatalf("generator produced no Static host script in %d runs; the property is vacuous", total)
	}
	t.Logf("property: %d runs, %d static host scripts, all in the table", total, static)
}

// FuzzHostShape fuzzes the same property over arbitrary source.
func FuzzHostShape(f *testing.F) {
	g := &hostGen{r: rand.New(rand.NewSource(7))}
	for i := 0; i < 200; i++ {
		host, words, _ := g.argv()
		f.Add(g.render(host, words))
	}
	for _, r := range hostShapeRows {
		f.Add(hostShapeSource("pwsh", r.argv))
	}
	for _, r := range hostShapeNotStatic {
		f.Add(r.src)
	}
	f.Fuzz(func(t *testing.T, src string) {
		for _, d := range []Dialect{DialectUnknown, DialectWindowsPS51, DialectPwsh7} {
			checkStaticImpliesShape(t, src, d)
		}
	})
}
