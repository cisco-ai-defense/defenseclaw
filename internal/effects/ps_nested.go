// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// PowerShell nested bodies (DET111 D1, class R1): the child command line of
// Start-Process is split as the child splits it (CommandLineToArgvW), and the
// child's -Command / -EncodedCommand text or cmd /c body is lowered as its own
// script; $HOME and $env:NAME inside an expandable string are variable
// segments the walker resolves.

// psHomeVar is the word-segment name of PowerShell's automatic $HOME: the
// session home, fixed at start like ~ (never an environment variable, so it
// cannot collide with one: an environment name never starts with a $).
const psHomeVar = "$HOME"

// psVarSeg is the segment of a variable reference the walker can resolve:
// $env:NAME and the automatic $HOME.
func psVarSeg(v *psparse.Variable) (WordSeg, bool) {
	if v == nil || v.Splat {
		return WordSeg{}, false
	}
	switch {
	case strings.EqualFold(v.Scope, "env") && v.Name != "":
		return WordSeg{Var: v.Name}, true
	case v.Scope == "" && strings.EqualFold(v.Name, "home"):
		return WordSeg{Var: psHomeVar}, true
	}
	return WordSeg{}, false
}

// psStringWord lowers an expandable string ("$HOME\.aws\x", a bare
// $env:USERPROFILE\.ssh) whose only expansions are resolvable variables.
func psStringWord(sl *psparse.StringLit) (Word, bool) {
	if sl == nil || sl.Static || sl.Fused || len(sl.Parts) == 0 {
		return Word{}, false
	}
	var segs []WordSeg
	for _, p := range sl.Parts {
		if p.Expr == nil {
			if strings.ContainsAny(p.Lit, "`\x00") {
				return Word{}, false
			}
			segs = append(segs, WordSeg{Lit: p.Lit, Quoted: !sl.Bare})
			continue
		}
		switch x := p.Expr.(type) {
		case *psparse.Variable:
			seg, ok := psVarSeg(x)
			if !ok {
				return Word{}, false
			}
			seg.Quoted = !sl.Bare
			segs = append(segs, seg)
		case *psparse.StringLit:
			// a composed word ($HOME\.aws\x): its literal pieces
			if lit, ok := psparse.LiteralString(x); ok {
				segs = append(segs, WordSeg{Lit: lit, Quoted: !sl.Bare})
				continue
			}
			inner, ok := psStringWord(x)
			if !ok {
				return Word{}, false
			}
			segs = append(segs, inner.Segs...)
		default:
			return Word{}, false
		}
	}
	return Word{Segs: segs, Quoted: !sl.Bare}, true
}

// winArgv splits a Windows command line as CommandLineToArgvW does: blanks
// separate words outside quotes; 2n backslashes before a quote are n
// backslashes and the quote toggles; 2n+1 are n and a literal quote; "" inside
// quotes is a literal quote; other backslashes are literal.
func winArgv(line string) []string {
	var out []string
	var b strings.Builder
	inQ, have := false, false
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == '\\':
			n := 0
			for i < len(line) && line[i] == '\\' {
				n++
				i++
			}
			if i < len(line) && line[i] == '"' {
				b.WriteString(strings.Repeat(`\`, n/2))
				if n%2 == 1 {
					b.WriteByte('"')
					i++
				}
			} else {
				b.WriteString(strings.Repeat(`\`, n))
			}
			have = true
		case c == '"':
			if inQ && i+1 < len(line) && line[i+1] == '"' {
				b.WriteByte('"')
				i += 2
				have = true
				continue
			}
			inQ = !inQ
			have = true
			i++
		case (c == ' ' || c == '\t') && !inQ:
			if have {
				out = append(out, b.String())
				b.Reset()
				have = false
			}
			i++
		default:
			b.WriteByte(c)
			have = true
			i++
		}
	}
	if have {
		out = append(out, b.String())
	}
	return out
}

// psChildCommand reads the argv of a powershell / pwsh child (after the
// program): the -Command text (the rest of the line, joined by blanks) or the
// decoded -EncodedCommand. ok is false for a -File, a working-folder switch, a
// first positional (its meaning differs between editions) or an option the
// reader does not know.
func psChildCommand(args []string) (string, bool) {
	l, ok := psReadLaunch(args)
	if !ok || l.wd != "" || l.positional {
		return "", false
	}
	return l.code, true
}

// psLaunch is a powershell / pwsh command line read by psReadLaunch.
type psLaunch struct {
	code string
	wd   string // the -WorkingDirectory (-wd) folder
	// positional: the code is a positional argument (Windows PowerShell runs
	// it as -Command, pwsh as a -File script).
	positional bool
}

// psLaunchMaybe reads a powershell / pwsh call whose reading depends on the
// host edition, which effects never knows: a -WorkingDirectory (-wd) folder
// (pwsh has it, Windows PowerShell does not) or a positional script (Windows
// PowerShell runs it as -Command, pwsh as -File). Its body, run in the -wd
// folder, is a possible reading; the call stays opaque (DET111 R1, GAP-1557).
func psLaunchMaybe(c *psparse.Command) (*HostPayload, bool) {
	if b := psBaseNameOf(c); b != "powershell" && b != "pwsh" {
		return nil, false
	}
	if psHostHasEncodedArgs(c) {
		return nil, false
	}
	argv, ok := psHostArgv(c)
	if !ok {
		return nil, false
	}
	l, ok := psReadLaunch(argv)
	if !ok || (l.wd == "" && !l.positional) {
		return nil, false
	}
	return &HostPayload{Opaque: true, Maybe: l.code, MaybeCWD: l.wd, Dialect: DialectPowerShell}, true
}

// psHostArgv is the argv a host call passes when every element is literal: a
// switch as written, an argument its literal text.
func psHostArgv(c *psparse.Command) ([]string, bool) {
	var out []string
	for _, el := range c.Elements {
		switch e := el.(type) {
		case *psparse.Parameter:
			if e.HasColon {
				return nil, false
			}
			out = append(out, e.Raw)
		case *psparse.Arg:
			s, ok := psparse.LiteralString(e.Value)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		default:
			return nil, false
		}
	}
	return out, true
}

// psReadLaunch reads a powershell / pwsh argv: the -Command / -EncodedCommand
// body or a positional script, and the -WorkingDirectory folder. ok is false
// for an unknown switch, a -File script or no code.
func psReadLaunch(args []string) (psLaunch, bool) {
	var l psLaunch
	valued := []string{"executionpolicy", "windowstyle", "version", "inputformat", "outputformat", "configurationname", "settingsfile", "custompipename"}
	bare := []string{"noprofile", "noninteractive", "nologo", "noexit", "sta", "mta", "login", "noprofileloadtime", "interactive"}
	prefixOf := func(full, n string, min int) bool { return len(n) >= min && strings.HasPrefix(full, n) }
	code := func(rest []string) (psLaunch, bool) {
		l.code = strings.Join(rest, " ")
		return l, strings.TrimSpace(l.code) != "" && strings.TrimSpace(l.code) != "-"
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" || (a[0] != '-' && a[0] != '/') {
			l.positional = true
			return code(args[i:])
		}
		if len(a) < 2 {
			return l, false
		}
		n := strings.ToLower(a[1:])
		switch {
		case n == "c" || prefixOf("command", n, 3):
			return code(args[i+1:])
		case n == "e" || n == "ec" || prefixOf("encodedcommand", n, 3):
			if i+1 >= len(args) {
				return l, false
			}
			text, ok := psparse.DecodeEncodedCommand(args[i+1])
			l.code = text
			return l, ok
		case n == "wd" || prefixOf("workingdirectory", n, 3):
			if i+1 >= len(args) {
				return l, false
			}
			l.wd = args[i+1]
			i++
			continue
		case n == "nop" || n == "noni":
			continue
		case n == "ep" || n == "ex" || n == "w":
			i++
			continue
		}
		known := false
		for _, v := range valued {
			if prefixOf(v, n, 3) {
				known = true
				i++
				break
			}
		}
		if !known {
			for _, v := range bare {
				if prefixOf(v, n, 3) {
					known = true
					break
				}
			}
		}
		if !known {
			return l, false
		}
	}
	return l, false
}

// psStartProcessChild is the script a Start-Process of powershell / pwsh / cmd
// starts: the -ArgumentList (one literal string, or a list of literal strings
// joined by blanks, as Start-Process joins them) is the child's command line.
// A string with `" escapes (-ArgumentList "-Command `"...`"") is read by its
// decoded value as the child gets it (psparse.NestedScriptText, GAP-1941).
// ok is false when the child, the list or the line cannot be read.
func psStartProcessChild(c *psparse.Command) (text string, dialect Dialect, ok bool) {
	name, line, ok := psStartProcessLine(c)
	if !ok {
		return "", "", false
	}
	switch psLeaf(name) {
	case "cmd":
		body, ok := cmdSlashCBody("cmd "+line, []Word{{Value: "cmd", Static: true}, {Value: "/c", Static: true}})
		return body, DialectCMD, ok && strings.TrimSpace(body) != ""
	case "powershell", "pwsh":
		code, ok := psChildCommand(winArgv(line))
		return code, DialectPowerShell, ok
	}
	return "", "", false
}

// StartProcessChildArgv is the argv a Start-Process call hands the program it
// starts: the -FilePath (or first positional) program, then its command line
// (psStartProcessLine) split as the child splits it (CommandLineToArgvW,
// winArgv). It reads the same binding as the effects lowering, so a reader of
// the child of a native program (the actionfacts nested readings) and the
// lowering of a host child agree on the call (rel-1-0-10:GAP-0201). ok is
// false when the call has no -ArgumentList or cannot be bound.
func StartProcessChildArgv(c *psparse.Command) (argv []string, ok bool) {
	name, line, ok := psStartProcessLine(c)
	if !ok || name == "" {
		return nil, false
	}
	return append([]string{name}, winArgv(line)...), true
}

// WindowsCommandLineArgv splits a Windows command line into the argv a
// program gets from it, as CommandLineToArgvW does (winArgv): the reading of
// a PowerShell --% stop-parsing remainder, which the program gets verbatim
// (rel-1-0-10:GAP-0201).
func WindowsCommandLineArgv(line string) []string {
	return winArgv(line)
}

// psStartProcessLine is the program a Start-Process call starts and the
// command line it gives it: the -ArgumentList (one literal string, or a list
// of literal strings joined by blanks, as Start-Process joins them). ok is
// false when the call cannot be bound, names a parameter that changes how the
// child reads its words (-WorkingDirectory, -Credential, redirection files),
// or has no static program or list.
func psStartProcessLine(c *psparse.Command) (name, line string, ok bool) {
	b := psStartProcessBind(c)
	if b.unsettled {
		return "", "", false
	}
	for _, n := range b.params {
		switch n {
		case "filepath", "argumentlist", "wait", "nonewwindow", "passthru", "windowstyle", "verb":
		default:
			return "", "", false // -WorkingDirectory, -Credential, redirection files ...
		}
	}
	file, argList, positional := b.file, b.argList, b.positional
	if file == nil && len(positional) > 0 {
		file, positional = positional[0], positional[1:]
	}
	if argList == nil && len(positional) > 0 {
		argList, positional = positional[0], positional[1:]
	}
	if file == nil || argList == nil || len(positional) > 0 {
		return "", "", false
	}
	name, ok = psparse.LiteralString(file)
	if !ok {
		return "", "", false
	}
	// A string with `" escapes is read by its decoded value, as the child
	// gets it (psparse.NestedScriptText, GAP-1941).
	if s, ok := psparse.NestedScriptText(argList); ok {
		return name, s, true
	}
	items, ok := psparse.NestedScriptList(argList)
	if !ok {
		return "", "", false
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		if !it.Static {
			return "", "", false
		}
		parts = append(parts, it.Text)
	}
	return name, strings.Join(parts, " "), true
}

// psSPBinding is a Start-Process call bound as PowerShell binds it.
type psSPBinding struct {
	file, argList psparse.Expr
	positional    []psparse.Expr
	params        []string // the full names of the parameters given
	// unsettled: a parameter the reader cannot bind (an ambiguous prefix, a
	// name Start-Process does not have) or an element that is not an argument.
	unsettled bool
}

// psStartProcessSwitches take no value; psStartProcessValued take the next
// argument (or a :value).
var (
	psStartProcessSwitches = []string{"wait", "nonewwindow", "passthru", "usenewenvironment", "loaduserprofile", "whatif", "confirm"}
	psStartProcessValued   = []string{"filepath", "argumentlist", "credential", "workingdirectory", "verb", "windowstyle",
		"redirectstandarderror", "redirectstandardinput", "redirectstandardoutput", "environment"}
)

// psStartProcessParam resolves a parameter name (a unique prefix, or the args /
// lup aliases) to its full name; ok is false for an ambiguous or unknown one.
func psStartProcessParam(n string) (full string, isSwitch, ok bool) {
	switch n {
	case "args":
		return "argumentlist", false, true
	case "lup":
		return "loaduserprofile", true, true
	case "":
		return "", false, false
	}
	hits := 0
	for _, s := range psStartProcessSwitches {
		if strings.HasPrefix(s, n) {
			full, isSwitch, hits = s, true, hits+1
		}
	}
	for _, s := range psStartProcessValued {
		if strings.HasPrefix(s, n) {
			full, isSwitch, hits = s, false, hits+1
		}
	}
	return full, isSwitch, hits == 1
}

// psStartProcessBind binds a Start-Process call: a switch takes no value, a
// valued parameter takes its :value or the next argument, and the arguments
// left are positional (FilePath, then ArgumentList). The child pick and the
// child's command line read the same binding (DET111 R1, GAP-1655: a first
// positional taken before -WindowStyle Hidden consumed its value was a parser
// differential).
func psStartProcessBind(c *psparse.Command) psSPBinding {
	var b psSPBinding
	els := c.Elements
	for i := 0; i < len(els); i++ {
		switch e := els[i].(type) {
		case *psparse.Parameter:
			full, isSwitch, ok := psStartProcessParam(strings.ToLower(e.Name))
			if !ok {
				b.unsettled = true
				continue
			}
			b.params = append(b.params, full)
			if isSwitch {
				continue // a -Wait:$true colon value is the switch's own
			}
			var val psparse.Expr
			if e.HasColon {
				val = e.Colon
			} else if i+1 < len(els) {
				if a, isArg := els[i+1].(*psparse.Arg); isArg {
					val = a.Value
					i++
				}
			}
			switch full {
			case "filepath":
				b.file = val
			case "argumentlist":
				b.argList = val
			}
		case *psparse.Arg:
			b.positional = append(b.positional, e.Value)
		default:
			b.unsettled = true
		}
	}
	return b
}

// envItemCmdlets change an item of the drive they name: on the Env: drive, an
// environment variable.
var envItemCmdlets = set("set-item", "si", "new-item", "ni", "remove-item", "ri", "rm", "del", "erase", "rd", "rmdir",
	"clear-item", "cli", "set-content", "sc", "add-content", "ac", "clear-content", "clc", "rename-item", "rni", "ren",
	"copy-item", "cp", "copy", "cpi", "move-item", "mv", "move", "mi", "new-itemproperty", "set-itemproperty", "sp")

// noteSessionHome records a Set-Variable HOME update after its command runs.
// A literal value replaces the automatic home; an unresolved value disables
// the hook-home fallback for the rest of the current script.
func (lw *psLower) noteSessionHome(c *Cmd, cond bool) {
	if len(c.Words) < 2 || !c.Words[0].Static {
		return
	}
	name := psLeaf(c.Words[0].Value)
	if name != "set-variable" && name != "sv" {
		return
	}
	var variable string
	var value Word
	valueKnown := false
	for i := 1; i < len(c.Words); i++ {
		w := c.Words[i]
		if !w.Static {
			continue
		}
		switch strings.ToLower(w.Value) {
		case "-name":
			if i+1 < len(c.Words) && c.Words[i+1].Static {
				variable = c.Words[i+1].Value
				i++
			}
		case "-value":
			if i+1 < len(c.Words) {
				value, valueKnown = c.Words[i+1], true
				i++
			}
		default:
			if variable == "" && !strings.HasPrefix(w.Value, "-") {
				variable = w.Value
			}
		}
	}
	if !strings.EqualFold(variable, "HOME") {
		return
	}
	if !valueKnown || !value.Static {
		value = Word{Reason: ReasonDynamicExpansion}
	}
	assign := &Cmd{Cond: cond, Assigns: []Assign{{Name: psHomeVar, ValueWord: value}}}
	lw.out.Stmts = append(lw.out.Stmts, &Stmt{Cmds: []*Cmd{assign}, Cond: cond})
}

// noteEnvDrive records the variables a command changes through the Env: drive
// (Set-Item Env:USERPROFILE C:\x): the walker must not keep their old value.
func (lw *psLower) noteEnvDrive(c *Cmd) {
	if len(c.Words) < 2 || !c.Words[0].Static || !envItemCmdlets[psLeaf(c.Words[0].Value)] {
		return
	}
	for _, wd := range c.Words[1:] {
		if !wd.Static {
			continue
		}
		v := wd.Value
		if len(v) > 4 && strings.EqualFold(v[:4], "env:") {
			name := strings.TrimLeft(v[4:], `\/`)
			if name == "" || strings.ContainsAny(name, "*?[") {
				lw.out.Unknowns = append(lw.out.Unknowns, UnknownNode{Reason: ReasonDynamicExpansion})
				continue
			}
			lw.envChanged = append(lw.envChanged, name)
		}
	}
}

// noteEnvInvoke records [Environment]::SetEnvironmentVariable(NAME, ...): a
// literal NAME is unknown after the call; any other name leaves the call not
// fully known.
func (lw *psLower) noteEnvInvoke(v *psparse.Invoke, cond bool) {
	if !strings.EqualFold(v.Name, "SetEnvironmentVariable") {
		return
	}
	if len(v.Args) > 0 {
		if name, ok := psparse.LiteralString(v.Args[0]); ok && name != "" {
			lw.envChanged = append(lw.envChanged, name)
			lw.flushEnv(cond)
			return
		}
	}
	lw.out.Unknowns = append(lw.out.Unknowns, UnknownNode{Reason: ReasonDynamicExpansion})
}

// flushEnv lowers the recorded changes as assignments of an unknown value.
func (lw *psLower) flushEnv(cond bool) {
	if len(lw.envChanged) == 0 {
		return
	}
	c := &Cmd{Cond: cond}
	for _, name := range lw.envChanged {
		c.Assigns = append(c.Assigns, Assign{Name: name, ValueWord: Word{Reason: ReasonDynamicExpansion}})
	}
	lw.envChanged = nil
	lw.out.Stmts = append(lw.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: cond})
}

// psEncodedWithBlanks decodes the -EncodedCommand word of a host call whose
// only non-base64 runes are the blanks the host skips (space, tab, CR, LF).
func psEncodedWithBlanks(c *psparse.Command) (string, bool) {
	els := c.Elements
	for i := 0; i < len(els); i++ {
		p, ok := els[i].(*psparse.Parameter)
		if !ok {
			continue
		}
		n := strings.ToLower(p.Name)
		if n != "e" && n != "ec" && (len(n) < 3 || !strings.HasPrefix("encodedcommand", n)) {
			continue
		}
		var val psparse.Expr
		if p.HasColon {
			val = p.Colon
		} else if i+1 < len(els) {
			if a, ok := els[i+1].(*psparse.Arg); ok {
				val = a.Value
			}
		}
		sl, ok := val.(*psparse.StringLit)
		if !ok || !sl.Static || sl.Fused {
			return "", false
		}
		for _, r := range sl.Value {
			switch {
			case r == ' ' || r == '\t' || r == '\r' || r == '\n':
			case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/', r == '=':
			default:
				return "", false
			}
		}
		return psparse.DecodeEncodedCommand(sl.Value)
	}
	return "", false
}

// psExpandedCommand reads the -Command body of a host call that is one
// expandable string whose only expansions are the session $HOME and trusted
// $env: values ("Copy-Item $HOME\.aws\credentials ..."). Both readings agree
// on it: a PowerShell parent expands the string before the child starts, and a
// child that receives it verbatim expands the same variables to the same
// values (DET111 R1, GAP-1226).
//
// A body that also names plain session variables (foreach ($f in ...)) has no
// agreed reading: a PowerShell parent puts in values the call does not show,
// a child that gets the text verbatim reads the variables itself. The verbatim
// text is then returned with maybe set: the walker lowers it as a possible
// reading and the call stays opaque (DET111 R1, GAP-1550). Any other
// expansion (a subexpression, a scoped or splatted variable) keeps the body
// unread.
func psExpandedCommand(c *psparse.Command, o Options) (text string, maybe, ok bool) {
	els := c.Elements
	for i := 0; i < len(els); i++ {
		p, ok := els[i].(*psparse.Parameter)
		if !ok {
			continue
		}
		n := strings.ToLower(p.Name)
		if n != "c" && (len(n) < 3 || !strings.HasPrefix("command", n)) {
			continue
		}
		if p.HasColon || i+2 != len(els) {
			return "", false, false // the body must be the one, last argument
		}
		a, isArg := els[i+1].(*psparse.Arg)
		if !isArg {
			return "", false, false
		}
		sl, isLit := a.Value.(*psparse.StringLit)
		if !isLit {
			return "", false, false
		}
		if w, agreed := psStringWord(sl); agreed {
			text, ok = psExpandSegs(w.Segs, o)
			return text, false, ok
		}
		text, ok = psVerbatimBody(sl, o)
		return text, ok, ok
	}
	return "", false, false
}

// psExpandSegs writes an expandable string's segments with the session $HOME
// and trusted $env: values put in. ok is false for an unknown value or one
// that brings its own quoting or expansion.
func psExpandSegs(segs []WordSeg, o Options) (string, bool) {
	var b strings.Builder
	for _, seg := range segs {
		switch seg.Var {
		case "":
			b.WriteString(seg.Lit)
		case psHomeVar:
			v, ok := o.Env[psHomeVar]
			if !ok {
				v = o.Home
			}
			if v == "" {
				return "", false
			}
			b.WriteString(v)
		default:
			v, ok := psEnvValue(o.Env, seg.Var)
			if !ok {
				return "", false
			}
			b.WriteString(v)
		}
	}
	text := b.String()
	if strings.ContainsAny(text, "\"`$") {
		return "", false // a value that brings its own quoting or expansion
	}
	return text, true
}

// psVerbatimBody is the text a child host gets when the parent passes an
// expandable string unexpanded: literals and the resolvable variables as
// psExpandSegs writes them, a plain session variable ($f) kept as written.
// ok is false for any other part, or when no plain variable is kept (the
// agreed reading then applies).
func psVerbatimBody(sl *psparse.StringLit, o Options) (string, bool) {
	if sl == nil || sl.Static || sl.Fused || sl.Bare || len(sl.Parts) == 0 {
		return "", false
	}
	var b strings.Builder
	kept := false
	for _, p := range sl.Parts {
		if p.Expr == nil {
			if strings.ContainsAny(p.Lit, "\"`$\x00") {
				return "", false
			}
			b.WriteString(p.Lit)
			continue
		}
		v, isVar := p.Expr.(*psparse.Variable)
		if !isVar {
			return "", false
		}
		if seg, ok := psVarSeg(v); ok {
			text, ok := psExpandSegs([]WordSeg{seg}, o)
			if !ok {
				return "", false
			}
			b.WriteString(text)
			continue
		}
		if v.Splat || v.Scope != "" || !plainIdent(v.Name) {
			return "", false
		}
		b.WriteString("$" + v.Name)
		kept = true
	}
	return b.String(), kept
}

// psEnvValue looks a trusted environment value up the way Windows does: the
// name is case-insensitive.
func psEnvValue(env map[string]string, name string) (string, bool) {
	if v, ok := env[name]; ok {
		return v, true
	}
	for k, v := range env {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// psLegacyCmdBody is the body a PowerShell `cmd [switches] /c ARGS` hands
// cmd.exe when psparse declined it for legacy quoting only because its joined
// text shows the quotes PowerShell itself adds: every argument is a static
// word with no embedded double quote, no empty word and no blank-bearing word
// ending in a backslash (the 5.1 cases that change the argv), so the command
// line is the words joined with a blank, a blank-bearing word wrapped in
// quotes, and cmd's /c rule strips the first and last quote of the body
// (DET111 R1, GAP-0974: cmd /c cmd /c "..." from PowerShell). psparse also
// declines a payload it cannot locate (ps_cmd_argv); the same exact reading
// applies when every word before the run switch is a plain switch.
func psLegacyCmdBody(c *psparse.Command) (string, bool) {
	var words []string
	slash := -1
	for _, el := range c.Elements {
		var v string
		switch x := el.(type) {
		case *psparse.Arg:
			sl, ok := x.Value.(*psparse.StringLit)
			if !ok || !sl.Static || sl.Fused {
				return "", false
			}
			v = sl.Value
		case *psparse.Parameter:
			if x.HasColon {
				return "", false
			}
			v = x.Raw
		default:
			return "", false
		}
		if v == "" || strings.ContainsRune(v, '"') {
			return "", false
		}
		if strings.ContainsAny(v, " \t") {
			if strings.HasSuffix(v, `\`) {
				return "", false
			}
			v = `"` + v + `"`
		}
		if lv := strings.ToLower(v); slash < 0 {
			switch {
			case lv == "/c" || lv == "/k" || lv == "/r":
				slash = len(words)
			case !psCmdPlainSwitch(lv):
				// a fused, combined or quoting switch (/d/c, /crd, /s) before
				// the run switch: cmd reads it differently, stay opaque
				return "", false
			}
		}
		words = append(words, v)
	}
	if slash < 0 || slash+1 >= len(words) {
		return "", false
	}
	body := strings.Join(words[slash+1:], " ")
	if strings.HasPrefix(body, `"`) {
		if last := strings.LastIndex(body, `"`); last > 0 {
			body = body[1:last] + body[last+1:]
		}
	}
	return body, true
}

// psCmdPlainSwitch reports a word before cmd's run switch that does not change
// where or how the /c body is read: /d /q /a /u, and the
// /e: /f: /v: settings.
func psCmdPlainSwitch(w string) bool {
	switch w {
	case "/d", "/q", "/a", "/u":
		return true
	}
	for _, p := range []string{"/e:", "/f:", "/v:"} {
		if strings.HasPrefix(w, p) && !strings.Contains(w[len(p):], "/") {
			return true
		}
	}
	return false
}
