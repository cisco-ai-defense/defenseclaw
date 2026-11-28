// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// parsePowerShell lowers a PowerShell command into the neutral IR using the
// full-grammar parser in internal/psparse (lane s7-pwsh). It replaces the
// former hand tokenizer: the extractor and program table are unchanged; this
// adapter maps psparse's AST onto IR Cmds/Words at the dialect seam
// (EFFECTS.md "PowerShell AST"). Anything psparse could not resolve statically
// is a diagnostic -> a structural unknown; a dynamic value is a dynamic Word;
// a static nested script (-Command, iex 'lit', cmd /c) is expanded one level.
func parsePowerShell(command string, o Options) *Script {
	return lowerPSScript(command, o, true)
}

// parsePSSource parses a PowerShell script for lowering with
// psparse.ParseEffects: the pure-Go port of the Microsoft PowerShell parser
// through psparse.FromPwshparse by default, psparse.Parse when the port declines
// the input (or under psparse's legacyFrontend test seam). The legacy 1.0.10 PowerShell
// readers always use psparse.Parse (the raise-only floor). port reports that
// the port built the Script.
func parsePSSource(command string) (sc *psparse.Script, port bool, err error) {
	return psSourceParser(command, psparse.Options{Dialect: psparse.DialectUnknown})
}

// psSourceParser is the reader of parsePSSource. The frontend differential
// test (gap1915_frontend_diff_test.go) swaps in psparse.Parse to compare the
// port with the legacy reader on the same calls.
var psSourceParser = psparse.ParseEffects

func lowerPSScript(command string, o Options, expandNested bool) *Script {
	s := &Script{Dialect: DialectPowerShell}
	// The PowerShell edition is unknown unless the connector proves it, so a
	// dialect-divergent escape (backtick-e, \u{}) is not treated as static
	// (psparse review 3 / R4). A future caller that knows the host edition can
	// pass DialectPwsh7 / DialectWindowsPS51.
	sc, port, err := parsePSSource(command)
	if err != nil || sc == nil {
		s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonInvalidSyntax})
		return s
	}
	s.RunsNothing = port && sc.HasSyntaxError()
	return lowerPSParsed(s, sc, port, o, expandNested)
}

// lowerPSParsed lowers a parsed PowerShell Script into s; port reports that
// the parser port built sc (psparse.ParseEffects).
func lowerPSParsed(s *Script, sc *psparse.Script, port bool, o Options, expandNested bool) *Script {
	for _, d := range sc.Diagnostics {
		s.Unknowns = append(s.Unknowns, UnknownNode{Reason: psReason(d.Reason)})
	}
	lw := &psLower{out: s, o: o, hosts: map[psparse.Node]*HostPayload{}, port: port}
	var nested []psparse.NestedScript
	if expandNested {
		nested = psparse.ExtractNestedScripts(sc)
		// psparse owns the reading of a host call (cmd / powershell / pwsh): its
		// verdict is attached to the lowered command, which the walker unwraps in
		// program order (right cwd and env) and only when the verdict is Static.
		for _, ns := range nested {
			cmd, ok := ns.Source.(*psparse.Command)
			if !ok || !isHostName(psBaseNameOf(cmd)) {
				continue
			}
			hp := &HostPayload{Opaque: true}
			if !ns.Static && ns.Kind == psparse.KindEncodedCommand {
				// psparse keeps a base64 word with a tab, CR or LF NotStatic; the
				// host skips those (Convert.FromBase64String), so it is read the
				// way the host decodes it (DET111 R1, GAP-1199).
				if text, ok := psEncodedWithBlanks(cmd); ok {
					ns.Text, ns.Static = text, true
				}
			}
			if !ns.Static && ns.Kind == psparse.KindCmdC &&
				(ns.Reason == psparse.ReasonLegacyQuoting || ns.Reason == psparse.ReasonCmdArgv) {
				if text, ok := psLegacyCmdBody(cmd); ok {
					ns.Text, ns.Static, ns.Dialect = text, true, "cmd"
				}
			}
			if !ns.Static && ns.Kind == psparse.KindPowerShellCommand {
				if text, maybe, ok := psExpandedCommand(cmd, o); ok && !maybe {
					ns.Text, ns.Static = text, true
				} else if ok {
					hp.Maybe, hp.Dialect = text, DialectPowerShell
				}
			}
			if ns.Static && !psHostUnsafe(cmd, ns) {
				hp = &HostPayload{Text: ns.Text, Dialect: DialectPowerShell}
				if ns.Dialect == "cmd" {
					hp.Dialect = DialectCMD
				}
			}
			lw.hosts[ns.Source] = hp
		}
	}
	if expandNested {
		// A host call whose reading depends on the edition (-wd, a positional
		// script) is read as a possible reading (DET111 R1, GAP-1557).
		collectPSCommands(sc.Statements, 0, func(c *psparse.Command) {
			if hp := lw.hosts[c]; hp != nil && !hp.Opaque {
				return
			}
			if hp, ok := psLaunchMaybe(c); ok {
				lw.hosts[c] = hp
			}
		})
	}
	lw.statements(sc.Statements, false)
	if expandNested {
		// Start-Process launching powershell/pwsh/cmd: psparse joins/splits the
		// -ArgumentList wrongly (quotes, prefixes, dynamic elements), so the
		// extracted nested text is never trusted -- the child runs opaque code
		// (psparse delta review 5 (a)). Collect those host commands so we can both
		// drop their nested expansion and record the opacity.
		spShell := map[psparse.Node]bool{}
		collectPSCommands(sc.Statements, 0, func(c *psparse.Command) {
			if psStartProcessShellTarget(c) {
				spShell[c] = true
			}
		})
		// A child whose command line is literal is also read as the child reads
		// it (CommandLineToArgvW, then its -Command / -EncodedCommand or cmd /c
		// body), so what it runs is visible (DET111 R1, GAP-1577, GAP-1655). A
		// powershell or pwsh child keeps the opaque marker: its edition (and so
		// its exact argv reading) is not known, so the call is never fully
		// known. A cmd child has no edition: cmd reads its literal command line
		// one way, so its body is the call's reading (GAP-1577 var4: a Known
		// write of a cmd /c body started by Start-Process is Known).
		for n := range spShell {
			c, isCmd := n.(*psparse.Command)
			text, d, ok := "", DialectNone, false
			if isCmd {
				text, d, ok = psStartProcessChild(c)
			}
			if !ok || d != DialectCMD {
				s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonOpaqueCode})
			}
			if !ok {
				continue
			}
			var inner *Script
			if d == DialectCMD {
				inner = parseCMD(text, o)
			} else {
				inner = lowerPSScript(text, o, true)
			}
			s.Funcs = append(s.Funcs, inner.Funcs...)
			s.Stmts = append(s.Stmts, inner.Stmts...)
			s.Unknowns = append(s.Unknowns, inner.Unknowns...)
		}
		for _, ns := range nested {
			if spShell[ns.Source] {
				continue // never use a Start-Process-into-shell nested text (review 5 (a))
			}
			// A host call's verdict travels on its lowered command (above): the
			// walker unwraps a Static one in place and keeps an opaque one opaque.
			// The structure-level marker stays so a call psparse could not read is
			// never fully known even where the command was not lowered (a hashtable
			// key, an index), and psparse's own copy of the text is not walked twice.
			if hp := lw.hosts[ns.Source]; hp != nil {
				if hp.Opaque {
					s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonOpaqueCode})
				}
				continue
			}
			// A powershell/pwsh host carrying -EncodedArguments: psparse decodes
			// the CLIXML args blob as if it were the script (and misses the real
			// -EncodedCommand), so never re-parse it. The payload is opaque; the
			// walker also emits an opaque exec for the host (psparse delta review
			// 4 (c)).
			if cmd, ok := ns.Source.(*psparse.Command); ok && psHostHasEncodedArgs(cmd) {
				s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonOpaqueCode})
				continue
			}
			// A -Command / -EncodedCommand payload whose source carries a " is not
			// trusted under DialectUnknown / 5.1: the child drops the quotes (legacy
			// native argument passing), so the static parse can miss a command
			// inside the quoted span (psparse delta review 5 (b)).
			if ns.Static && ns.Dialect == "powershell" &&
				(ns.Kind == psparse.KindPowerShellCommand || ns.Kind == psparse.KindEncodedCommand) &&
				strings.Contains(ns.Text, `"`) {
				s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonOpaqueCode})
				continue
			}
			if !ns.Static {
				s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonOpaqueCode})
				continue
			}
			var inner *Script
			if ns.Dialect == "cmd" {
				inner = parseCMD(ns.Text, o)
			} else {
				inner = lowerPSScript(ns.Text, o, false)
			}
			s.Funcs = append(s.Funcs, inner.Funcs...)
			s.Stmts = append(s.Stmts, inner.Stmts...)
			s.Unknowns = append(s.Unknowns, inner.Unknowns...)
		}
	}
	return s
}

// psLeaf lower-cases a command/file name and strips its directory and a trailing
// .exe, so "C:\\WINDOWS\\System32\\cmd.exe" and "cmd" compare equal.
func psLeaf(name string) string {
	b := strings.ToLower(name)
	if i := strings.LastIndexAny(b, `\/`); i >= 0 {
		b = b[i+1:]
	}
	return strings.TrimSuffix(b, ".exe")
}

// isShellName reports a program that runs code from its arguments: powershell,
// pwsh or cmd.
func isShellName(name string) bool {
	switch psLeaf(name) {
	case "powershell", "pwsh", "cmd":
		return true
	}
	return false
}

// psStartProcessShellTarget reports a Start-Process (saps) command whose child
// is powershell/pwsh/cmd in any argument form -- the child's -ArgumentList is
// run as code we cannot reconstruct, so it is opaque (psparse delta review 5
// (a)). The child is bound as PowerShell binds it (psStartProcessBind): the
// -FilePath value, else the first positional left after the valued parameters
// took theirs (-WindowStyle Hidden powershell runs powershell). A binding the
// reader cannot settle (an ambiguous or unknown parameter) is a shell target
// when any argument names one.
func psStartProcessShellTarget(c *psparse.Command) bool {
	if n := psBaseNameOf(c); n != "start-process" && n != "saps" {
		return false
	}
	shell := func(e psparse.Expr) bool {
		s, ok := psparse.LiteralString(e)
		// A shell child, or a launcher (wt/conhost/start) that itself starts a
		// shell, runs an opaque payload (psparse delta review 5 (a) / review 6 (c)).
		return ok && (isShellName(s) || isLauncherName(s))
	}
	b := psStartProcessBind(c)
	if b.unsettled {
		for _, el := range c.Elements {
			switch e := el.(type) {
			case *psparse.Arg:
				if shell(e.Value) {
					return true
				}
			case *psparse.Parameter:
				if e.Colon != nil && shell(e.Colon) {
					return true
				}
			}
		}
		return false
	}
	target := b.file
	if target == nil && len(b.positional) > 0 {
		target = b.positional[0]
	}
	return target != nil && shell(target)
}

// psBaseNameOf returns the leaf name of a command, or "" when it is not a literal.
func psBaseNameOf(c *psparse.Command) string {
	if name, ok := psparse.LiteralString(c.Name); ok {
		return psLeaf(name)
	}
	return ""
}

// collectPSCommands calls fn for every command in the statements, descending one
// level into script-block arguments and block bodies, bounded by depth.
func collectPSCommands(sts []psparse.Statement, depth int, fn func(*psparse.Command)) {
	if depth > maxNestedDepth {
		return
	}
	for _, st := range sts {
		switch v := st.(type) {
		case *psparse.Pipeline:
			for seg := v; seg != nil; seg = seg.ChainRHS {
				for _, el := range seg.Elements {
					c, ok := el.(*psparse.Command)
					if !ok {
						continue
					}
					fn(c)
					for _, ce := range c.Elements {
						if a, ok := ce.(*psparse.Arg); ok {
							if sb, ok := a.Value.(*psparse.ScriptBlockExpr); ok {
								collectPSCommands(sb.Statements, depth+1, fn)
							}
						}
					}
				}
			}
		case *psparse.Block:
			collectPSCommands(v.Conditions, depth+1, fn)
			for _, b := range v.Bodies {
				if b != nil {
					collectPSCommands(b.Statements, depth+1, fn)
				}
			}
		}
	}
}

// psHostHasEncodedArgs reports a powershell/pwsh host command that carries an
// -EncodedArguments (/-encodeda/-ea) parameter, so its nested payload must not
// be re-parsed (psparse delta review 4 (c)).
func psHostHasEncodedArgs(c *psparse.Command) bool {
	if b := psBaseNameOf(c); b != "powershell" && b != "pwsh" {
		return false
	}
	for _, el := range c.Elements {
		p, ok := el.(*psparse.Parameter)
		if !ok {
			continue
		}
		n := strings.ToLower(p.Name)
		if n == "ea" || (strings.HasPrefix(n, "encodeda") && strings.HasPrefix("encodedarguments", n)) {
			return true
		}
	}
	return false
}

func psReason(code string) ReasonCode {
	switch code {
	case psparse.ReasonDynamicName, psparse.ReasonDynamicMember, psparse.ReasonNonLiteral:
		return ReasonDynamicExpansion
	case psparse.ReasonStopParsing:
		return ReasonOpaqueCode
	case psparse.ReasonDepthLimit, psparse.ReasonTruncated:
		return ReasonLimit
	default:
		return ReasonUnparsedConstruct
	}
}

type psLower struct {
	out   *Script
	o     Options
	hosts map[psparse.Node]*HostPayload
	// envChanged names the environment variables a command of the statement
	// being lowered changes through the Env: drive or
	// [Environment]::SetEnvironmentVariable: they are unknown after it.
	envChanged []string
	// port: the Script comes from the PowerShell parser port, so a native
	// program's argv is its elements one for one (nativeParamWords).
	port bool
	// funcs are the bodies of the functions defined so far, by lower-case
	// name; inlining names the ones being inlined now and inlined counts
	// every inlined call (psMaxInlinedCalls).
	funcs    map[string]*psparse.ScriptBlockExpr
	inlining []string
	inlined  int
	// aliases are the aliases Set-Alias / New-Alias set so far, by
	// lower-case name: the lower-case name of the command each one runs, ""
	// when the alias may or may not have been set (a built-in alias name
	// changed without -Force, a conditional command), rel-1-0-10:GAP-2257.
	aliases map[string]string
}

// psMaxInlinedCalls bounds the calls of script-defined functions one
// lowering inlines (each inline lowers the body again), and psMaxInlineDepth
// the nesting of such calls; a call past either is lowered as before (the
// walker reads the folder after it as unknown).
const (
	psMaxInlinedCalls = 32
	psMaxInlineDepth  = 4
)

func (lw *psLower) statements(sts []psparse.Statement, cond bool) {
	for _, st := range sts {
		lw.statement(st, cond)
	}
}

func (lw *psLower) statement(st psparse.Statement, cond bool) {
	switch v := st.(type) {
	case *psparse.Pipeline:
		lw.pipeline(v, cond)
	case *psparse.Assignment:
		lw.assignment(v, cond)
	case *psparse.Block:
		// A function (or filter) defined here shadows a cmdlet of the same name for
		// the rest of the script: the walker must not treat that name as the
		// cmdlet (round 8 H, rv7-B48). Names are case-insensitive.
		// function global:g defines g (rel-1-0-10:GAP-2257).
		fname := psFunctionName(v.Name)
		keyword := strings.ToLower(v.Keyword)
		if fname != "" {
			switch keyword {
			case "function", "filter", "workflow":
				lw.out.Funcs = append(lw.out.Funcs, fname)
			}
		}
		lw.statements(v.Conditions, cond)
		if fname != "" && (keyword == "function" || keyword == "filter") && len(v.Bodies) == 1 && v.Bodies[0] != nil {
			// A function (or filter) body runs where the function is called,
			// not here: its effects stay visible (conditional), but a
			// Set-Location in it does not move the folder of the statements
			// after the definition; a call of the function lowers the body
			// there (inlineCall), rel-1-0-10:GAP-1156, GAP-2257.
			sub := &Script{Dialect: lw.out.Dialect}
			outer := lw.out
			lw.out = sub
			lw.statements(v.Bodies[0].Statements, true)
			lw.out = outer
			lw.out.Stmts = append(lw.out.Stmts, &Stmt{Cmds: []*Cmd{{Sub: sub, Cond: true}}, Cond: true})
			if lw.funcs == nil {
				lw.funcs = map[string]*psparse.ScriptBlockExpr{}
			}
			lw.funcs[fname] = v.Bodies[0]
			return
		}
		for _, b := range v.Bodies {
			if b != nil {
				lw.statements(b.Statements, true)
			}
		}
	case *psparse.ExprStatement:
		// a bare expression: recurse for any nested commands via its sub-exprs.
		lw.exprCommands(v.Expr, cond)
	case *psparse.UnknownStatement:
		lw.out.Unknowns = append(lw.out.Unknowns, UnknownNode{Reason: psReason(v.Reason)})
	}
}

func (lw *psLower) pipeline(p *psparse.Pipeline, cond bool) {
	first := true
	for seg := p; seg != nil; seg = seg.ChainRHS {
		segCond := cond || !first
		var lastCmd *Cmd
		// A command is pipeline-fed when any element precedes it, including a
		// bare expression/string stage (review N5 S3/S4).
		for idx, el := range seg.Elements {
			switch e := el.(type) {
			case *psparse.Command:
				if lw.inlineCall(e, segCond) {
					// A redirection of the segment takes the output of the
					// inlined body: it gets a command of its own below.
					lastCmd = nil
					continue
				}
				lw.noteAlias(e, segCond)
				c := lw.command(e, segCond, idx > 0)
				if name, literal := psparse.LiteralString(e.Name); !literal && len(lw.funcs) > 0 {
					if _, block := e.Name.(*psparse.ScriptBlockExpr); !block {
						c.MayCallFunc = true
					}
				} else if literal && lw.mayCallFunc(name) {
					c.MayCallFunc = true
				}
				lw.out.Stmts = append(lw.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: segCond})
				lastCmd = c
				lw.noteEnvDrive(c)
				lw.flushEnv(segCond)
				lw.noteSessionHome(c, segCond)
			case *psparse.ExprStatement:
				lw.exprCommands(e.Expr, segCond)
			}
		}
		// pipeline redirections attach to the last stage's output.
		if lastCmd != nil {
			for _, r := range seg.Redirs {
				lw.addRedir(lastCmd, r)
			}
		} else if len(seg.Redirs) > 0 {
			c := &Cmd{Cond: segCond}
			for _, r := range seg.Redirs {
				lw.addRedir(c, r)
			}
			lw.out.Stmts = append(lw.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: segCond})
		}
		first = false
	}
}

// inlineCall lowers a call of a function this script defined as its body,
// in place and under the call's condition: PowerShell runs the body in the
// session, so its Set-Location moves the caller's folder (rel-1-0-10:
// GAP-1156: function g { cd .defenseclaw }; g; Set-Content config.yaml).
// The body runs whatever the call form (GAP-2257): with arguments (their
// commands run first; a parameter the body reads stays unknown), piped or
// fed by a pipe, redirected (the redirection gets a command of its own),
// with & or dot-sourced, or through an alias the script set. A recursive
// call, one past the bounds, and a name PowerShell resolves to a built-in
// alias first are not inlined.
func (lw *psLower) inlineCall(c *psparse.Command, cond bool) bool {
	if c.InvokeOp != "" && c.InvokeOp != "&" && c.InvokeOp != "." {
		return false
	}
	name, ok := lw.calledFunction(c)
	if !ok {
		return false
	}
	body := lw.funcs[name]
	if body == nil || lw.inlined >= psMaxInlinedCalls || len(lw.inlining) >= psMaxInlineDepth || slices.Contains(lw.inlining, name) {
		return false
	}
	for _, el := range c.Elements {
		switch e := el.(type) {
		case *psparse.Parameter:
			if e.HasColon && e.Colon != nil {
				lw.exprCommands(e.Colon, cond)
			}
		case *psparse.Arg:
			lw.exprCommands(e.Value, cond)
		case psparse.Expr:
			lw.exprCommands(e, cond)
		}
	}
	lw.inlined++
	lw.inlining = append(lw.inlining, name)
	lw.statements(body.Statements, cond)
	lw.inlining = lw.inlining[:len(lw.inlining)-1]
	if len(c.Redirs) > 0 {
		rc := &Cmd{Cond: cond}
		for _, r := range c.Redirs {
			lw.addRedir(rc, r)
		}
		lw.out.Stmts = append(lw.out.Stmts, &Stmt{Cmds: []*Cmd{rc}, Cond: cond})
	}
	return true
}

// calledFunction is the lower-case name of the script-defined function a
// command with a literal name runs: through an alias the script set first
// (an alias wins over a function), else the name itself unless it is a
// built-in alias. ok is false when the command runs no known function.
func (lw *psLower) calledFunction(c *psparse.Command) (string, bool) {
	name, ok := psparse.LiteralString(c.Name)
	if !ok {
		return "", false
	}
	name = strings.ToLower(name)
	if target, set := lw.aliases[name]; set {
		return target, target != ""
	}
	if psBuiltinAliases[name] {
		return "", false
	}
	return name, true
}

// mayCallFunc reports a literal command name that is an alias the script set
// for one of its functions, or may have set: a call of it that was not
// inlined leaves the folder unknown.
func (lw *psLower) mayCallFunc(name string) bool {
	target, set := lw.aliases[strings.ToLower(name)]
	return set && (target == "" || lw.funcs[target] != nil)
}

// noteAlias records the alias a Set-Alias / New-Alias (sal, nal) command
// with literal -Name and -Value sets (rel-1-0-10:GAP-2257). A built-in alias
// name changed without -Force may stay the built-in (a read-only one), and a
// conditional command may not run: both record the alias as unknown.
// -WhatIf sets nothing.
func (lw *psLower) noteAlias(c *psparse.Command, cond bool) {
	cmd, ok := psparse.LiteralString(c.Name)
	if !ok {
		return
	}
	switch strings.ToLower(cmd) {
	case "set-alias", "new-alias", "sal", "nal":
	default:
		return
	}
	var name, value string
	var positional []string
	force, literal := false, true
	take := func(e psparse.Expr) string {
		v, ok := psparse.LiteralString(e)
		if !ok {
			literal = false
		}
		return v
	}
	for i := 0; i < len(c.Elements); i++ {
		switch e := c.Elements[i].(type) {
		case *psparse.Parameter:
			p := strings.ToLower(e.Name)
			switch {
			case p == "":
				literal = false
			case strings.HasPrefix("force", p):
				force = true
			case len(p) >= 2 && strings.HasPrefix("whatif", p):
				return
			case strings.HasPrefix("passthru", p), len(p) >= 2 && strings.HasPrefix("confirm", p):
			case strings.HasPrefix("name", p), strings.HasPrefix("value", p),
				strings.HasPrefix("description", p), strings.HasPrefix("option", p), strings.HasPrefix("scope", p):
				var v string
				switch {
				case e.HasColon && e.Colon != nil:
					v = take(e.Colon)
				case i+1 < len(c.Elements):
					i++
					if a, ok := c.Elements[i].(*psparse.Arg); ok {
						v = take(a.Value)
					} else if x, ok := c.Elements[i].(psparse.Expr); ok {
						v = take(x)
					} else {
						literal = false
					}
				default:
					literal = false
				}
				if strings.HasPrefix("name", p) {
					name = v
				} else if strings.HasPrefix("value", p) {
					value = v
				}
			default:
				literal = false
			}
		case *psparse.Arg:
			positional = append(positional, take(e.Value))
		case psparse.Expr:
			positional = append(positional, take(e))
		}
	}
	for _, v := range positional {
		switch {
		case name == "":
			name = v
		case value == "":
			value = v
		}
	}
	if !literal || name == "" || value == "" {
		return
	}
	name = strings.ToLower(name)
	if lw.aliases == nil {
		lw.aliases = map[string]string{}
	}
	if cond || psBuiltinAliases[name] && !force {
		lw.aliases[name] = ""
		return
	}
	lw.aliases[name] = strings.ToLower(value)
}

// psFunctionName is the lower-case name a function definition defines: the
// name without a global:, script:, local: or private: scope (or function:
// drive) qualifier.
func psFunctionName(name string) string {
	name = strings.ToLower(name)
	for _, q := range []string{"global:", "script:", "local:", "private:", "function:"} {
		if rest, ok := strings.CutPrefix(name, q); ok {
			return rest
		}
	}
	return name
}

// psBuiltinAliases are the aliases PowerShell 7 and Windows PowerShell 5.1
// define in a new session. An alias is resolved before a function of the
// same name, so a call of one of these names runs the built-in command, not
// a function the script defines (function cd { }; cd x runs Set-Location).
var psBuiltinAliases = map[string]bool{
	"?": true, "%": true, "ac": true, "asnp": true, "cat": true, "cd": true, "cfs": true, "chdir": true,
	"clc": true, "clear": true, "clhy": true, "cli": true, "clp": true, "cls": true, "clv": true,
	"cnsn": true, "compare": true, "copy": true, "cp": true, "cpi": true, "cpp": true, "curl": true,
	"cvpa": true, "dbp": true, "del": true, "diff": true, "dir": true, "dnsn": true, "ebp": true,
	"echo": true, "epal": true, "epcsv": true, "epsn": true, "erase": true, "etsn": true, "exsn": true,
	"fc": true, "fhx": true, "fl": true, "foreach": true, "ft": true, "fw": true, "gal": true,
	"gbp": true, "gc": true, "gcb": true, "gci": true, "gcm": true, "gcs": true, "gdr": true,
	"gerr": true, "ghy": true, "gi": true, "gin": true, "gjb": true, "gl": true, "gm": true,
	"gmo": true, "gp": true, "gps": true, "gpv": true, "group": true, "gsn": true, "gsnp": true,
	"gsv": true, "gtz": true, "gu": true, "gv": true, "gwmi": true, "h": true, "history": true,
	"icm": true, "iex": true, "ihy": true, "ii": true, "ipal": true, "ipcsv": true, "ipmo": true,
	"ipsn": true, "irm": true, "ise": true, "iwmi": true, "iwr": true, "kill": true, "lp": true,
	"ls": true, "man": true, "md": true, "measure": true, "mi": true, "mount": true, "move": true,
	"mp": true, "mv": true, "nal": true, "ndr": true, "ni": true, "nmo": true, "npssc": true,
	"nsn": true, "nv": true, "ogv": true, "oh": true, "popd": true, "ps": true, "pushd": true,
	"pwd": true, "r": true, "rbp": true, "rcjb": true, "rcsn": true, "rd": true, "rdr": true,
	"ren": true, "ri": true, "rjb": true, "rm": true, "rmdir": true, "rmo": true, "rni": true,
	"rnp": true, "rp": true, "rsn": true, "rsnp": true, "rujb": true, "rv": true, "rvpa": true,
	"rwmi": true, "sajb": true, "sal": true, "saps": true, "sasv": true, "sbp": true, "sc": true,
	"scb": true, "select": true, "set": true, "shcm": true, "si": true, "sl": true, "sleep": true,
	"sls": true, "sort": true, "sp": true, "spjb": true, "spps": true, "spsv": true, "start": true,
	"stz": true, "sujb": true, "sv": true, "swmi": true, "tee": true, "trcm": true, "type": true,
	"wget": true, "where": true, "wjb": true, "write": true,
}

func (lw *psLower) assignment(a *psparse.Assignment, cond bool) {
	// $env:NAME = value updates the running environment (review PS-7).
	if v, ok := a.LHS.(*psparse.Variable); ok {
		name := ""
		switch {
		case strings.EqualFold(v.Scope, "env"):
			name = v.Name
		case v.Scope == "" && strings.EqualFold(v.Name, "home"):
			name = psHomeVar
		}
		if name != "" {
			c := &Cmd{Cond: cond, Assigns: []Assign{{Name: name, ValueWord: lw.exprWord(rhsExpr(a.RHS))}}}
			lw.out.Stmts = append(lw.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: cond})
			return
		}
	}
	// any command on the RHS still runs.
	lw.statement(a.RHS, cond)
}

func (lw *psLower) command(c *psparse.Command, cond, pipeIn bool) *Cmd {
	out := &Cmd{Cond: cond, PipeIn: pipeIn, Host: lw.hosts[c]}
	// `& { ... }` / `. { ... }` runs the block now, under the command's own
	// condition, in this session (a Set-Location or $env: change inside it
	// stays): its statements are lowered in place (DET111 R1, GAP-1255).
	if sb, ok := c.Name.(*psparse.ScriptBlockExpr); ok && (c.InvokeOp == "&" || c.InvokeOp == ".") {
		lw.statements(sb.Statements, cond)
		for _, el := range c.Elements {
			if e, ok := el.(psparse.Expr); ok {
				lw.exprCommands(e, true)
			} else if a, ok := el.(*psparse.Arg); ok {
				lw.exprCommands(a.Value, true)
			}
		}
		for _, r := range c.Redirs {
			lw.addRedir(out, r)
		}
		return out
	}
	// program name
	if name, ok := psparse.LiteralString(c.Name); ok && c.InvokeOp != "." {
		out.Words = append(out.Words, Word{Value: name, Static: true, Segs: []WordSeg{{Lit: name}}})
	} else {
		out.Words = append(out.Words, Word{Reason: ReasonDynamicExpansion})
	}
	native := psNativeName(c)
	for i := 0; i < len(c.Elements); i++ {
		switch e := c.Elements[i].(type) {
		case *psparse.Parameter:
			if native && lw.port {
				out.Words = append(out.Words, lw.nativeParamWords(e)...)
				continue
			}
			if native && !e.HasColon && i+1 < len(c.Elements) {
				if wd, ok := lw.fusedNativeArg(e, c.Elements[i+1]); ok {
					out.Words = append(out.Words, wd)
					i++
					continue
				}
			}
			out.Words = append(out.Words, Word{Value: "-" + e.Name, Static: true, Segs: []WordSeg{{Lit: "-" + e.Name}}})
			if e.HasColon && e.Colon != nil {
				// -Path:a,b,c : a comma list is several operands, never one path.
				out.Words = append(out.Words, lw.argWords(e.Colon)...)
				lw.exprCommands(e.Colon, true)
			}
		case *psparse.Arg:
			// A comma list / @( ) argument is several operands, one per element
			// (each static element its own, a non-static element UNKNOWN); it is
			// never collapsed into one path (psparse delta review 4 (a)).
			out.Words = append(out.Words, lw.argWords(e.Value)...)
			// a script-block / sub-expression argument (& { ... },
			// Invoke-Command -ScriptBlock { ... }) runs its inner commands
			// (review N20 H1/H2).
			lw.exprCommands(e.Value, true)
		case psparse.Expr:
			out.Words = append(out.Words, lw.argWords(e)...)
			lw.exprCommands(e, true)
		}
	}
	// `& { ... }` / `. { ... }`: the command name itself is a script block.
	lw.exprCommands(c.Name, true)
	for _, r := range c.Redirs {
		lw.addRedir(out, r)
	}
	return out
}

// psNativeName reports a command whose name is a program, not a cmdlet: a
// literal name with no Verb-Noun hyphen. PowerShell binds a cmdlet's -Name
// value to the parameter, but hands a native program the source text of a
// switch and the argument glued to it (-o$env:X\y) as one argv word.
func psNativeName(c *psparse.Command) bool {
	name := psBaseNameOf(c)
	return name != "" && !strings.Contains(name, "-")
}

// fusedNativeArg reads a psparse.Parse Script (the legacyFrontend seam reader
// and the deep-nesting fallback): psparse splits -o$env:X\y into
// a switch -o and a glued argument, and this joins them into one argv word
// (DET111 R1, GAP-1663), ok false when a blank separates them or the argument
// is several words. A port Script needs no join (nativeParamWords).
func (lw *psLower) fusedNativeArg(p *psparse.Parameter, next psparse.CommandElement) (Word, bool) {
	a, ok := next.(*psparse.Arg)
	if !ok {
		return Word{}, false
	}
	_, pEnd := p.Span()
	aStart, _ := a.Span()
	if pEnd != aStart {
		return Word{}, false
	}
	ws := lw.argWords(a.Value)
	if len(ws) != 1 {
		return Word{}, false
	}
	lw.exprCommands(a.Value, true)
	return fuseWord("-"+p.Name, ws[0]), true
}

// nativeParamWords is the argv a native program gets for a parameter token of
// a port Script, as PowerShell's native binder builds it (checked against
// pwsh 7.6.6 and Windows PowerShell 5.1): the token text as written, literal
// (-o$env:X\y is the parameter o$env with the argument X\y, passed as the one
// unexpanded word -o$env:X\y), and for the colon form the argument's value
// glued to "-name:" as one word (-o:$d\w is -o:<value of $d>\w), or a word of
// its own when a blank follows the colon. A cmdlet binds parameters instead.
func (lw *psLower) nativeParamWords(p *psparse.Parameter) []Word {
	head := p.Raw
	if head == "" {
		head = "-" + p.Name
	}
	if !p.HasColon {
		return []Word{{Value: head, Static: true, Segs: []WordSeg{{Lit: head}}}}
	}
	head += ":"
	hw := Word{Value: head, Static: true, Segs: []WordSeg{{Lit: head}}}
	if p.Colon == nil {
		return []Word{hw}
	}
	lw.exprCommands(p.Colon, true)
	ws := lw.argWords(p.Colon)
	ps, _ := p.Span()
	cs, _ := p.Colon.Span()
	if len(ws) != 1 || cs != ps+len(head) {
		return append([]Word{hw}, ws...)
	}
	return []Word{fuseWord(head, ws[0])}
}

// fuseWord is the one argv word of a literal switch text sw followed with no
// blank by the word w.
func fuseWord(sw string, w Word) Word {
	if w.Reason != "" {
		return Word{Reason: w.Reason}
	}
	segs := []WordSeg{{Lit: sw}}
	if w.Segs != nil {
		segs = append(segs, w.Segs...)
	} else {
		segs = append(segs, WordSeg{Lit: w.Value, Quoted: w.Quoted})
	}
	out := Word{Segs: segs, Static: w.Static, Quoted: w.Quoted}
	if w.Static {
		out.Value = sw + w.Value
	}
	return out
}

func (lw *psLower) addRedir(c *Cmd, r *psparse.Redirection) {
	if r == nil || r.Merge != "" || r.Target == nil {
		return // a stream merge (2>&1) is not a file write
	}
	red := Redir{FD: 1, Target: lw.exprWord(r.Target)}
	switch r.Op {
	case ">", "*>", "1>":
		red.Op = RedirWrite
	case ">>", "*>>", "1>>":
		red.Op = RedirAppend
	case "<":
		red.Op = RedirRead
	default:
		red.Op = RedirWrite
	}
	c.Redirs = append(c.Redirs, red)
}

// argWords lowers a command argument to one or more Words. A comma list
// (ArrayLit a,b,c) or an array sub-expression (@( ... )) becomes one Word per
// element, so the extractor never treats a multi-element argument as a single
// path; a non-literal element stays dynamic (UNKNOWN). A scalar lowers to one
// Word, unchanged (psparse delta review 4 (a)).
func (lw *psLower) argWords(e psparse.Expr) []Word {
	switch v := e.(type) {
	case *psparse.ArrayLit:
		var ws []Word
		for _, el := range v.Elements {
			ws = append(ws, lw.argWords(el)...)
		}
		if len(ws) == 0 {
			return []Word{{Reason: ReasonDynamicExpansion}}
		}
		return ws
	case *psparse.ArrayExpr:
		var ws []Word
		for _, st := range v.Statements {
			if es, ok := st.(*psparse.ExprStatement); ok {
				ws = append(ws, lw.argWords(es.Expr)...)
			} else {
				ws = append(ws, Word{Reason: ReasonDynamicExpansion})
			}
		}
		if len(ws) == 0 {
			return []Word{{Reason: ReasonDynamicExpansion}}
		}
		return ws
	default:
		return []Word{lw.exprWord(e)}
	}
}

// exprWord lowers a PowerShell expression to a Word: a static literal, an
// $env:VAR reference (resolved by the walker against the running env), else a
// dynamic word (review PS-3: a parenthesised/operator expression is dynamic).
func (lw *psLower) exprWord(e psparse.Expr) Word {
	if e == nil {
		return Word{Reason: ReasonDynamicExpansion}
	}
	if v, ok := e.(*psparse.Variable); ok {
		if seg, ok := psVarSeg(v); ok {
			return Word{Segs: []WordSeg{seg}}
		}
	}
	if s, ok := psparse.LiteralString(e); ok {
		return Word{Value: s, Static: true, Segs: []WordSeg{{Lit: s}}}
	}
	if sl, ok := e.(*psparse.StringLit); ok {
		if wd, ok := psStringWord(sl); ok {
			return wd // "$HOME\.aws\x", $env:USERPROFILE\.ssh (DET111 R1, GAP-0998)
		}
	}
	return Word{Reason: ReasonDynamicExpansion}
}

// exprCommands recurses into an expression for nested commands (script blocks,
// sub-expressions) so their effects are seen.
// exprCommands recurses into the sub-statements of an expression (script
// blocks, sub-expressions, arrays, parens, hashtable values) exactly once, so
// a nested $( ) / & { } is linear, not exponential (review R3-1). It does NOT
// use WalkCommands, which re-walks each command's whole subtree.
func (lw *psLower) exprCommands(e psparse.Expr, cond bool) {
	switch v := e.(type) {
	case nil:
	case *psparse.ScriptBlockExpr:
		lw.statements(v.Statements, true)
	case *psparse.SubExpr:
		lw.statements(v.Statements, true)
	case *psparse.ArrayExpr:
		lw.statements(v.Statements, true)
	case *psparse.Paren:
		lw.statement(v.Inner, true)
	case *psparse.Hashtable:
		for _, val := range v.Values {
			lw.exprCommands(val, cond)
		}
	case *psparse.ArrayLit:
		for _, el := range v.Elements {
			lw.exprCommands(el, cond)
		}
	case *psparse.Index:
		lw.exprCommands(v.Target, cond)
		lw.exprCommands(v.Index, cond)
	case *psparse.Member:
		lw.exprCommands(v.Target, cond)
	case *psparse.Invoke:
		lw.exprCommands(v.Target, cond)
		for _, a := range v.Args {
			lw.exprCommands(a, cond)
		}
		lw.noteEnvInvoke(v, cond)
	case *psparse.Binary:
		lw.exprCommands(v.LHS, cond)
		lw.exprCommands(v.RHS, cond)
	case *psparse.Unary:
		lw.exprCommands(v.Operand, cond)
	case *psparse.Convert:
		lw.exprCommands(v.Operand, cond)
	case *psparse.StringLit:
		for _, pt := range v.Parts {
			lw.exprCommands(pt.Expr, cond)
		}
	}
}

func rhsExpr(st psparse.Statement) psparse.Expr {
	switch v := st.(type) {
	case *psparse.ExprStatement:
		return v.Expr
	case *psparse.Pipeline:
		if len(v.Elements) == 1 {
			if es, ok := v.Elements[0].(*psparse.ExprStatement); ok {
				return es.Expr
			}
		}
	}
	return nil
}

// isHostName reports a program that runs a payload given in its arguments.
func isHostName(leaf string) bool {
	return leaf == "cmd" || leaf == "powershell" || leaf == "pwsh"
}

// psHostUnsafe reports a Static psparse payload that effects still does not
// trust: a -EncodedArguments blob (psparse decodes the CLIXML as the script), a
// -Command / -EncodedCommand text with a " (legacy native argument passing
// re-splits it on 5.1) and -WorkingDirectory / -wd (the text runs somewhere
// other than the caller's cwd, which a nested script cannot record).
func psHostUnsafe(cmd *psparse.Command, ns psparse.NestedScript) bool {
	if psHostHasEncodedArgs(cmd) || psHostHasWorkingDirectory(cmd) {
		return true
	}
	return ns.Dialect == "powershell" &&
		(ns.Kind == psparse.KindPowerShellCommand || ns.Kind == psparse.KindEncodedCommand) &&
		strings.Contains(ns.Text, `"`)
}

func psHostHasWorkingDirectory(c *psparse.Command) bool {
	if b := psBaseNameOf(c); b != "powershell" && b != "pwsh" {
		return false
	}
	for _, el := range c.Elements {
		p, ok := el.(*psparse.Parameter)
		if !ok {
			continue
		}
		n := strings.ToLower(p.Name)
		if n == "wd" || (len(n) >= 2 && strings.HasPrefix("workingdirectory", n)) {
			return true
		}
	}
	return false
}
