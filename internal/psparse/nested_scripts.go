// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "strings"

// NestedScript is a script embedded inside a command that the effects lane
// should re-parse (the parser does not recurse into it automatically because
// the inner dialect or decoding differs). Static is false when the payload
// could not be fully resolved (e.g. iex $var); such entries are never dropped
// so the caller can escalate.
type NestedScript struct {
	Kind    string // see the Kind* constants
	Dialect string // "powershell" or "cmd"
	Text    string // the resolved/decoded inner script, ready to re-parse
	Static  bool
	Reason  string // set when !Static (a Reason* code)
	Source  Node   // the command or expression it was embedded in
}

const (
	KindPowerShellCommand = "powershell-command" // powershell -Command "<text>"
	KindEncodedCommand    = "encodedcommand"     // powershell -EncodedCommand <b64 utf16le>
	KindIEXLiteral        = "iex-literal"        // Invoke-Expression '<text>'
	KindScriptBlockCreate = "scriptblock-create" // [scriptblock]::Create('<text>')
	KindStartProcessArgs  = "start-process-args" // Start-Process powershell -ArgumentList ...
	KindCmdC              = "cmd-c"              // cmd /c "<text>"
)

var psExeNames = map[string]bool{
	"powershell": true, "powershell.exe": true, "pwsh": true, "pwsh.exe": true,
}
var cmdExeNames = map[string]bool{"cmd": true, "cmd.exe": true}

// ExtractNestedScripts walks the whole script and returns every embedded
// script text (PowerShell -Command / -EncodedCommand, Invoke-Expression of a
// literal, [scriptblock]::Create of a literal, Start-Process -ArgumentList to
// a PowerShell host, and cmd /c payloads). Each is returned with Static and,
// when not static, a Reason — never silently dropped.
func ExtractNestedScripts(sc *Script) []NestedScript {
	var out []NestedScript
	WalkCommands(sc, func(c *Command) {
		out = append(out, nestedFromCommand(c)...)
	})
	walkInvokes(sc, func(inv *Invoke) {
		if ns, ok := nestedFromScriptBlockCreate(inv); ok {
			out = append(out, ns)
		}
	})
	return out
}

func nestedFromCommand(c *Command) []NestedScript {
	name, ok := LiteralString(c.Name)
	if !ok {
		return nil
	}
	lower := strings.ToLower(name)
	switch {
	case psExeNames[lower]:
		return powerShellHostScripts(c)
	case cmdExeNames[lower]:
		if ns, ok := cmdCScript(c); ok {
			return []NestedScript{ns}
		}
	case lower == "iex" || lower == "invoke-expression":
		if ns, ok := iexScript(c); ok {
			return []NestedScript{ns}
		}
	case lower == "start-process" || lower == "saps":
		if ns, ok := startProcessScript(c); ok {
			return []NestedScript{ns}
		}
	}
	return nil
}

// powerShellHostScripts pulls -Command / -EncodedCommand (and their aliases and
// positional script) out of a powershell/pwsh invocation.
func powerShellHostScripts(c *Command) []NestedScript {
	var out []NestedScript
	pos := positionalArgs(c)
	if val, ok := paramValue(c, "command", "c"); ok {
		out = append(out, resolveNested(val, KindPowerShellCommand, "powershell", c))
	} else if enc, ok := paramValue(c, "encodedcommand", "e", "ec", "encoded"); ok {
		out = append(out, decodeNested(enc, c))
	} else if len(pos) > 0 {
		// powershell "<script>" with no switch runs the first argument
		out = append(out, resolveNested(pos[0], KindPowerShellCommand, "powershell", c))
	}
	return out
}

func decodeNested(val Expr, src Node) NestedScript {
	ns := NestedScript{Kind: KindEncodedCommand, Dialect: "powershell", Source: src}
	lit, ok := LiteralString(val)
	if !ok {
		ns.Reason = ReasonNonLiteral
		return ns
	}
	if dec, ok := DecodeEncodedCommand(lit); ok {
		ns.Text, ns.Static = dec, true
	} else {
		ns.Reason = ReasonNonLiteral
	}
	return ns
}

func resolveNested(val Expr, kind, dialect string, src Node) NestedScript {
	ns := NestedScript{Kind: kind, Dialect: dialect, Source: src}
	if lit, ok := LiteralString(val); ok {
		ns.Text, ns.Static = lit, true
	} else {
		ns.Reason = ReasonNonLiteral
	}
	return ns
}

func cmdCScript(c *Command) (NestedScript, bool) {
	// cmd /c <rest> : the payload is the first argument after /c or /k.
	for i, el := range c.Elements {
		if a, ok := el.(*Arg); ok {
			if s, ok := LiteralString(a.Value); ok {
				ls := strings.ToLower(s)
				if ls == "/c" || ls == "/k" {
					if i+1 < len(c.Elements) {
						if next, ok := c.Elements[i+1].(*Arg); ok {
							return resolveNested(next.Value, KindCmdC, "cmd", c), true
						}
					}
				}
			}
		}
	}
	return NestedScript{}, false
}

func iexScript(c *Command) (NestedScript, bool) {
	pos := positionalArgs(c)
	if v, ok := paramValue(c, "command"); ok {
		return resolveNested(v, KindIEXLiteral, "powershell", c), true
	}
	if len(pos) > 0 {
		return resolveNested(pos[0], KindIEXLiteral, "powershell", c), true
	}
	return NestedScript{}, false
}

func startProcessScript(c *Command) (NestedScript, bool) {
	// Start-Process <exe> -ArgumentList ... ; only interesting when the exe is
	// a PowerShell host.
	exe := ""
	if v, ok := paramValue(c, "filepath", "path"); ok {
		exe, _ = LiteralString(v)
	} else if pos := positionalArgs(c); len(pos) > 0 {
		exe, _ = LiteralString(pos[0])
	}
	if !psExeNames[strings.ToLower(exe)] {
		return NestedScript{}, false
	}
	val, ok := paramValue(c, "argumentlist", "args")
	if !ok {
		return NestedScript{}, false
	}
	ns := NestedScript{Kind: KindStartProcessArgs, Dialect: "powershell", Source: c}
	if lit, ok := LiteralString(val); ok {
		// best-effort: if the arg list contains -EncodedCommand decode it,
		// otherwise treat the joined text as the script after -Command.
		if dec, kind, ok := decodeFromArgList(lit); ok {
			ns.Text, ns.Static, ns.Kind = dec, true, kind
		} else {
			ns.Text, ns.Static = stripCommandSwitch(lit), true
		}
	} else {
		ns.Reason = ReasonNonLiteral
	}
	return ns, true
}

func decodeFromArgList(s string) (string, string, bool) {
	fields := strings.Fields(s)
	for i, f := range fields {
		lf := strings.ToLower(f)
		if (lf == "-encodedcommand" || lf == "-e" || lf == "-ec") && i+1 < len(fields) {
			if dec, ok := DecodeEncodedCommand(fields[i+1]); ok {
				return dec, KindStartProcessArgs, true
			}
		}
	}
	return "", "", false
}

func stripCommandSwitch(s string) string {
	fields := strings.Fields(s)
	for i, f := range fields {
		lf := strings.ToLower(f)
		if lf == "-command" || lf == "-c" {
			return strings.Join(fields[i+1:], " ")
		}
	}
	return s
}

// nestedFromScriptBlockCreate handles [scriptblock]::Create('<text>') and
// [ScriptBlock]::Create("<text>").
func nestedFromScriptBlockCreate(inv *Invoke) (NestedScript, bool) {
	if !inv.Static || !strings.EqualFold(inv.Name, "Create") {
		return NestedScript{}, false
	}
	te, ok := inv.Target.(*TypeExpr)
	if !ok || !strings.EqualFold(strings.TrimSpace(te.Name), "scriptblock") {
		return NestedScript{}, false
	}
	if len(inv.Args) == 0 {
		return NestedScript{}, false
	}
	return resolveNested(inv.Args[0], KindScriptBlockCreate, "powershell", inv), true
}

// positionalArgs returns the positional (non-parameter) argument expressions.
func positionalArgs(c *Command) []Expr {
	var out []Expr
	for _, el := range c.Elements {
		if a, ok := el.(*Arg); ok {
			out = append(out, a.Value)
		}
	}
	return out
}

// paramValue returns the value bound to the first of the given parameter names
// (case-insensitive). It handles both -Name:value (Colon) and -Name value
// (the following positional argument).
func paramValue(c *Command, names ...string) (Expr, bool) {
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	for i, el := range c.Elements {
		p, ok := el.(*Parameter)
		if !ok || !want[strings.ToLower(p.Name)] {
			continue
		}
		if p.Colon != nil {
			return p.Colon, true
		}
		if i+1 < len(c.Elements) {
			if a, ok := c.Elements[i+1].(*Arg); ok {
				return a.Value, true
			}
		}
		return nil, false // a switch parameter with no value
	}
	return nil, false
}

// walkInvokes visits every *Invoke in the script.
func walkInvokes(sc *Script, fn func(*Invoke)) {
	if sc == nil {
		return
	}
	var we func(Expr)
	var ws func([]Statement)
	wcmd := func(c *Command) {
		we(c.Name)
		for _, el := range c.Elements {
			switch e := el.(type) {
			case *Parameter:
				we(e.Colon)
			case *Arg:
				we(e.Value)
			case Expr:
				we(e)
			}
		}
		for _, r := range c.Redirs {
			we(r.Target)
		}
	}
	we = func(e Expr) {
		switch v := e.(type) {
		case nil:
		case *Invoke:
			fn(v)
			we(v.Target)
			for _, a := range v.Args {
				we(a)
			}
		case *Member:
			we(v.Target)
		case *Index:
			we(v.Target)
			we(v.Index)
		case *Binary:
			we(v.LHS)
			we(v.RHS)
		case *Unary:
			we(v.Operand)
		case *Convert:
			we(v.Operand)
		case *Paren:
			if es, ok := v.Inner.(*ExprStatement); ok {
				we(es.Expr)
			} else if v.Inner != nil {
				ws([]Statement{v.Inner})
			}
		case *ScriptBlockExpr:
			ws(v.Statements)
		case *SubExpr:
			ws(v.Statements)
		case *ArrayExpr:
			ws(v.Statements)
		case *ArrayLit:
			for _, el := range v.Elements {
				we(el)
			}
		case *Hashtable:
			for _, val := range v.Values {
				we(val)
			}
		case *StringLit:
			for _, pt := range v.Parts {
				we(pt.Expr)
			}
		case *scriptExprWrap:
			wcmd(v.cmd)
		}
	}
	ws = func(sts []Statement) {
		for _, s := range sts {
			switch v := s.(type) {
			case *Pipeline:
				for p := v; p != nil; p = p.ChainRHS {
					for _, el := range p.Elements {
						switch e := el.(type) {
						case *Command:
							wcmd(e)
						case *ExprStatement:
							we(e.Expr)
						}
					}
				}
			case *Assignment:
				we(v.LHS)
				ws([]Statement{v.RHS})
			case *Block:
				ws(v.Conditions)
				for _, b := range v.Bodies {
					if b != nil {
						ws(b.Statements)
					}
				}
			case *Command:
				wcmd(v)
			case *ExprStatement:
				we(v.Expr)
			}
		}
	}
	ws(sc.Statements)
}
