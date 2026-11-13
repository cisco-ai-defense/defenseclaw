// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "strings"

// NestedScript is a script embedded inside a command that the effects lane
// should re-parse (its inner dialect or encoding differs). Static is false
// when the payload could not be fully resolved (e.g. iex $var); such entries
// are never dropped so the caller can escalate.
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

// ExtractNestedScripts walks the whole script and returns every embedded script
// text (PowerShell -Command / -EncodedCommand, Invoke-Expression of a literal
// or of its pipeline input, [scriptblock]::Create of a literal, Start-Process
// -ArgumentList to a PowerShell host, and cmd /c payloads). Each is returned
// with Static and, when not static, a Reason — never silently dropped.
func ExtractNestedScripts(sc *Script) []NestedScript {
	var out []NestedScript
	var walkStmts func([]Statement)
	var walkExpr func(Expr)

	walkPipeline := func(pl *Pipeline) {
		for p := pl; p != nil; p = p.ChainRHS {
			for idx, el := range p.Elements {
				cmd, ok := el.(*Command)
				if !ok {
					if es, ok := el.(*ExprStatement); ok {
						walkExpr(es.Expr)
					}
					continue
				}
				if ns, handled := iexNested(cmd, p.Elements, idx); handled {
					out = append(out, ns...)
				} else {
					out = append(out, nestedFromCommand(cmd)...)
				}
				// recurse into argument expressions / script blocks
				walkExpr(cmd.Name)
				for _, ce := range cmd.Elements {
					switch e := ce.(type) {
					case *Parameter:
						walkExpr(e.Colon)
					case *Arg:
						walkExpr(e.Value)
					case Expr:
						walkExpr(e)
					}
				}
			}
			for _, r := range p.Redirs {
				walkExpr(r.Target)
			}
		}
	}
	walkStmts = func(sts []Statement) {
		for _, s := range sts {
			switch v := s.(type) {
			case *Pipeline:
				walkPipeline(v)
			case *Assignment:
				walkExpr(v.LHS)
				walkStmts([]Statement{v.RHS})
			case *Block:
				walkStmts(v.Conditions)
				for _, b := range v.Bodies {
					if b != nil {
						walkStmts(b.Statements)
					}
				}
			case *ExprStatement:
				walkExpr(v.Expr)
			case *Command:
				out = append(out, nestedFromCommand(v)...)
			}
		}
	}
	walkExpr = func(e Expr) {
		switch v := e.(type) {
		case nil:
		case *ScriptBlockExpr:
			walkStmts(v.Statements)
		case *SubExpr:
			walkStmts(v.Statements)
		case *ArrayExpr:
			walkStmts(v.Statements)
		case *ArrayLit:
			for _, el := range v.Elements {
				walkExpr(el)
			}
		case *Hashtable:
			for _, k := range v.Keys {
				walkExpr(k)
			}
			for _, val := range v.Values {
				walkExpr(val)
			}
		case *TypeExpr:
			for _, a := range v.Args {
				walkExpr(a)
			}
		case *Paren:
			walkStmts([]Statement{v.Inner})
		case *Member:
			walkExpr(v.Target)
		case *Invoke:
			if ns, ok := nestedFromScriptBlockCreate(v); ok {
				out = append(out, ns)
			}
			walkExpr(v.Target)
			for _, a := range v.Args {
				walkExpr(a)
			}
		case *Index:
			walkExpr(v.Target)
			walkExpr(v.Index)
		case *Binary:
			walkExpr(v.LHS)
			walkExpr(v.RHS)
		case *Unary:
			walkExpr(v.Operand)
		case *Convert:
			walkExpr(v.Operand)
		case *StringLit:
			for _, pt := range v.Parts {
				walkExpr(pt.Expr)
			}
		case *scriptExprWrap:
			out = append(out, nestedFromCommand(v.cmd)...)
		}
	}
	if sc != nil {
		walkStmts(sc.Statements)
	}
	// Invariant: a nested script with no resolved text is never Static=true
	// (an empty payload from a dropped --% tail or an unresolved value must
	// escalate, never be trusted as "an empty script"). See N2.
	for i := range out {
		if out[i].Static && out[i].Text == "" {
			out[i].Static = false
			if out[i].Reason == "" {
				out[i].Reason = ReasonStopParsing
			}
		}
	}
	return out
}

// baseName lower-cases and strips the directory and a trailing .exe from a
// program name so a full path matches a host by basename.
func baseName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndexAny(n, `\/`); i >= 0 {
		n = n[i+1:]
	}
	n = strings.TrimSuffix(n, ".exe")
	return n
}

func isPSHost(name string) bool {
	switch baseName(name) {
	case "powershell", "pwsh":
		return true
	}
	return false
}

func nestedFromCommand(c *Command) []NestedScript {
	name, ok := LiteralString(c.Name)
	if !ok {
		return nil
	}
	switch {
	case isPSHost(name):
		return powerShellHostScripts(c, hostWords(c))
	case baseName(name) == "cmd":
		if ns, ok := cmdCScript(c); ok {
			return []NestedScript{ns}
		}
	case isIEX(name):
		if ns, ok := iexArgScript(c); ok {
			return []NestedScript{ns}
		}
	case isStartProcess(name):
		if ns, ok := startProcessScript(c); ok {
			return []NestedScript{ns}
		}
	}
	return nil
}

func isIEX(name string) bool {
	n := strings.ToLower(name)
	if i := strings.LastIndex(n, `\`); i >= 0 { // module-qualified: ...\invoke-expression
		n = n[i+1:]
	}
	return n == "iex" || n == "invoke-expression"
}

func isStartProcess(name string) bool {
	switch strings.ToLower(name) {
	case "start-process", "saps", "start":
		return true
	}
	return false
}

// hostWord is one argument word of a PowerShell/Start-Process host invocation.
type hostWord struct {
	text   string
	static bool
}

func hostWords(c *Command) []hostWord {
	var out []hostWord
	for _, el := range c.Elements {
		switch e := el.(type) {
		case *Parameter:
			out = append(out, hostWord{"-" + e.Name, true})
			if e.Colon != nil {
				v, ok := LiteralString(e.Colon)
				out = append(out, hostWord{v, ok})
			}
		case *Arg:
			v, ok := LiteralString(e.Value)
			out = append(out, hostWord{v, ok})
		case Expr:
			v, ok := LiteralString(e)
			out = append(out, hostWord{v, ok})
		}
	}
	return out
}

// powerShellHostScripts applies the pwsh CLI parameter rules to a
// powershell/pwsh invocation's argument words and returns the embedded script.
func powerShellHostScripts(src Node, words []hostWord) []NestedScript {
	for i := 0; i < len(words); i++ {
		w := words[i]
		name, cand := stripParamLead(w.text)
		if cand {
			canon, takesVal, known := resolvePSParam(name)
			if known {
				switch canon {
				case "command":
					return []NestedScript{joinRest(words[i+1:], KindPowerShellCommand, "powershell", src)}
				case "encodedcommand":
					if i+1 < len(words) {
						return []NestedScript{decodeWord(words[i+1], src)}
					}
					return []NestedScript{{Kind: KindEncodedCommand, Dialect: "powershell", Source: src, Reason: ReasonNonLiteral}}
				case "encodedarguments":
					// -EncodedArguments is serialized CLI XML passed to the child
					// process, never the script to run; skip its value and keep
					// scanning for -EncodedCommand / -Command (review 4 R4-4).
					i++
					continue
				case "file":
					return nil // a script file; its content is not inline
				default:
					if takesVal {
						i++ // skip the value
					}
					continue
				}
			}
			if dashLed(w.text) {
				// an unknown -parameter: the host CLI has an option outside the
				// modeled set, so we cannot know whether it takes a value or
				// where the payload begins. Fail closed (review 3 R3).
				return []NestedScript{{Kind: KindPowerShellCommand, Dialect: "powershell", Source: src, Reason: ReasonHostOption}}
			}
		}
		// a positional word before any -Command/-File: pwsh/powershell runs it
		// as the command (join the rest of the line).
		return []NestedScript{joinRest(words[i:], KindPowerShellCommand, "powershell", src)}
	}
	return nil
}

// joinRest joins the remaining words into one script, static only if every word
// is static.
func joinRest(words []hostWord, kind, dialect string, src Node) NestedScript {
	ns := NestedScript{Kind: kind, Dialect: dialect, Source: src, Static: true}
	parts := make([]string, 0, len(words))
	for _, w := range words {
		if !w.static {
			ns.Static = false
			ns.Reason = ReasonNonLiteral
			break
		}
		if w.text == "--%" { // the stop-parse token is consumed, not part of the payload
			continue
		}
		parts = append(parts, w.text)
	}
	if ns.Static {
		ns.Text = strings.Join(parts, " ")
	}
	return ns
}

func decodeWord(w hostWord, src Node) NestedScript {
	ns := NestedScript{Kind: KindEncodedCommand, Dialect: "powershell", Source: src}
	if !w.static {
		ns.Reason = ReasonNonLiteral
		return ns
	}
	if dec, ok := DecodeEncodedCommand(w.text); ok {
		ns.Text, ns.Static = dec, true
	} else {
		ns.Reason = ReasonNonLiteral
	}
	return ns
}

// stripParamLead strips a leading -, --, / or Unicode dash and returns the
// lower-cased parameter name and whether the word looked like a parameter.
func stripParamLead(w string) (string, bool) {
	rs := []rune(w)
	if len(rs) == 0 {
		return "", false
	}
	i := 0
	if isDash(rs[0]) {
		i = 1
		if i < len(rs) && isDash(rs[i]) {
			i++
		}
	} else if rs[0] == '/' {
		i = 1
	} else {
		return "", false
	}
	if i >= len(rs) {
		return "", false
	}
	return strings.ToLower(string(rs[i:])), true
}

func dashLed(w string) bool {
	rs := []rune(w)
	return len(rs) > 0 && isDash(rs[0])
}

// psParams is the pwsh CLI parameter set with whether each takes a value.
var psParams = []struct {
	name string
	val  bool
}{
	{"command", true}, {"encodedcommand", true}, {"encodedarguments", true},
	{"executionpolicy", true}, {"file", true}, {"configurationname", true},
	{"configurationfile", true}, {"custompipename", true}, {"inputformat", true},
	{"outputformat", true}, {"windowstyle", true}, {"workingdirectory", true},
	{"settingsfile", true},
	{"login", false}, {"mta", false}, {"sta", false}, {"noexit", false},
	{"nologo", false}, {"noninteractive", false}, {"noprofile", false},
	{"noprofileloadtime", false}, {"interactive", false}, {"version", true},
	{"help", false}, {"sshservermode", false},
}

// resolvePSParam resolves a (possibly abbreviated) pwsh CLI parameter name to
// its canonical form, following the CLI's unambiguous-prefix rule with the
// documented e/c tie-breaks (-e..-enc -> EncodedCommand, -c -> Command).
func resolvePSParam(s string) (canonical string, takesValue, known bool) {
	if s == "" {
		return "", false, false
	}
	var hits []int
	for i, p := range psParams {
		if strings.HasPrefix(p.name, s) {
			hits = append(hits, i)
		}
	}
	switch {
	case len(hits) == 1:
		return psParams[hits[0]].name, psParams[hits[0]].val, true
	case len(hits) > 1:
		// documented pwsh tie-breaks for ambiguous prefixes
		if s == "c" {
			return "command", true, true
		}
		if s[0] == 'e' { // -e / -en / -enc ... -> EncodedCommand
			return "encodedcommand", true, true
		}
		if s == "w" { // -w -> WindowStyle
			return "windowstyle", true, true
		}
		// if the shortest match is itself a prefix of every other match (e.g.
		// noprofile vs noprofileloadtime), it wins.
		short := hits[0]
		for _, h := range hits {
			if len(psParams[h].name) < len(psParams[short].name) {
				short = h
			}
		}
		allExtend := true
		for _, h := range hits {
			if !strings.HasPrefix(psParams[h].name, psParams[short].name) {
				allExtend = false
				break
			}
		}
		if allExtend {
			return psParams[short].name, psParams[short].val, true
		}
		return "", false, false // genuinely ambiguous
	}
	return "", false, false
}

func cmdCScript(c *Command) (NestedScript, bool) {
	for i, el := range c.Elements {
		a, ok := el.(*Arg)
		if !ok {
			continue
		}
		s, ok := LiteralString(a.Value)
		if !ok {
			continue
		}
		switch strings.ToLower(s) {
		case "/c", "/k", "/r":
			// the payload is every element after the switch, joined
			ns := NestedScript{Kind: KindCmdC, Dialect: "cmd", Source: c, Static: true}
			var parts []string
			for _, rest := range c.Elements[i+1:] {
				ra, ok := rest.(*Arg)
				if !ok {
					ns.Static = false
					ns.Reason = ReasonNonLiteral
					break
				}
				v, ok := LiteralString(ra.Value)
				if !ok {
					ns.Static = false
					ns.Reason = ReasonNonLiteral
					break
				}
				if v == "--%" { // stop-parse token consumed, not part of the payload
					continue
				}
				parts = append(parts, v)
			}
			if ns.Static {
				ns.Text = strings.Join(parts, " ")
			}
			return ns, true
		}
	}
	return NestedScript{}, false
}

// iexArgScript handles Invoke-Expression / iex with an explicit value
// (positional or -Command).
func iexArgScript(c *Command) (NestedScript, bool) {
	if v, ok := paramValue(c, "command"); ok {
		return resolveNested(v, KindIEXLiteral, "powershell", c), true
	}
	for _, el := range c.Elements {
		if a, ok := el.(*Arg); ok {
			return resolveNested(a.Value, KindIEXLiteral, "powershell", c), true
		}
	}
	return NestedScript{}, false
}

// iexNested handles iex/Invoke-Expression in a pipeline: an explicit value, or
// (the download-cradle form) its pipeline input from the previous element.
func iexNested(c *Command, elems []PipelineElement, idx int) ([]NestedScript, bool) {
	name, ok := LiteralString(c.Name)
	if !ok || !isIEX(name) {
		return nil, false
	}
	if ns, ok := iexArgScript(c); ok {
		return []NestedScript{ns}, true
	}
	// no value: the script is this command's pipeline input.
	if idx > 0 {
		if prev, ok := elems[idx-1].(*ExprStatement); ok {
			if arr, ok := prev.Expr.(*ArrayLit); ok {
				// pwsh runs each element of a piped-in list as its own script,
				// so emit one nested script per element; never join them
				// (review 4 R4-3). Unresolvable elements stay non-static.
				res := make([]NestedScript, 0, len(arr.Elements))
				for _, el := range arr.Elements {
					res = append(res, resolveNested(el, KindIEXLiteral, "powershell", c))
				}
				if len(res) == 0 {
					res = append(res, NestedScript{Kind: KindIEXLiteral, Dialect: "powershell", Source: c, Reason: ReasonNonLiteral})
				}
				return res, true
			}
			return []NestedScript{resolveNested(prev.Expr, KindIEXLiteral, "powershell", c)}, true
		}
	}
	return []NestedScript{{Kind: KindIEXLiteral, Dialect: "powershell", Source: c, Reason: ReasonNonLiteral}}, true
}

func startProcessScript(c *Command) (NestedScript, bool) {
	exe := ""
	if v, ok := paramValue(c, "filepath", "path"); ok {
		exe, _ = LiteralString(v)
	} else {
		for _, el := range c.Elements {
			if a, ok := el.(*Arg); ok {
				exe, _ = LiteralString(a.Value)
				break
			}
		}
	}
	if !isPSHost(exe) {
		return NestedScript{}, false
	}
	val, ok := paramValue(c, "argumentlist", "args")
	if !ok {
		return NestedScript{}, false
	}
	// the ArgumentList is a string or an array of strings; build host words.
	var words []hostWord
	switch v := val.(type) {
	case *ArrayLit:
		for _, el := range v.Elements {
			s, ok := LiteralString(el)
			words = append(words, hostWord{s, ok})
		}
	default:
		if s, ok := LiteralString(val); ok {
			for _, f := range strings.Fields(s) {
				words = append(words, hostWord{f, true})
			}
		} else {
			return NestedScript{Kind: KindStartProcessArgs, Dialect: "powershell", Source: c, Reason: ReasonNonLiteral}, true
		}
	}
	res := powerShellHostScripts(c, words)
	if len(res) == 0 {
		return NestedScript{}, false
	}
	ns := res[0]
	ns.Kind = KindStartProcessArgs
	return ns, true
}

// nestedFromScriptBlockCreate handles [scriptblock]::Create('<text>') and the
// module-qualified [System.Management.Automation.ScriptBlock]::Create(...).
func nestedFromScriptBlockCreate(inv *Invoke) (NestedScript, bool) {
	if !inv.Static || !strings.EqualFold(inv.Name, "Create") {
		return NestedScript{}, false
	}
	te, ok := inv.Target.(*TypeExpr)
	if !ok || !isScriptBlockType(te.Name) {
		return NestedScript{}, false
	}
	if len(inv.Args) == 0 {
		return NestedScript{}, false
	}
	return resolveNested(inv.Args[0], KindScriptBlockCreate, "powershell", inv), true
}

func isScriptBlockType(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimPrefix(n, "system.management.automation.")
	return n == "scriptblock"
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

// paramValue returns the value bound to the first of the given parameter names
// (case-insensitive), handling -Name:value (Colon) and -Name value.
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
		return nil, false
	}
	return nil, false
}
