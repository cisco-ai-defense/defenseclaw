// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// PythonCodeOnlyReads reports inline Python code that is PROVEN to write
// nothing (rel-1-0-10:GAP-0104, GAP-0244, GAP-0269). The proof is a match
// against one small grammar of read shapes; code that does not match is
// UNCERTAIN and the caller treats it as a possible write. There is no
// general Python tokenizer here: a form the grammar does not list is never
// read, so a disagreement with CPython's lexer can only add findings.
//
// The grammar, in full. Code is statements separated by newlines or ";"
// (no indentation, no blocks, no continuation lines):
//
//	statement  = "import" module {"," module}
//	           | "from" module "import" name {"," name}   (pairs in pythonReadFromImports)
//	           | NAME "=" expression                       (NAME is new, plain ASCII, not reserved)
//	           | expression
//	expression = primary {"." method "(" args ")" | "[" expression "]"}
//	primary    = STRING | INTEGER | bound NAME | "sys" "." "argv" "[" INTEGER "]"
//	           | callee "(" args ")"      (callee in pythonReadCallees, pythonReadBuiltins
//	                                       or a name imported from the table)
//
// A STRING is a quoted literal with no prefix, no backslash, no triple
// quote and no newline. open() takes a path and a literal read mode
// ("r", "rb", "rt") and an optional literal encoding. The only operators
// are "(" ")" "[" "]" "," "." "=" and ";". A character outside printable
// ASCII (outside a string) ends the read, because CPython normalises
// identifiers (NFKC) and this reader does not. No name is called unless the
// tables list it, so there is no alias, no function passed as a value, no
// lambda, comprehension, f-string or t-string, no decorator, and no
// exec, eval, getattr or __import__.
func PythonCodeOnlyReads(code string) bool {
	if code == "" || len(code) > pythonReadMaxBytes {
		return false
	}
	p := &pythonReadParser{code: code, modules: map[string]bool{}, bound: map[string]bool{}, imported: map[string]bool{}}
	return p.program()
}

// The reviewed read shapes, as data. Adding a name here is a review
// decision: it must read and never write, whatever its arguments.
const pythonReadMaxBytes = 16 << 10

var (
	// pythonReadModules may be imported (no alias, no star). They resolve
	// from the standard library; the working directory is first on
	// sys.path for -c and stdin code, the same trust the shell tools carry.
	pythonReadModules = pythonReadSet("json sys tomllib pathlib hashlib")
	// pythonReadFromImports lists the names "from module import name" may bind.
	pythonReadFromImports = map[string]map[string]bool{
		"pathlib": pythonReadSet("Path"),
		"hashlib": pythonReadSet("sha256"),
	}
	// pythonReadCallees are the dotted module functions that may be called.
	pythonReadCallees = pythonReadSet("json.load json.loads tomllib.load tomllib.loads pathlib.Path hashlib.sha256")
	// pythonReadBuiltins are the builtins that may be called. open is
	// special-cased (read mode only); print only writes the output stream.
	pythonReadBuiltins = pythonReadSet("print len sorted list str repr int min max sum set tuple open")
	// pythonReadMethods are the methods that may be called on a value.
	pythonReadMethods = pythonReadSet("read read_text read_bytes get keys items values strip splitlines split " +
		"decode hexdigest exists is_file is_dir startswith endswith lower")
	pythonReadModes = pythonReadSet(`r rb rt`)
	// pythonReadReserved names may never be assigned.
	pythonReadReserved = pythonReadSet("False None True and as assert async await break class continue def del elif else " +
		"except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield " +
		"print len sorted list str repr int min max sum set tuple open json sys tomllib pathlib hashlib Path sha256 match case type")
)

func pythonReadSet(text string) map[string]bool {
	set := map[string]bool{}
	for _, word := range strings.Fields(text) {
		set[word] = true
	}
	return set
}

type pythonReadToken struct {
	kind byte // 'i' name, 'n' integer, 's' string, 'o' operator, ';' end of statement
	text string
}

type pythonReadParser struct {
	code     string
	toks     []pythonReadToken
	at       int
	depth    int
	modules  map[string]bool // modules imported by the code
	bound    map[string]bool // names assigned by the code
	imported map[string]bool // names bound by "from module import name"
}

func (p *pythonReadParser) program() bool {
	if !p.lex() {
		return false
	}
	statements := 0
	for p.at < len(p.toks) {
		if p.toks[p.at].kind == ';' {
			p.at++
			continue
		}
		if !p.statement() {
			return false
		}
		statements++
		if p.at < len(p.toks) && p.toks[p.at].kind != ';' {
			return false
		}
	}
	return statements > 0
}

// lex splits the code into the few token kinds the grammar names. Any other
// byte, and any string shape beyond the plain literal, is not read.
func (p *pythonReadParser) lex() bool {
	code := p.code
	for i := 0; i < len(code); {
		c := code[i]
		switch {
		case c == ' ' || c == '\t':
			if i == 0 || code[i-1] == '\n' {
				return false // indentation: a block or an error, never a read
			}
			i++
		case c == '\n':
			p.toks = append(p.toks, pythonReadToken{kind: ';'})
			i++
		case c == ';':
			p.toks = append(p.toks, pythonReadToken{kind: ';'})
			i++
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(code) && code[j] != c {
				if code[j] == '\\' || code[j] == '\n' || code[j] < ' ' || code[j] > '~' {
					return false
				}
				j++
			}
			if j >= len(code) {
				return false
			}
			// A triple quote opens a multi-line string.
			if j == i+1 && j+1 < len(code) && code[j+1] == c {
				return false
			}
			p.toks = append(p.toks, pythonReadToken{kind: 's', text: code[i+1 : j]})
			i = j + 1
			if i < len(code) && pythonReadIdentByte(code[i]) {
				return false
			}
		case pythonReadLetter(c):
			j := i
			for j < len(code) && pythonReadIdentByte(code[j]) {
				j++
			}
			if j < len(code) && (code[j] == '"' || code[j] == '\'') {
				return false // a string prefix (f, t, r, b, u, ...): not read
			}
			p.toks = append(p.toks, pythonReadToken{kind: 'i', text: code[i:j]})
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(code) && code[j] >= '0' && code[j] <= '9' {
				j++
			}
			if j < len(code) && pythonReadIdentByte(code[j]) || j-i > 6 {
				return false
			}
			p.toks = append(p.toks, pythonReadToken{kind: 'n', text: code[i:j]})
			i = j
		case strings.IndexByte("()[],.=", c) >= 0:
			p.toks = append(p.toks, pythonReadToken{kind: 'o', text: string(c)})
			i++
		default:
			return false
		}
		if len(p.toks) > 2048 {
			return false
		}
	}
	return true
}

func pythonReadLetter(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func pythonReadIdentByte(c byte) bool {
	return pythonReadLetter(c) || c >= '0' && c <= '9'
}

func (p *pythonReadParser) peek() pythonReadToken {
	if p.at < len(p.toks) {
		return p.toks[p.at]
	}
	return pythonReadToken{kind: ';'}
}

func (p *pythonReadParser) op(text string) bool {
	if t := p.peek(); t.kind == 'o' && t.text == text {
		p.at++
		return true
	}
	return false
}

func (p *pythonReadParser) word(text string) bool {
	if t := p.peek(); t.kind == 'i' && t.text == text {
		p.at++
		return true
	}
	return false
}

func (p *pythonReadParser) name() (string, bool) {
	if t := p.peek(); t.kind == 'i' {
		p.at++
		return t.text, true
	}
	return "", false
}

func (p *pythonReadParser) statement() bool {
	switch {
	case p.word("import"):
		for {
			module, ok := p.name()
			if !ok || !pythonReadModules[module] {
				return false
			}
			p.modules[module] = true
			if !p.op(",") {
				return true
			}
		}
	case p.word("from"):
		module, ok := p.name()
		names := pythonReadFromImports[module]
		if !ok || names == nil || !p.word("import") {
			return false
		}
		for {
			name, ok := p.name()
			if !ok || !names[name] {
				return false
			}
			p.imported[name] = true
			if !p.op(",") {
				return true
			}
		}
	}
	// NAME "=" expression: the target is new and plain.
	if t := p.peek(); t.kind == 'i' && p.at+1 < len(p.toks) && p.toks[p.at+1].kind == 'o' && p.toks[p.at+1].text == "=" {
		if pythonReadReserved[t.text] || p.bound[t.text] || strings.HasPrefix(t.text, "_") {
			return false
		}
		p.at += 2
		if !p.expression() {
			return false
		}
		p.bound[t.text] = true
		return true
	}
	return p.expression()
}

func (p *pythonReadParser) expression() bool {
	if p.depth++; p.depth > 8 {
		return false
	}
	defer func() { p.depth-- }()
	if !p.primary() {
		return false
	}
	for {
		switch {
		case p.op("."):
			method, ok := p.name()
			if !ok || !pythonReadMethods[method] || !p.op("(") || !p.arguments(method) {
				return false
			}
		case p.op("["):
			if !p.expression() || !p.op("]") {
				return false
			}
		default:
			return true
		}
	}
}

func (p *pythonReadParser) primary() bool {
	t := p.peek()
	switch t.kind {
	case 's', 'n':
		p.at++
		return true
	case 'i':
	default:
		return false
	}
	p.at++
	switch {
	case t.text == "sys" && p.modules["sys"]:
		if !p.op(".") || !p.word("argv") || !p.op("[") {
			return false
		}
		if n := p.peek(); n.kind != 'n' {
			return false
		}
		p.at++
		return p.op("]")
	case p.bound[t.text]:
		return true
	case p.modules[t.text]:
		if !p.op(".") {
			return false
		}
		member, ok := p.name()
		callee := t.text + "." + member
		return ok && pythonReadCallees[callee] && p.op("(") && p.arguments(callee)
	case p.imported[t.text], pythonReadBuiltins[t.text]:
		return p.op("(") && p.arguments(t.text)
	}
	return false
}

// arguments reads the arguments after "(" up to and including ")". Only
// open takes keywords, and only a literal mode or encoding; its second
// positional argument is the mode, a literal read mode.
func (p *pythonReadParser) arguments(callee string) bool {
	count, positional := 0, 0
	for {
		if p.op(")") {
			return true
		}
		if count > 0 && !p.op(",") {
			return false
		}
		if p.op(")") {
			return true // trailing comma
		}
		count++
		if t := p.peek(); callee == "open" && t.kind == 'i' && p.at+1 < len(p.toks) &&
			p.toks[p.at+1].kind == 'o' && p.toks[p.at+1].text == "=" {
			value := p.toks[min(p.at+2, len(p.toks)-1)]
			if value.kind != 's' || t.text != "mode" && t.text != "encoding" || t.text == "mode" && !pythonReadModes[value.text] {
				return false
			}
			p.at += 3
			continue
		}
		start := p.at
		if !p.expression() {
			return false
		}
		positional++
		if callee == "open" && positional == 2 && (p.at != start+1 || p.toks[start].kind != 's' || !pythonReadModes[p.toks[start].text]) {
			return false
		}
		if callee == "open" && positional > 2 {
			return false
		}
	}
}
