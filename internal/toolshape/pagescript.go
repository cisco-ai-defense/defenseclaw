// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package toolshape

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// A page script is the JavaScript a browser-automation tool (Puppeteer,
// Playwright, Chrome DevTools MCP) runs inside the page the session has open.
// This file is the small structural data-flow reading of that text (experiment
// EXP-1xx, GAP-0560): does a value read from the page's session state
// (document.cookie, localStorage, sessionStorage, indexedDB, the Cookie Store
// API) reach a network send (fetch, XMLHttpRequest, navigator.sendBeacon,
// WebSocket, an element src or action assignment), and is the literal
// destination host of that send known?
//
// It is a lexer and a name-level taint pass, not a JavaScript engine: a name is
// tainted when an assignment, declaration or function body that defines it
// reads session state or another tainted name. Scope, control flow and
// property sensitivity are ignored, and a flow it cannot see (a value passed
// through a promise callback's parameter, a computed sink name, eval) is not
// reported. What it reports is a flow it saw. A destination that is not a
// literal host stays unknown.

// Bounds on one page script (bounded.Truncated: the caller judges a call with a
// bound hit as unknown at least, and what was read before the bound is judged).
const (
	maxPageScript = 256 << 10 // bytes of one page script read (bounded.Bytes)
	maxPageTokens = 1 << 16   // tokens read from it (bounded.Nodes)
	maxPageSends  = 64        // sends reported (bounded.Items)
	maxPageDefs   = 1 << 10   // definitions tracked for the taint pass (bounded.Items)
	maxPageRefs   = 1 << 17   // names recorded across all definitions (bounded.Nodes)
	maxTaintDepth = 16        // levels of one value handed on from name to name (bounded.Depth)
	maxPageWork   = 1 << 22   // steps of every pass together: a bracket or expression scan counts one per token (bounded.Time)
)

// SinkKind is the kind of network send a page script makes.
type SinkKind string

// Sinks.
const (
	SinkFetch     SinkKind = "fetch"
	SinkXHR       SinkKind = "xhr"
	SinkBeacon    SinkKind = "sendBeacon"
	SinkWebSocket SinkKind = "websocket"
	SinkElement   SinkKind = "element"
)

// DestKind says what a page script's destination is known to be.
type DestKind uint8

// Destination kinds.
const (
	// DestUnknown: the destination is not a literal (a variable, a call, a
	// concatenation that builds the host).
	DestUnknown DestKind = iota
	// DestHost: the literal text names a host (Host is set, lower-case, no port).
	DestHost
	// DestSameOrigin: a relative URL, or one built from location: the page's own
	// origin by construction.
	DestSameOrigin
	// DestNotNetwork: data:, blob:, javascript: and the like. Not a send.
	DestNotNetwork
)

// PageSend is one send whose data carries session state.
type PageSend struct {
	Sink SinkKind
	Dest DestKind
	Host string
}

// PageFlow is the reading of one page script.
type PageFlow struct {
	// Sends are the sends that carry session state (at most maxPageSends).
	Sends []PageSend
	// ReadsState reports that the script reads session state at all.
	ReadsState bool
	// Gotos are the literal URLs the script navigates to itself (page.goto), in
	// order: a script that names its page carries its own origin.
	Gotos []string
	// Truncated is the set of bounds the reading reached.
	Truncated bounded.CapSet
}

type jsKind uint8

const (
	jsIdent jsKind = iota + 1
	jsStr
	jsNum
	jsPunct
	jsRegex
)

type jsTok struct {
	kind jsKind
	s    string // identifier, decoded string text or static template text, punctuation
	nl   bool   // a line break precedes the token
	tmpl bool   // a template-literal segment
	end  bool   // a string, or the last segment of a template (the literal ends here)
}

// jsMultiPunct are the punctuators of more than one character, longest first.
var jsMultiPunct = []string{
	">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
	"=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
}

func isIdentStart(r rune) bool { return r == '_' || r == '$' || unicode.IsLetter(r) }
func isIdentPart(r rune) bool  { return isIdentStart(r) || unicode.IsDigit(r) }

// regexAfter reports that a '/' after this token starts a regular expression.
func regexAfter(prev *jsTok) bool {
	if prev == nil {
		return true
	}
	switch prev.kind {
	case jsNum, jsStr, jsRegex:
		return false
	case jsIdent:
		switch prev.s {
		case "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "await", "yield":
			return true
		}
		return false
	}
	return prev.s != ")" && prev.s != "]" && prev.s != "}"
}

// lexJS reads the page script into tokens, to the token bound. Comments and
// white space are dropped (a line break is kept as a flag on the next token).
func lexJS(src string, trunc *bounded.Truncated) []jsTok {
	var toks []jsTok
	nl := false
	// tmplDepth holds, for each open template substitution, the brace depth at
	// which its closing } returns to the template text.
	var tmplDepth []int
	brace := 0
	emit := func(t jsTok) bool {
		if len(toks) >= maxPageTokens {
			trunc.Hit(bounded.Nodes)
			return false
		}
		t.nl, nl = nl, false
		toks = append(toks, t)
		return true
	}
	// scanTemplate reads template text from i (just after the backtick or the }
	// of a substitution) and emits one segment; it returns the next index.
	scanTemplate := func(i int) (int, bool) {
		var sb strings.Builder
		for i < len(src) {
			c := src[i]
			switch {
			case c == '\\' && i+1 < len(src):
				var s string
				s, i = decodeEscape(src, i)
				sb.WriteString(s)
			case c == '`':
				return i + 1, emit(jsTok{kind: jsStr, s: sb.String(), tmpl: true, end: true})
			case c == '$' && i+1 < len(src) && src[i+1] == '{':
				ok := emit(jsTok{kind: jsStr, s: sb.String(), tmpl: true})
				tmplDepth = append(tmplDepth, brace)
				brace++
				return i + 2, ok
			default:
				sb.WriteByte(c)
				i++
			}
		}
		return i, emit(jsTok{kind: jsStr, s: sb.String(), tmpl: true, end: true})
	}
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n' || c == '\r':
			nl = true
			i++
		case c == ' ' || c == '\t' || c == '\v' || c == '\f':
			i++
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				i = len(src)
			} else {
				if strings.ContainsAny(src[i+2:i+2+end], "\n\r") {
					nl = true
				}
				i += end + 4
			}
		case c == '"' || c == '\'':
			var sb strings.Builder
			i++
			for i < len(src) && src[i] != c && src[i] != '\n' {
				if src[i] == '\\' && i+1 < len(src) {
					var s string
					s, i = decodeEscape(src, i)
					sb.WriteString(s)
					continue
				}
				sb.WriteByte(src[i])
				i++
			}
			i++ // the closing quote
			if !emit(jsTok{kind: jsStr, s: sb.String(), end: true}) {
				return toks
			}
		case c == '`':
			var ok bool
			if i, ok = scanTemplate(i + 1); !ok {
				return toks
			}
		case c == '/' && regexAfter(lastTok(toks)):
			j, inClass := i+1, false
			for j < len(src) && src[j] != '\n' {
				if src[j] == '\\' {
					j += 2
					continue
				}
				if src[j] == '[' {
					inClass = true
				} else if src[j] == ']' {
					inClass = false
				} else if src[j] == '/' && !inClass {
					break
				}
				j++
			}
			j = min(j+1, len(src))
			for j < len(src) && isIdentPart(rune(src[j])) {
				j++
			}
			if !emit(jsTok{kind: jsRegex, s: ""}) {
				return toks
			}
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && (isIdentPart(rune(src[j])) || src[j] == '.' && j+1 < len(src) && src[j+1] >= '0' && src[j+1] <= '9') {
				j++
			}
			if !emit(jsTok{kind: jsNum, s: src[i:j]}) {
				return toks
			}
			i = j
		default:
			r, size := utf8.DecodeRuneInString(src[i:])
			if isIdentStart(r) {
				j := i + size
				for j < len(src) {
					r2, s2 := utf8.DecodeRuneInString(src[j:])
					if !isIdentPart(r2) {
						break
					}
					j += s2
				}
				if !emit(jsTok{kind: jsIdent, s: src[i:j]}) {
					return toks
				}
				i = j
				continue
			}
			if c == '}' && len(tmplDepth) > 0 && brace-1 == tmplDepth[len(tmplDepth)-1] {
				tmplDepth = tmplDepth[:len(tmplDepth)-1]
				brace--
				var ok bool
				if i, ok = scanTemplate(i + 1); !ok {
					return toks
				}
				continue
			}
			p := string(c)
			for _, m := range jsMultiPunct {
				if strings.HasPrefix(src[i:], m) {
					p = m
					break
				}
			}
			switch p {
			case "{":
				brace++
			case "}":
				brace--
			}
			if !emit(jsTok{kind: jsPunct, s: p}) {
				return toks
			}
			i += len(p)
		}
	}
	return toks
}

func lastTok(toks []jsTok) *jsTok {
	if len(toks) == 0 {
		return nil
	}
	return &toks[len(toks)-1]
}

// decodeEscape reads the escape that starts at src[i] (a backslash) and returns
// its text and the next index. \xHH and \uHHHH \u{H...} are decoded so a host
// spelled with escapes is read as the host.
func decodeEscape(src string, i int) (string, int) {
	if i+1 >= len(src) {
		return "", i + 1
	}
	switch c := src[i+1]; c {
	case 'n':
		return "\n", i + 2
	case 't':
		return "\t", i + 2
	case 'r':
		return "\r", i + 2
	case 'x':
		if i+3 < len(src) {
			if v, err := strconv.ParseUint(src[i+2:i+4], 16, 8); err == nil {
				return string(rune(v)), i + 4
			}
		}
	case 'u':
		if i+2 < len(src) && src[i+2] == '{' {
			if end := strings.IndexByte(src[i:min(len(src), i+12)], '}'); end > 0 {
				if v, err := strconv.ParseUint(src[i+3:i+end], 16, 32); err == nil {
					return string(rune(v)), i + end + 1
				}
			}
		} else if i+5 < len(src) {
			if v, err := strconv.ParseUint(src[i+2:i+6], 16, 16); err == nil {
				return string(rune(v)), i + 6
			}
		}
	case '\n':
		return "", i + 2
	}
	return string(src[i+1]), i + 2
}

// pageGlobals are the names a global may be reached through (window.fetch).
var pageGlobals = map[string]bool{"window": true, "self": true, "globalThis": true, "top": true, "parent": true, "frames": true}

// jsReader is the state of one analysis.
type jsReader struct {
	t     []jsTok
	match []int // index of the bracket that closes (or opens) the one at i, -1 when none
	trunc *bounded.Truncated
	// work is the budget of every scan that can cross many tokens (an
	// expression's end, a call's arguments, a taint search): a script built to
	// make each of them cross the rest of the script would otherwise cost
	// tokens squared. Spent, the scans stop and the reading is truncated.
	work    *bounded.Counter
	ends    map[int]int      // exprEnd by start token
	assigns map[string][]int // assignment operators by the name they assign (built once)
}

func (r *jsReader) tok(i int) *jsTok {
	if i < 0 || i >= len(r.t) {
		return nil
	}
	return &r.t[i]
}

func (r *jsReader) is(i int, s string) bool {
	t := r.tok(i)
	return t != nil && t.kind != jsStr && t.s == s
}

func (r *jsReader) ident(i int) (string, bool) {
	t := r.tok(i)
	if t == nil || t.kind != jsIdent {
		return "", false
	}
	return t.s, true
}

func (r *jsReader) isDot(i int) bool { return r.is(i, ".") || r.is(i, "?.") }

// member reads a member access that starts at i (".name" or "['name']") and
// returns the name and the index after it.
func (r *jsReader) member(i int) (string, int, bool) {
	if r.isDot(i) {
		if name, ok := r.ident(i + 1); ok {
			return name, i + 2, true
		}
		return "", i, false
	}
	if r.is(i, "[") && r.tok(i+1) != nil && r.t[i+1].kind == jsStr && r.t[i+1].end && !r.t[i+1].tmpl && r.is(i+2, "]") {
		return r.t[i+1].s, i + 3, true
	}
	return "", i, false
}

// freeIdent reports that token i is the identifier name used as a free name
// or as a member of a global (window.fetch): not a property of another value.
func (r *jsReader) freeIdent(i int, name string) bool {
	if n, ok := r.ident(i); !ok || n != name {
		return false
	}
	if i == 0 || !r.isDot(i-1) {
		return true
	}
	g, ok := r.ident(i - 2)
	return ok && pageGlobals[g]
}

func (r *jsReader) isAssignOp(i int) bool {
	t := r.tok(i)
	if t == nil || t.kind != jsPunct {
		return false
	}
	switch t.s {
	case "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**=", "<<=", ">>=", ">>>=", "&&=", "||=", "??=":
		return true
	}
	return false
}

// stateRead reports that a session-state read starts at token i.
func (r *jsReader) stateRead(i int) bool {
	name, ok := r.ident(i)
	if !ok {
		return false
	}
	switch name {
	case "document":
		if !r.freeIdent(i, name) {
			return false
		}
		if m, next, ok := r.member(i + 1); ok && m == "cookie" {
			return !r.isAssignOp(next)
		}
	case "localStorage", "sessionStorage":
		if !r.freeIdent(i, name) {
			return false
		}
		if m, next, ok := r.member(i + 1); ok {
			switch m {
			case "setItem", "removeItem", "clear":
				return false
			}
			// localStorage.key = value writes.
			return !r.isAssignOp(next)
		}
		return true
	case "indexedDB":
		return r.freeIdent(i, name)
	case "cookieStore":
		if !r.freeIdent(i, name) {
			return false
		}
		if m, _, ok := r.member(i + 1); ok && (m == "set" || m == "delete") {
			return false
		}
		return true
	case "cookies", "storageState":
		// page.cookies(), context.cookies(), context.storageState()
		return i > 0 && r.isDot(i-1) && r.is(i+1, "(")
	}
	if pageGlobals[name] && r.is(i+1, "[") {
		// window['localStorage']: a global named in brackets.
		if m, _, ok := r.member(i + 1); ok {
			switch m {
			case "localStorage", "sessionStorage", "indexedDB", "cookieStore":
				return true
			}
		}
	}
	return false
}

// buildMatch pairs every bracket with its partner.
func (r *jsReader) buildMatch() {
	r.match = make([]int, len(r.t))
	for i := range r.match {
		r.match[i] = -1
	}
	var stack []int
	for i, t := range r.t {
		if t.kind != jsPunct {
			continue
		}
		switch t.s {
		case "(", "[", "{":
			stack = append(stack, i)
		case ")", "]", "}":
			if n := len(stack); n > 0 {
				j := stack[n-1]
				stack = stack[:n-1]
				r.match[i], r.match[j] = j, i
			}
		}
	}
}

// closeOf is the index of the bracket that closes the one at i, or len(t).
func (r *jsReader) closeOf(i int) int {
	if i >= 0 && i < len(r.match) && r.match[i] > i {
		return r.match[i]
	}
	return len(r.t)
}

func binaryOp(s string) bool {
	switch s {
	case "+", "-", "*", "/", "%", "**", "&&", "||", "??", "==", "===", "!=", "!==", "<", ">", "<=", ">=", "&", "|", "^", "<<", ">>", ">>>",
		"?", ":", ".", "?.", "(", "[", "=>", ",":
		return true
	}
	return false
}

// exprEnd is the end (exclusive) of the expression that starts at lo: at a
// ; or , outside brackets, a closing bracket of an outer group, or a line
// break the expression cannot continue across.
func (r *jsReader) exprEnd(lo int) int {
	if e, ok := r.ends[lo]; ok {
		return e
	}
	depth := 0
	for j := lo; j < len(r.t); j++ {
		if !r.work.Take() {
			return j
		}
		t := r.t[j]
		if t.kind == jsPunct {
			switch t.s {
			case "(", "[", "{":
				depth++
				continue
			case ")", "]", "}":
				if depth == 0 {
					r.ends[lo] = j
					return j
				}
				depth--
				continue
			case ";", ",":
				if depth == 0 {
					r.ends[lo] = j
					return j
				}
			}
		}
		if depth == 0 && t.nl && j > lo {
			prev := r.t[j-1]
			prevOpen := prev.kind == jsPunct && (binaryOp(prev.s) || prev.s == "!" || prev.s == "~")
			next := t.kind == jsPunct && binaryOp(t.s)
			if !prevOpen && !next && (t.kind != jsStr || !t.tmpl) {
				r.ends[lo] = j
				return j
			}
		}
	}
	r.ends[lo] = len(r.t)
	return len(r.t)
}

// args returns the [lo, hi) ranges of the top-level arguments of the call whose
// "(" is at open.
func (r *jsReader) args(open int) [][2]int {
	end := r.closeOf(open)
	var out [][2]int
	lo, depth := open+1, 0
	for j := open + 1; j < end; j++ {
		if !r.work.Take() {
			return out
		}
		t := r.t[j]
		if t.kind != jsPunct {
			continue
		}
		switch t.s {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		case ",":
			if depth == 0 {
				out = append(out, [2]int{lo, j})
				lo = j + 1
			}
		}
	}
	if lo < end {
		out = append(out, [2]int{lo, end})
	}
	return out
}

// def is a name and the token range that gives it a value.
type def struct {
	name   string
	lo, hi int
}

// AnalyzePageScript reads one page script (see the file comment).
func AnalyzePageScript(code string) PageFlow {
	var flow PageFlow
	var trunc bounded.Truncated
	if len(code) > maxPageScript {
		code = code[:maxPageScript]
		trunc.Hit(bounded.Bytes)
	}
	work := bounded.NewCounter(&trunc, bounded.Time, maxPageWork)
	r := &jsReader{trunc: &trunc, work: &work, ends: map[int]int{}}
	r.t = lexJS(code, &trunc)
	r.buildMatch()

	// Session-state reads.
	reads := make([]bool, len(r.t))
	for i := range r.t {
		if r.stateRead(i) {
			reads[i] = true
			flow.ReadsState = true
		}
	}
	if !flow.ReadsState {
		flow.Truncated = trunc.Set(&work)
		return flow
	}

	defs := r.definitions(&trunc)
	// refs[d] are the names a definition's range uses; direct[d] that it reads
	// session state itself.
	refs := make([][]string, len(defs))
	direct := make([]bool, len(defs))
	budget := maxPageRefs
	for d, df := range defs {
		for i := df.lo; i < df.hi && i < len(r.t); i++ {
			if !r.work.Take() {
				break
			}
			if reads[i] {
				direct[d] = true
			}
			if name, ok := r.ident(i); ok && (i == 0 || !r.isDot(i-1)) {
				if budget <= 0 {
					trunc.Hit(bounded.Nodes)
					break
				}
				budget--
				refs[d] = append(refs[d], name)
			}
		}
	}
	tainted := map[string]bool{}
	for d, df := range defs {
		if direct[d] {
			tainted[df.name] = true
		}
	}
	// One level per round, from the names tainted at the end of the last: a name
	// handed on more than maxTaintDepth times is cut (bounded.Depth).
	for level := 1; ; level++ {
		next := map[string]bool{}
		for d, df := range defs {
			if tainted[df.name] || next[df.name] {
				continue
			}
			for _, n := range refs[d] {
				if tainted[n] {
					next[df.name] = true
					break
				}
			}
		}
		if len(next) == 0 {
			break
		}
		if !trunc.Within(bounded.Depth, level, maxTaintDepth) {
			break
		}
		for n := range next {
			tainted[n] = true
		}
	}

	hasTaint := func(lo, hi int) bool {
		for i := lo; i < hi && i < len(r.t); i++ {
			if !r.work.Take() {
				return false
			}
			if reads[i] {
				return true
			}
			if name, ok := r.ident(i); ok && tainted[name] && (i == 0 || !r.isDot(i-1)) {
				// An object key ({ cookie: 1 }) is not a use of the name.
				if r.is(i+1, ":") && (r.is(i-1, "{") || r.is(i-1, ",")) {
					continue
				}
				return true
			}
		}
		return false
	}
	r.sends(&flow, &trunc, hasTaint)
	if len(flow.Sends) > 0 {
		flow.Gotos = r.gotos(&trunc)
	}
	flow.Truncated = trunc.Set(&work)
	return flow
}

// callbackMethods are the methods that hand their receiver's value to the
// callback they take.
var callbackMethods = map[string]bool{"then": true, "forEach": true, "map": true, "filter": true, "reduce": true, "flatMap": true, "some": true, "every": true, "find": true}

// definitions finds what hands a value to a name: assignments, declarations,
// function declarations (the body is the value), loop variables, the
// parameters of a callback (the receiver is the value) and the parameters of a
// function the script calls (the call's argument is the value).
func (r *jsReader) definitions(trunc *bounded.Truncated) []def {
	var defs []def
	full := false
	add := func(name string, lo, hi int) {
		if name == "" || full {
			return
		}
		if len(defs) >= maxPageDefs {
			trunc.Hit(bounded.Items)
			full = true
			return
		}
		defs = append(defs, def{name: name, lo: lo, hi: hi})
	}
	params := map[string][]string{} // function name -> parameter names
	for i := range r.t {
		switch {
		case r.isAssignOp(i):
			lo := i + 1
			hi := r.exprEnd(lo)
			for _, name := range r.targets(i) {
				add(name, lo, hi)
			}
			// const f = (a, b) => ... and const f = function (a, b) {...}
			if n, ok := r.ident(i - 1); ok && r.is(i, "=") {
				if ps, ok := r.functionParams(lo); ok {
					params[n] = ps
				}
			}
		case r.t[i].kind == jsIdent && r.t[i].s == "function":
			// function name(...) { body }
			if name, ok := r.ident(i + 1); ok && r.is(i+2, "(") {
				close := r.closeOf(i + 2)
				if r.is(close+1, "{") {
					add(name, close+1, r.closeOf(close+1))
				}
				params[name] = r.paramNames(i+3, close)
			}
		case r.t[i].kind == jsIdent && (r.t[i].s == "of" || r.t[i].s == "in"):
			// for (const c of EXPR)
			if n, ok := r.ident(i - 1); ok && i >= 2 {
				if kw, ok := r.ident(i - 2); ok && (kw == "const" || kw == "let" || kw == "var") {
					add(n, i+1, r.exprEnd(i+1))
				}
			}
		case r.isDot(i):
			// RECEIVER.then(p => ...): p holds what the receiver yields.
			if m, next, ok := r.member(i); ok && callbackMethods[m] && r.is(next, "(") {
				if as := r.args(next); len(as) > 0 {
					if ps, ok := r.functionParams(as[0][0]); ok {
						lo := r.chainStart(i - 1)
						for _, p := range ps {
							add(p, lo, i)
						}
					}
				}
			}
		}
	}
	// A call of a function the script defines: each argument is the value of
	// the parameter in its place.
	for i := range r.t {
		name, ok := r.ident(i)
		if !ok || params[name] == nil || !r.is(i+1, "(") || (i > 0 && (r.isDot(i-1) || r.is(i-1, "function"))) {
			continue
		}
		for k, a := range r.args(i + 1) {
			if k < len(params[name]) {
				add(params[name][k], a[0], a[1])
			}
		}
	}
	return defs
}

// functionParams reads the parameter names of an arrow function or function
// expression that starts at token i.
func (r *jsReader) functionParams(i int) ([]string, bool) {
	if n, ok := r.ident(i); ok && n == "async" {
		i++
	}
	if n, ok := r.ident(i); ok && n == "function" {
		if name, ok := r.ident(i + 1); ok && name != "" && r.is(i+2, "(") {
			i++
		}
		if r.is(i+1, "(") {
			return r.paramNames(i+2, r.closeOf(i+1)), true
		}
		return nil, false
	}
	if r.is(i, "(") {
		close := r.closeOf(i)
		if r.is(close+1, "=>") {
			return r.paramNames(i+1, close), true
		}
		return nil, false
	}
	if n, ok := r.ident(i); ok && r.is(i+1, "=>") {
		return []string{n}, true
	}
	return nil, false
}

// paramNames are the names in a parameter list [lo, hi): the identifiers that
// start a parameter (a default value after = is not one).
func (r *jsReader) paramNames(lo, hi int) []string {
	var out []string
	depth, want := 0, true
	for j := lo; j < hi && j < len(r.t); j++ {
		t := r.t[j]
		if t.kind == jsPunct {
			switch t.s {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				depth--
			case ",":
				if depth == 0 {
					want = true
				}
			case "=":
				if depth == 0 {
					want = false
				}
			}
			continue
		}
		if t.kind == jsIdent && (want || depth > 0) {
			out = append(out, t.s)
			if depth == 0 {
				want = false
			}
		}
	}
	return out
}

// chainStart is the first token of the member and call chain that ends at
// token j.
func (r *jsReader) chainStart(j int) int {
	for {
		if !r.work.Take() {
			return j + 1
		}
		for j >= 0 && (r.is(j, ")") || r.is(j, "]")) {
			if r.match[j] < 0 {
				return j + 1
			}
			j = r.match[j] - 1
		}
		if _, ok := r.ident(j); ok {
			j--
			if j >= 0 && r.isDot(j) {
				j--
				continue
			}
		}
		return j + 1
	}
}

// targets are the names an assignment at token i (an assignment operator)
// gives a value to: a plain name, the root of a member or index target, or the
// names of a declaration pattern.
func (r *jsReader) targets(i int) []string {
	j := i - 1
	if j < 0 {
		return nil
	}
	switch {
	case r.is(j, "}") || r.is(j, "]"):
		open := r.match[j]
		if open < 0 {
			return nil
		}
		// A declaration pattern: const { a, b: c } = ..., const [a, b] = ...
		if open > 0 {
			if kw, ok := r.ident(open - 1); ok && (kw == "const" || kw == "let" || kw == "var") {
				var names []string
				for k := open + 1; k < j; k++ {
					if n, ok := r.ident(k); ok && !r.is(k+1, ":") {
						names = append(names, n)
					}
				}
				return names
			}
		}
		if r.is(j, "]") {
			// x[key] = ...: the root of the access
			return r.root(open - 1)
		}
		return nil
	default:
		return r.root(j)
	}
}

// root is the root name of the member or index chain that ends at token j.
func (r *jsReader) root(j int) []string {
	for j >= 0 && r.work.Take() {
		switch {
		case r.is(j, "]") && r.match[j] >= 0:
			j = r.match[j] - 1
		case r.is(j, ")") && r.match[j] >= 0:
			j = r.match[j] - 1
		default:
			if name, ok := r.ident(j); ok {
				if j > 0 && r.isDot(j-1) {
					j -= 2
					continue
				}
				return []string{name}
			}
			return nil
		}
	}
	return nil
}

// sends finds the network sends whose arguments carry session state.
func (r *jsReader) sends(flow *PageFlow, trunc *bounded.Truncated, hasTaint func(lo, hi int) bool) {
	report := func(sink SinkKind, dest [2]int, haveDest bool) bool {
		if len(flow.Sends) >= maxPageSends {
			trunc.Hit(bounded.Items)
			return false
		}
		s := PageSend{Sink: sink}
		if haveDest {
			s.Dest, s.Host = r.destination(dest[0], dest[1])
		}
		flow.Sends = append(flow.Sends, s)
		return true
	}
	xhrVar := map[string]*xhrState{}
	wsVar := map[string]*wsState{}
	for i := range r.t {
		name, isIdent := r.ident(i)
		if !isIdent {
			continue
		}
		switch {
		case name == "fetch" && r.freeIdent(i, name) && r.is(i+1, "("):
			as := r.args(i + 1)
			if len(as) > 0 && hasTaint(as[0][0], r.closeOf(i+1)) {
				if !report(SinkFetch, as[0], true) {
					return
				}
			}
		case name == "navigator" && (i == 0 || !r.isDot(i-1)):
			if m, next, ok := r.member(i + 1); ok && m == "sendBeacon" && r.is(next, "(") {
				as := r.args(next)
				if len(as) > 0 && hasTaint(as[0][0], r.closeOf(next)) {
					if !report(SinkBeacon, as[0], true) {
						return
					}
				}
			}
		case name == "new" && r.is(i+2, "("):
			ctor, _ := r.ident(i + 1)
			switch ctor {
			case "XMLHttpRequest":
				if v := r.declaredName(i); v != "" {
					xhrVar[v] = &xhrState{}
				}
			case "WebSocket":
				as := r.args(i + 2)
				st := &wsState{}
				if len(as) > 0 {
					st.dest, st.haveDest = as[0], true
					st.tainted = hasTaint(as[0][0], r.closeOf(i+2))
				}
				if v := r.declaredName(i); v != "" {
					wsVar[v] = st
				}
				if st.tainted && !report(SinkWebSocket, st.dest, st.haveDest) {
					return
				}
			}
		case r.is(i+1, ".") || r.is(i+1, "?."):
			// x.open(method, url), x.setRequestHeader(k, v), x.send(body)
			if m, next, ok := r.member(i + 1); ok && r.is(next, "(") && (i == 0 || !r.isDot(i-1)) {
				switch {
				case xhrVar[name] != nil:
					st := xhrVar[name]
					as := r.args(next)
					switch m {
					case "open":
						if len(as) > 1 {
							st.dest, st.haveDest = as[1], true
							if hasTaint(as[1][0], as[1][1]) {
								st.tainted = true
							}
						}
					case "setRequestHeader":
						if len(as) > 1 && hasTaint(as[1][0], as[1][1]) {
							st.tainted = true
						}
					case "send":
						if st.tainted || len(as) > 0 && hasTaint(as[0][0], as[0][1]) {
							if !report(SinkXHR, st.dest, st.haveDest) {
								return
							}
						}
					}
				case wsVar[name] != nil && m == "send":
					st := wsVar[name]
					as := r.args(next)
					if !st.tainted && len(as) > 0 && hasTaint(as[0][0], as[0][1]) {
						if !report(SinkWebSocket, st.dest, st.haveDest) {
							return
						}
					}
				}
			}
		}
	}
	// el.setAttribute("src", value) and ("action", value).
	for i := range r.t {
		if name, ok := r.ident(i); !ok || name != "setAttribute" || i == 0 || !r.isDot(i-1) || !r.is(i+1, "(") {
			continue
		}
		as := r.args(i + 1)
		if len(as) > 1 && as[0][1]-as[0][0] == 1 {
			if k := r.t[as[0][0]]; k.kind == jsStr && (strings.EqualFold(k.s, "src") || strings.EqualFold(k.s, "action")) &&
				hasTaint(as[1][0], as[1][1]) {
				if !report(SinkElement, as[1], true) {
					return
				}
			}
		}
	}
	// Element src and action assignments.
	for i := range r.t {
		if !r.is(i, "=") && !r.is(i, "+=") {
			continue
		}
		prop, ok := r.ident(i - 1)
		if !ok || (prop != "src" && prop != "action") || i < 2 || !r.isDot(i-2) {
			continue
		}
		hi := r.exprEnd(i + 1)
		if hasTaint(i+1, hi) {
			if !report(SinkElement, [2]int{i + 1, hi}, true) {
				return
			}
		}
	}
}

type xhrState struct {
	dest     [2]int
	haveDest bool
	tainted  bool
}

type wsState struct {
	dest     [2]int
	haveDest bool
	tainted  bool
}

// declaredName is the name a "new X(...)" at token i is assigned to
// (const x = new X(...), x = new X(...)), or "".
func (r *jsReader) declaredName(i int) string {
	if r.is(i-1, "=") {
		if n := r.root(i - 2); len(n) == 1 {
			return n[0]
		}
	}
	return ""
}

// gotos are the literal URLs the script navigates to itself (page.goto('...')).
func (r *jsReader) gotos(trunc *bounded.Truncated) []string {
	var out []string
	for i := range r.t {
		if name, ok := r.ident(i); ok && name == "goto" && i > 0 && r.isDot(i-1) && r.is(i+1, "(") {
			if as := r.args(i + 1); len(as) > 0 && as[0][1]-as[0][0] == 1 {
				if t := r.t[as[0][0]]; t.kind == jsStr && t.end && !t.tmpl {
					if len(out) >= maxPageSends {
						trunc.Hit(bounded.Items)
						return out
					}
					out = append(out, t.s)
				}
			}
		}
	}
	return out
}

// URLHost is the lower-case host of a URL, without port, or "".
func URLHost(raw string) string { return hostOf(raw) }

// destination classifies the destination expression [lo, hi): the literal text
// it starts with, a name bound once to an expression that starts with one, or an
// expression built from location.
func (r *jsReader) destination(lo, hi int) (DestKind, string) { return r.destinationAt(lo, hi, 0) }

func (r *jsReader) destinationAt(lo, hi, depth int) (DestKind, string) {
	if lo >= hi || lo >= len(r.t) || depth > 3 {
		return DestUnknown, ""
	}
	// new URL(<expr>, ...) reads as its first argument.
	if n, _ := r.ident(lo); n == "new" {
		if u, _ := r.ident(lo + 1); u == "URL" && r.is(lo+2, "(") {
			if as := r.args(lo + 2); len(as) > 0 {
				return r.destinationAt(as[0][0], as[0][1], depth+1)
			}
		}
		return DestUnknown, ""
	}
	first := r.t[lo]
	switch first.kind {
	case jsStr:
		return classifyLiteral(first.s, lo+1 == hi && first.end, first.end)
	case jsIdent:
		if r.isLocation(lo) {
			return DestSameOrigin, ""
		}
		// A name bound once: const u = "https://host/path" + x.
		if blo, bhi, ok := r.boundOnce(first.s); ok && (lo < blo || lo >= bhi) {
			return r.destinationAt(blo, bhi, depth+1)
		}
	}
	return DestUnknown, ""
}

// isLocation reports location.origin and its relatives at token i, with or
// without a window or document in front.
func (r *jsReader) isLocation(i int) bool {
	if n, ok := r.ident(i); ok && (pageGlobals[n] || n == "document") && r.isDot(i+1) {
		return r.isLocation(i + 2)
	}
	if n, ok := r.ident(i); ok && n == "location" {
		if m, _, ok := r.member(i + 1); ok {
			switch m {
			case "origin", "host", "hostname", "href", "protocol", "pathname":
				return true
			}
		}
	}
	return false
}

// boundOnce is the range of the expression a name is bound to when the script
// assigns the name exactly once.
func (r *jsReader) boundOnce(name string) (lo, hi int, ok bool) {
	if r.assigns == nil {
		// One pass for every name; the right side is read only for a name
		// assigned once.
		r.assigns = map[string][]int{}
		r.work.TakeN(len(r.t))
		for i := range r.t {
			if !r.isAssignOp(i) {
				continue
			}
			if n, isName := r.ident(i - 1); isName && !(i >= 2 && r.isDot(i-2)) {
				if len(r.assigns[n]) < 2 {
					r.assigns[n] = append(r.assigns[n], i)
				}
			}
		}
	}
	at := r.assigns[name]
	if len(at) != 1 {
		return 0, 0, false
	}
	lo, hi = at[0]+1, r.exprEnd(at[0]+1)
	return lo, hi, lo < hi
}

// classifyLiteral reads the literal text a destination starts with. whole is
// true when the literal is the whole expression; ended is true when the literal
// text itself ends here (not a template segment cut by a substitution).
func classifyLiteral(s string, whole, ended bool) (DestKind, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return DestUnknown, ""
	}
	lower := strings.ToLower(s)
	for _, scheme := range []string{"data:", "blob:", "javascript:", "about:", "mailto:", "tel:"} {
		if strings.HasPrefix(lower, scheme) {
			return DestNotNetwork, ""
		}
	}
	rest := ""
	switch {
	case strings.HasPrefix(s, "//"):
		rest = s[2:]
	case reSchemeAuth.MatchString(s):
		rest = s[strings.Index(s, "://")+3:]
	case strings.HasPrefix(s, "/"), strings.HasPrefix(s, "?"), strings.HasPrefix(s, "#"), strings.HasPrefix(s, "."):
		return DestSameOrigin, ""
	case strings.Contains(s, "://"):
		return DestUnknown, ""
	default:
		// "collect?x=": a relative reference. A bare word could also be the start
		// of a host built by concatenation ("evil" + ".com"); a literal that
		// ends with a path or query separator, or is the whole expression, is
		// relative.
		if whole || strings.ContainsAny(s, "/?#") {
			return DestSameOrigin, ""
		}
		return DestUnknown, ""
	}
	// The host runs to the first /, ?, # or the end of the literal; it is read
	// only when the literal text itself ends it.
	end := strings.IndexAny(rest, "/?#\\")
	if end < 0 {
		if !whole || !ended {
			return DestUnknown, ""
		}
		end = len(rest)
	}
	authority := rest[:end]
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	u, err := url.Parse("//" + authority)
	if err != nil || u.Hostname() == "" {
		return DestUnknown, ""
	}
	return DestHost, strings.ToLower(u.Hostname())
}

var reSchemeAuth = regexp.MustCompile(`(?i)^(?:https?|wss?|ftp)://`)
