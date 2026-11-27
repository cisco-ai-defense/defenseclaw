// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Nested and staged bodies (DET111 D1, class R1). A body another program runs
// is lowered as a nested Script of the same IR, in the scope the host program
// gives it, never re-judged as another spelling of the call:
//
//   - the text a shell reads on standard input: a static here-document or
//     here-string, the exact literal an echo / printf / cat <<E upstream of a
//     pipe prints, a process substitution that prints a literal
//     (sh < <(cat <<E ... E)), or a file an earlier statement of the call wrote;
//   - source / . of /dev/stdin, of a process substitution or of a file the
//     call wrote, in the current shell;
//   - sh FILE / bash FILE / ./FILE of a file the call wrote (cat > x <<E; sh x);
//   - sh -c BODY ARG0 ARG1 with $0, $1 ... bound to the arguments;
//   - eval of all its arguments joined, and eval of a body whose only unknown
//     parts are variables (the variables stay variables in the lowered text);
//   - a program word that is a variable ("$SHELL" -c BODY, "$s" <<< BODY): the
//     body is lowered as a possible shell body, every effect of it conditional
//     with an unknown role;
//   - read NAME <<< WORD binds NAME, so a later "$NAME" resolves;
//   - inline interpreter code (python -c CODE, python3 - <<E): the code is
//     Data; the path literals it names and the arguments handed to it are
//     opaque effects with their target placed (reach R-CODE).

// fileBody is the text an earlier statement of the call wrote to a file.
type fileBody struct {
	text string
	cond bool
}

// maxFileBodies bounds the in-call file texts the walker keeps.
const maxFileBodies = 32

// maxCodeLiterals bounds the path literals read from one inline code text.
const maxCodeLiterals = 16

func (w *walker) bodyKey(abs string) string {
	return Target{Type: TargetPath, Path: abs, Flavor: w.o.flavor(), CaseFold: w.o.CaseInsensitive}.Key()
}

// noteFileBody records the full text a known write laid down.
func (w *walker) noteFileBody(e Effect, text string) {
	k := e.Target.Key()
	if k == "" || e.TargetState != TargetStateKnown || e.Kind != KindWrite {
		return
	}
	if w.fileText == nil {
		w.fileText = map[string]fileBody{}
	}
	if _, ok := w.fileText[k]; !ok && len(w.fileText) >= maxFileBodies {
		return
	}
	w.fileText[k] = fileBody{text: text, cond: e.Cond || w.condFrame > 0}
}

// forgetFileBody drops the text of a file a later effect changes. A change
// whose target is not known may hit any recorded file: each text is then only
// possible (conditional).
func (w *walker) forgetFileBody(e Effect) {
	if len(w.fileText) == 0 {
		return
	}
	switch e.Kind {
	case KindWrite, KindAppend, KindDelete, KindLink:
	default:
		return
	}
	if k := e.Target.Key(); k != "" && e.TargetState == TargetStateKnown {
		delete(w.fileText, k)
		return
	}
	for k, b := range w.fileText {
		b.cond = true
		w.fileText[k] = b
	}
}

// scriptBody is the text of the file a spelling names, when the call wrote it
// earlier or the session saw it written (Options.SessionFiles).
func (w *walker) scriptBody(spelling string) (fileBody, bool) {
	abs, ok, _ := placePath(spelling, w.opts())
	if !ok {
		return fileBody{}, false
	}
	if b, ok := w.fileText[w.bodyKey(abs)]; ok {
		return b, true
	}
	if t, ok := w.o.SessionFiles[abs]; ok {
		return fileBody{text: t}, true
	}
	return fileBody{}, false
}

// isStdinPath names the standard input of the running process.
func isStdinPath(v string) bool {
	switch v {
	case "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0":
		return true
	}
	return false
}

// stdinText is the text a command reads on standard input when the call says
// what it is. The last stdin redirect wins, as in the shell.
func (w *walker) stdinText(c *Cmd) (text string, cond, ok bool) {
	found := false
	for _, r := range c.Redirs {
		if !stdinFD(r) {
			continue
		}
		switch r.Op {
		case RedirHeredoc:
			found = true
			text, cond, ok = r.Body, false, !r.BodyExpands
		case RedirHereString:
			found = true
			text, cond, ok = "", false, false
			if rv := w.resolveWord(r.Target); rv.Static && !rv.Glob {
				text, ok = rv.Value+"\n", true
			}
		case RedirRead:
			found = true
			text, cond, ok = w.redirInput(r.Target)
		}
	}
	if found {
		return text, cond, ok
	}
	if c.PipeIn && w.stageIn.exact && len(w.stageIn.reads) == 0 {
		return w.stageIn.text, false, true
	}
	return "", false, false
}

// redirInput is the text a `< word` redirect feeds: the output of a process
// substitution that prints a literal, or a file the call wrote.
func (w *walker) redirInput(t Word) (string, bool, bool) {
	if t.ProcSub != nil {
		text, ok := staticOutput(t.ProcSub)
		return text, false, ok
	}
	rv := w.resolveWord(t)
	if !rv.Static || rv.Glob {
		return "", false, false
	}
	if b, ok := w.scriptBody(rv.Value); ok {
		return b.text, b.cond, true
	}
	return "", false, false
}

// staticOutput is what a nested script prints when it is one command that
// prints a literal exactly (see exactOutput).
func staticOutput(s *Script) (string, bool) {
	if s == nil || len(s.Unknowns) > 0 {
		return "", false
	}
	var st *Stmt
	for _, x := range s.Stmts {
		if x.ExecMark {
			continue
		}
		if st != nil {
			return "", false
		}
		st = x
	}
	if st == nil || len(st.Cmds) != 1 {
		return "", false
	}
	c := st.Cmds[0]
	if c.Sub != nil || len(c.Nested) > 0 || len(c.Assigns) > 0 || len(c.Words) == 0 {
		return "", false
	}
	for _, wd := range c.Words {
		if !wd.Static {
			return "", false
		}
	}
	if stdoutRedirected(c.Redirs) {
		return "", false
	}
	return exactOutput(c.Words[0].Value, c.Words[1:], c.Redirs, nil)
}

// stdoutRedirected reports a redirect that sends a command's stdout to a file
// (or another descriptor), away from the pipe.
func stdoutRedirected(redirs []Redir) bool {
	for _, r := range redirs {
		switch r.Op {
		case RedirWrite, RedirAppend, RedirClobber, RedirDup:
			if r.FD == 1 || r.FD < 0 {
				return true
			}
		}
	}
	return false
}

// stdoutToAgentStderr reports a final stdout duplicate to the call's
// visible stderr. It is separate from stdoutRedirected: a pipe no longer
// receives these bytes, but the agent still sees them.
func stdoutToAgentStderr(redirs []Redir) bool {
	// 0 is an output sink, 1 and 2 are the agent-visible original streams.
	// Duplications take the destination as it stands at that point in order.
	stdout, stderr := 1, 2
	for _, r := range redirs {
		fd := r.FD
		if fd < 0 {
			fd = 1
		}
		dest := 0
		if r.Op == RedirDup && r.Target.Static {
			switch r.Target.Value {
			case "1":
				dest = stdout
			case "2":
				dest = stderr
			}
		}
		switch r.Op {
		case RedirWrite, RedirAppend, RedirClobber, RedirDup:
			switch fd {
			case 1:
				stdout = dest
			case 2:
				stderr = dest
			}
		}
	}
	return stdout == 2
}

// exactOutput is the exact text a command prints on stdout when it is a
// printer whose output does not depend on anything the call does not show:
// echo with no -e and no backslash (dash's echo reads escapes), printf with
// one format that has no % and no backslash, cat of a static here-document or
// here-string (resolve, when set, resolves the here-string word). Where the
// text goes (a pipe, a redirect) is the caller's question.
func exactOutput(program string, args []Word, redirs []Redir, resolve func(Word) Word) (string, bool) {
	var body string
	haveBody := false
	for _, r := range redirs {
		switch r.Op {
		case RedirHeredoc:
			if stdinFD(r) {
				body, haveBody = r.Body, !r.BodyExpands
			}
		case RedirHereString:
			if stdinFD(r) {
				haveBody = false
				if resolve != nil {
					if rv := resolve(r.Target); rv.Static && !rv.Glob {
						body, haveBody = rv.Value+"\n", true
					}
				} else if r.Target.Static && !r.Target.Glob {
					body, haveBody = r.Target.Value+"\n", true
				}
			}
		case RedirRead:
			if stdinFD(r) {
				haveBody = false
			}
		}
	}
	for _, a := range args {
		if !a.Static {
			return "", false
		}
	}
	switch program {
	case "echo":
		newline := true
		parts := make([]string, 0, len(args))
		for _, a := range args {
			if len(parts) == 0 && isEchoSwitch(a.Value) {
				if strings.ContainsAny(a.Value, "e") {
					return "", false
				}
				if strings.Contains(a.Value, "n") {
					newline = false
				}
				continue
			}
			if strings.Contains(a.Value, `\`) {
				return "", false
			}
			parts = append(parts, a.Value)
		}
		out := strings.Join(parts, " ")
		if newline {
			out += "\n"
		}
		return out, true
	case "printf":
		if len(args) != 1 || strings.ContainsAny(args[0].Value, `%\`) {
			return "", false
		}
		return args[0].Value, true
	case "cat":
		if len(args) > 1 || (len(args) == 1 && args[0].Value != "-") || !haveBody {
			return "", false
		}
		return body, true
	}
	return "", false
}

// shellInvocation splits the arguments of sh / bash / zsh / dash / ksh: the -c
// code, or the script operand, and the words after it (the positional
// parameters). Options whose next word is a value are skipped.
type shellArgv struct {
	hasC   bool
	code   Word // the -c command string
	script Word // the script operand when there is no -c
	hasArg bool // code or script present
	stdin  bool // no -c and no script (or -s): the shell reads its commands from stdin
	rest   []Word
	// readStdin: -s, the positionals are arguments and stdin is the script.
	readStdin bool
}

func shellInvocation(args []Word) shellArgv {
	var sc shellArgv
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			break
		}
		v := a.Value
		if v == "" {
			break
		}
		if v == "--" || v == "-" {
			i++
			break
		}
		if strings.HasPrefix(v, "--") {
			switch v {
			case "--rcfile", "--init-file":
				i++
			}
			continue
		}
		if (v[0] == '-' || v[0] == '+') && len(v) > 1 {
			for _, r := range v[1:] {
				switch r {
				case 'c':
					sc.hasC = true
				case 's':
					sc.readStdin = true
				}
			}
			if strings.HasSuffix(v, "o") || strings.HasSuffix(v, "O") {
				i++ // -o NAME / +O NAME
			}
			continue
		}
		break
	}
	if sc.readStdin && !sc.hasC {
		sc.stdin = true
		sc.rest = args[i:]
		return sc
	}
	if i < len(args) {
		if sc.hasC {
			sc.code = args[i]
		} else {
			sc.script = args[i]
		}
		sc.hasArg = true
		sc.rest = args[i+1:]
	} else if !sc.hasC {
		sc.stdin = true
	}
	return sc
}

// isPOSIXShell names the shells whose argv is read by shellInvocation.
func isPOSIXShell(program string) bool {
	switch program {
	case "sh", "bash", "zsh", "dash", "ksh":
		return true
	}
	return false
}

// unwrapWithArgs lowers code in a child shell whose positional parameters are
// args ($0 first). A dynamic argument leaves its parameter unknown.
func (w *walker) unwrapWithArgs(code string, dialect Dialect, depth int, cond bool, origin Origin, args []Word) {
	w.positional = args
	w.positionalSet = true
	w.unwrapCodeScoped(code, true, dialect, depth, cond, origin, true)
	w.positional, w.positionalSet = nil, false
}

// bindPositional installs the pending positional parameters in the child env.
func (w *walker) bindPositional() {
	if !w.positionalSet {
		return
	}
	args := w.positional
	w.positional, w.positionalSet = nil, false
	for i, a := range args {
		if i > 9 {
			break
		}
		name := strconv.Itoa(i)
		if a.Static {
			w.env[name] = a.Value
		} else {
			delete(w.env, name)
		}
	}
}

// unwrapUncertain lowers a body that a program may run as shell code (the
// program word is a variable): every effect of it is conditional and its role
// is unknown, so it reaches the decision as a maybe, never as a known proof.
func (w *walker) unwrapUncertain(code string, dialect Dialect, depth int, origin Origin, args []Word, childScope bool) {
	start := len(w.res.Effects)
	if args != nil {
		w.unwrapWithArgs(code, dialect, depth, true, origin, args)
	} else {
		w.unwrapCodeScoped(code, true, dialect, depth, true, origin, childScope)
	}
	for i := start; i < len(w.res.Effects); i++ {
		e := &w.res.Effects[i]
		e.Cond = true
		e.addReason(ReasonDynamicExpansion, ScopeRole)
	}
}

// variableProgram reports a program word built only of variable expansions
// and literals around them ("$SHELL", ${S}, "$X"sh): a shell the call names
// by a variable.
func variableProgram(wd Word) bool {
	hasVar := false
	for _, s := range wd.Segs {
		if s.Var != "" {
			hasVar = true
		}
	}
	return hasVar
}

// shellVariable is the inherited login-shell slot: it names an
// interpreter even when the call does not provide its absolute path.
func shellVariable(raw Word) bool {
	return len(raw.Segs) == 1 && raw.Segs[0].Var == "SHELL"
}

// possibleShell lowers the body a variable program word may run as a shell:
// its -c code, or the text it reads on standard input.
func (w *walker) possibleShell(c *Cmd, raw Word, args []Word, dialect Dialect, depth int, origin Origin) {
	if dialect != DialectPOSIX || !variableProgram(raw) {
		return
	}
	sc := shellInvocation(args)
	switch {
	case sc.hasC && sc.hasArg && sc.code.Static:
		w.unwrapUncertain(sc.code.Value, dialect, depth, origin, sc.rest, true)
	case sc.hasC && sc.hasArg:
		w.possibleShellOpaque(origin, shellVariable(raw))
	case sc.stdin:
		if text, _, ok := w.stdinText(c); ok {
			w.unwrapUncertain(text, dialect, depth, origin, nil, true)
		} else if hasStdinSource(c) {
			w.possibleShellOpaque(origin, shellVariable(raw))
		}
	}
}

// possibleShellOpaque is the code a variable program word may run as a shell
// when the call does not show it (a -c body, a here-string or a pipe built by a
// substitution): an opaque code exec, conditional and of unknown role -- the
// reading a named shell gets for an unseen body, as a maybe (DET111 R1,
// GAP-1554).
func (w *walker) possibleShellOpaque(origin Origin, knownShellSlot bool) {
	e := Effect{Kind: KindExec, Cond: true, Target: Target{Type: TargetProcess, Link: LinkNotChecked},
		TargetState: TargetStateUnknown, RoleState: RoleStateUnknown, Origin: origin}
	e.addReason(ReasonOpaqueCode, ScopeTarget)
	e.addReason(ReasonDynamicExpansion, ScopeRole)
	if knownShellSlot && len(w.stageIn.fetches) == 1 {
		e.Data = &Data{Kind: DataCode, Sources: []Source{{Kind: SourceEffect, Effect: w.stageIn.fetches[0]}}}
	}
	w.emit(e)
}

// evalText is the text eval runs: its arguments joined by blanks. A word whose
// only unknown parts are variable expansions keeps them as ${NAME} in the text
// (eval expands them when it reads the text); uncertain is then true. ok is
// false when a word is otherwise dynamic.
func evalText(args []Word, raw []Word) (text string, uncertain, ok bool) {
	parts := make([]string, 0, len(args))
	for i, a := range args {
		if a.Static {
			parts = append(parts, a.Value)
			continue
		}
		var r Word
		if i < len(raw) {
			r = raw[i]
		}
		if r.Segs == nil {
			return "", false, false
		}
		var b strings.Builder
		for _, s := range r.Segs {
			if s.Var != "" {
				b.WriteString("${" + s.Var + "}")
				continue
			}
			b.WriteString(s.Lit)
		}
		parts = append(parts, b.String())
		uncertain = true
	}
	if len(parts) == 0 {
		return "", false, false
	}
	return strings.Join(parts, " "), uncertain, true
}

// rawWordsFor maps resolved words back to the frontend words by span, so the
// variable segments of a word that did not resolve are still visible.
func rawWordsFor(resolved []Word, raw []Word) []Word {
	out := make([]Word, len(resolved))
	for i, r := range resolved {
		for _, x := range raw {
			if x.Span == r.Span && x.Span != [2]int{} {
				out[i] = x
				break
			}
		}
	}
	return out
}

// bindStdinScriptTail accounts for a shell reading its script from stdin: a
// read or xargs on the first script line can consume the next literal line as
// data. That line then supplies an operand or a variable, rather than running
// as a command. The proof is bounded to a two-line script with one plain
// absolute path and no competing stdin redirection.
func bindStdinScriptTail(sub *Script, code string) {
	if sub == nil || len(sub.Unknowns) != 0 || len(sub.Stmts) < 2 {
		return
	}
	lines := strings.Split(strings.TrimSuffix(code, "\n"), "\n")
	if len(lines) != 2 {
		return
	}
	data := lines[1]
	if !strings.HasPrefix(data, "/") || strings.ContainsAny(data, " \t\r\\'\"$`*?[]{}();&|<>") {
		return
	}
	first := sub.Stmts[0]
	last := sub.Stmts[len(sub.Stmts)-1]
	if len(first.Cmds) != 1 || len(last.Cmds) != 1 || len(last.Cmds[0].Words) != 1 {
		return
	}
	for _, stmt := range sub.Stmts[:len(sub.Stmts)-1] {
		if stmt.Span[1] > len(lines[0]) || stmt.Background {
			return
		}
	}
	reader, tail := first.Cmds[0], last.Cmds[0]
	if len(reader.Words) == 0 || len(reader.Redirs) != 0 || reader.PipeIn || reader.Pipeline || reader.Async ||
		!reader.Words[0].Static || len(tail.Redirs) != 0 || !tail.Words[0].Static ||
		tail.Words[0].Value != data || last.Span[0] < len(lines[0])+1 {
		return
	}
	switch reader.Words[0].Value {
	case "read":
		args := reader.Words[1:]
		if len(args) == 2 && args[0].Static && args[0].Value == "-r" {
			args = args[1:]
		}
		if len(args) != 1 || !args[0].Static || !plainIdent(args[0].Value) {
			return
		}
		reader.Redirs = append(reader.Redirs, Redir{Op: RedirHeredoc, Body: data + "\n"})
	case "xargs":
		if len(reader.Words) < 2 || !reader.Words[1].Static || strings.HasPrefix(reader.Words[1].Value, "-") {
			return
		}
		reader.Words = append(reader.Words[1:], Word{Value: data, Static: true})
	default:
		return
	}
	sub.Stmts = sub.Stmts[:len(sub.Stmts)-1]
}

// bindRead applies `read [-r] NAME <<< WORD` (or a static here-document): NAME
// gets the first line, IFS blanks trimmed. Anything else leaves the names
// unknown (unbindReader already dropped them).
func (w *walker) bindRead(c *Cmd, args []Word) {
	if c.Pipeline || c.Async {
		return
	}
	raw := false
	var name string
	for _, a := range args {
		if !a.Static {
			return
		}
		switch {
		case a.Value == "-r":
			raw = true
		case strings.HasPrefix(a.Value, "-"):
			return
		case name != "":
			return
		default:
			name = a.Value
		}
	}
	if name == "" || !plainIdent(name) {
		return
	}
	text, _, ok := w.stdinText(c)
	if !ok || c.PipeIn {
		return
	}
	if nl := strings.IndexByte(text, '\n'); nl >= 0 {
		text = text[:nl]
	}
	if !raw && strings.Contains(text, `\`) {
		return
	}
	text = strings.Trim(text, " \t")
	w.ownVars()
	w.env[name] = text
}

// interpreterNames are the inline-code interpreters whose code is Data.
func isCodeInterpreter(program string) bool {
	switch program {
	case "python", "python3", "node", "nodejs", "ruby", "perl", "php":
		return true
	}
	if strings.HasPrefix(program, "python3.") || strings.HasPrefix(program, "python2") {
		return true
	}
	return false
}

// interpCall splits an interpreter's arguments: inline code (-c / -e / -E /
// --eval), stdin code (a lone - or nothing), the script, and the arguments
// handed to the code.
type interpCall struct {
	inline     bool
	code       Word
	stdin      bool
	scriptSeen bool
	args       []Word
}

func interpreterInvocation(args []Word) interpCall {
	var ic interpCall
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			break
		}
		switch a.Value {
		case "-c", "-e", "-E", "--eval", "-p", "--print":
			if i+1 < len(args) {
				ic.inline = true
				ic.code = args[i+1]
				ic.args = args[i+2:]
			}
			return ic
		case "-m":
			ic.scriptSeen = true
			return ic
		case "-":
			ic.stdin = true
			ic.args = args[i+1:]
			return ic
		case "--":
			i++
			if i < len(args) {
				ic.scriptSeen = true
			} else {
				ic.stdin = true
			}
			return ic
		}
		if !strings.HasPrefix(a.Value, "-") {
			break
		}
	}
	if i < len(args) {
		ic.scriptSeen = true
		return ic
	}
	ic.stdin = true
	return ic
}

var (
	pythonOpenArgRead    = regexp.MustCompile(`\bopen\s*\(\s*sys\s*\.\s*argv\s*\[\s*([1-9][0-9]*)\s*\]\s*(?:,\s*['"]r(?:b|t)?['"])?\s*\)\s*\.read\s*\(`)
	pythonOpenSingleRead = regexp.MustCompile(`\bopen\s*\(\s*'([^'\\\n]+)'\s*(?:,\s*['"]r(?:b|t)?['"])?\s*\)\s*\.read\s*\(`)
	pythonOpenDoubleRead = regexp.MustCompile(`\bopen\s*\(\s*"([^"\\\n]+)"\s*(?:,\s*['"]r(?:b|t)?['"])?\s*\)\s*\.read\s*\(`)
	// pythonPrintOpenRead is a read whose text the code prints at once:
	// print(open(...).read()) or sys.stdout.write(open(...).read()).
	pythonPrintOpenRead   = regexp.MustCompile(`\b(?:print|sys\s*\.\s*stdout\s*\.\s*write)\s*\(\s*open\s*\(\s*(?:sys\s*\.\s*argv\s*\[\s*[1-9][0-9]*\s*\]|'[^'\\\n]+'|"[^"\\\n]+")\s*(?:,\s*['"]r(?:b|t)?['"])?\s*\)\s*\.read\s*\(\s*\)\s*\)`)
	pythonOpenArgWrite    = regexp.MustCompile(`\bopen\s*\(\s*sys\s*\.\s*argv\s*\[\s*([1-9][0-9]*)\s*\]\s*,\s*['"]([awx](?:b|t)?)['"]\s*\)\s*\.write\s*\(`)
	pythonOpenSingleWrite = regexp.MustCompile(`\bopen\s*\(\s*'([^'\\\n]+)'\s*,\s*['"]([awx](?:b|t)?)['"]\s*\)\s*\.write\s*\(`)
	pythonOpenDoubleWrite = regexp.MustCompile(`\bopen\s*\(\s*"([^"\\\n]+)"\s*,\s*['"]([awx](?:b|t)?)['"]\s*\)\s*\.write\s*\(`)
)

// The bounded Python delete calls (os.remove, os.unlink, os.rmdir,
// shutil.rmtree, pathlib Path(...).unlink() / .rmdir()) on a literal path,
// os.path.expanduser of one, or a literal sys.argv index (GAP-1478).
const pythonDeleteFunc = `(?:\bos\s*\.\s*(?:remove|unlink|rmdir)|\bshutil\s*\.\s*rmtree)\s*\(\s*`

var (
	pythonDeleteLiteral = regexp.MustCompile(pythonDeleteFunc +
		`(?:os\s*\.\s*path\s*\.\s*(expanduser)\s*\(\s*)?(?:'([^'\\\n]+)'|"([^"\\\n]+)")`)
	pythonDeleteArg  = regexp.MustCompile(pythonDeleteFunc + `sys\s*\.\s*argv\s*\[\s*([1-9][0-9]*)\s*\]`)
	pythonPathDelete = regexp.MustCompile(`\b(?:pathlib\s*\.\s*)?Path\s*\(\s*` +
		`(?:os\s*\.\s*path\s*\.\s*(expanduser)\s*\(\s*(?:'([^'\\\n]+)'|"([^"\\\n]+)")\s*\)|(?:'([^'\\\n]+)'|"([^"\\\n]+)"))` +
		`\s*\)\s*\.\s*(?:unlink|rmdir)\s*\(`)
	pythonRenameLiteral = regexp.MustCompile(`\bos\s*\.\s*rename\s*\(\s*(?:'([^'\\\n]+)'|"([^"\\\n]+)")\s*,`)
	nodeDirectDelete    = regexp.MustCompile(`\brequire\s*\(\s*['"](?:node:)?fs['"]\s*\)\s*\.\s*unlinkSync\s*\(\s*(?:'([^'\\\n]+)'|"([^"\\\n]+)")`)
	nodeFSBinding       = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*['"](?:node:)?fs['"]\s*\)`)
	rubyFileDelete      = regexp.MustCompile(`\bFile\s*\.\s*delete\s*\(\s*(?:'([^'\\\n]+)'|"([^"\\\n]+)")`)
)

// inlineDeleteTargets recognizes bounded static file deletion and rename
// sources in inline Python, Node and Ruby code. Dynamic paths stay opaque.
func inlineDeleteTargets(program, code string, args []Word) (map[int]bool, map[string]bool) {
	argDeletes, literalDeletes := map[int]bool{}, map[string]bool{}
	add := func(expanded bool, lits ...string) {
		for _, lit := range lits {
			if lit != "" && pathLike(lit) && (expanded || !strings.HasPrefix(lit, "~")) {
				literalDeletes[lit] = true
			}
		}
	}
	switch {
	case program == "python" || program == "python3" || strings.HasPrefix(program, "python3.") || strings.HasPrefix(program, "python2"):
		for _, match := range pythonDeleteArg.FindAllStringSubmatch(code, maxCodeLiterals) {
			index, err := strconv.Atoi(match[1])
			if err == nil && index > 0 && index <= len(args) {
				argDeletes[index-1] = true
			}
		}
		for _, match := range pythonDeleteLiteral.FindAllStringSubmatch(code, maxCodeLiterals) {
			add(match[1] != "", match[2], match[3])
		}
		for _, match := range pythonPathDelete.FindAllStringSubmatch(code, maxCodeLiterals) {
			add(true, match[2], match[3])
			add(false, match[4], match[5])
		}
		for _, match := range pythonRenameLiteral.FindAllStringSubmatch(code, maxCodeLiterals) {
			add(false, match[1], match[2])
		}
	case program == "node" || program == "nodejs":
		for _, match := range nodeDirectDelete.FindAllStringSubmatch(code, maxCodeLiterals) {
			add(false, match[1], match[2])
		}
		for _, binding := range nodeFSBinding.FindAllStringSubmatch(code, maxCodeLiterals) {
			call := regexp.MustCompile(`\b` + regexp.QuoteMeta(binding[1]) + `\s*\.\s*unlinkSync\s*\(\s*(?:'([^'\\\n]+)'|"([^"\\\n]+)")`)
			for _, match := range call.FindAllStringSubmatch(code, maxCodeLiterals) {
				add(false, match[1], match[2])
			}
		}
	case program == "ruby":
		for _, match := range rubyFileDelete.FindAllStringSubmatch(code, maxCodeLiterals) {
			add(false, match[1], match[2])
		}
	}
	return argDeletes, literalDeletes
}

// pythonOpenReadSources recognizes bounded Python open(...).read() forms with
// a literal path or a literal sys.argv index. Other code remains opaque.
func pythonOpenReadSources(program, code string, args []Word) (map[int]bool, map[string]bool) {
	argReads, literalReads := map[int]bool{}, map[string]bool{}
	if program != "python" && program != "python3" && !strings.HasPrefix(program, "python3.") && !strings.HasPrefix(program, "python2") {
		return argReads, literalReads
	}
	for _, match := range pythonOpenArgRead.FindAllStringSubmatch(code, maxCodeLiterals) {
		index, err := strconv.Atoi(match[1])
		if err == nil && index > 0 && index <= len(args) {
			argReads[index-1] = true
		}
	}
	for _, pattern := range []*regexp.Regexp{pythonOpenSingleRead, pythonOpenDoubleRead} {
		for _, match := range pattern.FindAllStringSubmatch(code, maxCodeLiterals) {
			if pathLike(match[1]) {
				literalReads[match[1]] = true
			}
		}
	}
	return argReads, literalReads
}

// pythonOpenWriteTargets recognizes bounded Python open(..., mode).write() forms.
func pythonOpenWriteTargets(program, code string, args []Word) (map[int]Kind, map[string]Kind) {
	argWrites, literalWrites := map[int]Kind{}, map[string]Kind{}
	if program != "python" && program != "python3" && !strings.HasPrefix(program, "python3.") && !strings.HasPrefix(program, "python2") {
		return argWrites, literalWrites
	}
	kindFor := func(mode string) Kind {
		if strings.HasPrefix(mode, "a") {
			return KindAppend
		}
		return KindWrite
	}
	for _, match := range pythonOpenArgWrite.FindAllStringSubmatch(code, maxCodeLiterals) {
		index, err := strconv.Atoi(match[1])
		if err == nil && index > 0 && index <= len(args) {
			argWrites[index-1] = kindFor(match[2])
		}
	}
	for _, pattern := range []*regexp.Regexp{pythonOpenSingleWrite, pythonOpenDoubleWrite} {
		for _, match := range pattern.FindAllStringSubmatch(code, maxCodeLiterals) {
			if pathLike(match[1]) {
				literalWrites[match[1]] = kindFor(match[2])
			}
		}
	}
	return argWrites, literalWrites
}

// codeLiterals returns the quoted string literals of a code text that look
// like paths (a separator, or a leading . or ~), at most maxCodeLiterals.
func codeLiterals(code string) []string {
	var out []string
	for i := 0; i < len(code) && len(out) < maxCodeLiterals; i++ {
		q := code[i]
		if q != '\'' && q != '"' && q != '`' {
			continue
		}
		j := i + 1
		for j < len(code) && code[j] != q && code[j] != '\n' {
			if code[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(code) || code[j] != q {
			i = j
			continue
		}
		lit := code[i+1 : j]
		i = j
		if len(lit) < 2 || len(lit) > maxSpellingBytes || strings.ContainsAny(lit, " \t\r\n$%{}") {
			continue
		}
		if strings.ContainsAny(lit, `/\`) || lit[0] == '.' || lit[0] == '~' {
			out = append(out, lit)
		}
	}
	return out
}

// opaquePathEffect is an effect of code the walker does not read on a path the
// call names: the target is placed, the role is unknown (reach R-CODE).
func (w *walker) opaquePathEffect(spelling string, origin Origin, cond bool) {
	e := Effect{Kind: KindOpaque, Cond: cond, RoleState: RoleStateUnknown, TargetState: TargetStateKnown,
		Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive, Spelling: cap4k(spelling)},
		Origin: origin}
	if abs, ok, reason := placePath(spelling, w.opts()); ok {
		e.Target.Path = abs
	} else {
		e.addReason(reason, ScopeTarget)
	}
	e.addReason(ReasonOpaqueCode, ScopeRole)
	w.emit(e)
}

// inlineCode lowers bounded Python open(...).read(), explicit write-mode
// open(...).write() and delete-call paths paths as file
// effects; other path literals and arguments
// remain opaque. It reports whether the call has inline or stdin code (its
// positionals are then arguments, not a program to run).
func (w *walker) inlineCode(c *Cmd, args []Word, origin Origin, cond bool) bool {
	ic := interpreterInvocation(args)
	code := ""
	switch {
	case ic.inline:
		if ic.code.Static {
			code = ic.code.Value
		}
	case ic.stdin:
		text, _, ok := w.stdinText(c)
		if !ok {
			return true
		}
		code = text
	default:
		return false
	}
	seen := map[string]bool{}
	readArgs, readLiterals := pythonOpenReadSources(origin.Program, code, ic.args)
	// The stage-level stdout proof applies to every read in this command.
	// Keep it only when there is exactly one recognized read and that read
	// is the direct argument of print/write, so unrelated reads stay private.
	readCount := len(pythonOpenArgRead.FindAllStringIndex(code, maxCodeLiterals)) +
		len(pythonOpenSingleRead.FindAllStringIndex(code, maxCodeLiterals)) +
		len(pythonOpenDoubleRead.FindAllStringIndex(code, maxCodeLiterals))
	if readCount == 1 && (len(readArgs) > 0 || len(readLiterals) > 0) && pythonPrintOpenRead.MatchString(code) {
		// The code prints what it reads on the call's stdout, as cat does:
		// the stage shows its reads unless it is piped on or redirected
		// (commandStage), so python3 -c 'print(open(sys.argv[1]).read())'
		// KEY is the read cat KEY is (rel-1-0-10:GAP-0893).
		w.printsOut = true
	}
	writeArgs, writeLiterals := pythonOpenWriteTargets(origin.Program, code, ic.args)
	deleteArgs, deleteLiterals := inlineDeleteTargets(origin.Program, code, ic.args)
	emitRead := func(spelling string) {
		if seen[spelling] {
			return
		}
		seen[spelling] = true
		if e := w.effectForOperand(operand{value: spelling, static: true, role: RoleRead}, Program{}, origin, cond, false, false, false, origin.Dialect, origin.Depth); e != nil {
			w.emit(*e)
		}
	}
	emitRole := func(spelling string, role Role) {
		if seen[spelling] {
			return
		}
		seen[spelling] = true
		if e := w.effectForOperand(operand{value: spelling, static: true, role: role}, Program{}, origin, cond, false, false, false, origin.Dialect, origin.Depth); e != nil {
			w.emit(*e)
		}
	}
	emitWrite := func(spelling string, kind Kind) {
		role := RoleWrite
		if kind == KindAppend {
			role = RoleAppend
		}
		emitRole(spelling, role)
	}
	for _, lit := range codeLiterals(code) {
		if kind, ok := writeLiterals[lit]; ok {
			emitWrite(lit, kind)
			continue
		}
		if readLiterals[lit] {
			emitRead(lit)
			continue
		}
		if deleteLiterals[lit] {
			emitRole(lit, RoleDelete)
			continue
		}
		if !seen[lit] {
			seen[lit] = true
			w.opaquePathEffect(lit, origin, cond)
		}
	}
	raws := rawWordsFor(ic.args, c.Words)
	for i, a := range ic.args {
		if kind, ok := writeArgs[i]; ok && a.Static && pathLike(a.Value) {
			emitWrite(a.Value, kind)
			continue
		}
		if readArgs[i] && a.Static && pathLike(a.Value) {
			emitRead(a.Value)
			continue
		}
		if deleteArgs[i] && a.Static && pathLike(a.Value) {
			emitRole(a.Value, RoleDelete)
			continue
		}
		if !a.Static {
			// A dynamic word (a ~ whose home the call changed: su -c, GAP-0662)
			// keeps its as-written spelling, so a protected tail still reaches
			// the classifier with an unknown target.
			if sp := rawSpelling(raws[i]); pathLike(sp) && !seen[sp] {
				seen[sp] = true
				w.opaqueDynamicEffect(sp, origin, cond)
			}
			continue
		}
		if seen[a.Value] || !pathLike(a.Value) {
			continue
		}
		seen[a.Value] = true
		if a.Glob {
			w.opaqueGlobEffect(a.Value, origin, cond) // a brace list or wildcard the shell expands
			continue
		}
		w.opaquePathEffect(a.Value, origin, cond)
	}
	// A prefix assignment (P=PATH python3 -c CODE) hands its value to the code
	// through the environment when the code names it (DET111 R1, GAP-0662).
	if ic.inline && code != "" && w.spec != nil {
		names := make([]string, 0, len(w.spec.assigns))
		for n := range w.spec.assigns {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			ca := w.spec.assigns[n]
			if !ca.ok || seen[ca.val] || !pathLike(ca.val) || !strings.Contains(code, n) {
				continue
			}
			seen[ca.val] = true
			w.opaquePathEffect(ca.val, origin, cond)
		}
	}
	return true
}

// pathLike reports a word that looks like a path: a separator, or a leading .
// or ~.
func pathLike(v string) bool {
	return strings.ContainsAny(v, `/\`) || strings.HasPrefix(v, ".") || strings.HasPrefix(v, "~")
}

// rawSpelling is a frontend word as written, its variables as $NAME; "" when
// it has no segments.
func rawSpelling(wd Word) string {
	var b strings.Builder
	for _, s := range wd.Segs {
		if s.Var != "" {
			b.WriteString("$" + s.Var)
			continue
		}
		b.WriteString(s.Lit)
	}
	return b.String()
}

// opaqueDynamicEffect is opaquePathEffect for a spelling the walker cannot
// place: the target is unknown and carries the spelling.
func (w *walker) opaqueDynamicEffect(spelling string, origin Origin, cond bool) {
	e := Effect{Kind: KindOpaque, Cond: cond, RoleState: RoleStateUnknown, TargetState: TargetStateUnknown,
		Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive, Spelling: cap4k(spelling)},
		Origin: origin}
	e.addReason(ReasonDynamicExpansion, ScopeTarget)
	e.addReason(ReasonOpaqueCode, ScopeRole)
	w.emit(e)
}

// opaqueGlobEffect is opaquePathEffect for a pattern: the target is the glob.
func (w *walker) opaqueGlobEffect(pattern string, origin Origin, cond bool) {
	e := Effect{Kind: KindOpaque, Cond: cond, RoleState: RoleStateUnknown, TargetState: TargetStateKnown,
		Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive, Glob: cap4k(pattern)},
		Origin: origin}
	e.addReason(ReasonGlob, ScopeTarget)
	e.addReason(ReasonOpaqueCode, ScopeRole)
	w.emit(e)
}

// nestedBodies lowers the bodies of eval and source / . that the operand loop
// does not: eval runs all its arguments joined; source runs the text of
// /dev/stdin or of a process substitution in the current shell.
func (w *walker) nestedBodies(c *Cmd, program string, inner []Word, dialect Dialect, depth int, cond bool, origin Origin) {
	if dialect != DialectPOSIX || len(inner) < 2 {
		return
	}
	switch program {
	case "eval":
		args := inner[1:]
		if len(args) > 0 && args[0].Static && args[0].Value == "--" {
			args = args[1:]
		}
		text, uncertain, ok := evalText(args, rawWordsFor(args, c.Words))
		if !ok {
			return
		}
		if uncertain {
			w.unwrapUncertain(text, dialect, depth, origin, nil, false)
			return
		}
		w.unwrapCodeScoped(text, true, dialect, depth, cond, origin, false)
	case "source", ".":
		arg := inner[1]
		if arg.Static && arg.Value == "--" && len(inner) > 2 {
			arg = inner[2]
		}
		switch {
		case arg.ProcSub != nil:
			if text, ok := staticOutput(arg.ProcSub); ok {
				w.unwrapCodeScoped(text, true, dialect, depth, cond, origin, false)
			}
		case arg.Static && isStdinPath(arg.Value):
			if text, tcond, ok := w.stdinText(c); ok {
				w.unwrapCodeScoped(text, true, dialect, depth, cond || tcond, origin, false)
			} else if hasStdinSource(c) {
				w.opaqueExec(origin, cond)
			}
		}
	}
}

// runWrittenScript lowers the text of a script file the call wrote earlier
// when a shell or source / . runs it (cat > x <<E; sh x; . x).
func (w *walker) runWrittenScript(value, program string, sc shellArgv, dialect Dialect, depth int, cond bool, origin Origin, childScope bool) {
	if dialect != DialectPOSIX {
		return
	}
	b, ok := w.scriptBody(value)
	if !ok {
		return
	}
	if !childScope {
		w.unwrapCodeScoped(b.text, true, dialect, depth, cond || b.cond, origin, false)
		return
	}
	if isPOSIXShell(program) && !sc.hasC && sc.hasArg && sc.script.Static && sc.script.Value == value {
		w.unwrapWithArgs(b.text, dialect, depth, cond || b.cond, origin, append([]Word{sc.script}, sc.rest...))
	}
}

// teeData gives tee's file writes the text tee reads on stdin, and records it
// as the text of each file it wrote (tee x.py <<E, GAP-1640).
func (w *walker) teeData(c *Cmd, args []Word, cmdNo, from int, appendFlag string, dialect Dialect) {
	text, _, ok := w.stdinText(c)
	if !ok && dialect == DialectPowerShell && c.PipeIn && w.stageIn.literal != "" {
		text, ok = w.stageIn.literal, true
	}
	if !ok {
		return
	}
	appendMode := appendFlag != "" && hasAppendFlag(args, appendFlag, dialect)
	for i := from; i < len(w.res.Effects); i++ {
		e := &w.res.Effects[i]
		if e.Origin.Command != cmdNo || (e.Kind != KindWrite && e.Kind != KindAppend) || (e.Data != nil && e.Data.Text != "") {
			continue
		}
		if e.Data == nil {
			e.Data = &Data{Kind: DataStdin}
		}
		e.Data.Text, e.Data.Bytes = cap8k(text), len(text)
		if !appendMode && len(text) <= maxDataText {
			w.noteFileBody(*e, text)
		}
	}
}
