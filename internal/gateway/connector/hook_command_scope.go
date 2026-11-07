package connector

import (
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	// maxHookWorkDirs bounds the working directories followed at one point of
	// a command. The set holds only directories that exist, and the directory
	// the shell really stands in is always kept ahead of the ones it stays in
	// when a change fails.
	maxHookWorkDirs = 1024
	// maxHookDirStats bounds the directory changes tried while one command is
	// walked; after that a change leaves the directories as they were.
	maxHookDirStats = 200000
	// maxHookFunctionCalls bounds the function bodies walked at their call
	// sites, so functions that call each other twice cannot grow without end.
	maxHookFunctionCalls = 1000
	// maxHookWordVariants bounds the readings of one word whose variables hold
	// more than one value.
	maxHookWordVariants = 64
)

// hookState is what the walk knows at one point of a command: the directories
// the shell may stand in, and the literal values each variable may hold (a
// variable that is not there is unknown). Both are replaced, never changed in
// place, so a branch cannot alter the state of the one before it.
type hookState struct {
	dirs []string
	vars map[string][]string
}

// setVar returns the state with name holding values; no values make it
// unknown.
func (st hookState) setVar(name string, values []string) hookState {
	vars := make(map[string][]string, len(st.vars)+1)
	for k, v := range st.vars {
		vars[k] = v
	}
	if len(values) == 0 {
		delete(vars, name)
	} else {
		vars[name] = values
	}
	st.vars = vars
	return st
}

// hookJoinStates is the state after either of two branches.
func hookJoinStates(a, b hookState) hookState {
	out := hookState{dirs: hookUnionDirs(a.dirs, b.dirs), vars: a.vars}
	if len(b.vars) > 0 {
		out.vars = make(map[string][]string, len(a.vars)+len(b.vars))
		for k, v := range a.vars {
			out.vars[k] = v
		}
		for k, v := range b.vars {
			out.vars[k] = hookUnionStrings(out.vars[k], v)
		}
	}
	return out
}

func hookUnionStrings(a, b []string) []string {
	out := slices.Clone(a)
	for _, v := range b {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// hookWorkDirs follows the working directory and the literal variables through
// a hook command, so a relative word is resolved from the directory the
// command stands in when it is read, not from the directory of the process
// that scans it. It answers one state per word: "cd D && bash ./f" reads ./f in
// D, "D=x; cd $D" goes to x, "(cd D; ...)" leaves D at the closing bracket,
// "env -C D bash ./f" and "env --chdir=D ..." change it for that call only,
// "a || b" and the branches of if, case and loops read the directories any
// earlier branch left, and a function body is read at each call, from the
// directory the call stands in. "cd" and "pushd" follow the logical path (a
// ".." step is lexical) unless -P is given; "env -C" opens the directory with
// the kernel, as "cd -P" does. A directory change counts when the directory
// exists now (the shell would stay where it is otherwise); a target that is
// not literal leaves the directory as it was, which is the answer for a
// command that does not change directory.
type hookWorkDirs struct {
	scan   *hookPathScan
	home   string
	words  map[*syntax.Word]hookState
	calls  map[*syntax.CallExpr]hookState
	funcs  map[string]*syntax.Stmt
	active map[string]bool
	stats  int
	runs   int
}

// trackWorkDirs returns the state in effect at each word of file, starting
// from start, and the state each call reads its arguments in. A word that is
// not in the map is read from start (the command was not walked, as on Windows
// where relative words are not resolved).
func (s *hookPathScan) trackWorkDirs(file *syntax.File, home string, start hookState) (map[*syntax.Word]hookState, map[*syntax.CallExpr]hookState) {
	t := &hookWorkDirs{
		scan: s, home: home,
		words:  map[*syntax.Word]hookState{},
		calls:  map[*syntax.CallExpr]hookState{},
		funcs:  map[string]*syntax.Stmt{},
		active: map[string]bool{},
	}
	if !s.fold {
		t.run(file.Stmts, start)
	}
	return t.words, t.calls
}

// record notes the state a word is read in; a function body read at several
// calls keeps every directory.
func (t *hookWorkDirs) record(word *syntax.Word, st hookState) {
	if prev, ok := t.words[word]; ok {
		st = hookJoinStates(prev, st)
	}
	t.words[word] = st
}

func (t *hookWorkDirs) run(stmts []*syntax.Stmt, in hookState) hookState {
	for _, stmt := range stmts {
		in = t.stmt(stmt, in)
	}
	return in
}

// direct records the state for each word under node and follows the command
// substitutions among them, which run in a subshell.
func (t *hookWorkDirs) direct(node syntax.Node, in hookState) {
	syntax.Walk(node, func(n syntax.Node) bool {
		switch n := n.(type) {
		case *syntax.Word:
			t.record(n, in)
		case *syntax.CmdSubst:
			t.run(n.Stmts, in)
			return false
		case *syntax.ProcSubst:
			t.run(n.Stmts, in)
			return false
		}
		return true
	})
}

func (t *hookWorkDirs) stmt(stmt *syntax.Stmt, in hookState) hookState {
	for _, redirect := range stmt.Redirs {
		t.direct(redirect, in)
	}
	switch cmd := stmt.Cmd.(type) {
	case nil:
		return in
	case *syntax.CallExpr:
		return t.call(cmd, in)
	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.AndStmt:
			return t.stmt(cmd.Y, t.stmt(cmd.X, in))
		case syntax.OrStmt:
			return hookJoinStates(t.stmt(cmd.X, in), t.stmt(cmd.Y, in))
		default: // a pipeline: each side runs in a subshell
			t.stmt(cmd.X, in)
			t.stmt(cmd.Y, in)
			return in
		}
	case *syntax.Subshell:
		t.run(cmd.Stmts, in)
		return in
	case *syntax.Block:
		return t.run(cmd.Stmts, in)
	case *syntax.FuncDecl:
		// The body runs where the function is called, not where it is
		// defined: it is walked at each call.
		t.funcs[cmd.Name.Value] = cmd.Body
		return in
	case *syntax.DeclClause:
		out := in
		for _, arg := range cmd.Args {
			t.direct(arg, in)
			out = t.assign(arg, out)
		}
		return out
	case *syntax.IfClause:
		return t.ifClause(cmd, in)
	case *syntax.WhileClause:
		cond := t.run(cmd.Cond, in)
		return hookJoinStates(cond, t.run(cmd.Do, cond))
	case *syntax.ForClause:
		if loop, ok := cmd.Loop.(*syntax.WordIter); ok {
			var values []string
			known := len(loop.Items) > 0
			for _, item := range loop.Items {
				t.direct(item, in)
				if items := t.values(item, in); items != nil {
					values = append(values, items...)
				} else {
					known = false
				}
			}
			body := in.setVar(loop.Name.Value, nil)
			if known {
				body = in.setVar(loop.Name.Value, values)
			}
			return hookJoinStates(in, t.run(cmd.Do, body))
		}
	case *syntax.CaseClause:
		t.direct(cmd.Word, in)
		out := in
		for _, item := range cmd.Items {
			for _, pattern := range item.Patterns {
				t.direct(pattern, in)
			}
			out = hookJoinStates(out, t.run(item.Stmts, in))
		}
		return out
	}
	// Any other compound command: each command reads the state every earlier
	// one left, and the whole leaves them all.
	cur := in
	syntax.Walk(stmt.Cmd, func(n syntax.Node) bool {
		switch n := n.(type) {
		case *syntax.Stmt:
			cur = hookJoinStates(cur, t.stmt(n, cur))
			return false
		case *syntax.Word:
			t.record(n, cur)
		case *syntax.CmdSubst:
			t.run(n.Stmts, cur)
			return false
		case *syntax.ProcSubst:
			t.run(n.Stmts, cur)
			return false
		}
		return true
	})
	return cur
}

// ifClause follows the condition into the branch it selects; the whole leaves
// the state of either branch.
func (t *hookWorkDirs) ifClause(clause *syntax.IfClause, in hookState) hookState {
	cond := t.run(clause.Cond, in)
	out := t.run(clause.Then, cond)
	if clause.Else == nil {
		return hookJoinStates(out, cond)
	}
	return hookJoinStates(out, t.ifClause(clause.Else, cond))
}

// assign returns the state after one NAME=value: the literal values the
// variable may hold, or unknown when the value is not literal.
func (t *hookWorkDirs) assign(a *syntax.Assign, in hookState) hookState {
	if a.Name == nil || a.Naked {
		return in
	}
	if a.Append || a.Index != nil || a.Array != nil {
		return in.setVar(a.Name.Value, nil)
	}
	if a.Value == nil {
		return in.setVar(a.Name.Value, []string{""})
	}
	return in.setVar(a.Name.Value, t.values(a.Value, in))
}

func (t *hookWorkDirs) call(call *syntax.CallExpr, in hookState) hookState {
	if len(call.Args) == 0 {
		// Assignments alone stay for the commands after them.
		out := in
		for _, assign := range call.Assigns {
			t.direct(assign, out)
			out = t.assign(assign, out)
		}
		return out
	}
	// Assignments before a command reach that command (and a shell it starts)
	// only; its words are expanded before they apply.
	reads := in
	for _, assign := range call.Assigns {
		t.direct(assign, reads)
		reads = t.assign(assign, reads)
	}
	program, operands, dir := hookProgramWord(call.Args)
	cwd := reads
	if dir != nil {
		// env opens the directory from where it stands, before it changes it.
		t.direct(dir, reads)
		cwd = t.chdir(reads, dir, true)
	}
	t.calls[call] = reads
	for _, arg := range call.Args {
		if arg != dir {
			t.direct(arg, cwd)
		}
	}
	if dir != nil || program == nil {
		return in
	}
	name := program.Lit()
	if program == call.Args[0] {
		if body, ok := t.funcs[name]; ok && !t.active[name] && t.runs < maxHookFunctionCalls {
			t.runs++
			t.active[name] = true
			out := t.stmt(body, in)
			delete(t.active, name)
			return out
		}
	}
	switch name {
	case "cd", "pushd":
		target, physical := hookChdirOperand(operands)
		return t.chdir(in, target, physical)
	}
	return in
}

// values returns the literal texts word may have in state st, with the known
// variables replaced, or nil when it is not literal.
func (t *hookWorkDirs) values(word *syntax.Word, st hookState) []string {
	var out []string
	for _, variant := range hookWordVariants(word, st.vars) {
		text, ok := t.scan.literalWord(variant, t.home)
		if !ok {
			return nil
		}
		out = hookUnionStrings(out, []string{text})
	}
	return out
}

// chdir returns the state after "cd target" from each directory in in; a nil
// target is "cd" alone, which goes home. A physical change resolves links
// first, as the kernel does for "cd -P" and "env -C"; otherwise the path is
// cleaned as written, so ".." leaves the directory the shell was told about.
func (t *hookWorkDirs) chdir(in hookState, target *syntax.Word, physical bool) hookState {
	texts := []string{t.home}
	if target != nil {
		texts = t.values(hookHomeWord(target, t.home), in)
	}
	if len(texts) == 0 || t.stats >= maxHookDirStats {
		return in
	}
	bases := in.dirs
	if len(bases) == 0 {
		bases = []string{""}
	}
	var moved, stayed []string
	for _, base := range bases {
		failed := false
		for _, text := range texts {
			if dir, ok := t.enter(base, text, physical); ok {
				moved = hookAppendDir(moved, dir)
			} else {
				failed = true
			}
		}
		if failed && base != "" {
			stayed = hookAppendDir(stayed, base) // the change fails: the shell stays
		}
	}
	out := hookUnionDirs(moved, stayed)
	if len(out) == 0 {
		return in
	}
	in.dirs = out
	return in
}

// enter returns the directory the shell stands in after changing from base to
// text, and whether the change succeeds.
func (t *hookWorkDirs) enter(base, text string, physical bool) (string, bool) {
	t.stats++
	if !path.IsAbs(text) && base == "" {
		return "", false
	}
	if physical {
		name := text
		if !path.IsAbs(text) {
			name = strings.TrimSuffix(base, "/") + "/" + text
		}
		resolved, err := filepath.EvalSymlinks(filepath.FromSlash(name))
		if err != nil {
			return "", false
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.IsDir() {
			return "", false
		}
		return filepath.ToSlash(resolved), true
	}
	dir := path.Clean(text)
	if !path.IsAbs(text) {
		dir = path.Join(base, text)
	}
	info, err := os.Stat(filepath.FromSlash(dir))
	if err != nil || !info.IsDir() {
		return "", false
	}
	return dir, true
}

func hookAppendDir(dirs []string, dir string) []string {
	if len(dirs) >= maxHookWorkDirs || slices.Contains(dirs, dir) {
		return dirs
	}
	return append(dirs, dir)
}

func hookUnionDirs(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	out := slices.Clone(a)
	for _, dir := range b {
		out = hookAppendDir(out, dir)
	}
	return out
}

// hookChdirOperand returns the directory word of the operands of cd or pushd
// after their options (nil for "cd" alone), and whether -P, the last of -L and
// -P, asks for the physical directory.
func hookChdirOperand(operands []*syntax.Word) (target *syntax.Word, physical bool) {
	for i, word := range operands {
		lit := word.Lit()
		switch {
		case lit == "--":
			if i+1 < len(operands) {
				return operands[i+1], physical
			}
			return nil, physical
		case len(lit) > 1 && strings.HasPrefix(lit, "-"):
			for _, option := range lit[1:] {
				switch option {
				case 80: // P
					physical = true
				case 76: // L
					physical = false
				}
			}
		default:
			return word, physical
		}
	}
	return nil, physical
}

// hookWordVariants returns the readings of word with each plain $NAME or
// ${NAME} of a known variable replaced by one of its values.
func hookWordVariants(word *syntax.Word, vars map[string][]string) []*syntax.Word {
	if len(vars) == 0 {
		return []*syntax.Word{word}
	}
	var out []*syntax.Word
	for _, parts := range hookPartVariants(word.Parts, vars) {
		out = append(out, &syntax.Word{Parts: parts})
	}
	return out
}

func hookPartVariants(parts []syntax.WordPart, vars map[string][]string) [][]syntax.WordPart {
	results := [][]syntax.WordPart{nil}
	for _, part := range parts {
		options := hookPartOptions(part, vars)
		var next [][]syntax.WordPart
		for _, done := range results {
			for _, option := range options {
				if len(next) < maxHookWordVariants {
					next = append(next, append(slices.Clone(done), option...))
				}
			}
		}
		results = next
	}
	return results
}

// hookPartOptions returns the ways to read one part: itself, or the values of
// a known variable. A double-quoted part that holds a known variable is split
// into quoted pieces around it, so a value needs no escaping.
func hookPartOptions(part syntax.WordPart, vars map[string][]string) [][]syntax.WordPart {
	switch part := part.(type) {
	case *syntax.ParamExp:
		if name, ok := hookPlainParam(part); ok {
			var options [][]syntax.WordPart
			for _, value := range vars[name] {
				options = append(options, []syntax.WordPart{&syntax.SglQuoted{Value: value}})
			}
			if options != nil {
				return options
			}
		}
	case *syntax.DblQuoted:
		var pieces []syntax.WordPart
		split := false
		for _, inner := range part.Parts {
			if param, ok := inner.(*syntax.ParamExp); ok {
				if name, plain := hookPlainParam(param); plain && len(vars[name]) > 0 {
					pieces, split = append(pieces, inner), true
					continue
				}
			}
			pieces = append(pieces, &syntax.DblQuoted{Dollar: part.Dollar, Parts: []syntax.WordPart{inner}})
		}
		if split {
			return hookPartVariants(pieces, vars)
		}
	}
	return [][]syntax.WordPart{{part}}
}

// hookHomeWord returns word with a leading "~", "$HOME" or "${HOME}" made the
// home directory text, which the literal reader refuses to guess.
func hookHomeWord(word *syntax.Word, home string) *syntax.Word {
	if len(word.Parts) == 0 {
		return word
	}
	rest := word.Parts[1:]
	switch first := word.Parts[0].(type) {
	case *syntax.Lit:
		if first.Value == "~" || strings.HasPrefix(first.Value, "~/") {
			parts := []syntax.WordPart{&syntax.SglQuoted{Value: home}}
			if tail := first.Value[1:]; tail != "" {
				parts = append(parts, &syntax.Lit{Value: tail})
			}
			return &syntax.Word{Parts: append(parts, rest...)}
		}
	case *syntax.ParamExp:
		if hookHomeParam(first) {
			return &syntax.Word{Parts: append([]syntax.WordPart{&syntax.SglQuoted{Value: home}}, rest...)}
		}
	case *syntax.DblQuoted:
		if len(first.Parts) > 0 {
			if param, ok := first.Parts[0].(*syntax.ParamExp); ok && hookHomeParam(param) {
				inner := &syntax.DblQuoted{Parts: append([]syntax.WordPart{&syntax.Lit{Value: home}}, first.Parts[1:]...)}
				return &syntax.Word{Parts: append([]syntax.WordPart{inner}, rest...)}
			}
		}
	}
	return word
}

// hookHomeParam reports whether param is a plain $HOME or ${HOME}.
func hookHomeParam(param *syntax.ParamExp) bool {
	name, ok := hookPlainParam(param)
	return ok && name == "HOME"
}

// hookHasParam reports whether word holds a parameter expansion, quoted or not.
func hookHasParam(word *syntax.Word) bool {
	found := false
	syntax.Walk(word, func(n syntax.Node) bool {
		if _, ok := n.(*syntax.ParamExp); ok {
			found = true
		}
		return !found
	})
	return found
}

// hookPlainParam returns the name of a plain $NAME or ${NAME}.
func hookPlainParam(param *syntax.ParamExp) (string, bool) {
	if param.Param == nil || param.Exp != nil || param.Index != nil || param.Slice != nil || param.Repl != nil ||
		param.Length || param.Excl || param.Width {
		return "", false
	}
	return param.Param.Value, true
}

// hookCommandOperands returns the words a runner reads as command text: the one
// word after -c for a shell, all the operands of eval, which joins them.
func hookCommandOperands(name string, operand *syntax.Word, operands []*syntax.Word) []*syntax.Word {
	if name == "eval" {
		return operands
	}
	return []*syntax.Word{operand}
}

type hookRunner int

const (
	hookNotRunner hookRunner = iota
	hookShellRunner
	hookSourceRunner
	hookScriptRunner
	hookEvalRunner
)

// hookScriptOperand returns the word a runner opens as its script file, and
// whether the runner reads that word as command text instead ("bash -c", eval).
// The runners are the shells, the builtins source and ".", and the script
// interpreters; for any other program every argument may be run as text, so no
// word is a file name. An interpreter with an option before the script
// ("python -c ...", "node -e ...") is not read: nil, unless the option is one
// that takes no value and runs no code (hookInterpreterFlag: "python3 -u x").
func hookScriptOperand(name string, operands []*syntax.Word) (operand *syntax.Word, command bool) {
	kind := hookRunnerOf(name)
	for i := 0; kind != hookNotRunner && i < len(operands); i++ {
		word := operands[i]
		lit := word.Lit()
		switch {
		case kind == hookSourceRunner:
			return word, false
		case kind == hookEvalRunner:
			return word, true
		case kind == hookScriptRunner:
			switch {
			case lit == "--":
				if i+1 < len(operands) {
					return operands[i+1], false
				}
				return nil, false
			case hookInterpreterFlag(name, lit):
				continue
			case strings.HasPrefix(lit, "-"):
				return nil, false
			}
			return word, false
		case lit == "--":
			if i+1 < len(operands) {
				return operands[i+1], command
			}
			return nil, false
		case slices.Contains([]string{"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}, lit):
			i++
		case len(lit) > 1 && (lit[0] == '-' || lit[0] == '+'):
			// A short option cluster that holds c reads the next word as the
			// command.
			if lit[0] == '-' && !strings.HasPrefix(lit, "--") && strings.Contains(lit, "c") {
				command = true
			}
		default:
			return word, command
		}
	}
	return nil, false
}

// hookRunnerOf classifies a program name. Interpreters may carry a version
// ("python3.12").
func hookRunnerOf(name string) hookRunner {
	switch name {
	case "bash", "sh", "dash", "zsh", "ksh", "mksh", "ash", "csh", "tcsh":
		return hookShellRunner
	case "source", ".":
		return hookSourceRunner
	case "eval":
		return hookEvalRunner
	}
	if hookInterpreterOf(name) != "" {
		return hookScriptRunner
	}
	return hookNotRunner
}

// hookInterpreterOf returns the script interpreter a program name is
// ("python3.12" is "python"), or "".
func hookInterpreterOf(name string) string {
	for _, interpreter := range []string{"python", "nodejs", "node", "perl", "ruby", "php", "lua"} {
		if tail, ok := strings.CutPrefix(name, interpreter); ok && strings.Trim(tail, "0123456789.") == "" {
			return interpreter
		}
	}
	return ""
}

// hookInterpreterFlags are, per interpreter, the single-letter options that
// take no value and run no code, so the word after a cluster of them is the
// script. Any other option may take a value or hold code and leaves every word
// after it as text.
var hookInterpreterFlags = map[string]string{
	"python": "uBEsSIOqbdvxRPit",
	"perl":   "wWTtUX",
	"ruby":   "wdv",
	"php":    "nq",
}

// hookNodeFlags are the long options of node that take no value.
var hookNodeFlags = []string{"--no-warnings", "--no-deprecation", "--trace-warnings", "--enable-source-maps"}

// hookInterpreterFlag reports whether lit is options of the interpreter that
// run no code and take no value.
func hookInterpreterFlag(name, lit string) bool {
	interpreter := hookInterpreterOf(name)
	if interpreter == "node" || interpreter == "nodejs" {
		return slices.Contains(hookNodeFlags, lit)
	}
	letters := hookInterpreterFlags[interpreter]
	if letters == "" || len(lit) < 2 || !strings.HasPrefix(lit, "-") || strings.HasPrefix(lit, "--") {
		return false
	}
	return strings.Trim(lit[1:], letters) == ""
}
