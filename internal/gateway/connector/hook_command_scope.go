package connector

import (
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// maxHookWorkDirs bounds the working directories followed at one point of a
// command. A command that forks the directory more often than this keeps the
// first ones; the rest of the scan is unchanged.
const maxHookWorkDirs = 16

// hookWorkDirs follows the working directory through a hook command, so a
// relative word is resolved from the directory the command stands in when it
// is read, not from the directory of the process that scans it. It answers one
// set per word: "cd D && bash ./f" reads ./f in D, "(cd D; ...)" leaves D at
// the closing bracket, "env -C D bash ./f" and "env --chdir=D ..." change it
// for that call only, and "a || b", the branches of if, case and loops read the
// directories any earlier branch left. A directory change counts when the
// directory exists now (the shell would stay where it is otherwise); a target
// that is not literal (a variable, a substitution) leaves the directory as it
// was, which is the answer for a command that does not change directory.
type hookWorkDirs struct {
	scan  *hookPathScan
	home  string
	words map[*syntax.Word][]string
}

// trackWorkDirs returns the working directories in effect at each word of
// file, starting from start. A word that is not in the map is read from start
// (the command was not walked, as on Windows where relative words are not
// resolved).
func (s *hookPathScan) trackWorkDirs(file *syntax.File, home string, start []string) map[*syntax.Word][]string {
	t := &hookWorkDirs{scan: s, home: home, words: map[*syntax.Word][]string{}}
	if !s.fold {
		t.run(file.Stmts, start)
	}
	return t.words
}

func (t *hookWorkDirs) run(stmts []*syntax.Stmt, in []string) []string {
	for _, stmt := range stmts {
		in = t.stmt(stmt, in)
	}
	return in
}

// direct records the directories in effect for each word under node and
// follows the command substitutions among them, which run in a subshell.
func (t *hookWorkDirs) direct(node syntax.Node, in []string) {
	syntax.Walk(node, func(n syntax.Node) bool {
		switch n := n.(type) {
		case *syntax.Word:
			t.words[n] = in
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

func (t *hookWorkDirs) stmt(stmt *syntax.Stmt, in []string) []string {
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
			return hookUnionDirs(t.stmt(cmd.X, in), t.stmt(cmd.Y, in))
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
		t.stmt(cmd.Body, in) // runs where it is called, which is not known
		return in
	case *syntax.IfClause:
		return t.ifClause(cmd, in)
	case *syntax.WhileClause:
		cond := t.run(cmd.Cond, in)
		return hookUnionDirs(cond, t.run(cmd.Do, cond))
	case *syntax.ForClause:
		if loop, ok := cmd.Loop.(*syntax.WordIter); ok {
			for _, item := range loop.Items {
				t.direct(item, in)
			}
			return hookUnionDirs(in, t.run(cmd.Do, in))
		}
	case *syntax.CaseClause:
		t.direct(cmd.Word, in)
		out := in
		for _, item := range cmd.Items {
			for _, pattern := range item.Patterns {
				t.direct(pattern, in)
			}
			out = hookUnionDirs(out, t.run(item.Stmts, in))
		}
		return out
	}
	// Any other compound command: each command reads the directories every
	// earlier one left, and the whole leaves them all.
	cur := in
	syntax.Walk(stmt.Cmd, func(n syntax.Node) bool {
		switch n := n.(type) {
		case *syntax.Stmt:
			cur = hookUnionDirs(cur, t.stmt(n, cur))
			return false
		case *syntax.Word:
			t.words[n] = cur
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
// the directories of either branch.
func (t *hookWorkDirs) ifClause(clause *syntax.IfClause, in []string) []string {
	cond := t.run(clause.Cond, in)
	out := t.run(clause.Then, cond)
	if clause.Else == nil {
		return hookUnionDirs(out, cond)
	}
	return hookUnionDirs(out, t.ifClause(clause.Else, cond))
}

func (t *hookWorkDirs) call(call *syntax.CallExpr, in []string) []string {
	for _, assign := range call.Assigns {
		t.direct(assign, in)
	}
	program, operands, dir := hookProgramWord(call.Args)
	cwd := in
	if dir != nil {
		cwd = t.chdir(in, dir)
	}
	for _, arg := range call.Args {
		t.direct(arg, cwd)
	}
	if dir != nil || program == nil {
		return in
	}
	switch program.Lit() {
	case "cd", "pushd":
		return t.chdir(in, hookChdirOperand(operands))
	}
	return in
}

// chdir returns the directories after "cd target" from each directory in in;
// a nil target is "cd" alone, which goes home.
func (t *hookWorkDirs) chdir(in []string, target *syntax.Word) []string {
	text := t.home
	if target != nil {
		var ok bool
		if text, ok = t.scan.literalWord(hookHomeWord(target, t.home), t.home); !ok {
			return in
		}
	}
	bases := in
	if len(bases) == 0 {
		bases = []string{""}
	}
	var out []string
	for _, base := range bases {
		dir := path.Clean(text)
		if !path.IsAbs(text) && base != "" {
			dir = path.Join(base, text)
		}
		info, err := os.Stat(filepath.FromSlash(dir))
		if err != nil || !info.IsDir() || !path.IsAbs(dir) {
			if base != "" {
				out = hookAppendDir(out, base) // the change fails: the shell stays
			}
			continue
		}
		out = hookAppendDir(out, dir)
		// The process stands in the physical directory, whose ".." differs
		// from the logical one when the target is a link.
		if physical, err := filepath.EvalSymlinks(filepath.FromSlash(dir)); err == nil {
			out = hookAppendDir(out, filepath.ToSlash(physical))
		}
	}
	if len(out) == 0 {
		return in
	}
	return out
}

func hookAppendDir(dirs []string, dir string) []string {
	if len(dirs) >= maxHookWorkDirs || slices.Contains(dirs, dir) {
		return dirs
	}
	return append(dirs, dir)
}

func hookUnionDirs(a, b []string) []string {
	out := slices.Clone(a)
	for _, dir := range b {
		out = hookAppendDir(out, dir)
	}
	return out
}

// hookChdirOperand returns the directory word of the operands of cd or pushd
// after their options, or nil for "cd" alone.
func hookChdirOperand(operands []*syntax.Word) *syntax.Word {
	for i, word := range operands {
		lit := word.Lit()
		switch {
		case lit == "--":
			if i+1 < len(operands) {
				return operands[i+1]
			}
			return nil
		case len(lit) > 1 && lit[0] == '-':
			continue
		default:
			return word
		}
	}
	return nil
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
	return param.Param != nil && param.Param.Value == "HOME" && param.Exp == nil && param.Index == nil &&
		param.Slice == nil && param.Repl == nil && !param.Length && !param.Excl && !param.Width
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
// ("python -c ...", "node -e ...") is not read: nil.
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
			if strings.HasPrefix(lit, "-") {
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
	for _, interpreter := range []string{"python", "node", "nodejs", "perl", "ruby", "php", "lua"} {
		if tail, ok := strings.CutPrefix(name, interpreter); ok && strings.Trim(tail, "0123456789.") == "" {
			return hookScriptRunner
		}
	}
	return hookNotRunner
}
