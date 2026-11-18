// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Copy operand words spelled with a shell name whose value the command
// itself fixes (rel-1-0-10:GAP-0839). A cp word that is not static may expand
// to a link option, which opens a copy scope; where the scope has no known
// destination, every write of the call is unknown. Two readings fix the
// value of such a word without running anything:
//
//   - boundedLoopIteratorWords: the name of a for loop over fixed plain names,
//     used in the loop body (for f in a.log b.tsv; do cp s/$f d/$f; done);
//   - straightLineWords: a name a top-level assignment statement fixed, used
//     by a later top-level statement (E=~/out; ...; cp a.txt $E/dir/).
//
// Both read only statements that cannot rebind a name of the shell
// (statementKeepsNames), in a command that defines no function.

// loopIteratorWord is a word of a for loop body spelled with the loop name:
// the one word it is in each pass, in order.
type loopIteratorWord struct {
	loop   *syntax.ForClause
	values []string
}

// shellBuiltinNames are the builtins and reserved words of bash, zsh, ksh
// and dash: they run in the shell itself, and many can bind a name (read,
// printf -v, getopts, vared, zparseopts, eval, source). Any other static
// program word runs a separate program, which cannot bind a name of the
// calling shell.
var shellBuiltinNames = []string{
	".", ":", "[", "[[", "alias", "autoload", "bg", "bind", "bindkey", "break", "builtin", "bye", "caller",
	"cap", "case", "cd", "chdir", "clone", "command", "compadd", "comparguments", "compcall", "compctl",
	"compdef", "compdescribe", "compfiles", "compgen", "compgroups", "complete", "compopt", "compquote",
	"comptags", "comptry", "compvalues", "continue", "coproc", "declare", "dirs", "disable", "disown", "do",
	"done", "echo", "echotc", "echoti", "elif", "else", "emulate", "enable", "esac", "eval", "exec", "exit",
	"export", "false", "fc", "fg", "fi", "float", "for", "foreach", "function", "functions", "getcap", "getln",
	"getopts", "hash", "help", "history", "if", "in", "integer", "jobs", "kill", "let", "limit", "local", "log",
	"logout", "mapfile", "nameref", "nocorrect", "noglob", "popd", "print", "printf", "private", "pushd",
	"pushln", "pwd", "r", "read", "readarray", "readonly", "rehash", "repeat", "return", "sched", "select",
	"set", "setcap", "setopt", "shift", "shopt", "source", "stat", "strftime", "suspend", "test", "then",
	"time", "times", "trap", "true", "ttyctl", "type", "typeset", "ulimit", "umask", "unalias", "unfunction",
	"unhash", "unlimit", "unset", "unsetopt", "until", "vared", "wait", "whence", "where", "which", "while",
	"zcompile", "zcurses", "zdelattr", "zformat", "zftp", "zgetattr", "zle", "zlistattr", "zmodload",
	"zparseopts", "zprof", "zpty", "zregexparse", "zselect", "zsetattr", "zsocket", "zstyle", "zsystem", "ztcp",
}

// programKeepsNames reports a static program word that cannot bind a name
// of the calling shell: one of knownWordPrograms, or a program that is no
// shell builtin, spelled as a plain name or path.
func programKeepsNames(program string) bool {
	base := programBase(program)
	if slices.Contains(knownWordPrograms, base) {
		return true
	}
	if base == "" || strings.HasPrefix(base, "-") || slices.Contains(shellBuiltinNames, base) {
		return false
	}
	for i := 0; i < len(program); i++ {
		b := program[i]
		if (b < '0' || b > '9') && (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') && strings.IndexByte("._+-/", b) < 0 {
			return false
		}
	}
	return true
}

// statementKeepsNames reports a foreground statement that is one simple
// call or an && / || list of them, each with no assignment and a program
// word for which programKeepsNames holds, whose words and redirects (here
// documents included) hold no arithmetic, command or process substitution
// and no parameter operator other than a plain read. calls gets its calls.
func statementKeepsNames(stmt *syntax.Stmt, home string, calls *[]*syntax.CallExpr) bool {
	if stmt == nil || stmt.Background || stmt.Coprocess {
		return false
	}
	plain := true
	syntax.Walk(stmt, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.ArithmExp, *syntax.ArithmCmd, *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ExtGlob,
			*syntax.BraceExp, *syntax.FuncDecl, *syntax.DeclClause, *syntax.LetClause, *syntax.TestClause:
			plain = false
		case *syntax.ParamExp:
			plain = plain && simpleScalarParameter(node)
		}
		return plain
	})
	if !plain {
		return false
	}
	var visit func(*syntax.Stmt) bool
	visit = func(stmt *syntax.Stmt) bool {
		if stmt == nil || stmt.Background || stmt.Coprocess {
			return false
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			if len(cmd.Assigns) != 0 || len(cmd.Args) == 0 {
				return false
			}
			program, fixed := StaticWord(cmd.Args[0], home)
			if !fixed || !programKeepsNames(program) {
				return false
			}
			*calls = append(*calls, cmd)
			return true
		case *syntax.BinaryCmd:
			return (cmd.Op == syntax.AndStmt || cmd.Op == syntax.OrStmt) && visit(cmd.X) && visit(cmd.Y)
		}
		return false
	}
	return visit(stmt)
}

// commandDefinesFunction reports a function definition anywhere in file: a
// call may then run a function of that name in the shell itself.
func commandDefinesFunction(file *syntax.File) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if _, ok := node.(*syntax.FuncDecl); ok {
			found = true
		}
		return !found
	})
	return found
}

// boundedLoopIteratorWords reads the for loops over at most 32 fixed plain
// names (a.log b.tsv) whose body statements all keep names: a body word made
// of plain text and the unquoted loop name (/var/tmp/stage/$f) is one fixed
// word in each pass, never an option.
func boundedLoopIteratorWords(command string, file *syntax.File, home string) map[*syntax.Word]loopIteratorWord {
	if file == nil || !strings.Contains(command, "for") || !strings.Contains(command, "cp") ||
		commandDefinesFunction(file) {
		return nil
	}
	out := map[*syntax.Word]loopIteratorWord{}
	syntax.Walk(file, func(node syntax.Node) bool {
		loop, ok := node.(*syntax.ForClause)
		if !ok {
			return true
		}
		iter, ok := loop.Loop.(*syntax.WordIter)
		if !ok || loop.Select || iter.Name == nil || !iter.InPos.IsValid() || len(iter.Items) == 0 ||
			len(iter.Items) > 32 || !plainShellName(iter.Name.Value) {
			return true
		}
		values := make([]string, 0, len(iter.Items))
		for _, item := range iter.Items {
			value, fixed := StaticWord(item, home)
			if !fixed || !loopPlainValue(value) {
				return true
			}
			values = append(values, value)
		}
		var calls []*syntax.CallExpr
		for _, stmt := range loop.Do {
			if !statementKeepsNames(stmt, home, &calls) {
				return true
			}
		}
		for _, call := range calls {
			for _, word := range call.Args[1:] {
				prefix, name, suffix, uses := nameWordParts(word)
				if !uses || name != iter.Name.Value {
					continue
				}
				spelled := make([]string, len(values))
				for i, value := range values {
					spelled[i] = prefix + value + suffix
				}
				out[word] = loopIteratorWord{loop: loop, values: spelled}
			}
		}
		return true
	})
	return out
}

// straightLineWords reads the top-level statements in order. An assignment
// statement fixes a name to a plain value (E=~/out, D=$E/sub); a statement
// that keeps names keeps every fixed name, and its call words spelled with
// one (cp a.txt $E/dir/) get the fixed word; any other statement may rebind
// any name, so none stays fixed after it. An IFS assignment ends the
// reading.
func straightLineWords(command string, file *syntax.File, home string) map[*syntax.Word]string {
	if file == nil || !strings.Contains(command, "=") || !strings.Contains(command, "cp") ||
		commandDefinesFunction(file) {
		return nil
	}
	fixed := map[string]string{}
	out := map[*syntax.Word]string{}
	for _, stmt := range file.Stmts {
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) == 0 && len(stmt.Redirs) == 0 &&
			!stmt.Background && !stmt.Coprocess && !stmt.Negated {
			for _, assign := range call.Assigns {
				if assign.Name == nil || assign.Name.Value == "IFS" {
					return out
				}
				name := assign.Name.Value
				value, known := assignmentPlainValue(assign, fixed, home)
				if !known {
					if !assignmentReadsOnly(assign) {
						clear(fixed)
					}
					delete(fixed, name)
					continue
				}
				fixed[name] = value
			}
			continue
		}
		var calls []*syntax.CallExpr
		if !statementKeepsNames(stmt, home, &calls) {
			clear(fixed)
			continue
		}
		for _, call := range calls {
			for _, word := range call.Args[1:] {
				prefix, name, suffix, uses := nameWordParts(word)
				if value, known := fixed[name]; uses && known && (prefix != "" || !strings.HasPrefix(value, "-")) {
					out[word] = prefix + value + suffix
				}
			}
		}
	}
	return out
}

// assignmentPlainValue is the value of a plain assignment, static or a fixed
// name with plain text after it, when it is a plain path.
func assignmentPlainValue(assign *syntax.Assign, fixed map[string]string, home string) (string, bool) {
	if assign.Append || assign.Naked || assign.Array != nil || assign.Index != nil || assign.Value == nil {
		return "", false
	}
	value, static := StaticWord(assign.Value, home)
	if !static {
		prefix, name, suffix, uses := nameWordParts(assign.Value)
		base, known := fixed[name]
		if !uses || !known {
			return "", false
		}
		value = prefix + base + suffix
	}
	return value, plainPathValue(value)
}

// assignmentReadsOnly reports an assignment value whose expansion cannot
// bind another name: plain text, quotes and plain parameter reads.
func assignmentReadsOnly(assign *syntax.Assign) bool {
	plain := assign.Index == nil && assign.Array == nil
	if assign.Value == nil || !plain {
		return plain
	}
	syntax.Walk(assign.Value, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.ArithmExp, *syntax.CmdSubst, *syntax.ProcSubst:
			plain = false
		case *syntax.ParamExp:
			plain = plain && simpleScalarParameter(node)
		}
		return plain
	})
	return plain
}

// nameWordParts splits a word made of optional plain text, one unquoted
// plain name read ($f, ${f}) and optional plain text.
func nameWordParts(word *syntax.Word) (prefix, name, suffix string, ok bool) {
	if word == nil || len(word.Parts) == 0 || len(word.Parts) > 3 {
		return "", "", "", false
	}
	at := -1
	for i, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.ParamExp:
			if at >= 0 || !simpleScalarParameter(part) {
				return "", "", "", false
			}
			at, name = i, part.Param.Value
		case *syntax.Lit:
			if !plainWordText(part.Value) {
				return "", "", "", false
			}
		default:
			return "", "", "", false
		}
	}
	if at < 0 || at > 1 || len(word.Parts) > at+2 {
		return "", "", "", false
	}
	if at == 1 {
		prefix = word.Parts[0].(*syntax.Lit).Value
		if strings.HasPrefix(prefix, "-") {
			return "", "", "", false
		}
	}
	if at+1 < len(word.Parts) {
		suffix = word.Parts[at+1].(*syntax.Lit).Value
	}
	return prefix, name, suffix, true
}

// plainShellName is a plain variable name bash does not set itself.
func plainShellName(name string) bool {
	return simpleScalarParameter(&syntax.ParamExp{Param: &syntax.Lit{Value: name}})
}

// loopPlainValue is a file name of letters, digits and . _ + -, not
// starting with a dash: one word that is no option and no pattern.
func loopPlainValue(value string) bool {
	if value == "" || value == "." || value == ".." || strings.HasPrefix(value, "-") {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b < '0' || b > '9') && (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') && strings.IndexByte("._+-", b) < 0 {
			return false
		}
	}
	return true
}

// plainPathValue is a path of letters, digits and . _ + - / : (no blank
// that splits it, no pattern), not starting with a dash.
func plainPathValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b < '0' || b > '9') && (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') && strings.IndexByte("._+-/:", b) < 0 {
			return false
		}
	}
	return true
}

// plainWordText is unquoted text with no pattern, brace, quote, escape,
// tilde or expansion character.
func plainWordText(text string) bool {
	return text != "" && !strings.ContainsAny(text, "*?[]{}~\\'\"$`!@()=")
}
