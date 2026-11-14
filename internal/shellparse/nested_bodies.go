// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// MaxNestedBodyBytes bounds the nested shell-body text one hook call may
// make the readers re-read. A static argument or here-document of a call
// can be a shell program in its own right (bash -c, sh -c, eval, env, ssh,
// xargs, a shell fed a here-document), and the hook-path and gateway
// readers parse such a body again at every level they descend, so their
// work grows with the size of a body times its depth. A call of twelve
// nested bash -c bodies (0.8 MB) took 3 to 8.5 s to decide, past the hook
// answer window (GAP-0677). A body at depth k counts len(body) * (k-2)^2
// bytes, because each further level is read again by more readers: the
// bodies of the call itself (depth 1) and theirs (depth 2) count nothing,
// so a bash -c script of any size, and the -c programs it runs, stay under
// the bound, and so does a third-level body of up to 16 KiB. Nine nested
// bash -c bodies of a short command (30 KB, read in about 1 s on a loaded
// build host) stay under it; ten (89 KB, about 2.4 s) and more do not. A
// call past the bound is not read; the gateway grades it by its text
// (readingBoundProtectedFindings in the gateway).
const MaxNestedBodyBytes = 16 << 10

// MaxNestedBodyProofBytes is the nested-body weight (NestedBodyWeight) past
// which the readers no longer prove a protected target of the call: nine
// nested bash -c bodies of a protected write (9 KiB) were read in full and
// allowed. Past it the gateway keeps the over-limit block for a call whose
// text may name a protected target, and reads any other in full.
const MaxNestedBodyProofBytes = 8 << 10

// nestedBodyMinCommand is the command size below which the nested-body
// measure is skipped: a command this short cannot hold enough nested text
// to cost a reader more than an ordinary parse.
const nestedBodyMinCommand = 4 << 10

// nestedBodyMaxDepth stops the measure descending, so it recurses a bounded
// number of times whatever the command.
const nestedBodyMaxDepth = 64

// PastReadingBounds reports whether command is past the reading bounds of
// the hook-path and gateway readers: it nests or expands too far (TooDeep),
// or its nested shell bodies would make the readers re-read more than
// MaxNestedBodyBytes (NestedBodiesOverBudget). Callers take their
// over-limit path and hand the command to no reader.
func PastReadingBounds(command string) bool {
	return TooDeep(command) || NestedBodiesOverBudget(command)
}

// NestedBodiesOverBudget reports whether the nested shell bodies of command
// weigh more than MaxNestedBodyBytes (see there). Each body is parsed once
// and the measure stops as soon as the bound is passed, so it costs about
// two parses of the command. Every static word of a call that could be a
// program (it has a blank or a shell operator) and every static
// here-document is a candidate body, whatever the program: the readers
// descend into more programs than one list would name. A body that does
// not parse is counted but not descended.
func NestedBodiesOverBudget(command string) bool {
	return NestedBodyWeight(command) > MaxNestedBodyBytes
}

// NestedBodyWeight is the weight of the nested shell bodies of command, as
// MaxNestedBodyBytes defines it. The measure stops once the weight passes
// MaxNestedBodyBytes, so the result is exact up to that bound.
func NestedBodyWeight(command string) int {
	if len(command) < nestedBodyMinCommand {
		return 0
	}
	work := 0
	var visit func(text string, depth int, code bool) bool
	visit = func(text string, depth int, code bool) bool {
		if depth >= 3 {
			work += len(text) * (depth - 2) * (depth - 2)
			if work > MaxNestedBodyBytes {
				return true
			}
		}
		if depth >= nestedBodyMaxDepth {
			return false
		}
		// A body is a command the readers parse: it is under the reading
		// budget like the call that carries it, and the measure does not
		// parse a body past it. The first stage reads a single-quoted body as
		// data (its brackets are not nesting, its words are no tokens), so
		// the body is the one place the budget sees what it holds. A body a
		// shell is given (bash -c, eval) that is past the budget, nesting
		// included, is past the nested bound; any other candidate (an
		// argument of echo, a here-document: text a program reads) is not
		// parsed and not counted.
		if depth > 0 && (nestingBound(text) != "" || BudgetExceeded(text) != "") {
			if code {
				work = MaxNestedBodyBytes + 1
				return true
			}
			return false
		}
		if nestingBound(text) != "" {
			return false
		}
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
		if err != nil || file == nil {
			return false
		}
		// A body is strictly shorter than the text that holds it (it is a
		// quoted or escaped part of it): a body as long as its text is the
		// text again ($ names itself), which the measure would count at
		// every level down to the depth bound, and a call carrying a 4 KiB
		// comment weighed 17 KiB for it (GAP-0381).
		over := false
		fed := map[*syntax.Redirect]bool{}
		syntax.Walk(file, func(node syntax.Node) bool {
			if over {
				return false
			}
			switch node := node.(type) {
			case *syntax.CallExpr:
				for _, arg := range node.Args {
					if body, ok := staticBodyWord(arg); ok && len(body) < len(text) && visit(body, depth+1, shellBodyProgram(node)) {
						over = true
						return false
					}
				}
			case *syntax.Stmt:
				// A here-document fed to a shell is code: bash <<EOF.
				if call, isCall := node.Cmd.(*syntax.CallExpr); isCall && shellBodyProgram(call) {
					for _, redirect := range node.Redirs {
						fed[redirect] = true
					}
				}
			case *syntax.Redirect:
				if body, ok := staticBodyWord(node.Hdoc); ok && len(body) < len(text) && visit(body, depth+1, fed[node]) {
					over = true
					return false
				}
			}
			return true
		})
		return over
	}
	visit(command, 0, false)
	return work
}

// shellBodyProgram reports that call hands its arguments to a shell as code:
// the program is a shell, or eval, directly or behind a wrapper that runs
// the next command (sudo, env, nohup, ...), as the readers unwrap it.
func shellBodyProgram(call *syntax.CallExpr) bool {
	wrapper := ""
	for i := 0; i < len(call.Args); i++ {
		name := bodyWordName(call.Args[i])
		if wrapper != "" && (strings.HasPrefix(name, "-") || strings.Contains(name, "=")) {
			// An option or an assignment of the wrapper; skip the value an
			// option takes as a separate word.
			if bodyWrapperValueOption[wrapper+" "+name] {
				i++
			}
			continue
		}
		switch name {
		case "bash", "sh", "zsh", "dash", "ksh", "ash", "eval":
			return true
		case "sudo", "doas", "env", "nohup", "nice", "ionice", "time", "command", "exec", "setsid", "stdbuf", "timeout", "chroot", "unbuffer":
			wrapper = name
			if name == "timeout" {
				i++ // the duration
			}
			continue
		}
		return false
	}
	return false
}

// bodyWordName is the program name of word: its static value without the
// directory.
func bodyWordName(word *syntax.Word) string {
	name, ok := staticBodyWord(word)
	if !ok {
		name = word.Lit()
	}
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// bodyWrapperValueOption lists the options of the wrappers that take a
// separate value word (sudo -u user, env -u NAME, nice -n 5).
var bodyWrapperValueOption = map[string]bool{
	"sudo -u": true, "sudo -g": true, "sudo -h": true, "sudo -p": true, "sudo -C": true, "sudo -D": true, "sudo -r": true, "sudo -t": true, "sudo -U": true,
	"doas -u": true, "doas -C": true,
	"env -u": true, "env -C": true, "env -S": true,
	"nice -n": true, "ionice -c": true, "ionice -n": true,
	"stdbuf -i": true, "stdbuf -o": true, "stdbuf -e": true,
	"timeout -s": true, "timeout -k": true,
}

// staticBodyWord is the shell value of a word made only of literal and
// quoted literal parts, when that value could be a program: it has a blank
// or a shell operator.
func staticBodyWord(word *syntax.Word) (string, bool) {
	if word == nil {
		return "", false
	}
	var value strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			value.WriteString(unescapeLiteral(part.Value, false))
		case *syntax.SglQuoted:
			if part.Dollar {
				return "", false
			}
			value.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, inner := range part.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				value.WriteString(unescapeLiteral(lit.Value, true))
			}
		default:
			return "", false
		}
	}
	body := value.String()
	return body, strings.ContainsAny(body, " \t\n;|&<>()`$")
}

// unescapeLiteral removes the backslashes the shell removes from a literal:
// before any byte outside quotes, and before $, `, ", \ and newline inside
// double quotes (an escaped newline is removed with its backslash).
func unescapeLiteral(value string, doubleQuoted bool) string {
	if !strings.Contains(value, `\`) {
		return value
	}
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			next := value[i+1]
			if !doubleQuoted || strings.IndexByte("$`\"\\\n", next) >= 0 {
				i++
				if next != '\n' {
					out.WriteByte(next)
				}
				continue
			}
		}
		out.WriteByte(value[i])
	}
	return out.String()
}
