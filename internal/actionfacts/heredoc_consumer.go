// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// hereDocConsumer is what the command of a quoted here-document does with
// its body (syntaxTailHereDocConsumer).
type hereDocConsumer uint8

const (
	// hereDocData: every command of the opener line is a program of
	// hereDocDataPrograms, a closed list of programs that never run their
	// standard input as code, named by a bare word or a trusted path after
	// the full launcher unwrap, in a call whose statements bind no PATH (or
	// other resolution variable), define no function, alias, hash or enable
	// entry of that name, and source or eval nothing the reading cannot
	// follow (hereDocCallBindings). The body is its data.
	hereDocData hereDocConsumer = iota
	// hereDocUnknown: any other command. No command text, a text that does
	// not parse, a word made at run time, an interpreter (python3 -, perl,
	// awk, sed), a launcher, shell or program not on the list, an untrusted
	// path of the program or of a wrapper, a name spelled in another case,
	// an assignment that changes which program a word names (PATH=, env
	// PATH=, BASH_ENV=, LD_PRELOAD=), or a name the call may redefine. The
	// unknown tier of the pack (ONE BOUND rule).
	hereDocUnknown
	// hereDocRunsCode: a command runs its standard input as shell code: a
	// shell reading its script from stdin, through any chain of launchers
	// the shared resolution follows, source or . of the standard input, or
	// a privilege wrapper or scheduler that does (posixStdinCodeTarget).
	hereDocRunsCode
)

// hereDocDataPrograms are the programs whose standard input is data and is
// never run as code, whatever their options (except sort's compress program,
// hereDocDataOptions). Interpreters, pagers (less and more run commands and
// input preprocessors), stream editors with a command language (sed, awk),
// and every launcher or shell are not on it (rel-1-0-10:GAP-0902, the 1.0.10
// lead's ruling: data is a closed allowlist; everything else is unknown).
var hereDocDataPrograms = map[string]bool{
	"cat": true, "tac": true, "tee": true, "head": true, "tail": true, "wc": true,
	"sort": true, "uniq": true, "cut": true, "tr": true, "paste": true, "fold": true,
	"nl": true, "rev": true, "column": true, "expand": true, "unexpand": true,
	"grep": true, "egrep": true, "fgrep": true,
	"base64": true, "base32": true, "od": true, "xxd": true, "hexdump": true,
	"md5sum": true, "md5": true, "sha1sum": true, "sha224sum": true, "sha256sum": true,
	"sha384sum": true, "sha512sum": true, "b2sum": true, "shasum": true, "cksum": true, "sum": true,
	"diff": true, "cmp": true,
	// Builtins that never read their standard input as code.
	"read": true, "echo": true, "printf": true, "true": true, "false": true, ":": true,
}

// hereDocExtraShells are POSIX-family shells the shared shell sets
// (posixShellProgram, layoutShells, shellProgram) do not list. Each reads
// its script from the standard input when no script operand is given.
var hereDocExtraShells = map[string]bool{
	"yash": true, "posh": true, "oksh": true, "loksh": true, "lksh": true,
	"pdksh": true, "ksh93": true, "bosh": true,
}

// syntaxTailHereDocConsumer reads the command of a quoted here-document
// (shellparse.SyntaxTailHereDoc.Consumer). Each simple command of the text is
// one that may get the body (cat <<'EOF' | sh pipes it on, cat <<'EOF' > f &&
// sh f runs it); the reading of the line is the strongest of its commands.
// Data is the narrow case: a command that is not positively known to never
// run its input is the unknown tier, never data (rel-1-0-10:GAP-0876,
// GAP-0889, GAP-0902).
func syntaxTailHereDocConsumer(consumer string) hereDocConsumer {
	return hereDocTextConsumer(consumer, nil, 0)
}

// syntaxTailHereDocConsumerIn is syntaxTailHereDocConsumer for the
// here-document doc of a call whose readable statements are statements
// (SyntaxTail.Statements): a data consumer that the statements, or the
// script before it in its own argument (doc.Script), may rename is the
// unknown tier (hereDocCallBindings, rel-1-0-10:GAP-0913). A script the
// reading cannot unquote or parse may bind anything.
func syntaxTailHereDocConsumerIn(doc shellparse.SyntaxTailHereDoc, statements []string) hereDocConsumer {
	bindings := hereDocCallBindings(statements)
	script := strings.TrimRight(doc.Script, " \t\n;&|")
	switch {
	case !doc.ScriptKnown:
		bindings.unresolved = true
	case strings.TrimSpace(script) != "":
		if file, ok := shellparse.Parse(script); ok && file != nil {
			bindings.read(file, 0)
		} else {
			bindings.unresolved = true
		}
	}
	return hereDocTextConsumer(doc.Consumer, bindings, 0)
}

func hereDocTextConsumer(consumer string, bindings *hereDocBindings, depth int) hereDocConsumer {
	if strings.TrimSpace(consumer) == "" || depth > maxControlNesting {
		return hereDocUnknown
	}
	file, ok := shellparse.Parse(consumer)
	if !ok || file == nil {
		return hereDocUnknown
	}
	verdict := hereDocData
	syntax.Walk(file, func(node syntax.Node) bool {
		call, isCall := node.(*syntax.CallExpr)
		if !isCall || len(call.Args) == 0 {
			return verdict != hereDocRunsCode
		}
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		for index, arg := range call.Args {
			words[index], static[index] = simpleStaticWord(arg, nil)
		}
		reading := hereDocArgvConsumer(words, static, bindings, depth)
		if reading == hereDocData {
			for _, assign := range call.Assigns {
				if assign.Name != nil && resolutionVariable(assign.Name.Value) {
					// PATH=/tmp/x cat, BASH_ENV=/tmp/x bash -c cat: another
					// program, or another file's code, may get the body.
					reading = hereDocUnknown
				}
			}
			if bindings.renames(words[0]) {
				reading = hereDocUnknown
			}
		}
		verdict = max(verdict, reading)
		return verdict != hereDocRunsCode
	})
	return verdict
}

// hereDocArgvConsumer reads one simple command (words, with static[i] false
// for a word the shell makes at run time) that gets a here-document body on
// its standard input. Launchers are followed with the shared resolution
// (StaticPrefixWrapperChild, then launcherInner); the program they reach
// decides.
func hereDocArgvConsumer(words []string, static []bool, bindings *hereDocBindings, depth int) hereDocConsumer {
	if depth > maxControlNesting {
		return hereDocUnknown
	}
	if len(words) == 0 || len(static) != len(words) || !static[0] || words[0] == "" {
		return hereDocUnknown
	}
	if allStatic(static) && posixStdinCodeTarget(words) {
		return hereDocRunsCode
	}
	if run, wrapped := StaticPrefixWrapperChild(words, static); wrapped {
		child := hereDocArgvConsumer(words[run.Index:], static[run.Index:], bindings, depth+1)
		if child == hereDocData && (run.ChangesResolution || hereDocUntrustedPathWord(words[:run.Index])) {
			// env PATH=... cat, or /tmp/x/nohup cat: the program that runs
			// may not be the one the words name.
			return hereDocUnknown
		}
		return child
	}
	program, trusted := commandProgram(words[0]), true
	if program == "" {
		// A path outside the trusted directories (./bash, /usr/local/bin/bash)
		// is read by its name for code, and is never data.
		program, trusted = strings.ToLower(path.Base(strings.ReplaceAll(words[0], `\`, "/"))), false
	}
	verdict := hereDocProgramConsumer(program, words, static, bindings, depth)
	if !trusted && verdict == hereDocData {
		return hereDocUnknown
	}
	return verdict
}

// hereDocProgramConsumer reads the program word of one simple command after
// the static prefix wrappers.
func hereDocProgramConsumer(program string, words []string, static []bool, bindings *hereDocBindings, depth int) hereDocConsumer {
	switch {
	case program == "busybox" || program == "toybox":
		// busybox APPLET ..., toybox APPLET ...: the applet is the program.
		return hereDocArgvConsumer(words[1:], static[1:], bindings, depth+1)
	case posixShellProgram(program) || layoutShells[program] || shellProgram(program) || hereDocExtraShells[program]:
		return hereDocShellConsumer(words, static, bindings, depth)
	case program == "source" || program == ".":
		return hereDocSourceConsumer(words, static)
	case program == "eval":
		if !allStatic(static) {
			return hereDocUnknown
		}
		return hereDocTextConsumer(strings.Join(words[1:], " "), bindings, depth+1)
	}
	if inner := launcherInner(words); inner != nil {
		at := len(words) - len(inner)
		return hereDocArgvConsumer(words[at:], static[at:], bindings, depth+1)
	}
	if hereDocDataPrograms[program] && path.Base(strings.ReplaceAll(words[0], `\`, "/")) == program && hereDocDataOptions(program, words) {
		// Named as it is installed: CAT is another file on a case-sensitive
		// disk.
		return hereDocData
	}
	// An interpreter, a launcher, a shell runner, an option layout the
	// reading does not follow, or a program not known to keep its input as
	// data.
	return hereDocUnknown
}

// hereDocDataOptions reports the options of a data program that keep its
// input data: sort --compress-program=PROG pipes the input through PROG (any
// --c... long option, which GNU getopt may expand to it, is not data).
func hereDocDataOptions(program string, words []string) bool {
	if program != "sort" {
		return true
	}
	for _, word := range words[1:] {
		if word == "--" {
			break
		}
		if strings.HasPrefix(word, "--c") {
			return false
		}
	}
	return true
}

// hereDocUntrustedPathWord reports a wrapper chain word with a path outside
// the trusted directories (commandProgram is empty for it): the wrapper
// that runs may not be the one its name says. An env assignment word
// (FOO=/x) names no program; PATH= is ChangesResolution.
func hereDocUntrustedPathWord(words []string) bool {
	for _, word := range words {
		if strings.ContainsAny(word, `/\`) && !strings.HasPrefix(word, "-") &&
			!hereDocAssignmentWord(word) && commandProgram(word) == "" {
			return true
		}
	}
	return false
}

// hereDocAssignmentWord reports an env assignment word NAME=value whose
// NAME is an identifier, so a path word (/tmp/a=b/nohup) is not one.
func hereDocAssignmentWord(word string) bool {
	name, _, cut := strings.Cut(word, "=")
	if !cut || name == "" || name[0] >= '0' && name[0] <= '9' {
		return false
	}
	for _, c := range name {
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// hereDocBindings is what the readable statements of a call bind that can
// change the program a data consumer word runs (hereDocCallBindings,
// rel-1-0-10:GAP-0913).
type hereDocBindings struct {
	// unresolved: a binding the reading cannot follow: a sourced file, eval
	// or trap code that is not static or does not parse, a command word made
	// at run time, enable -f, a name reference (declare -n), a statement that
	// does not parse.
	unresolved bool
	// resolution: a variable that controls command lookup (PATH, zsh path,
	// the startup and loader variables, BASH_CMDS, BASH_ALIASES: see
	// hereDocResolutionName) is written in any form the parser reads: an
	// assignment, a declaration, a for or select name, read, mapfile,
	// printf -v, getopts, unset, let, arithmetic or an expansion that
	// assigns, behind any command or builtin prefix, or a name made at run
	// time (bind).
	resolution bool
	// names are the function, alias, hash and enable names the text defines.
	names map[string]bool
}

// renames reports a consumer word the bindings may make another program.
// A word with a path is not looked up as a function, alias or hash entry,
// but a resolution variable (LD_PRELOAD) or an unresolved binding still
// applies to it.
func (b *hereDocBindings) renames(word string) bool {
	if b == nil {
		return false
	}
	if b.unresolved || b.resolution {
		return true
	}
	return !strings.ContainsAny(word, `/\`) && b.names[word]
}

// hereDocResolutionName reports a name whose value changes the program a
// word runs or the file a shell reads first: PATH and the other resolution
// variables (resolutionVariable: IFS, ENV, BASH_ENV, LD_*, DYLD_*), the zsh
// path array and the function path, the tables bash keeps of the program
// and the alias of a name, the corresponding zsh command, alias and function
// tables, and the zsh startup directory (rel-1-0-10:GAP-0927, GAP-0978).
var hereDocLookupNames = map[string]bool{
	"path": true, "fpath": true, "FPATH": true, "ZDOTDIR": true,
	"BASH_CMDS": true, "BASH_ALIASES": true,
	"commands": true, "aliases": true, "functions": true,
}

func hereDocResolutionName(name string) bool {
	return hereDocLookupNames[name] || resolutionVariable(name)
}

// hereDocCallBindings reads statements with the parser and the shared
// binding reader (callBindsNames, the one that follows USER and LOGNAME):
// never with a pattern on the raw text.
func hereDocCallBindings(statements []string) *hereDocBindings {
	bindings := &hereDocBindings{names: map[string]bool{}}
	for _, statement := range statements {
		file, ok := shellparse.Parse(statement)
		if !ok || file == nil {
			bindings.unresolved = true
			continue
		}
		bindings.read(file, 0)
	}
	return bindings
}

// bind is the one rule of the reading (rel-1-0-10:GAP-0927): a write to a
// variable that controls how a command word is looked up is a binding that
// may rename the consumer, and a write to a name made at run time may be
// that variable. name is the written name as the text spells it (an array
// subscript and a backslash are not part of the name).
func (b *hereDocBindings) bind(name string, static bool) {
	name, _, _ = strings.Cut(strings.ReplaceAll(name, `\`, ""), "[")
	if !static || hereDocResolutionName(name) {
		b.resolution = true
	}
}

// read adds the bindings of node (a parsed statement or eval or trap code):
// every write the parser can see to a variable that controls command
// lookup, every change of the function, alias, hash or enable table, and
// every name reference, which can turn any later write into either.
func (b *hereDocBindings) read(node syntax.Node, depth int) {
	if depth > maxControlNesting {
		b.unresolved = true
		return
	}
	syntax.Walk(node, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.Assign:
			switch {
			case typed.Name != nil && !typed.Naked:
				b.bind(typed.Name.Value, true)
			case typed.Name == nil && typed.Value != nil:
				// A declaration word that is no plain assignment
				// (export PA""TH=x, declare "$N=x"): its name is its static
				// text before =, or any name. An option is no name.
				text, static := simpleStaticWord(typed.Value, nil)
				if static && strings.HasPrefix(text, "-") {
					break
				}
				name, _, _ := strings.Cut(text, "=")
				b.bind(name, static)
			}
		case *syntax.DeclClause:
			// The same builtin option table used by readCall also validates
			// declaration words that the shell parser represents as a clause.
			if typed.Variant != nil {
				words, static := []string{}, []bool{}
				for _, arg := range typed.Args {
					if arg.Name != nil {
						words, static = append(words, arg.Name.Value), append(static, true)
					} else if arg.Value != nil {
						word, known := simpleStaticWord(arg.Value, nil)
						words, static = append(words, word), append(static, known)
					}
				}
				if _, _, _, unknown := hereDocParse(words, static, 0, typed.Variant.Value); unknown {
					b.unresolved = true
				}
			}
			if typed.Variant != nil && typed.Variant.Value == "nameref" {
				b.unresolved = true
			}
			if typed.Variant != nil && hereDocDeclaresLocal(typed.Variant.Value) {
				for _, arg := range typed.Args {
					switch {
					case arg.Name != nil && arg.Naked:
						// local PATH, declare PATH: a new variable of that
						// name, though it has no value.
						b.bind(arg.Name.Value, true)
					case arg.Name == nil && arg.Value != nil:
						// declare -n: a name reference.
						if text, static := simpleStaticWord(arg.Value, nil); static {
							b.namerefOption(text)
						}
					}
				}
			}
		case *syntax.LetClause:
			// let "PATH=5": a quoted expression is a word, not a parsed
			// assignment.
			for _, expr := range typed.Exprs {
				if word, isWord := expr.(*syntax.Word); isWord {
					text, static := simpleStaticWord(word, nil)
					if !static || hereDocMentionsResolutionName(text) {
						b.resolution = true
					}
				}
			}
		case *syntax.WordIter:
			if typed.Name != nil {
				b.bind(typed.Name.Value, true)
			}
		case *syntax.CoprocClause:
			if typed.Name != nil {
				text, static := simpleStaticWord(typed.Name, nil)
				b.bind(text, static)
			}
		case *syntax.BinaryArithm:
			if hereDocArithAssigns(typed.Op.String()) {
				b.bindArith(typed.X)
			}
		case *syntax.UnaryArithm:
			if typed.Op == syntax.Inc || typed.Op == syntax.Dec {
				b.bindArith(typed.X)
			}
		case *syntax.ParamExp:
			if typed.Exp != nil && (typed.Exp.Op == syntax.AssignUnset || typed.Exp.Op == syntax.AssignUnsetOrNull) {
				// ${PATH:=/x}
				if typed.Excl || typed.Param == nil {
					b.resolution = true
				} else {
					b.bind(typed.Param.Value, true)
				}
			}
		case *syntax.FuncDecl:
			if typed.Name != nil {
				b.names[typed.Name.Value] = true
			}
		case *syntax.CallExpr:
			if len(callBindsNames(typed, hereDocResolutionName, []string{"PATH"})) != 0 {
				b.resolution = true
			}
			b.readCall(typed, depth)
		}
		return true
	})
}

// hereDocDeclaresLocal reports a declaration keyword that makes a variable
// of the name it gets without a value.
func hereDocDeclaresLocal(variant string) bool {
	return variant == "declare" || variant == "typeset" || variant == "local"
}

// hereDocArithAssigns reports the operator text of an arithmetic assignment
// (=, +=, <<=, **=), not of a comparison.
func hereDocArithAssigns(op string) bool {
	switch op {
	case "==", "!=", "<=", ">=":
		return false
	}
	return strings.HasSuffix(op, "=")
}

// bindArith binds the target of an arithmetic assignment: a name, or any
// name when the target is not a plain word.
func (b *hereDocBindings) bindArith(target syntax.ArithmExpr) {
	word, isWord := target.(*syntax.Word)
	if !isWord {
		b.resolution = true
		return
	}
	text, static := simpleStaticWord(word, nil)
	b.bind(text, static)
}

// namerefOption marks a declaration option group that makes a name
// reference (declare -n, local -rn): the reference may point at any name, so
// no later write is read (unresolved).
func (b *hereDocBindings) namerefOption(option string) {
	if strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "--") && strings.ContainsRune(option, 'n') {
		b.unresolved = true
	}
}

// hereDocOption is the value of an option that takes one: the text after
// the letter in the same word (-vPATH), or the next word (-v PATH).
type hereDocOption struct {
	letter byte
	text   string
	static bool
}

type hereDocBuiltinOptions struct {
	letters          string
	valued           string
	ambiguous        string
	firstOperandEnds bool
}

// hereDocBuiltinOptionTable and hereDocLookupNames drive the rebind reading.
// These are the union of the bash and zsh builtin spellings; an option with
// dialect-dependent operand boundaries is ambiguous and uses the unknown tier.
var hereDocBuiltinOptionTable = map[string]hereDocBuiltinOptions{
	"read":      {letters: "aAdeniNptursEkclqz", valued: "aAdinNptu", ambiguous: "knpt"},
	"mapfile":   {letters: "dnOstuCc", valued: "dnOsuCc"},
	"readarray": {letters: "dnOstuCc", valued: "dnOsuCc"},
	"hash":      {letters: "dlprtfmvL", valued: "p"},
	"declare":   {letters: "aAfFgiIlnrtuxEHLRUTZmp", valued: "EFLRZip", ambiguous: "EFLRZipT"},
	"typeset":   {letters: "aAfFgiIlnrtuxEHLRUTZmp", valued: "EFLRZip", ambiguous: "EFLRZipT"},
	"local":     {letters: "aAfFgiIlnrtuxEHLRUTZmp", valued: "EFLRZip", ambiguous: "EFLRZipT"},
	"readonly":  {letters: "aAfFgiIlnrtuxEHLRUTZmp", valued: "EFLRZip", ambiguous: "EFLRZipT"},
	"export":    {letters: "fnpT", ambiguous: "T"},
	"printf":    {letters: "v", valued: "v", firstOperandEnds: true},
	"wait":      {letters: "fnp", valued: "p"},
	"getopts":   {},
	"unset":     {letters: "fvnm"},
	"alias":     {letters: "gLmr"},
	"enable":    {letters: "adfnps", valued: "f"},
}

// hereDocParse splits the words of a builtin call from index from into its
// operands (indexes) and the values of the options in its table, the way the
// builtins read them: a word that starts with - is a group of letters up to
// the first that takes a value, the rest of the word is the value, or the
// next word when the letter ends the group; -- ends the options. A word made
// at run time is an operand. An unrecognized, incomplete or ambiguous option
// uses the unknown tier. printf stops at its format operand.
func hereDocParse(words []string, static []bool, from int, builtin string) (operands []int, options []hereDocOption, groups []string, unknown bool) {
	spec, exists := hereDocBuiltinOptionTable[builtin]
	if !exists {
		return nil, nil, nil, true
	}
	flags := true
	for index := from; index < len(words); index++ {
		word := words[index]
		switch {
		case !static[index] || !flags || len(word) < 2 || word[0] != '-' && word[0] != '+':
			operands = append(operands, index)
			if spec.firstOperandEnds {
				return operands, options, groups, unknown
			}
		case word == "--":
			flags = false
		default:
			groups = append(groups, word)
			for at := 1; at < len(word); at++ {
				letter := word[at]
				if !strings.ContainsRune(spec.letters, rune(letter)) || strings.ContainsRune(spec.ambiguous, rune(letter)) {
					unknown = true
				}
				if strings.IndexByte(spec.valued, letter) < 0 {
					continue
				}
				if at+1 < len(word) {
					options = append(options, hereDocOption{letter, word[at+1:], true})
				} else if index+1 < len(words) {
					index++
					options = append(options, hereDocOption{letter, words[index], static[index]})
				} else {
					unknown = true
				}
				break
			}
		}
	}
	return operands, options, groups, unknown
}

// readCall adds what a call changes: a variable that controls command
// lookup (printf -v, read, mapfile, getopts, unset, let, wait -p, a
// declaration), the function, alias, hash and enable tables, the code of
// eval and trap, and every name for a sourced file, enable -f or a command
// word made at run time. The words are read as the shell reads them: past
// the command and builtin prefixes, attached option values included.
func (b *hereDocBindings) readCall(call *syntax.CallExpr, depth int) {
	if len(call.Args) == 0 {
		return
	}
	words := make([]string, len(call.Args))
	static := make([]bool, len(call.Args))
	for index, arg := range call.Args {
		words[index], static[index] = simpleStaticWord(arg, nil)
	}
	at := 0
	for at < len(words) && static[at] && (words[at] == "builtin" || words[at] == "command") {
		at++
		for at < len(words) && static[at] && strings.HasPrefix(words[at], "-") {
			at++
		}
	}
	if at >= len(words) {
		return
	}
	if !static[at] {
		// $CMD NAME=...: the word may be alias, eval or source.
		b.unresolved = true
		return
	}
	// target binds every name of operands, or any name for one made at run
	// time.
	target := func(operands []int) {
		for _, index := range operands {
			b.bind(words[index], static[index])
		}
	}
	// unresolvedOperands marks a table change whose operand is made at run
	// time.
	unresolvedOperands := func(operands []int) {
		for _, index := range operands {
			if !static[index] {
				b.unresolved = true
			}
		}
	}
	switch words[at] {
	case "printf":
		// printf -v NAME FORMAT ARGS: only the options before the format.
		_, options, _, unknown := hereDocParse(words, static, at+1, "printf")
		b.unresolved = b.unresolved || unknown
		for _, option := range options {
			if option.letter == 'v' {
				b.bind(option.text, option.static)
			}
		}
	case "read", "mapfile", "readarray":
		operands, options, _, unknown := hereDocParse(words, static, at+1, words[at])
		b.unresolved = b.unresolved || unknown
		target(operands)
		for _, option := range options {
			if (option.letter == 'a' || option.letter == 'A') && words[at] == "read" {
				// read -a/-A NAME fills the array NAME.
				b.bind(option.text, option.static)
			} else if option.letter == 'C' {
				// The callback may run code before the consumer.
				b.unresolved = true
			}
		}
	case "wait":
		_, options, _, unknown := hereDocParse(words, static, at+1, "wait")
		b.unresolved = b.unresolved || unknown
		for _, option := range options {
			if option.letter == 'p' {
				b.bind(option.text, option.static)
			}
		}
	case "getopts":
		// getopts OPTSTRING NAME: the second operand is the variable.
		operands, _, _, unknown := hereDocParse(words, static, at+1, "getopts")
		b.unresolved = b.unresolved || unknown
		if len(operands) > 1 {
			target(operands[1:2])
		}
	case "unset":
		operands, _, _, unknown := hereDocParse(words, static, at+1, "unset")
		b.unresolved = b.unresolved || unknown
		target(operands)
	case "let":
		// Every word is an arithmetic expression that may assign.
		for index := at + 1; index < len(words); index++ {
			if !static[index] || hereDocMentionsResolutionName(words[index]) {
				b.resolution = true
			}
		}
	case "export", "declare", "typeset", "local", "readonly":
		// A declaration the parser reads as a plain call (export PA\TH=x):
		// each NAME=value word, after the shell removes its backslashes, or
		// any name for a word made at run time.
		operands, _, groups, unknown := hereDocParse(words, static, at+1, words[at])
		b.unresolved = b.unresolved || unknown
		if hereDocDeclaresLocal(words[at]) {
			for _, group := range groups {
				b.namerefOption(group)
			}
		}
		for _, index := range operands {
			name, _, assigned := strings.Cut(words[index], "=")
			if static[index] && !assigned && !hereDocDeclaresLocal(words[at]) {
				// export PATH, readonly PATH: no new value.
				continue
			}
			b.bind(name, static[index])
		}
	case "alias":
		operands, _, _, unknown := hereDocParse(words, static, at+1, "alias")
		b.unresolved = b.unresolved || unknown
		unresolvedOperands(operands)
		for _, index := range operands {
			if name, _, cut := strings.Cut(words[index], "="); cut && static[index] {
				b.names[name] = true
			}
		}
	case "hash":
		// hash -p FILE NAME makes NAME run FILE; hash NAME only looks NAME
		// up on PATH.
		operands, _, groups, unknown := hereDocParse(words, static, at+1, "hash")
		b.unresolved = b.unresolved || unknown
		unresolvedOperands(operands)
		path, directory := false, false
		for _, group := range groups {
			path = path || strings.ContainsRune(group, 'p')
			directory = directory || strings.ContainsRune(group, 'd')
		}
		if directory {
			// Bash forgets a command entry; zsh writes its named-directory
			// table. Either can change a later lookup.
			b.unresolved = true
		}
		for _, index := range operands {
			if !static[index] {
				continue
			}
			if name, _, assigned := strings.Cut(words[index], "="); assigned {
				if !directory {
					b.names[name] = true
				}
			} else if path {
				b.names[words[index]] = true
			}
		}
	case "enable":
		operands, _, groups, unknown := hereDocParse(words, static, at+1, "enable")
		b.unresolved = b.unresolved || unknown
		unresolvedOperands(operands)
		for _, group := range groups {
			if strings.ContainsRune(group, 'f') {
				b.unresolved = true
			}
		}
		for _, index := range operands {
			if static[index] {
				b.names[words[index]] = true
			}
		}
	case ".", "source":
		b.unresolved = true
	case "eval", "trap":
		code := words[at+1:]
		if words[at] == "trap" {
			code = code[:min(len(code), 1)]
		}
		if !allStatic(static[at+1:]) {
			b.unresolved = true
			return
		}
		file, ok := shellparse.Parse(strings.Join(code, " "))
		if !ok || file == nil {
			b.unresolved = true
			return
		}
		b.read(file, depth+1)
	}
}

// hereDocMentionsResolutionName reports an arithmetic word (an argument of
// let) that spells a name of hereDocResolutionName.
func hereDocMentionsResolutionName(word string) bool {
	return slices.ContainsFunc(strings.FieldsFunc(word, func(c rune) bool {
		return c != '_' && (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z')
	}), hereDocResolutionName)
}

// hereDocShellConsumer reads a shell's arguments as the shell does: options
// up to the first operand or --; -c (alone or in a group, -ec) makes the
// first operand the script, whose commands get the body; -s, or no operand,
// reads the script from the standard input (the body); any other operand is
// a script file whose reading of the body is not known.
func hereDocShellConsumer(words []string, static []bool, bindings *hereDocBindings, depth int) hereDocConsumer {
	script, stdin, operand := false, false, -1
options:
	for index := 1; index < len(words); index++ {
		if !static[index] {
			return hereDocUnknown
		}
		word := words[index]
		switch {
		case word == "--" || word == "-":
			if index+1 < len(words) {
				operand = index + 1
			}
			break options
		case word == "-o" || word == "+o" || word == "--rcfile" || word == "--init-file":
			index++
		case strings.HasPrefix(word, "--"):
		case len(word) > 1 && (word[0] == '-' || word[0] == '+'):
			if word[0] == '-' {
				script = script || strings.ContainsRune(word[1:], 'c')
				stdin = stdin || strings.ContainsRune(word[1:], 's')
			}
		default:
			operand = index
			break options
		}
	}
	switch {
	case script:
		if operand < 0 || !static[operand] {
			return hereDocUnknown
		}
		return hereDocTextConsumer(words[operand], bindings, depth+1)
	case stdin || operand < 0:
		return hereDocRunsCode
	default:
		return hereDocUnknown
	}
}

// hereDocSourceConsumer reads source FILE and . FILE: the standard input as
// the file runs the body in the shell; another file is not known.
func hereDocSourceConsumer(words []string, static []bool) hereDocConsumer {
	at := 1
	if at < len(words) && words[at] == "--" {
		at++
	}
	if at >= len(words) || !static[at] {
		return hereDocUnknown
	}
	if posixStdinFilePath(words[at]) {
		return hereDocRunsCode
	}
	return hereDocUnknown
}

// posixStdinFilePath reports a file name that is the standard input of the
// process that opens it.
func posixStdinFilePath(name string) bool {
	switch path.Clean(name) {
	case "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0":
		return true
	}
	return false
}

func allStatic(static []bool) bool {
	for _, known := range static {
		if !known {
			return false
		}
	}
	return true
}
