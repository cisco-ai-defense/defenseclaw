// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// knownWordPrograms cannot set a variable of the calling shell: external
// programs and builtins without a binding form. In strict, a command that
// runs any other program (read, wait -p, printf -v, eval, source, trap,
// command, builtin, exec, env, a function or a dynamic program word) has no
// known parameter words: a wrapper or a deferred string can rebind the name
// (rel-1-0-2:GAP-0004 review). The list is an allowlist on purpose. test and
// [ are left out: test -v "a[f=-3]" evaluates the subscript, which assigns
// (rel-1-0-6:GAP-0235 review). Static cd and pushd have a separate check.
var knownWordPrograms = []string{
	":", "awk", "cat", "chmod", "cmp", "cp", "diff", "echo", "false", "find", "gcp", "git", "go",
	"grep", "head", "ln", "ls", "make", "mkdir", "mv", "rm", "rmdir", "sed", "sort", "tail", "tar",
	"touch", "true", "uniq", "wc",
}

// mayHaveKnownCopyWord is the cheap gate of knownWordParameterUses: the
// command names a copy program and has a parameter expansion.
func mayHaveKnownCopyWord(command string) bool {
	return strings.IndexByte(command, '$') >= 0 && strings.Contains(command, "cp")
}

// literalProgramWord reads a program word spelled as one plain literal
// without the expansion StaticWord does; others take the slow path.
func literalProgramWord(word *syntax.Word, home string) (string, bool) {
	if word != nil && len(word.Parts) == 1 {
		if lit, ok := word.Parts[0].(*syntax.Lit); ok && !strings.ContainsAny(lit.Value, "\\~*?[$") {
			return lit.Value, true
		}
	}
	return StaticWord(word, home)
}

// knownWordParameterUses returns the unquoted copy-operand parameter words of
// file ($f, ${f}) that the shell expands to exactly one fixed word which is
// not an option: f is bound only by plain assignments and for loops whose
// values are fixed plain names (no blank, pattern or quoting character, no
// leading dash), the use sits in the body of such a loop or after a
// top-level assignment that always runs, and every program the command runs
// is in knownWordPrograms. Such a word reads as a quoted single parameter
// ("$f"), so for f in a.txt b.txt; do cp $f build/; done and
// f=a.txt; cp $f out.txt read as their quoted spellings do
// (rel-1-0-2:GAP-0004). Any other binding (an arithmetic, a default
// expansion, a function, an IFS change) or program leaves every word
// unknown. command is the text file was parsed from; most commands leave at
// its cheap gate.
func knownWordParameterUses(command string, file *syntax.File, home string) map[*syntax.Word]bool {
	uses, _ := knownWordParameters(command, file, home, nil, nil, false)
	return uses
}

// knownWordParameterUsesAt is knownWordParameterUses for a command read in
// cwd: an assignment right after a leading directory change (cd DIR &&
// f=a.txt; cp $f out.txt) runs when DIR is enterable (cdEnterable), so it
// binds f for what follows as a top-level assignment does. The same holds
// within a sole subshell (rel-1-0-6:GAP-0320, GAP-0362).
func knownWordParameterUsesAt(command string, file *syntax.File, home string, cdOK func(string) bool, placed map[*syntax.CallExpr][]string) map[*syntax.Word]bool {
	uses, _ := knownWordParameters(command, file, home, cdOK, placed, false)
	return uses
}

// cdEnterable reports a cd operand word naming, from cwd, a directory that
// exists and that this account may enter (directoryEnterable): from the
// hook client's CdEnterableFactPrefix fact when the caller has evidence (a
// managed gateway cannot search the home), else from this process's own
// view of the disk, which the client records as that fact. A word that starts with "-" or holds a
// dot-dot component, and a missing or unreadable directory are not. A
// bare relative word that exists from cwd is entered whatever CDPATH
// holds: bash falls back to it when no CDPATH entry matches.
func cdEnterable(cwd string, facts map[string]string, record bool) func(string) bool {
	return func(word string) bool {
		if word == "" || strings.HasPrefix(word, "-") || !filepath.IsAbs(cwd) {
			return false
		}
		for _, part := range strings.Split(filepath.ToSlash(word), "/") {
			if part == ".." {
				return false
			}
		}
		path := OperandPath(word, cwd)
		key := CdEnterableFactPrefix + path
		if !record && facts != nil {
			// The client's own check of the same directory. The
			// DirectoryFactPrefix value is the physical name of a logical
			// directory and is written for a missing one too, so it does
			// not prove the cd succeeds (rel-1-0-6:GAP-0320 review 5).
			// Where this process can walk the path itself it also checks
			// it, as the opaque-scope fact stands in only for an
			// incomplete walk: a forged fact cannot make a missing
			// directory enterable (review 6). Both must hold, since a
			// managed service may enter what the user cannot.
			if _, complete := writePathForms(path, 0); complete && !directoryEnterable(path) {
				return false
			}
			return facts[key] == "1"
		}
		enterable := directoryEnterable(path)
		if record && facts != nil && enterable {
			facts[key] = "1"
		}
		return enterable
	}
}

// knownWordParameterValues returns, for the uses knownWordParameterUses
// accepts, the one value every binding of the name gives (f=out.txt, or a
// for loop over that single name). A copy operand spelled with such a word
// is that fixed file, so f=out.txt; cp a.txt $f reads as cp a.txt out.txt
// on the hook client and the gateway alike (rel-1-0-6:GAP-0235). A name
// bound to more than one value has none.
func knownWordParameterValues(command string, file *syntax.File, home string) map[*syntax.Word]string {
	_, values := knownWordParameters(command, file, home, nil, nil, false)
	return values
}

func knownWordParameters(command string, file *syntax.File, home string, cdOK func(string) bool, placed map[*syntax.CallExpr][]string, balanced bool) (map[*syntax.Word]bool, map[*syntax.Word]string) {
	if file == nil || !mayHaveKnownCopyWord(command) {
		return nil, nil
	}
	safeValue := func(value string) bool {
		return value != "" && !strings.HasPrefix(value, "-") &&
			!strings.ContainsAny(value, "\r\n*?[]{}$`\\\"'()|&;<>!~#=,\x00")
	}
	safePlain := func(value string) bool {
		return safeValue(value) && !strings.ContainsAny(value, " \t")
	}
	type loop struct {
		from, to uint
	}
	unsafeNames := map[string]bool{}
	// bound: the distinct values the bindings of each name give.
	bound := map[string]map[string]bool{}
	bind := func(name, value string) {
		if bound[name] == nil {
			bound[name] = map[string]bool{}
		}
		bound[name][value] = true
	}
	loops := map[string][]loop{}
	after := map[string]uint{}
	afterDirectory := map[string]bool{}
	rejected := false
	statements := file.Stmts
	// A declared function whose body cannot rebind a name is evaluated at
	// its direct call, not at the earlier declaration. This supplies a
	// known value for a copy in the body without treating an unknown call
	// as a proof.
	balancedFunctions := map[string]*syntax.FuncDecl{}
	functionUseAt := map[*syntax.Word]uint{}
	if balanced {
		for _, stmt := range file.Stmts {
			if fn, ok := stmt.Cmd.(*syntax.FuncDecl); ok && fn.Name != nil &&
				!slices.Contains(knownWordPrograms, fn.Name.Value) && balancedFunctionBody(fn, home) {
				balancedFunctions[fn.Name.Value] = fn
			}
		}
		for name, fn := range balancedFunctions {
			var callAt uint
			syntax.Walk(file, func(node syntax.Node) bool {
				if call, ok := node.(*syntax.CallExpr); ok && call.Pos().Offset() > fn.End().Offset() && len(call.Args) == 1 {
					if program, fixed := literalProgramWord(call.Args[0], home); fixed && program == name &&
						(callAt == 0 || call.Pos().Offset() < callAt) {
						callAt = call.Pos().Offset()
					}
				}
				return true
			})
			if callAt != 0 {
				syntax.Walk(fn.Body, func(node syntax.Node) bool {
					if word, ok := node.(*syntax.Word); ok {
						functionUseAt[word] = callAt
					}
					return true
				})
			}
		}
	}
	subshellScope := false
	if cdOK != nil && len(statements) == 1 && len(statements[0].Redirs) == 0 &&
		!statements[0].Background && !statements[0].Negated && !statements[0].Coprocess {
		if subshell, ok := statements[0].Cmd.(*syntax.Subshell); ok && len(subshell.Stmts) > 0 {
			if pair, ok := subshell.Stmts[0].Cmd.(*syntax.BinaryCmd); ok && pair.Op == syntax.AndStmt {
				if _, valid := leadingDirectoryOperand(pair.X, home); valid {
					// This binding stays in the sole subshell; it never
					// applies to a later outer statement.
					statements = subshell.Stmts
					subshellScope = true
				}
			}
		}
	}
	var leadingPushd *syntax.CallExpr
	if len(statements) > 0 {
		if pair, ok := statements[0].Cmd.(*syntax.BinaryCmd); ok && pair.Op == syntax.AndStmt {
			if call, ok := pair.X.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 {
				program, _ := StaticWord(call.Args[0], home)
				if _, valid := leadingDirectoryOperand(pair.X, home); valid && program == "pushd" {
					leadingPushd = call
				}
			}
		}
	}
	// A loop list may be the one plain word assigned immediately before
	// the top-level loop. The shell expands that list before assigning its
	// iterator; the adjacent binding cannot be changed in between.
	priorLoopWord := func(loop *syntax.ForClause, item *syntax.Word) (string, bool) {
		if item == nil || len(item.Parts) != 1 {
			return "", false
		}
		param, ok := item.Parts[0].(*syntax.ParamExp)
		if !ok || !simpleScalarParameter(param) {
			return "", false
		}
		for i, top := range statements {
			if top.Cmd != loop || i == 0 || top.Background || top.Negated || len(top.Redirs) != 0 {
				continue
			}
			previous := statements[i-1]
			if pair, ok := previous.Cmd.(*syntax.BinaryCmd); ok {
				if i != 1 || pair.Op != syntax.AndStmt || cdOK == nil {
					return "", false
				}
				dir, known := leadingDirectoryOperand(pair.X, home)
				if !known || !cdOK(dir) {
					return "", false
				}
				previous = pair.Y
			}
			if previous.Background || previous.Negated || len(previous.Redirs) != 0 {
				return "", false
			}
			call, ok := previous.Cmd.(*syntax.CallExpr)
			if !ok || len(call.Args) != 0 || len(call.Assigns) != 1 {
				return "", false
			}
			assign := call.Assigns[0]
			if assign.Name == nil || assign.Name.Value != param.Param.Value || assign.Value == nil ||
				assign.Append || assign.Array != nil || assign.Index != nil {
				return "", false
			}
			value, fixed := StaticWord(assign.Value, home)
			return value, fixed && safeValue(value)
		}
		return "", false
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if rejected {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl:
			if !balanced || node.Name == nil || balancedFunctions[node.Name.Value] != node {
				rejected = true
			}
		case *syntax.DeclClause:
			if !balanced {
				rejected = true
				break
			}
			names, ok := declarationDestinations(node)
			if !ok {
				rejected = true
				break
			}
			for _, name := range names {
				unsafeNames[name] = true
			}
		case *syntax.ArithmCmd, *syntax.ArithmExp, *syntax.LetClause, *syntax.TestClause,
			*syntax.CoprocClause, *syntax.ProcSubst:
			rejected = true
		case *syntax.Assign:
			// An index is arithmetic, which can assign (a[f=-3]=x).
			if node.Index != nil || node.Array != nil {
				rejected = true
				break
			}
			if node.Name == nil {
				rejected = true
				break
			}
			name := node.Name.Value
			if name == "IFS" {
				// Field splitting of every unquoted word changes.
				rejected = true
				break
			}
			value, fixed := "", false
			if node.Value != nil {
				value, fixed = StaticWord(node.Value, home)
			}
			if node.Append || node.Naked || node.Array != nil || node.Index != nil || !fixed || !safeValue(value) {
				unsafeNames[name] = true
			}
			bind(name, value)
		case *syntax.ForClause:
			iter, ok := node.Loop.(*syntax.WordIter)
			if !ok || iter.Name == nil || node.Select {
				rejected = true
				break
			}
			name := iter.Name.Value
			if name == "IFS" {
				rejected = true
				break
			}
			if !iter.InPos.IsValid() || len(iter.Items) == 0 {
				unsafeNames[name] = true
				break
			}
			for _, item := range iter.Items {
				value, fixed := StaticWord(item, home)
				if !fixed {
					value, fixed = priorLoopWord(node, item)
				}
				if !fixed || !safeValue(value) {
					unsafeNames[name] = true
				}
				bind(name, value)
			}
			loops[name] = append(loops[name], loop{node.DoPos.Offset(), node.DonePos.Offset()})
		case *syntax.ParamExp:
			// An index or a slice offset is arithmetic, which can assign
			// (${a[f=-3]}, ${x:f=1}) (rel-1-0-6:GAP-0235 review).
			if node.Index != nil || node.Slice != nil {
				rejected = true
				break
			}
			if node.Param != nil && node.Exp != nil {
				unsafeNames[node.Param.Value] = true
			}
		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				break
			}
			program, static := literalProgramWord(node.Args[0], home)
			if static && programBase(program) == "env" {
				words, fixed := make([]string, len(node.Args)), make([]bool, len(node.Args))
				for i, arg := range node.Args {
					words[i], fixed[i] = StaticWord(arg, home)
				}
				if run, ok := actionfacts.StaticPrefixWrapperChild(words, fixed); ok &&
					run.Index < len(words) && fixed[run.Index] && !run.DirUnknown && !run.ChangesResolution &&
					slices.Contains(knownWordPrograms, programBase(words[run.Index])) {
					// The shell expands the parameter before this fixed wrapper
					// runs its child; the child cannot rebind the shell value.
					break
				}
			}
			if static && program == "cd" && staticDirectoryCall(node, home) || node == leadingPushd {
				// A fixed directory change does not rebind an accepted
				// parameter word (rel-1-0-6:GAP-0320, GAP-0362).
				break
			}
			if balanced && static {
				if names, ok := shellBinderDestinations(node, home); ok {
					for _, name := range names {
						unsafeNames[name] = true
					}
					break
				}
			}
			if balanced && static && len(node.Args) == 1 && balancedFunctions[program] != nil {
				break
			}
			if !static || !slices.Contains(knownWordPrograms, programBase(program)) {
				rejected = true
			}
		}
		return !rejected
	})
	if rejected {
		return nil, nil
	}
	// A top-level assignment statement, or the first statement of a
	// top-level AND list, always runs before what follows it. So does the
	// statement right after the leading directory change of the first AND
	// list, when that directory is enterable (cdOK).
	var first func(*syntax.Stmt, bool) (*syntax.Stmt, bool)
	first = func(stmt *syntax.Stmt, leading bool) (*syntax.Stmt, bool) {
		if stmt == nil || stmt.Background || stmt.Negated || stmt.Coprocess {
			return nil, false
		}
		if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && pair.Op == syntax.AndStmt {
			if leading && cdOK != nil {
				if dir, ok := leadingDirectoryOperand(pair.X, home); ok && cdOK(dir) {
					selected, _ := first(pair.Y, false)
					// Plain cd keeps its earlier binding: the client places
					// nested copy destinations in the enclosing statement's
					// directory (rel-1-0-6:GAP-0415).
					call, _ := pair.X.Cmd.(*syntax.CallExpr)
					program, _ := StaticWord(call.Args[0], home)
					return selected, subshellScope || program != "cd" || len(call.Args) != 2
				}
			}
			return first(pair.X, false)
		}
		return stmt, false
	}
	for i, top := range statements {
		stmt, fromDirectory := first(top, i == 0)
		if stmt == nil || len(stmt.Redirs) != 0 {
			continue
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) != 0 {
			continue
		}
		for _, assign := range call.Assigns {
			if assign.Name != nil {
				if _, seen := after[assign.Name.Value]; !seen {
					after[assign.Name.Value] = stmt.End().Offset()
					afterDirectory[assign.Name.Value] = fromDirectory
				}
			}
		}
	}
	// Within one AND chain, reaching a later call proves that the plain
	// assignment in an earlier leg ran. This includes a chain beginning
	// with a static directory change. The value is scoped to that chain:
	// a statement after it may run even if the directory change failed.
	chainAfter := map[string]uint{}
	chainEnd := map[string]uint{}
	if balanced {
		validChain := true
		var leaves func(*syntax.Stmt) []*syntax.Stmt
		leaves = func(stmt *syntax.Stmt) []*syntax.Stmt {
			if stmt == nil || stmt.Background || stmt.Negated || stmt.Coprocess {
				validChain = false
				return nil
			}
			if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && pair.Op == syntax.AndStmt {
				return append(leaves(pair.X), leaves(pair.Y)...)
			}
			return []*syntax.Stmt{stmt}
		}
		for _, top := range statements {
			validChain = true
			chain := leaves(top)
			if !validChain || len(chain) < 2 {
				continue
			}
			if dir, ok := leadingDirectoryOperand(chain[0], home); ok && (cdOK == nil || !cdOK(dir)) {
				continue
			}
			for _, stmt := range chain[:len(chain)-1] {
				if len(stmt.Redirs) != 0 {
					continue
				}
				call, ok := stmt.Cmd.(*syntax.CallExpr)
				if !ok || len(call.Args) != 0 {
					continue
				}
				for _, assign := range call.Assigns {
					if assign.Name != nil && chainAfter[assign.Name.Value] == 0 {
						chainAfter[assign.Name.Value] = stmt.End().Offset()
						chainEnd[assign.Name.Value] = top.End().Offset()
					}
				}
			}
		}
	}
	uses := map[*syntax.Word]bool{}
	values := map[*syntax.Word]string{}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		for _, word := range call.Args[1:] {
			// $D/rest or $NAME.tgz: one known value and a plain literal
			// tail is a fixed path. It gets a value only, not the
			// one-word source reading (rel-1-0-6:GAP-0329, GAP-0395).
			suffix := ""
			if len(word.Parts) == 2 {
				lit, isLit := word.Parts[1].(*syntax.Lit)
				if !isLit || (!strings.HasPrefix(lit.Value, "/") && !strings.HasPrefix(lit.Value, ".")) ||
					!safePlain(strings.ReplaceAll(lit.Value, "/", "x")) {
					continue
				}
				suffix = lit.Value
			} else if len(word.Parts) != 1 {
				continue
			}
			param, ok := word.Parts[0].(*syntax.ParamExp)
			quoted := false
			if double, isQuoted := word.Parts[0].(*syntax.DblQuoted); isQuoted && len(double.Parts) == 1 {
				// "$f" with a known plain value is the same one word; it
				// only gets a value, the source rule already reads it.
				param, ok = double.Parts[0].(*syntax.ParamExp)
				quoted = true
			}
			if !ok || !simpleScalarParameter(param) || unsafeNames[param.Param.Value] {
				continue
			}
			name, at := param.Param.Value, word.Pos().Offset()
			if calledAt := functionUseAt[word]; calledAt != 0 {
				at = calledAt
			}
			known := false
			if end, bound := after[name]; bound && at > end {
				// Only placed calls have client destination evidence after a
				// directory change. A nested use must retain the unknown
				// reading at a managed gateway (GAP-0402).
				_, isPlaced := placed[call]
				known = !afterDirectory[name] || isPlaced || balanced
			}
			if balanced && at > chainAfter[name] && at < chainEnd[name] {
				known = true
			}
			for _, body := range loops[name] {
				known = known || at > body.from && at < body.to
			}
			if known && !quoted && suffix == "" {
				plain := true
				for value := range bound[name] {
					plain = plain && safePlain(value)
				}
				if plain {
					uses[word] = true
				}
			}
			if known && len(bound[name]) == 1 {
				for value := range bound[name] {
					// A quoted parameter stays one argv word with blanks.
					// An unquoted value may split into several words.
					if quoted || safePlain(value) {
						values[word] = value + suffix
					}
				}
			}
		}
		return true
	})
	return uses, values
}

func balancedFunctionBody(fn *syntax.FuncDecl, home string) bool {
	if fn == nil || fn.Body == nil {
		return false
	}
	declarationArgs := map[*syntax.Assign]bool{}
	syntax.Walk(fn.Body, func(node syntax.Node) bool {
		if decl, ok := node.(*syntax.DeclClause); ok {
			for _, arg := range decl.Args {
				declarationArgs[arg] = true
			}
		}
		return true
	})
	safe := true
	syntax.Walk(fn.Body, func(node syntax.Node) bool {
		if !safe {
			return false
		}
		switch node := node.(type) {
		case *syntax.Assign:
			safe = declarationArgs[node]
		case *syntax.DeclClause:
			_, safe = declarationDestinations(node)
		case *syntax.FuncDecl, *syntax.ForClause, *syntax.ArithmCmd,
			*syntax.ArithmExp, *syntax.LetClause, *syntax.TestClause,
			*syntax.CoprocClause, *syntax.ProcSubst:
			safe = false
		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				return true
			}
			program, fixed := literalProgramWord(node.Args[0], home)
			_, binder := shellBinderDestinations(node, home)
			safe = fixed && (slices.Contains(knownWordPrograms, programBase(program)) || binder)
		}
		return safe
	})
	return safe
}

// printfFormatDoesNotBind checks a fixed format for %n, which can assign a
// variable named by any later argument. The caller has parsed -v separately.
func printfFormatDoesNotBind(args []*syntax.Word, formatIndex int, home string) bool {
	if formatIndex >= len(args) {
		return false
	}
	format, fixed := StaticWord(args[formatIndex], home)
	if !fixed {
		return false
	}
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		if i >= len(format) {
			return false
		}
		if format[i] == '%' {
			continue
		}
		if format[i] == '(' {
			end := strings.IndexByte(format[i+1:], ')')
			if end < 0 || i+end+2 >= len(format) || format[i+end+2] != 'T' {
				return false
			}
			i += end + 2
			continue
		}
		for i < len(format) && (format[i] < 'A' || format[i] > 'Z') && (format[i] < 'a' || format[i] > 'z') {
			if format[i] == '%' {
				return false
			}
			i++
		}
		if i >= len(format) || format[i] == 'n' {
			return false
		}
	}
	return true
}

type binderOperandRole uint8

const (
	binderNoPosition binderOperandRole = iota
	binderAllPositions
	binderFirstPosition
)

type shellBinderSpec struct {
	flags, values, destinations, reject string
	position                            binderOperandRole
}

// Bash option roles are checked before retaining a known copy word. An
// unrecognized option or dynamic destination leaves the entire proof unknown.
var shellBinderSpecs = map[string]shellBinderSpec{
	"read":      {"ers", "adinNptu", "a", "", binderAllPositions},
	"mapfile":   {"t", "cCdOnsu", "", "C", binderFirstPosition},
	"readarray": {"t", "cCdOnsu", "", "C", binderFirstPosition},
	"printf":    {"", "v", "v", "", binderNoPosition},
	"wait":      {"fn", "p", "p", "", binderNoPosition},
	"pwd":       {"LP", "", "", "", binderNoPosition},
}

// shellBinderDestinations returns only variables a supported Bash builtin
// can write. builtin and command select the builtin directly; an option on
// either wrapper is left unknown. This proof never changes the strict scan.
func shellBinderDestinations(call *syntax.CallExpr, home string) ([]string, bool) {
	if call == nil || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return nil, false
	}
	args := call.Args
	for len(args) > 1 {
		wrapper, fixed := literalProgramWord(args[0], home)
		if !fixed || wrapper != "builtin" && wrapper != "command" {
			break
		}
		args = args[1:]
	}
	program, fixed := literalProgramWord(args[0], home)
	if !fixed {
		return nil, false
	}
	if program == "getopts" {
		if len(args) < 3 {
			return nil, false
		}
		if _, fixed := StaticWord(args[1], home); !fixed {
			return nil, false
		}
		name, fixed := StaticWord(args[2], home)
		return []string{name}, fixed && plainShellVariableName(name)
	}
	if program == "declare" || program == "typeset" || program == "local" ||
		program == "export" || program == "readonly" {
		return declarationWordDestinations(args[1:], home)
	}
	spec, found := shellBinderSpecs[program]
	if !found {
		return nil, false
	}
	names := make([]string, 0, 2)
	positional := make([]string, 0, len(args)-1)
	formatIndex := -1
	options := true
	arrayDestination := false
	for index := 1; index < len(args); index++ {
		if program == "printf" && formatIndex >= 0 {
			// After the fixed format, operands are print data. A nested
			// command or expansion in one is visited by the syntax walk.
			break
		}
		word, fixed := StaticWord(args[index], home)
		if !fixed {
			return nil, false
		}
		if options && word == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(word, "-") && len(word) > 1 {
			for pos := 1; pos < len(word); pos++ {
				option := word[pos]
				if strings.ContainsRune(spec.reject, rune(option)) {
					return nil, false
				}
				if strings.ContainsRune(spec.flags, rune(option)) {
					continue
				}
				if !strings.ContainsRune(spec.values, rune(option)) {
					return nil, false
				}
				value := word[pos+1:]
				if value == "" {
					index++
					if index == len(args) {
						return nil, false
					}
					value, fixed = StaticWord(args[index], home)
					if !fixed {
						return nil, false
					}
				}
				if strings.ContainsRune(spec.destinations, rune(option)) {
					if !plainShellVariableName(value) {
						return nil, false
					}
					names = append(names, value)
					arrayDestination = program == "read" && option == 'a'
				}
				break // the rest of this word is the option value
			}
			continue
		}
		options = false
		if program == "printf" {
			formatIndex = index
		}
		positional = append(positional, word)
	}
	switch spec.position {
	case binderAllPositions:
		if !arrayDestination {
			names = append(names, positional...)
		}
	case binderFirstPosition:
		if len(positional) > 0 {
			names = append(names, positional[0])
		}
	}
	for _, name := range names {
		if !plainShellVariableName(name) {
			return nil, false
		}
	}
	if program == "printf" {
		if formatIndex < 0 || !printfFormatDoesNotBind(args, formatIndex, home) {
			return nil, false
		}
	}
	return names, true
}

func declarationWordDestinations(args []*syntax.Word, home string) ([]string, bool) {
	names := make([]string, 0, len(args))
	options := true
	for _, arg := range args {
		word, fixed := StaticWord(arg, home)
		if !fixed {
			return nil, false
		}
		if options && word == "--" {
			options = false
			continue
		}
		if options && len(word) > 1 && (word[0] == '-' || word[0] == '+') {
			if strings.ContainsRune(word[1:], 'n') {
				return nil, false // nameref can write through another name
			}
			continue
		}
		options = false
		name, _, _ := strings.Cut(word, "=")
		if !plainShellVariableName(name) {
			return nil, false
		}
		names = append(names, name)
	}
	return names, true
}

func declarationDestinations(decl *syntax.DeclClause) ([]string, bool) {
	if decl == nil || decl.Variant == nil || decl.Variant.Value == "nameref" {
		return nil, false
	}
	names := make([]string, 0, len(decl.Args))
	for _, arg := range decl.Args {
		if arg.Name == nil {
			return nil, false
		}
		name := arg.Name.Value
		if strings.HasPrefix(name, "-") || strings.HasPrefix(name, "+") {
			if strings.ContainsRune(name[1:], 'n') {
				return nil, false
			}
			continue
		}
		if !plainShellVariableName(name) {
			return nil, false
		}
		names = append(names, name)
	}
	return names, true
}

// shellSpecialParameters are names bash sets itself (on every command, at
// each read, or from the environment), so an assignment does not fix their
// value: $_ is the last argument of the previous command (rel-1-0-6:GAP-0235
// review). Every BASH_ name is rejected as well.
var shellSpecialParameters = []string{
	"_", "BASHPID", "BASH_ARGC", "BASH_ARGV", "BASH_COMMAND", "BASH_LINENO", "BASH_REMATCH", "BASH_SOURCE",
	"BASH_SUBSHELL", "COLUMNS", "COMP_CWORD", "COMP_LINE", "COMP_POINT", "DIRSTACK", "EPOCHREALTIME",
	"EPOCHSECONDS", "FUNCNAME", "GROUPS", "HISTCMD", "HOME", "HOSTNAME", "IFS", "LINENO", "LINES",
	"OLDPWD", "OPTARG", "OPTIND", "PATH", "PIPESTATUS", "PPID", "PWD", "RANDOM", "REPLY", "SECONDS",
	"SHELLOPTS", "SHLVL", "SRANDOM", "UID", "EUID",
}

// simpleScalarParameter accepts $name or ${name} of a plain variable name
// that bash does not set itself.
func simpleScalarParameter(param *syntax.ParamExp) bool {
	if param == nil || param.Param == nil || param.Excl || param.Length || param.Width || param.IsSet ||
		param.Index != nil || param.Slice != nil || param.Repl != nil || param.Names != 0 ||
		param.Exp != nil || param.Flags != nil || param.NestedParam != nil || len(param.Modifiers) != 0 {
		return false
	}
	name := param.Param.Value
	return plainShellVariableName(name)
}

func plainShellVariableName(name string) bool {
	if name == "" || slices.Contains(shellSpecialParameters, name) || strings.HasPrefix(name, "BASH_") {
		return false
	}
	for i, ch := range name {
		if ch != '_' && (ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') &&
			(i == 0 || ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}

// staticDirectoryCall reports a directory-changing call whose words are all
// fixed, with no assignment in front of it.
func staticDirectoryCall(call *syntax.CallExpr, home string) bool {
	if len(call.Assigns) != 0 {
		return false
	}
	for _, arg := range call.Args {
		if _, static := StaticWord(arg, home); !static {
			return false
		}
	}
	return true
}

// directoryChangeOperand is the shared operand parser for the known-word
// reader and the statement directory walk. Only cd's logical -L and --
// forms are read; a physical cd or a pushd option stays unknown.
func directoryChangeOperand(call *syntax.CallExpr, home string) (string, bool) {
	if call == nil || len(call.Args) < 2 || !staticDirectoryCall(call, home) {
		return "", false
	}
	program, _ := StaticWord(call.Args[0], home)
	index := 1
	if program == "cd" {
		for index < len(call.Args)-1 {
			option, _ := StaticWord(call.Args[index], home)
			if option != "-L" && option != "--" {
				return "", false
			}
			index++
			if option == "--" {
				break
			}
		}
	} else if program != "pushd" {
		return "", false
	}
	if index+1 != len(call.Args) {
		return "", false
	}
	dir, _ := StaticWord(call.Args[index], home)
	if dir == "" || strings.HasPrefix(dir, "-") || program == "pushd" &&
		(strings.HasPrefix(dir, "+") || !pushdBypassesCDPath(dir)) {
		return "", false
	}
	return dir, true
}

// leadingDirectoryOperand returns the static directory of a leading cd or
// pushd statement with no redirect or shell control modifier.
func leadingDirectoryOperand(stmt *syntax.Stmt, home string) (string, bool) {
	if stmt == nil || len(stmt.Redirs) != 0 || stmt.Background || stmt.Negated || stmt.Coprocess {
		return "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return "", false
	}
	return directoryChangeOperand(call, home)
}
