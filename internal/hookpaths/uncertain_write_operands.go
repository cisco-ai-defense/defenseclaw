// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/awkprog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"mvdan.cc/sh/v3/syntax"
)

// callPrograms are the programs of command by what the effects model reads of
// them (actionfacts classify.go; this package keeps no list of verbs): writers
// are those it reads as a write, an append, a permission or attribute change,
// a copy, a move or a disk write; harmless are those whose every operation is
// a read, a list or a search, beside the execute every call has. A program in
// neither group is one the model does not classify, and an unclassified
// program is not proven harmless: its operands are read as a writer's
// (rel-1-0-10 GAP-0415).
func callPrograms(command, cwd, home string) (writers, harmless map[string]bool) {
	facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home})
	writers, harmless = map[string]bool{}, map[string]bool{}
	for _, fact := range facts.Commands {
		writes, reads, other := false, false, false
		for _, operation := range fact.Operations {
			switch operation {
			case actionfacts.OperationWrite, actionfacts.OperationAppend, actionfacts.OperationPermissionChange,
				actionfacts.OperationCopy, actionfacts.OperationMove, actionfacts.OperationDiskWrite:
				writes = true
			case actionfacts.OperationRead, actionfacts.OperationList, actionfacts.OperationSearch:
				reads = true
			case actionfacts.OperationExecute:
				// Every call runs its program (actionfacts adds execute to each
				// command fact), so execute says nothing about the operands.
				// Counting it as another operation left no program harmless:
				// ls, cat and base64 glob operands were read as unproven writes.
			default:
				other = true
			}
		}
		reads = reads && !other
		for _, name := range []string{programBase(fact.Program), programBase(fact.Executable)} {
			switch {
			case writes:
				writers[name] = true
			case reads:
				harmless[name] = true
			}
		}
	}
	for name := range writers {
		delete(harmless, name)
	}
	return writers, harmless
}

// nestedShellBodyDepth bounds how many bash -c bodies the operand walk reads
// into.
const nestedShellBodyDepth = 3

// forEachWriteOperand walks every operand of a writer call (and every output
// redirect) of command, bodies of a nested bash -c, sh -c and the like
// included, through the one word resolver, and calls visit with each result.
// It stops when visit returns true. Variable values come from the plain
// assignments before the call, in order (actionUpdateValues).
func forEachWriteOperand(command, cwd, home string, startup ShellStartup, visit func(resolvedWord) bool) bool {
	if home == "" || !filepath.IsAbs(cwd) || actionWindowsHome(home) {
		return false
	}
	return walkWriteOperands(command, cwd, home, startup, 0, false, visit)
}

// capsOnly reads the operands of the calls the effects model classifies as
// writers (capWriters) and no redirect: the walk that judges a possible write
// also reads an operand of a program the model does not classify.
func walkWriteOperands(command, cwd, home string, startup ShellStartup, depth int, capsOnly bool, visit func(resolvedWord) bool) bool {
	var capWriters map[string]bool
	if capsOnly {
		capWriters = capWriterPrograms(capWriterFacts(command, cwd, home))
	}
	return walkWriteOperandsOf(command, cwd, home, startup, depth, capsOnly, capWriters, visit)
}

// walkWriteOperandsOf is walkWriteOperands with the cap writers of command
// already read (nil unless capsOnly).
func walkWriteOperandsOf(command, cwd, home string, startup ShellStartup, depth int, capsOnly bool,
	capWriters map[string]bool, visit func(resolvedWord) bool) bool {
	file, parsed := parseShell(command)
	if !parsed {
		return false
	}
	options := shellGlobOptionsForCall(command, startup)
	_, harmless := callPrograms(command, cwd, home)
	values := actionValues{"HOME": home, "PWD": cwd}
	stop := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if stop {
			return false
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		values["PWD"] = cwd
		actionUpdateValues(stmt, values, cwd, home)
		for _, redirect := range stmt.Redirs {
			if !capsOnly && redirect.Word != nil && actionOutputRedirect(redirect.Op) &&
				visit(resolveWriteWord(redirect.Word, values, cwd, options)) {
				stop = true
				return false
			}
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		program, fixed := staticProgramWord(call.Args[0], home)
		if !fixed {
			return true
		}
		name := programBase(program)
		if depth < nestedShellBodyDepth && slices.Contains([]string{"bash", "sh", "dash", "zsh", "ksh"}, name) {
			for i := 1; i+1 < len(call.Args); i++ {
				if flag, fixed := StaticWord(call.Args[i], home); fixed && (flag == "-c" || capsOnly && shellCommandCluster(flag)) {
					if body, fixed := StaticWord(call.Args[i+1], home); fixed &&
						walkWriteOperands(body, cwd, home, startup, depth+1, capsOnly, visit) {
						stop = true
						return false
					}
				}
			}
		}
		if capsOnly && !capWriters[name] {
			// A launcher, find or xargs the walk reads as harmless may still
			// run a writer.
			if children, ok := capChildCalls(command, call, home); ok {
				for _, child := range children {
					if depth < nestedShellBodyDepth && walkWriteOperands(child, cwd, home, startup, depth+1, true, visit) {
						stop = true
						return false
					}
				}
				return true
			}
			// A call the model did not read as its own command (a
			// function body) is classified by its own text.
			if text, ok := shellNodeText(command, call); harmless[name] || !ok ||
				!capWriterPrograms(capWriterFacts(text, cwd, home))[name] {
				return true
			}
		} else if harmless[name] {
			return true
		}
		for _, word := range call.Args[1:] {
			if text, fixed := StaticWord(word, home); fixed && len(text) > 0 && text[0] == '-' {
				continue // an option
			}
			if visit(resolveWriteWord(word, values, cwd, options)) {
				stop = true
				return false
			}
		}
		return true
	})
	return stop
}

// UncertainWriteReason reports an operand of a write or metadata call that
// the one shell word resolver cannot settle (an unknown variable, a command
// substitution, a glob form it does not model exactly, a glob option the
// call may have changed, a directory it cannot read, a result past its
// bound). It returns "" when every operand is proven, else the
// UnprovenReasonKey class of the first uncertain one (unprovenReasonTitles).
//
// This is the explicit UNCERTAIN result of the resolver (rel-1-0-10
// GAP-0293 round 3): such an operand is not proven to leave the protected
// files alone, so the pack tier decides it (GAP-0350), never a plain allow.
// startup is the agent's shell startup (nil: this process's own).
func UncertainWriteReason(command, cwd, home string, startup *ShellStartup) string {
	return uncertainWriteReason(command, cwd, home, startup, false, false)
}

// UncertainGlobWriteReason is UncertainWriteReason for what pathname
// expansion alone leaves open: a glob form or a glob option the resolver
// does not model (the word's literal is still a candidate), a directory the
// walk cannot read. A result past the bound is the bound rule's (TRUNCATED
// follows the pack, the judge still decides). An operand that is uncertain
// before any glob (an unknown variable, a command substitution, a default
// expansion) is not reported: the dynamic operand proofs judge it, as they
// do on rel/1.0.10, and reading it here made every loop variable, function
// parameter and dynamic word of a writer an unproven target
// (rel-1-0-10:GAP-0378, GAP-0379, GAP-0380; the pack tier consumes this).
//
// The resolver adds evidence only where its walk can see the folders. In a
// view hidden from this process (actionGlobViewHidden: the working folder or
// the home is not there for it, as for a cd target that does not exist here)
// it sees nothing the protected-target readers do not, and their name
// fallback for such a pattern decides the call, as on rel/1.0.10: reading
// every glob operand there as uncertain made plain builds, listings and edits
// an unproven authorized-keys write (the owner A/B of s7/hlinkport-r2
// bf8dc50428). blind is a gateway behind ProtectHome, which sees no folder
// of the home: the client's evidence decides its words (rel-1-0-6:GAP-0675),
// so its hidden words stay uncertain.
//
// A word uncertain only because its pattern form or a glob option is not
// modeled is proven when a reading wider than any bash may take names no
// protected file (resolverSuperset): a sourced file or an extglob search
// pattern in a folder with no protected file or link to one is no unproven
// target. A wider reading that names one keeps the word uncertain.
func UncertainGlobWriteReason(command, cwd, home string, startup *ShellStartup, blind bool) string {
	return uncertainWriteReason(command, cwd, home, startup, true, blind)
}

func uncertainWriteReason(command, cwd, home string, startup *ShellStartup, globOnly, blind bool) string {
	if globOnly && !blind && actionGlobViewHidden(cwd, home) {
		return ""
	}
	current := CurrentShellStartup()
	if startup != nil {
		current = *startup
	}
	reason := ""
	forEachWriteOperand(command, cwd, home, current, func(resolved resolvedWord) bool {
		if globOnly && resolved.superset != nil && !supersetReachesProtected(resolved.superset, home) {
			// a wider reading than any bash may take names no protected file
			return false
		}
		if globOnly && (resolved.preGlob || resolved.uncertain == wordUncertainTruncated) {
			// uncertain before any glob: the dynamic operand proofs judge it;
			// past the bound: the bound rule judges it (TRUNCATED follows the
			// pack and the judge still decides, TestBoundRuleJudgeStillDecides)
			return false
		}
		reason = resolved.uncertain
		return reason != ""
	})
	return reason
}

// supersetReachesProtected reports a path of a word's wider reading
// (resolvedWord.superset) that is a protected file or reaches one: the
// protected names, a link or a hard link to one, the .ssh folder.
func supersetReachesProtected(paths []string, home string) bool {
	var memo *TargetMemo
	protected := memo.protectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	for _, path := range paths {
		if protectedReachPathWith(path, protected, ssh, memo) {
			return true
		}
	}
	return false
}

// harmlessWriterOptions are the options of a writer call that take no value:
// a call with any other option word is not read here.
var harmlessWriterOptions = map[string]bool{
	"-f": true, "-r": true, "-R": true, "-v": true, "-p": true, "-a": true, "-n": true, "-i": true, "-u": true,
	"-l": true, "-s": true, "-T": true, "-P": true, "-H": true, "-L": true, "-d": true, "-x": true, "--": true,
	"--force": true, "--recursive": true, "--verbose": true, "--preserve": true, "--archive": true,
	"--no-clobber": true, "--interactive": true, "--update": true, "--link": true, "--symbolic-link": true,
}

// unsafeAssignmentNames are shell variables whose assignment changes how a
// later word, program or path is read.
var unsafeAssignmentNames = map[string]bool{
	"HOME": true, "PWD": true, "OLDPWD": true, "PATH": true, "IFS": true, "CDPATH": true, "ENV": true,
	"BASH_ENV": true, "SHELLOPTS": true, "BASHOPTS": true, "GLOBIGNORE": true, "PS4": true, "PROMPT_COMMAND": true,
}

// writersAllProvenSafe reports a call that is only plain assignments and
// calls of writers the effects model knows (writerPrograms), whose operands
// the one resolver settles to files that are none of the protected ones: such
// a call cannot write a protected file, so a text mention of a protected name
// in it (a variable assigned a link name and never used, a default that is
// not taken) is no reason to carry a block to a managed gateway
// (rel-1-0-10 GAP-0415; the pinned GAP-0934 binding rows). Anything else in
// the call (cd, trap, a nested shell, a function, control flow, a redirect
// other than an output, an option that takes a value, an unknown program)
// leaves it unproven.
func writersAllProvenSafe(command, cwd, home string, memo *TargetMemo) bool {
	if home == "" || !filepath.IsAbs(cwd) || actionWindowsHome(home) {
		return false
	}
	file, parsed := parseShell(command)
	if !parsed || len(file.Stmts) == 0 || len(file.Stmts) > 32 {
		return false
	}
	writers, harmless := callPrograms(command, cwd, home)
	options := shellGlobOptionsForCall(command, memo.shellStartup())
	protected := memo.protectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	values := actionValues{"HOME": home, "PWD": cwd}
	for _, stmt := range file.Stmts {
		if stmt.Background || stmt.Negated || stmt.Coprocess || len(stmt.Redirs) != 0 {
			return false
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok {
			return false
		}
		if len(call.Args) == 0 {
			for _, assign := range call.Assigns {
				if assign.Name == nil || assign.Value == nil || assign.Append || assign.Array != nil || assign.Index != nil ||
					unsafeAssignmentNames[assign.Name.Value] || assign.Name.Value[0] == 'L' && len(assign.Name.Value) > 3 && assign.Name.Value[:3] == "LD_" {
					return false
				}
			}
			actionUpdateValues(stmt, values, cwd, home)
			continue
		}
		if len(call.Assigns) != 0 {
			return false
		}
		program, fixed := staticProgramWord(call.Args[0], home)
		if fixed && harmless[programBase(program)] {
			continue // reads, lists or searches: no write to prove
		}
		if fixed && awkProgramWritesNothing(call, program, cwd, home) {
			continue // an inline awk program with no file output: its operands are inputs
		}
		if !fixed || !writers[programBase(program)] {
			return false
		}
		for _, word := range call.Args[1:] {
			if text, fixed := StaticWord(word, home); fixed && len(text) > 0 && text[0] == '-' {
				if !harmlessWriterOptions[text] {
					return false
				}
				continue
			}
			resolved := resolveWriteWord(word, values, cwd, options)
			if resolved.uncertain != "" || resolved.literal != "" {
				return false
			}
			for _, candidate := range resolved.candidates {
				if protectedReachPathWith(candidate, protected, ssh, memo) {
					return false
				}
			}
		}
	}
	return true
}

// commandMayExpand reports a command with a character the shell expands or
// reads as code: a parameter or command substitution, a glob or brace
// pattern, a backslash or backtick, a subshell or process substitution. A
// command without one is fixed text: every word names exactly what it reads
// as, and the walk of its operands judges them by what each verb does with
// them (a read operand of a writer is not a write). The managed carry
// (hookpaths.go) is for the other commands, whose word a managed gateway
// behind ProtectHome cannot place (rel-1-0-10 GAP-0415).
func commandMayExpand(command string) bool {
	return strings.ContainsAny(command, "$*?[{\\`(")
}

// UnprovenBoundedPaths is the UnprovenReasonKey class of a call whose write
// operand expanded to more paths than the resolver reads (MaxResolvedCandidates):
// the hook client tells a managed gateway, which cannot read the home, that
// the call is truncated at the bounded.Paths cap (rel-1-0-10 GAP-0438).
const UnprovenBoundedPaths = "bounded-paths"

// WriteOperandCaps are the caps the one resolver hit reading the write
// operands of command (bounded.Paths: a word expanded to more than
// MaxResolvedCandidates paths). A call that hit one is truncated: the caller
// judges what was read as before and the bound rule floors it to the unknown
// tier of the pack (internal/guardrail/bounded). Only an operand of a call the
// effects model classifies as a writer is read (capWriterFact): a read, a
// listing or a search with a wide glob, and a program the model does not
// classify, is not a write the bound could hide a protected file from. A
// command without a character the shell expands cannot hit one.
//
// The writer is the one the call runs, wherever it is spelled: behind a
// launcher (env, nice, timeout, nohup, sudo, setsid, xargs), in a find -exec,
// a bash -lc or an eval body, or in a function body (capChildCalls). The walk
// named a call by its first word only, so env touch D/* read env, which the
// model does not classify, and the bound never hit (rel-1-0-10:GAP-0438, the
// GAP-0497 spellings).
func WriteOperandCaps(command, cwd, home string) bounded.CapSet {
	var set bounded.CapSet
	if !commandMayExpand(command) {
		return set
	}
	if home == "" || !filepath.IsAbs(cwd) || actionWindowsHome(home) {
		return set
	}
	startup := CurrentShellStartup()
	facts := capWriterFacts(command, cwd, home)
	walkWriteOperandsOf(command, cwd, home, startup, 0, true, capWriterPrograms(facts), func(resolved resolvedWord) bool {
		set = set.Union(resolved.caps)
		return false
	})
	return set
}

// capWriterFacts are the command facts of command the cap reads its writers
// from.
func capWriterFacts(command, cwd, home string) actionfacts.Facts {
	return actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home})
}

// capWriterPrograms are the programs of facts the effects model reads as a
// writer (capWriterFact).
func capWriterPrograms(facts actionfacts.Facts) map[string]bool {
	out := map[string]bool{}
	for _, fact := range facts.Commands {
		if capWriterFact(fact) {
			out[programBase(fact.Program)] = true
			out[programBase(fact.Executable)] = true
		}
	}
	return out
}

// capWriterFact reports a command the effects model reads as a write that is
// the program's own: a permission or attribute change, a copy, a move, a disk
// write, a delete, or a write or append that no redirect of the call explains
// (a redirect makes the model read any program as a writer).
func capWriterFact(fact actionfacts.CommandFact) bool {
	writes := false
	for _, operation := range fact.Operations {
		switch operation {
		case actionfacts.OperationPermissionChange, actionfacts.OperationCopy, actionfacts.OperationMove,
			actionfacts.OperationDiskWrite, actionfacts.OperationDelete:
			writes = true
		case actionfacts.OperationWrite, actionfacts.OperationAppend:
			writes = writes || len(fact.Redirects) == 0
		}
	}
	return writes
}

// awkProgramWritesNothing reports an awk call whose one inline program the
// output reader (awkOutputProof: strings, regular expression literals and
// comments are data) proves has no file output and nothing it cannot prove.
// Its operands are inputs, so a protected name in a regular expression or an
// input operand is not a write (the managed carry, rel-1-0-10 GAP-0415).
// A program file (-f, --file), an option the reader does not settle, a
// program that starts a command and a program that is not fixed text are not
// proven.
func awkProgramWritesNothing(call *syntax.CallExpr, program, cwd, home string) bool {
	switch programBase(program) {
	case "awk", "gawk", "mawk", "nawk":
	default:
		return false
	}
	words := make([]string, len(call.Args))
	for i, arg := range call.Args {
		text, fixed := StaticWord(arg, home)
		if !fixed {
			text = "\x00input" // an input operand or an assignment value, never program text
		}
		words[i] = text
	}
	for _, word := range words[1:] {
		if word == "--" {
			break
		}
		if strings.HasPrefix(word, "-f") || strings.HasPrefix(word, "--file") {
			return false // a program file: its text is not read here
		}
	}
	programs, _ := awkprog.ProgramWords(words)
	if len(programs) != 1 || programs[0] == "\x00input" {
		return false
	}
	// A command the program starts (system, print |, | getline) is judged
	// as the shell body it is (rel-1-0-10:GAP-0499), never proven safe here.
	if parsed := awkprog.Parse(programs[0]); len(parsed.Channels) > 0 || parsed.Truncated || parsed.Directive || parsed.Malformed {
		return false
	}
	output, unsafe, _ := awkOutputProof(programs[0], cwd, home)
	return !output && !unsafe
}

// shellCommandCluster reports a short option cluster of a shell that holds
// -c (bash -lc, sh -ec, bash -xc BODY): the shell runs the word after it.
func shellCommandCluster(flag string) bool {
	if len(flag) < 3 || flag[0] != '-' || flag[1] == '-' || !strings.ContainsRune(flag, 'c') {
		return false
	}
	return strings.Trim(flag[1:], "abcefhiklmnprstuvxBCEHPT") == ""
}

// capChildCalls are the texts of the calls call runs as a command of its own,
// for the cap walk: the child of a launcher chain (actionfacts.WrapperChildIndex:
// env, nice, timeout, nohup, sudo, setsid, xargs, ...), a busybox applet,
// each find -exec, -execdir, -ok or -okdir program, and an eval body. ok is
// false for any other call.
func capChildCalls(command string, call *syntax.CallExpr, home string) ([]string, bool) {
	args := call.Args
	values, static := make([]string, len(args)), make([]bool, len(args))
	for i, word := range args {
		values[i], static[i] = StaticWord(word, home)
	}
	span := func(from, to int) (string, bool) {
		if from <= 0 || to > len(args) || from >= to {
			return "", false
		}
		start, end := int(args[from].Pos().Offset()), int(args[to-1].End().Offset())
		if start < 0 || end > len(command) || start >= end {
			return "", false
		}
		return command[start:end], true
	}
	if index := actionfacts.WrapperChildIndex(values, static); index > 0 {
		child, ok := span(index, len(args))
		return []string{child}, ok
	}
	switch programBase(values[0]) {
	case "busybox":
		// busybox APPLET ARGS runs the applet.
		if len(args) > 2 && static[1] && !strings.HasPrefix(values[1], "-") {
			child, ok := span(1, len(args))
			return []string{child}, ok
		}
	case "eval":
		child, ok := span(1, len(args))
		if !ok {
			return nil, false
		}
		for i := 1; i < len(args); i++ {
			if !static[i] {
				return nil, false
			}
		}
		return []string{strings.Join(values[1:], " ")}, child != ""
	case "find":
		var children []string
		for i := 1; i < len(args); i++ {
			if !static[i] || values[i] != "-exec" && values[i] != "-execdir" && values[i] != "-ok" && values[i] != "-okdir" {
				continue
			}
			end := i + 1
			for end < len(args) && !(static[end] && (values[end] == ";" || values[end] == "+")) {
				end++
			}
			if child, ok := span(i+1, end); ok {
				children = append(children, child)
			}
			i = end
		}
		return children, len(children) > 0
	}
	return nil, false
}

// shellNodeText is the source text of node in command.
func shellNodeText(command string, node syntax.Node) (string, bool) {
	start, end := int(node.Pos().Offset()), int(node.End().Offset())
	if start < 0 || end > len(command) || start >= end {
		return "", false
	}
	return command[start:end], true
}
