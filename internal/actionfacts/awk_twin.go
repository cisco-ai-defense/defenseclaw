// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/awkprog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// MaxAwkNestedShellStrings is how many shell STRINGs deep an awk program is
// read (sh -c "sh -c 'awk ...'"); a program nested deeper is truncated (cap
// depth). It is the depth of the wrapper twin reading.
const MaxAwkNestedShellStrings = maxNestedShellStrings

// AwkTwin is the reading of a command in which the shell commands its awk
// programs start are written out (rel-1-0-10:GAP-0499).
type AwkTwin struct {
	// Text is the POSIX reading of the command in which every awk call whose
	// program starts a shell command through system(), print | or | getline,
	// with the command written as string literals, is written as the group
	// that runs those commands (an sh -c call behind a prefix wrapper, a
	// find -exec, an xargs or an assignment; the command itself when the awk
	// call is the whole command). Awk starts each command in a shell of its
	// own, so the call runs what the hook would run for that command
	// directly; the awk call itself, with its own file outputs, is judged as
	// written. A prefix wrapper (env, nohup, timeout, ...) stays in front of
	// the sh call, and a shell STRING (sh -c "awk ...") is read the same way.
	// Empty when no call was rewritten. A caller counts only a block proven on
	// the reading.
	Text string
	// Bodies are the shell scripts the awk calls run, each as a plain command.
	Bodies []string
	// Truncated is the cap the reading hit: an awk program inside shell
	// STRINGs nested past maxNestedShellStrings is not read, and a program
	// past awkprog.MaxProgramBytes is read to its cap only, so the call is
	// judged at least at the unknown tier of the pack (internal/guardrail/bounded).
	Truncated bounded.CapSet
	// ProgramFiles reports an awk call that names a program file (-f, --file,
	// -E, --exec, -W exec). FilesUnknown reports that one of those calls runs
	// code the reading does not know: a file the reader of the caller could
	// not read, a computed file name, or a file whose commands are computed.
	// A caller answers it at the unknown tier; the hook client, which reads
	// as the user, tells a gateway that cannot read the user's files when it
	// read them all (hookpaths.AwkFilesKey).
	ProgramFiles, FilesUnknown bool
}

// awkFileState is what the twin reading learns about program files.
type awkFileState struct {
	programFiles, unknown bool
	// dirs are the folders the text being read may start in: the folders
	// the calls of an enclosing text may run in at the shell string that
	// holds it (one, the hook's own folder "", for the call itself).
	dirs []awkDir
	// awkPath is set when the text names AWKPATH, which gawk searches for a
	// bare -f name.
	awkPath bool
}

// awkDir is a folder a call may run in, spelled relative to the folder the
// hook runs in (or absolute); unknown when no words give it (cd -, cd with
// no operand, a ~ or a variable, popd).
type awkDir struct {
	prefix  string
	unknown bool
}

// maxAwkDirs is the most folders one awk call is read in: past it the
// folder is unknown, the cap paths of the bound rule.
const maxAwkDirs = 8

// awkDirEvent is a cd, pushd, popd or chdir of a text at offset at. certain
// are the offset ranges in which the change certainly ran: the right side of
// an && whose left side is a chain of calls the change is one of (cd x &&
// awk -f f runs awk only once the cd succeeded). Anywhere else (after a ;,
// behind false && or ||, in an if branch, a subshell, a pipeline stage) the
// change may or may not have run, so a later call may run in either folder
// (rel-1-0-10:GAP-0852).
type awkDirEvent struct {
	at      int
	certain [][2]int
	target  string
	unknown bool
}

// awkDirsAt are the folders a call at offset at may run in: the folders the
// text starts in, through each change before it, replaced where the change
// certainly ran and added to where it may not have.
func awkDirsAt(start []awkDir, events []awkDirEvent, at int, trunc *bounded.Truncated) []awkDir {
	dirs := slices.Clone(start)
	if len(dirs) == 0 {
		dirs = []awkDir{{}}
	}
	for _, event := range events {
		if event.at >= at {
			break
		}
		changed := make([]awkDir, 0, len(dirs))
		for _, dir := range dirs {
			switch {
			case dir.unknown || event.unknown:
				changed = append(changed, awkDir{unknown: true})
			default:
				changed = append(changed, awkDir{prefix: awkJoinDir(dir.prefix, event.target)})
			}
		}
		certain := slices.ContainsFunc(event.certain, func(span [2]int) bool { return span[0] <= at && at < span[1] })
		if certain {
			dirs = changed
		} else {
			dirs = append(dirs, changed...)
		}
		dirs = slices.Compact(slices.SortedFunc(slices.Values(dirs), func(a, b awkDir) int {
			if a.unknown != b.unknown {
				if a.unknown {
					return 1
				}
				return -1
			}
			return strings.Compare(a.prefix, b.prefix)
		}))
		if len(dirs) > maxAwkDirs {
			trunc.Hit(bounded.Paths)
			dirs = append(dirs[:maxAwkDirs-1], awkDir{unknown: true})
		}
	}
	return dirs
}

// awkCertainSpans maps each call of file that is one of the left side of an
// && (a chain of calls joined by &&) to the offset ranges of the right side
// of that &&: the commands there run only once the call succeeded.
func awkCertainSpans(file *syntax.File) map[*syntax.CallExpr][][2]int {
	spans := map[*syntax.CallExpr][][2]int{}
	var chain func(stmt *syntax.Stmt) []*syntax.CallExpr
	chain = func(stmt *syntax.Stmt) []*syntax.CallExpr {
		if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess {
			return nil
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			return []*syntax.CallExpr{cmd}
		case *syntax.BinaryCmd:
			if cmd.Op == syntax.AndStmt {
				return append(chain(cmd.X), chain(cmd.Y)...)
			}
		}
		return nil
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if and, ok := node.(*syntax.BinaryCmd); ok && and.Op == syntax.AndStmt && and.Y != nil {
			span := [2]int{int(and.Y.Pos().Offset()), int(and.Y.End().Offset())}
			for _, call := range chain(and.X) {
				spans[call] = append(spans[call], span)
			}
		}
		return true
	})
	return spans
}

// awkAbsoluteName reports a program file name that names the same file
// wherever the call runs.
func awkAbsoluteName(name string) bool {
	return strings.HasPrefix(name, "/") || len(name) > 2 && name[1] == ':' && (name[2] == '\\' || name[2] == '/')
}

// awkJoinDir is dir (relative to the hook's folder, or absolute) with name
// below it; the system resolves any "..", links included.
func awkJoinDir(dir, name string) string {
	switch {
	case dir == "":
		return name
	case awkAbsoluteName(name):
		return name
	}
	return strings.TrimRight(dir, "/") + "/" + name
}

// awkChangeDir is the change of folder of a cd or pushd of the words.
func awkChangeDir(words []string, static []bool, at int) awkDirEvent {
	target := ""
	for i := at + 1; i < len(words); i++ {
		if !static[i] {
			return awkDirEvent{unknown: true}
		}
		if strings.HasPrefix(words[i], "-") && words[i] != "-" && words[i] != "--" {
			continue
		}
		if words[i] == "--" {
			continue
		}
		target = words[i]
		break
	}
	if target == "" || target == "-" || strings.HasPrefix(target, "~") || strings.HasPrefix(target, "+") {
		return awkDirEvent{unknown: true}
	}
	return awkDirEvent{target: target}
}

// awkReaderFor is the program file reader of an awk call that may run in
// dirs (awkDirsAt): a relative name is read below each of the folders, as the
// shell opens it there, and the files read are the program, joined as awk
// joins the files of several -f options, so the strongest of them decides; a
// name read in none of the folders is unread, the unknown tier. A folder no
// words give (cd -, a computed folder), or a bare name looked up through
// AWKPATH with no static value, is unread too: a call that may run there is
// also the unknown tier (state.unknown), whatever the other folders prove. A
// static AWKPATH assignment on the call itself names the folders gawk
// searches. An absolute name is the same file wherever the call runs.
func awkReaderFor(files awkprog.FileReader, state *awkFileState, dirs []awkDir, run PrefixWrapperRun, awkPath string, awkPathSet bool) awkprog.FileReader {
	if files == nil {
		return nil
	}
	if len(dirs) == 1 && dirs[0] == (awkDir{}) && run.Dir == "" && !run.DirUnknown && !state.awkPath && !awkPathSet {
		return files
	}
	lookup := func(prefix, name string) (string, bool) {
		if !strings.ContainsAny(name, `/\`) && (state.awkPath || awkPathSet) {
			if !awkPathSet {
				return "", false
			}
			for _, dir := range strings.Split(awkPath, ":") {
				if dir == "" {
					dir = "."
				}
				if text, ok := files(awkJoinDir(awkJoinDir(prefix, dir), name)); ok {
					return text, true
				}
			}
			return "", false
		}
		return files(awkJoinDir(prefix, name))
	}
	return func(name string) (string, bool) {
		if awkAbsoluteName(name) || name == "-" {
			return files(name)
		}
		var texts []string
		for _, dir := range dirs {
			if dir.unknown || run.DirUnknown {
				state.unknown = true
				continue
			}
			prefix := dir.prefix
			if run.Dir != "" {
				prefix = awkJoinDir(prefix, run.Dir)
			}
			if text, ok := lookup(prefix, name); ok && !slices.Contains(texts, text) {
				texts = append(texts, text)
			}
		}
		if len(texts) == 0 {
			return "", false
		}
		return strings.Join(texts, "\n"), true
	}
}

// wholeCommand reports that call is the only statement of the command, with
// no redirection, background or negation around it.
func wholeCommand(file *syntax.File, call *syntax.CallExpr) bool {
	if len(file.Stmts) != 1 {
		return false
	}
	stmt := file.Stmts[0]
	return stmt.Cmd == syntax.Command(call) && len(stmt.Redirs) == 0 && !stmt.Background && !stmt.Negated && !stmt.Coprocess
}

// AwkCommandTwin reads the awk programs of a POSIX command, with no reach to
// program files. The zero AwkTwin means the command has none that start a
// command.
func AwkCommandTwin(command string) AwkTwin {
	return AwkCommandTwinFiles(command, nil)
}

// AwkCommandTwinFiles is AwkCommandTwin for a caller that can read a program
// file (the hook client, which runs as the user): the commands a -f, --file,
// -E, --exec or -W exec file starts are read like those of an inline program,
// and a file the reader cannot read is reported as Unread.
func AwkCommandTwinFiles(command string, files awkprog.FileReader) AwkTwin {
	var trunc bounded.Truncated
	var state awkFileState
	text, bodies := awkCommandTwin(command, 0, &trunc, files, &state)
	return AwkTwin{Text: text, Bodies: bodies, Truncated: trunc.Set(),
		ProgramFiles: state.programFiles, FilesUnknown: state.unknown}
}

// awkProgramWord reports an awk program name.
func awkProgramWord(word string) bool {
	switch wrapperProgramName(word) {
	case "awk", "gawk", "mawk", "nawk":
		return true
	}
	return false
}

func awkCommandTwin(command string, depth int, trunc *bounded.Truncated, files awkprog.FileReader, state *awkFileState) (twin string, bodies []string) {
	defer func() {
		if recover() != nil {
			twin, bodies = "", nil
		}
	}()
	if !strings.Contains(command, "awk") {
		return "", nil
	}
	if strings.Contains(command, "AWKPATH") {
		state.awkPath = true
	}
	file, parsed := shellparse.Parse(command)
	if !parsed {
		return "", nil
	}
	certain := awkCertainSpans(file)
	var dirEvents []awkDirEvent
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	replace := func(from, to syntax.Pos, text string) {
		start, end := int(from.Offset()), int(to.Offset())
		if start >= 0 && end >= start && end <= len(command) {
			edits = append(edits, edit{start: start, end: end, text: text})
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, isCall := node.(*syntax.CallExpr)
		if !isCall || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		prefixes := make([]string, len(call.Args))
		holed := make([]string, len(call.Args))
		for i, arg := range call.Args {
			word := projectPOSIXWord(arg)
			words[i], static[i], prefixes[i], holed[i] = word.Value, !word.Expands, word.staticPrefix, word.holeText
		}
		index := 0
		var run PrefixWrapperRun
		if wrapped, ok := StaticPrefixWrapperChild(words, static); ok {
			run, index = wrapped, wrapped.Index
		}
		if index >= len(words) || !static[index] {
			return true
		}
		switch wrapperProgramName(words[index]) {
		case "cd", "pushd":
			event := awkChangeDir(words, static, index)
			event.at, event.certain = int(call.Pos().Offset()), certain[call]
			dirEvents = append(dirEvents, event)
		case "popd", "chdir":
			dirEvents = append(dirEvents, awkDirEvent{at: int(call.Pos().Offset()), certain: certain[call], unknown: true})
		}
		dirs := awkDirsAt(state.dirs, dirEvents, int(call.Pos().Offset()), trunc)
		awkPath, awkPathSet := "", false
		for _, assign := range call.Assigns {
			if assign.Name != nil && assign.Name.Value == "AWKPATH" && assign.Value != nil {
				if value := projectPOSIXWord(assign.Value); !value.Expands {
					awkPath, awkPathSet = value.Value, true
				}
			}
		}
		// awkAt reads the awk call that is call.Args[first:last+1] and
		// writes the commands it starts in its place. handed words (a find
		// {} or an xargs -I string) are the entry the program is given, not
		// text of it.
		awkAt := func(first, last int, direct bool, handed func(string) bool) {
			dynamic := make([]bool, last-first+1)
			prefix := make([]string, last-first+1)
			hole := make([]string, last-first+1)
			for i := range dynamic {
				dynamic[i], prefix[i], hole[i] = !static[first+i], prefixes[first+i], holed[first+i]
				if static[first+i] && handed != nil && handed(words[first+i]) {
					dynamic[i], prefix[i], hole[i] = true, "", awkprog.Hole
				}
			}
			reading := awkprog.Call{Words: words[first : last+1], Dynamic: dynamic, Prefix: prefix, Holed: hole, Files: awkReaderFor(files, state, dirs, run, awkPath, awkPathSet)}.Read()
			if reading.Files > 0 {
				state.programFiles = true
				state.unknown = state.unknown || reading.Unread || reading.Dynamic
			}
			if reading.Truncated {
				trunc.Hit(bounded.Bytes)
			}
			if reading.Body == "" {
				return
			}
			// A bare awk call is the commands it starts written as the
			// group that runs them, the plain form the readers list the
			// targets of; with a prefix wrapper, an assignment, a find -exec
			// or an xargs in front the commands run through sh -c, which
			// keeps them.
			text := "sh -c " + posixSingleQuoted(reading.Body)
			if direct {
				switch {
				case wholeCommand(file, call) && !strings.Contains(reading.Body, "\n"):
					text = reading.Body // the command alone is the direct command itself
				default:
					text = "{ " + reading.Body + "\n}"
				}
			}
			replace(call.Args[first].Pos(), call.Args[last].End(), text)
			bodies = append(bodies, reading.Body)
		}
		switch name := wrapperProgramName(words[index]); name {
		case "awk", "gawk", "mawk", "nawk":
			awkAt(index, len(words)-1, index == 0 && len(call.Assigns) == 0, nil)
		case "busybox":
			// busybox awk is the awk applet.
			if next := index + 1; next < len(words) && static[next] && awkProgramWord(words[next]) {
				awkAt(next, len(words)-1, false, nil)
			}
		case "find":
			// find -exec awk ... ; and find -exec awk ... + run the awk call
			// on each entry; a word holding {} is the entry, not program text.
			for i := index + 1; i+1 < len(words); i++ {
				if !static[i] {
					continue
				}
				switch words[i] {
				case "-exec", "-execdir", "-ok", "-okdir":
				default:
					continue
				}
				end := i + 1
				for end < len(words) && (!static[end] || words[end] != ";" && words[end] != "+") {
					end++
				}
				if end < len(words) && end > i+1 && static[i+1] && awkProgramWord(words[i+1]) {
					awkAt(i+1, end-1, false, func(word string) bool { return strings.Contains(word, "{}") })
				}
				i = end
			}
		case "xargs":
			// xargs awk ... runs the awk call with the items it reads added
			// to its operands; a word holding the -I string is the item.
			start, handedString, known := XargsProgram(words[index:])
			if known && index+start < len(words) && static[index+start] && awkProgramWord(words[index+start]) {
				awkAt(index+start, len(words)-1, false, func(word string) bool { return handedString != "" && strings.Contains(word, handedString) })
			}
		default:
			text, shell := shellOptionsString(call.Args, index)
			if !shell {
				var plain bool
				if text, plain = plainShellString(call.Args, index); !plain {
					return true
				}
			}
			value := projectPOSIXWord(call.Args[text])
			if value.Expands || !strings.Contains(value.Value, "awk") {
				return true
			}
			if !trunc.Within(bounded.Depth, depth+1, maxNestedShellStrings) {
				return true // an awk program in the string is not read
			}
			// The string's calls start in the folders this call may run in.
			outer := state.dirs
			state.dirs = dirs
			inner, innerBodies := awkCommandTwin(value.Value, depth+1, trunc, files, state)
			state.dirs = outer
			if inner != "" && inner != value.Value {
				replace(call.Args[text].Pos(), call.Args[text].End(), posixSingleQuoted(inner))
				bodies = append(bodies, innerBodies...)
			}
		}
		return true
	})
	if len(edits) == 0 {
		return "", nil
	}
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var out strings.Builder
	last := 0
	for _, change := range edits {
		if change.start < last {
			return "", nil
		}
		out.WriteString(command[last:change.start])
		out.WriteString(change.text)
		last = change.end
	}
	out.WriteString(command[last:])
	return out.String(), bodies
}

// AwkCall is the awk call of a command fact: its argv, which words expand at
// run time and the text each starts with, ready for awkprog.Call.Read. The
// facts reading has no reach to a program file (the hook client reads those).
func AwkCall(command CommandFact) awkprog.Call {
	call := awkprog.Call{Words: command.Argv}
	if len(command.Arguments) == len(command.Argv) {
		call.Dynamic = make([]bool, len(command.Argv))
		call.Prefix = make([]string, len(command.Argv))
		call.Holed = make([]string, len(command.Argv))
		for i, argument := range command.Arguments {
			call.Dynamic[i], call.Prefix[i], call.Holed[i] = argument.Expands, argument.staticPrefix, argument.holeText
		}
	}
	return call
}

// IsAwkCall reports a command fact that runs awk with an argv whose program
// name is static, though some other word may expand: the reading of its
// programs handles the computed words (awkprog.Call).
func IsAwkCall(command CommandFact) bool {
	return len(command.Argv) >= 2 && command.Executable != "" && awkProgramWord(command.Executable)
}
