// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
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
	// dirChanged is set once the walk meets a cd, pushd or popd: the call
	// after it runs in a folder the reading does not track, so a program file
	// named relative to the hook's folder may be another file
	// (rel-1-0-10:GAP-0733). awkPath is set when the text names AWKPATH, which
	// gawk searches for a bare -f name.
	dirChanged, awkPath bool
}

// awkReaderFor is the program file reader of an awk call run in a folder the
// reading may not know (wrapperDir: env -C, sudo -D set one it does not
// resolve, or an earlier cd; or a bare name with AWKPATH set): a relative
// name is then unread, so the call is the unknown tier, never the verdict of
// a file at another place. An absolute name is the same file wherever the
// call runs.
func awkReaderFor(files awkprog.FileReader, state *awkFileState, run PrefixWrapperRun) awkprog.FileReader {
	if files == nil {
		return nil
	}
	moved := state.dirChanged || run.Dir != "" || run.DirUnknown
	if !moved && !state.awkPath {
		return files
	}
	return func(name string) (string, bool) {
		absolute := strings.HasPrefix(name, "/") || len(name) > 2 && name[1] == ':' && (name[2] == '\\' || name[2] == '/')
		if !absolute && (moved || !strings.ContainsAny(name, `/\`)) {
			return "", false
		}
		return files(name)
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
		case "cd", "pushd", "popd", "chdir":
			state.dirChanged = true
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
			reading := awkprog.Call{Words: words[first : last+1], Dynamic: dynamic, Prefix: prefix, Holed: hole, Files: awkReaderFor(files, state, run)}.Read()
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
			if inner, innerBodies := awkCommandTwin(value.Value, depth+1, trunc, files, state); inner != "" && inner != value.Value {
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
