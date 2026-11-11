// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// A command line is read for the name of a link to a skill folder only where
// the call can read through it. Six parts of a line run nothing that opens a
// file, and a name inside them is not a read in the balanced tiers:
//
//   - the body of a function the line defines and never calls (a name held in
//     a variable can call any function, so then every body counts);
//   - a lookup (command -v, type), which prints where a program is;
//   - quoted text that is the argument of a program, because a word that
//     holds blanks is one word and never a program of its own (echo "cd x");
//   - the arguments of echo and printf, which print them, when nothing takes
//     the output as input (a pipe, a command substitution, a redirection to a
//     file, a function body); a path they spell that leads into a skill
//     folder through a link is not a read, the folder named by its own path
//     is still named, and a line that also reads or runs something still
//     reads a name they hold, as before;
//   - a comment, which the shell skips;
//   - the pattern operand of grep and rg, which is text to match (rg --files
//     has none: all its operands are places to list).
//
// Everything else keeps the whole-text name check of operand_context.go. The
// strict tier reads none of this: it keeps every word.

// liveReading is a command line less the parts above.
type liveReading struct {
	// live is the line without the bodies of functions nothing calls, the
	// comments, the search patterns and the arguments of echo and printf.
	// Words with a slash are read from it.
	live string
	// names is the line without the bodies, the comments, the search patterns
	// and the lookups. The name check reads it.
	names string
	// argv is the argument vector with the elements that are text to match or
	// to print left empty; nil for a command line.
	argv []string
	// printed holds the text echo and printf print, left out of live and argv:
	// the words of a command line, the elements of a vector.
	printed []string
	// reads is set where a live word reads, copies, writes or runs, or a
	// redirection opens a file.
	reads bool
}

type textSpan struct{ start, end int }

// readLiveLine reads one command line or argument vector. A line that does
// not parse is read whole, as operand_context.go always read it.
func readLiveLine(line string, argv []string) liveReading {
	whole := liveReading{live: line, names: line}
	if argv != nil {
		words := make([]commandWord, len(argv))
		for i, element := range argv {
			words[i] = commandWord{text: element, names: []string{programName(element)}}
		}
		reading := liveReading{live: line, names: line, argv: argv}
		if isLookup(words) {
			reading.names = ""
			return reading
		}
		reading.reads = callReads(words)
		masked := append([]string(nil), argv...)
		for _, i := range searchPatterns(words) {
			masked[i] = ""
		}
		reading.names = strings.Join(masked, " ")
		if printsOnly(words) {
			for i := 1; i < len(masked); i++ {
				reading.printed = append(reading.printed, masked[i])
				masked[i] = ""
			}
		}
		reading.argv = masked
		return reading
	}
	file, ok := shellparse.ParseWithComments(line)
	if !ok {
		whole.reads = holdsReaderWord(textForms(line))
		return whole
	}
	called := calledFunctions(file)
	redefined := definedFunctions(file)
	var dead, printed, lookups []textSpan
	var printedText []string
	var stack []syntax.Node
	reads := false
	visit := func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.FuncDecl:
			if called[n.Name.Value] {
				return true
			}
			dead = append(dead, textSpan{int(n.Pos().Offset()), int(n.End().Offset())})
			return false
		case *syntax.Comment:
			dead = append(dead, textSpan{int(n.Hash.Offset()), int(n.Hash.Offset()) + 1 + len(n.Text)})
		case *syntax.Redirect:
			reads = reads || !inertRedirect(n)
		case *syntax.CallExpr:
			if len(n.Args) == 0 {
				return true
			}
			words := make([]commandWord, len(n.Args))
			for i, arg := range n.Args {
				words[i] = readCommandWord(arg)
			}
			if isLookup(words) {
				lookups = append(lookups, textSpan{int(n.Pos().Offset()), int(n.End().Offset())})
				return false
			}
			reads = reads || callReads(words)
			for _, i := range searchPatterns(words) {
				dead = append(dead, textSpan{words[i].start, words[i].end})
			}
			if printsOnly(words) && !redefined[words[0].text] && outputGoesNowhere(stack) {
				for _, word := range words[1:] {
					printed = append(printed, textSpan{word.start, word.end})
					if word.start >= 0 && word.end <= len(line) && word.start < word.end {
						printedText = append(printedText, line[word.start:word.end])
					}
				}
			}
		}
		return true
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		keep := visit(node)
		if keep {
			stack = append(stack, node)
		}
		return keep
	})
	kept := blankSpans(line, dead)
	return liveReading{live: blankSpans(kept, printed), names: blankSpans(kept, lookups), reads: reads, printed: printedText}
}

// definedFunctions are the names of the functions a command line defines.
func definedFunctions(file *syntax.File) map[string]bool {
	defined := map[string]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if decl, ok := node.(*syntax.FuncDecl); ok {
			defined[decl.Name.Value] = true
		}
		return true
	})
	return defined
}

// printsOnly reports whether a simple command is echo or printf with words
// whose value is in the text: it prints them and opens nothing. A path to
// another program of that name (./echo) is not the builtin.
func printsOnly(words []commandWord) bool {
	if len(words) == 0 {
		return false
	}
	switch words[0].text {
	case "echo", "printf", "/bin/echo", "/usr/bin/echo", "/bin/printf", "/usr/bin/printf":
	default:
		return false
	}
	for _, word := range words {
		if word.dynamic {
			return false
		}
	}
	return true
}

// outputGoesNowhere reports whether what a command prints is not taken as
// input to anything that could read through a link. stack holds the nodes
// above the command, outermost first. The output is taken where it is
// substituted into another command (a command or process substitution), where
// it is printed by the body of a function (called where it is not known),
// where it is redirected to a file that may be read or run later, and where
// it is piped to another command.
func outputGoesNowhere(stack []syntax.Node) bool {
	for i, node := range stack {
		switch n := node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.FuncDecl:
			return false
		case *syntax.Stmt:
			for _, redirect := range n.Redirs {
				if !inertRedirect(redirect) {
					return false
				}
			}
		case *syntax.BinaryCmd:
			if (n.Op == syntax.Pipe || n.Op == syntax.PipeAll) && i+1 < len(stack) && stack[i+1] == syntax.Node(n.X) {
				return false
			}
		}
	}
	return true
}

// blankSpans replaces the spans of text with blanks. A span outside the text
// is ignored.
func blankSpans(text string, spans []textSpan) string {
	if len(spans) == 0 {
		return text
	}
	out := []byte(text)
	for _, s := range spans {
		for i := max(s.start, 0); i < min(s.end, len(out)); i++ {
			out[i] = 0x20
		}
	}
	return string(out)
}

// callReads reports whether a simple command holds a word that reads, copies,
// writes or runs. Each word is judged whole, so quoted text with blanks in it
// is not a program; a program named by an expansion cannot be told and
// counts.
func callReads(words []commandWord) bool {
	if printsOnly(words) {
		return false
	}
	for i, word := range words {
		switch {
		case word.dynamic:
			if i == 0 {
				return true
			}
		case word.isOneOf(readerWords), i == 0 && word.text == ".":
			return true
		}
	}
	return false
}

// inertRedirect reports whether a redirection opens no file: a duplicated
// descriptor (2>&1, >&-) and the null device.
func inertRedirect(r *syntax.Redirect) bool {
	if r.Word == nil {
		return false
	}
	word := readCommandWord(r.Word)
	switch {
	case word.dynamic:
		return false
	case word.text == "/dev/null":
		return true
	case r.Op == syntax.DplIn || r.Op == syntax.DplOut:
		return word.text == "-" || strings.Trim(word.text, "0123456789") == ""
	}
	return false
}

// isLookup reports whether a simple command only looks a program up and runs
// nothing: command -v, command -V, and type where it is a shell builtin (on
// Windows type prints a file). A word that expands cannot be told.
func isLookup(words []commandWord) bool {
	for _, word := range words {
		if word.dynamic {
			return false
		}
	}
	i := 0
	if words[0].isOneOf(wordSet("builtin")) && len(words) > 1 {
		i = 1
	}
	switch {
	case words[i].isOneOf(wordSet("type")):
		return runtime.GOOS != "windows"
	case words[i].isOneOf(wordSet("command")):
		for _, option := range words[i+1:] {
			if !option.isOption() {
				return false
			}
			if queriesCommand(words[i], option.text) {
				return true
			}
		}
	}
	return false
}

// searchSpec lists the options of a search program that matter for finding
// its pattern operand.
type searchSpec struct {
	// patternShort and patternLong give the pattern as their value (-e),
	// fileShort and fileLong give a file of patterns (-f): with either, no
	// operand is the pattern.
	patternShort, fileShort string
	patternLong, fileLong   []string
	// otherShort and otherLong take a value that is neither.
	otherShort string
	otherLong  []string
	// followShort and followLong make the search follow the links it meets.
	followShort string
	followLong  string
	// noPatternLong make the command search for nothing: every operand is a
	// place (rg --files lists them).
	noPatternLong []string
}

var searchSpecs = map[string]searchSpec{
	"grep": {
		patternShort: "e", fileShort: "f", patternLong: []string{"regexp"}, fileLong: []string{"file"},
		otherShort: "ABCDdm",
		otherLong: []string{"after-context", "before-context", "context", "devices", "directories", "max-count", "include",
			"exclude", "exclude-dir", "exclude-from", "label", "binary-files", "group-separator"},
		followShort: "R", followLong: "dereference-recursive",
	},
	"rg": {
		patternShort: "e", fileShort: "f", patternLong: []string{"regexp"}, fileLong: []string{"file"},
		otherShort: "ABCEMTdgjmrt",
		otherLong: []string{"after-context", "before-context", "context", "max-count", "glob", "iglob", "type", "type-not",
			"type-add", "type-clear", "threads", "max-depth", "max-filesize", "max-columns", "replace", "encoding",
			"ignore-file", "pre", "pre-glob", "sort", "sortr", "path-separator", "context-separator", "colors", "engine"},
		followShort: "L", followLong: "follow", noPatternLong: []string{"files"},
	},
}

func searchSpecOf(word commandWord) (searchSpec, bool) {
	for _, name := range word.names {
		switch name {
		case "grep", "egrep", "fgrep", "zgrep":
			return searchSpecs["grep"], true
		case "rg":
			return searchSpecs["rg"], true
		}
	}
	return searchSpec{}, false
}

// effectiveProgram gives the index of the program a simple command runs,
// behind the wrappers (sudo, env, xargs, nice, ...). It is -1 where a word
// that expands is in the way.
func effectiveProgram(words []commandWord) int {
	for i := 0; i < len(words); i++ {
		word := words[i]
		if word.dynamic {
			return -1
		}
		if !word.isOneOf(runnerWrappers) {
			return i
		}
		next, queryOnly := skipWrapperOptions(word, words, i+1)
		if queryOnly {
			return -1
		}
		i = next - 1
	}
	return -1
}

// searchPatterns lists the words of a grep or rg command that are the text
// to look for: the value of -e or --regexp, and with neither -e nor -f the
// first operand. Nothing is listed where the command may follow links in the
// folder it searches (grep -R, rg -L), where a word expands, or where an
// option is an abbreviation that could take a file (--fil): then the word
// might be a file, and it is read as a name.
func searchPatterns(words []commandWord) []int {
	program := effectiveProgram(words)
	if program < 0 {
		return nil
	}
	spec, ok := searchSpecOf(words[program])
	if !ok {
		return nil
	}
	for _, word := range words {
		if word.dynamic {
			return nil
		}
	}
	var patterns, operands []int
	patternGiven, endOfOptions := false, false
	take := func(j int, list *[]int) int {
		if j+1 < len(words) {
			j++
			if list != nil {
				*list = append(*list, j)
			}
		}
		return j
	}
	exact := func(name string, list []string) bool {
		for _, entry := range list {
			if entry == name {
				return true
			}
		}
		return false
	}
	for j := program + 1; j < len(words); j++ {
		text := words[j].text
		switch {
		case endOfOptions || !strings.HasPrefix(text, "-") || text == "-":
			operands = append(operands, j)
		case text == "--":
			endOfOptions = true
		case strings.HasPrefix(text, "--"):
			name, _, attached := strings.Cut(text[2:], "=")
			switch {
			case name == spec.followLong, exact(name, spec.noPatternLong):
				return nil
			case exact(name, spec.patternLong):
				patternGiven = true
				if attached {
					patterns = append(patterns, j)
				} else {
					j = take(j, &patterns)
				}
			case exact(name, spec.fileLong):
				patternGiven = true
				if !attached {
					j = take(j, nil)
				}
			case exact(name, spec.otherLong):
				if !attached {
					j = take(j, nil)
				}
			case abbreviatesAny(name, spec):
				return nil
			}
		default:
			letters := text[1:]
			for k := 0; k < len(letters); k++ {
				last := k == len(letters)-1
				switch c := letters[k]; {
				case strings.IndexByte(spec.followShort, c) >= 0:
					return nil
				case strings.IndexByte(spec.patternShort, c) >= 0:
					patternGiven = true
					if last {
						j = take(j, &patterns)
					} else {
						patterns = append(patterns, j)
					}
					k = len(letters)
				case strings.IndexByte(spec.fileShort, c) >= 0:
					patternGiven = true
					if last {
						j = take(j, nil)
					}
					k = len(letters)
				case strings.IndexByte(spec.otherShort, c) >= 0:
					if last {
						j = take(j, nil)
					}
					k = len(letters)
				}
			}
		}
	}
	if !patternGiven && len(operands) > 0 {
		patterns = append(patterns, operands[0])
	}
	return patterns
}

// abbreviatesAny reports whether a long option that is none of the known
// names is the start of one: GNU programs accept an unambiguous prefix.
func abbreviatesAny(name string, spec searchSpec) bool {
	known := append(append(append([]string{}, spec.patternLong...), spec.fileLong...), spec.otherLong...)
	known = append(known, spec.followLong)
	for _, entry := range known {
		if strings.HasPrefix(entry, name) {
			return true
		}
	}
	return false
}
