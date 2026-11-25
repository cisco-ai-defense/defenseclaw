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
	"slices"
	"strings"
)

// ripgrep 14.1's command line (substrate-1:GAP-0673). Every reading of an
// rg argv (its operands, the pattern options, the hidden-file rule) parses
// it with this one table, the way rg's parser (lexopt) does, so no value
// form is read one way in one place and another way elsewhere:
//   - --opt=v and --opt v; a value option with no = takes the next word,
//     even one that starts with "-";
//   - -xv, -x v and -x=v: one = after the letter is dropped;
//   - bundled letters, -lte: -l, then -t with the value e.
// The table is rg 14.1's (rg --help and rg --generate complete-fish), with
// the long aliases --maxdepth and --passthrough. An option rg does not know
// makes rg refuse the call; it is kept as a switch with no name.

// rgShortOptions is the long name of every short option letter.
var rgShortOptions = map[byte]string{
	'.': "hidden", '0': "null", 'A': "after-context", 'B': "before-context",
	'C': "context", 'E': "encoding", 'F': "fixed-strings", 'H': "with-filename",
	'I': "no-filename", 'L': "follow", 'M': "max-columns", 'N': "no-line-number",
	'P': "pcre2", 'S': "smart-case", 'T': "type-not", 'U': "multiline",
	'V': "version", 'a': "text", 'b': "byte-offset", 'c': "count",
	'd': "max-depth", 'e': "regexp", 'f': "file", 'g': "glob", 'h': "help",
	'i': "ignore-case", 'j': "threads", 'l': "files-with-matches",
	'm': "max-count", 'n': "line-number", 'o': "only-matching", 'p': "pretty",
	'q': "quiet", 'r': "replace", 's': "case-sensitive", 't': "type",
	'u': "unrestricted", 'v': "invert-match", 'w': "word-regexp",
	'x': "line-regexp", 'z': "search-zip",
}

// rgValueOptions is the long options that take a value. Every other option
// is a switch.
var rgValueOptions = map[string]bool{
	"after-context": true, "before-context": true, "color": true, "colors": true,
	"context": true, "context-separator": true, "dfa-size-limit": true,
	"encoding": true, "engine": true, "field-context-separator": true,
	"field-match-separator": true, "file": true, "generate": true, "glob": true,
	"hostname-bin": true, "hyperlink-format": true, "iglob": true,
	"ignore-file": true, "max-columns": true, "max-count": true,
	"max-depth": true, "maxdepth": true, "max-filesize": true,
	"path-separator": true, "pre": true, "pre-glob": true,
	"regex-size-limit": true, "regexp": true, "replace": true, "sort": true,
	"sortr": true, "threads": true, "type": true, "type-add": true,
	"type-clear": true, "type-not": true,
}

// rgOption is one option of an rg argv: its long name ("" for an option
// rg does not know), its value and the argv index of the word its value
// is in (the option word itself for a switch or an attached value).
type rgOption struct {
	name, value string
	word        int
}

// rgCommandLine is an rg argv parsed: its options in order, the argv
// index of each option word, and the argv indexes of its positional words
// (the pattern, unless -e or -f gives it, then the paths). rg reads a
// path "-" as standard input; stdin says one was given, and it is no
// operand. A "-" where the pattern goes is the pattern
// (substrate-1:GAP-0679): rg --hidden - . searches . for "-".
// literal is the index of the first word after "--" (len(argv) when there
// is none): no word from there on is an option.
type rgCommandLine struct {
	options     []rgOption
	optionWords []int
	operands    []int
	stdin       bool
	literal     int
}

func parseRgCommandLine(argv []string) rgCommandLine {
	line := rgCommandLine{literal: len(argv)}
	var positionals []int
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			line.literal = i + 1
			for j := i + 1; j < len(argv); j++ {
				positionals = append(positionals, j)
			}
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positionals = append(positionals, i)
			continue
		}
		line.optionWords = append(line.optionWords, i)
		if strings.HasPrefix(arg, "--") {
			name, value, attached := strings.Cut(arg[2:], "=")
			if rgValueOptions[name] && !attached && i+1 < len(argv) {
				i++
				value = argv[i]
			}
			line.options = append(line.options, rgOption{name, value, i})
			continue
		}
		for j := 1; j < len(arg); j++ {
			name := rgShortOptions[arg[j]]
			if !rgValueOptions[name] {
				line.options = append(line.options, rgOption{name: name, word: i})
				continue
			}
			value := strings.TrimPrefix(arg[j+1:], "=")
			if j+1 == len(arg) && i+1 < len(argv) {
				i++
				value = argv[i]
			}
			line.options = append(line.options, rgOption{name, value, i})
			break
		}
	}
	// rg takes the pattern from -e or -f wherever they stand, else from
	// the first positional word; every other positional is a path.
	fromOption, _ := line.patternOptions()
	for k, index := range positionals {
		if argv[index] == "-" && (fromOption || k > 0) {
			line.stdin = true
			continue
		}
		line.operands = append(line.operands, index)
	}
	return line
}

// rgArgvWords is an rg argv for parseRgCommandLine. A word the shell may
// expand keeps its place: a glob is its text (bash passes a glob that
// matches nothing on unchanged, as in rg -g=*.env), and a word with a part
// known only when it runs is its known start and "*" for the rest, so an
// option keeps its value and a value that may whitelist hidden files
// counts (substrate-1:GAP-0673).
func rgArgvWords(command CommandFact) []string {
	words := slices.Clone(command.Argv)
	for i, word := range words {
		if word != "" || i >= len(command.Arguments) {
			continue
		}
		switch argument := command.Arguments[i]; {
		case argument.StaticGlob != "":
			words[i] = argument.StaticGlob
		case argument.Expands:
			words[i] = argument.staticPrefix + "*"
		}
	}
	return words
}

// has reports an option of the command line by its long name.
func (l rgCommandLine) has(name string) bool {
	for _, option := range l.options {
		if option.name == name {
			return true
		}
	}
	return false
}

// patternOptions is searchPatternOptions for rg: whether -e or -f gives
// the pattern, and the pattern files -f names.
func (l rgCommandLine) patternOptions() (bool, []string) {
	fromOption := false
	var files []string
	for _, option := range l.options {
		switch option.name {
		case "regexp":
			fromOption = true
		case "file":
			fromOption = true
			if option.value != "" && option.value != "-" {
				files = append(files, option.value)
			}
		}
	}
	return fromOption, files
}

// rgSearchFilterOf is the rgFilter of an rg command line, in ripgrep
// 14.1's order of the options (substrate-1:GAP-0683); argv is
// rgArgvWords(command), cwd the folder it runs in (rgWorkingFolder; ""
// when it is not known exactly: every glob is then unsure, see below, and
// types and the hidden rule, which read only a name, stay exact). Its documented default
// skips hidden (dot-named) files and folders (and .gitignore'd paths,
// which are not modelled: a non-hidden file counts as read). The filter
// reads what rg reads:
//   - --hidden (-.), until a later --no-hidden; and the second
//     --unrestricted (-uu), which turns --hidden on where it stands;
//   - the --glob globs, then the --iglob globs (rg adds every -g glob
//     before every --iglob glob, whatever their order on the line), case
//     folded with --glob-case-insensitive; an include glob whitelists past
//     the hidden rule;
//   - the file types -t selects and -T excludes (substrate-1:GAP-0671),
//     each resolved by name once the whole argv is read, as rg does (-te
//     before --type-add 'e:*.env' reads .env): --type-add NAME:GLOB adds
//     one glob (a "," in it is no separator), NAME:include:TYPE,... copies
//     the globs those types have then, --type-clear empties a type and -t
//     all selects every type defined at that point (substrate-1:GAP-0673).
//     A built-in type matches the credentials file names
//     rgBuiltinTypeProbeNames lists;
//   - an --ignore-file, unless --no-ignore-files: its "!" lines can
//     whitelist a hidden file or folder past the hidden rule (never past an
//     override glob or a type; its contents are not read here), so hidden
//     counts as on.
//
// Count when unsure: the filter that reads every file (hidden on, no glob,
// no type) when a word known only when it runs may be an option word
// (rgWordMayBeOption: rg $F, rg -$X, rg --hidden$E; it may be --hidden or
// any glob), or a --type-add value is known only then. A --glob or --iglob
// value known only then matches every path (an include) or none (one that
// starts with "!"); a -t value known only then selects every type, a -T or
// --type-clear one excludes or clears none. A glob this model does not
// read exactly (rgGlobRegexp) is unsure in the same way, and so is every
// glob of an rg whose working folder is not known exactly (cwd "").
//
// A file or folder the command names is read whatever its name
// (credentialPathResolver.argument).
func rgSearchFilterOf(command CommandFact, argv []string, cwd string) *rgFilter {
	all := rgFilterAll
	line := parseRgCommandLine(argv)
	for _, index := range line.optionWords {
		if index < len(command.Arguments) && rgWordMayBeOption(command.Arguments[index]) {
			return all
		}
	}
	for _, index := range line.operands {
		if index < line.literal && index < len(command.Arguments) && rgWordMayBeOption(command.Arguments[index]) {
			return all
		}
	}
	runTime := func(option rgOption) bool {
		if option.word >= len(command.Arguments) {
			return false
		}
		argument := command.Arguments[option.word]
		return argument.Expands && argument.StaticGlob == ""
	}
	f := &rgFilter{}
	unrestricted, fold := 0, false
	ignoreFile, ignoreFiles := false, true
	var globs, iglobs []rgOption
	types := rgBuiltinTypes()
	type selection struct {
		name    string
		exclude bool
	}
	var selections []selection
	for _, option := range line.options {
		switch option.name {
		case "hidden":
			f.hidden = true
		case "no-hidden":
			f.hidden = false
		case "unrestricted":
			unrestricted++
			if unrestricted == 2 {
				f.hidden = true
			}
		case "glob":
			globs = append(globs, option)
		case "iglob":
			iglobs = append(iglobs, option)
		case "glob-case-insensitive":
			fold = true
		case "no-glob-case-insensitive":
			fold = false
		case "ignore-file":
			ignoreFile = true
		case "no-ignore-files":
			ignoreFiles = false
		case "ignore-files":
			ignoreFiles = true
		case "type", "type-not":
			exclude := option.name == "type-not"
			if runTime(option) {
				if exclude {
					break
				}
				option.value = "all"
			}
			if option.value != "all" {
				selections = append(selections, selection{option.value, exclude})
				break
			}
			names := make([]string, 0, len(types))
			for name := range types {
				names = append(names, name)
			}
			slices.Sort(names)
			for _, name := range names {
				selections = append(selections, selection{name, exclude})
			}
		case "type-add":
			if runTime(option) {
				return all
			}
			// rg refuses any other form (it then reads nothing).
			parts := strings.Split(option.value, ":")
			if parts[0] == "" || parts[0] == "all" || len(parts) < 2 || len(parts) > 3 || parts[len(parts)-1] == "" ||
				len(parts) == 3 && parts[1] != "include" {
				break
			}
			t := types[parts[0]]
			if t == nil {
				t = &rgType{names: map[string]bool{}}
				types[parts[0]] = t
			}
			if len(parts) == 2 {
				t.globs = append(t.globs, rgTypeGlob(parts[1]))
				break
			}
			for _, other := range strings.Split(parts[2], ",") {
				if from := types[other]; from != nil && from != t {
					t.globs = append(slices.Clip(t.globs), from.globs...)
					for name := range from.names {
						t.names[name] = true
					}
				}
			}
		case "type-clear":
			if !runTime(option) {
				delete(types, option.value)
			}
		}
	}
	if ignoreFile && ignoreFiles {
		f.hidden = true
	}
	if len(globs)+len(iglobs) > 0 {
		f.cwd = rgPhysicalFolder(cwd) // only an override glob reads it
	}
	add := func(option rgOption, fold bool) {
		g := rgGlob{exclude: strings.HasPrefix(option.value, "!")}
		if !runTime(option) {
			var ok bool
			if g, ok = rgOverrideGlob(option.value, fold); !ok {
				return
			}
		}
		if f.cwd == "" {
			// rg's working folder is not known exactly: what any glob
			// matches may depend on it (Gitignore::strip drops it from the
			// path byte by byte, even inside a file name), so the glob is
			// unsure (substrate-1:GAP-0684).
			g.re = nil
		}
		if !g.exclude {
			f.includes++
		}
		f.globs = append(f.globs, g)
	}
	for _, option := range globs {
		add(option, fold)
	}
	for _, option := range iglobs {
		add(option, true)
	}
	for _, s := range selections {
		f.selected = f.selected || !s.exclude
		t := types[s.name]
		if t == nil || len(t.globs) == 0 && len(t.names) == 0 {
			continue // matches no credentials file
		}
		f.types = append(f.types, rgTypeSelection{exclude: s.exclude, globs: t.globs, names: t.names})
	}
	return f
}

// rgBuiltinTypes is rg's built-in file types that match a credentials file
// name (rgBuiltinTypeProbeNames), for one command line to change.
func rgBuiltinTypes() map[string]*rgType {
	types := make(map[string]*rgType, len(rgBuiltinTypeProbeNames))
	for name, files := range rgBuiltinTypeProbeNames {
		t := &rgType{names: make(map[string]bool, len(files))}
		for _, file := range files {
			t.names[file] = true
		}
		types[name] = t
	}
	return types
}

// rgWordMayBeOption reports a word of an rg argv known only when it runs
// that rg may read as an option word, or that may finish one: a word with
// no static start ("$F", "$(printf %s --hidden)"), "-" and option letters
// that each take no value ("-$X", "-l$X"), or "--" and a name with no "="
// ("--hidden$E"). Such a word may be --hidden, so the rg counts as
// searching hidden files (count when unsure). A word after "--", or the
// value of a value option, is never an option.
func rgWordMayBeOption(argument ArgumentFact) bool {
	if !argument.Expands || argument.StaticGlob != "" {
		return false
	}
	prefix := argument.staticPrefix
	switch {
	case prefix == "":
		return true
	case strings.HasPrefix(prefix, "--"):
		return !strings.Contains(prefix, "=")
	case strings.HasPrefix(prefix, "-"):
		for j := 1; j < len(prefix); j++ {
			if rgValueOptions[rgShortOptions[prefix[j]]] {
				return false // the rest of the word is that option's value
			}
		}
		return true
	}
	return false
}
