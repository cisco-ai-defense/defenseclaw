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
// rg does not know) and its value.
type rgOption struct {
	name, value string
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
			line.options = append(line.options, rgOption{name, value})
			continue
		}
		for j := 1; j < len(arg); j++ {
			name := rgShortOptions[arg[j]]
			if !rgValueOptions[name] {
				line.options = append(line.options, rgOption{name: name})
				continue
			}
			value := strings.TrimPrefix(arg[j+1:], "=")
			if j+1 == len(arg) && i+1 < len(argv) {
				i++
				value = argv[i]
			}
			line.options = append(line.options, rgOption{name, value})
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

// rgSearchesHidden reports an rg that may read hidden (dot-named) files
// and folders, in ripgrep 14.1's order of the options. argv is
// rgArgvWords(command). Its documented default skips them (and
// .gitignore'd paths, which are not modelled: a non-hidden file counts as
// read). They are read with:
//   - --hidden (-.), until a later --no-hidden; and the second
//     --unrestricted (-uu), which turns --hidden on where it stands;
//   - a --glob or --iglob include that may match a dot-named file or
//     folder (an override glob whitelists past every ignore rule), by
//     rgGlobMayMatchHidden;
//   - a file type selected with -t or --type whose globs may match one
//     (substrate-1:GAP-0671): --type-add NAME:GLOB,... adds globs, and
//     NAME:include:TYPE,... copies the globs those types have then;
//     --type-clear empties a type. A selection is resolved by name once
//     the whole argv is read, as rg does (-te before --type-add 'e:*.env'
//     reads .env), and -t all selects every type defined at that point
//     (substrate-1:GAP-0673). No built-in rg type names a credentials
//     file, so only --type-add globs count. -T (--type-not) only excludes;
//   - an --ignore-file, unless --no-ignore-files: its "!" lines can
//     whitelist a hidden file (its contents are not read here);
//   - a word known only when it runs where rg may read it as an option
//     (rgWordMayBeOption: rg $F, rg -$X, rg --hidden$E), and a --type-add
//     or -t value known only then.
//
// A file or folder the command names is read whatever its name
// (credentialPathResolver.argument).
func rgSearchesHidden(command CommandFact, argv []string) bool {
	line := parseRgCommandLine(argv)
	for _, index := range line.optionWords {
		if index < len(command.Arguments) && rgWordMayBeOption(command.Arguments[index]) {
			return true
		}
	}
	for _, index := range line.operands {
		if index < line.literal && index < len(command.Arguments) && rgWordMayBeOption(command.Arguments[index]) {
			return true
		}
	}
	hidden, unrestricted, glob := false, 0, false
	ignoreFile, ignoreFiles := false, true
	types := make(map[string][]string)
	var selected []string
	for _, option := range line.options {
		switch option.name {
		case "hidden":
			hidden = true
		case "no-hidden":
			hidden = false
		case "unrestricted":
			unrestricted++
			if unrestricted == 2 {
				hidden = true
			}
		case "glob", "iglob":
			glob = glob || rgGlobMayMatchHidden(option.value)
		case "ignore-file":
			ignoreFile = true
		case "no-ignore-files":
			ignoreFiles = false
		case "ignore-files":
			ignoreFiles = true
		case "type":
			// A value rgArgvWords made from a word known only when it
			// runs ends in "*": it may be all.
			if option.value != "all" && !strings.Contains(option.value, "*") {
				selected = append(selected, option.value)
				break
			}
			for name := range types {
				selected = append(selected, name)
			}
		case "type-add":
			name, globs, ok := strings.Cut(option.value, ":")
			if !ok || strings.Contains(name, "*") {
				// rg refuses a literal NAME with no ":"; a value known only
				// when it runs may define any type.
				glob = true
				break
			}
			if included, ok := strings.CutPrefix(globs, "include:"); ok {
				for _, other := range strings.Split(included, ",") {
					types[name] = append(types[name], types[other]...)
				}
				break
			}
			types[name] = append(types[name], strings.Split(globs, ",")...)
		case "type-clear":
			delete(types, option.value)
		}
	}
	for _, name := range selected {
		for _, typeGlob := range types[name] {
			glob = glob || typeGlob != "" && rgGlobMayMatchHidden(typeGlob)
		}
	}
	return hidden || glob || ignoreFile && ignoreFiles
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

// rgGlobMayMatchHidden reports an rg include glob (--glob, --iglob, or a
// --type-add glob) that may match a dot-named file or folder. It counts
// when unsure (substrate-1:GAP-0680, GAP-0681): rg's glob engine is not
// modelled, and a glob counts unless it provably cannot match a dot-named
// path segment. That is: every segment, split at each "/", starts with a
// literal character that is not a dot (rgGlobLiteralStart), and the glob
// has no alternation ({...}), no "**", and no class that may match "/"
// (a negated class, [!x] or [^x], or one with a range or an escape:
// rg's classes match "/", so sub[!x].env matches sub/.env). A folder glob
// (".aws/", "*/") is such a segment too: it lets rg enter the folder, where
// any other include glob may then match. An exclude glob (!...) never adds
// a read, and "" and "/" name no segment.
func rgGlobMayMatchHidden(glob string) bool {
	if strings.HasPrefix(glob, "!") {
		return false
	}
	if strings.ContainsAny(glob, "{}") || strings.Contains(glob, "**") {
		return true
	}
	for i := 0; i < len(glob); i++ {
		if glob[i] != '[' {
			continue
		}
		body := glob[i+1:]
		if body == "" || body[0] == '!' || body[0] == '^' {
			return true
		}
		end := strings.IndexByte(body[1:], ']')
		if end < 0 || strings.ContainsAny(body[:end+1], "-/\\") {
			return true
		}
		i += end + 1
	}
	for _, segment := range strings.Split(glob, "/") {
		if segment != "" && !rgGlobLiteralStart(segment[0]) {
			return true
		}
	}
	return false
}

// rgGlobLiteralStart reports a first byte of a glob segment that matches
// only itself, and is no dot: a letter, a digit, one of _-+@%~=,:# or a
// byte of a non-ASCII character. Every other byte (".", "*", "?", "[",
// "\\", "!" ...) may start a dot-named match, or is not modelled.
func rgGlobLiteralStart(b byte) bool {
	return b >= 0x80 || 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' ||
		strings.IndexByte("_-+@%~=,:#", b) >= 0
}
