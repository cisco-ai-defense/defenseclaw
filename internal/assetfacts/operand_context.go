// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"slices"
	"strings"
)

// A word of a tool input is a path operand only where the call uses it as one.
// A slash-free word names a skill folder only when it names an existing entry
// of the working folder (a link, SKILL.md), and that is not enough on its own:
// the program a command runs (echo), the pattern of a search and the text
// field of a tool are words that may equal the name of a link without reading
// it. The context of a word, the field it comes from and the position it has
// in its command, decides whether it may be read as a path.

type fieldKind int

const (
	// kindCommand is a shell command line or an argument vector.
	kindCommand fieldKind = iota
	// kindPath is a field that holds one path: it is judged whole, with its
	// spaces and tabs, as well as split into words.
	kindPath
	// kindText is a field that holds a pattern, a query or other text: only a
	// word with a slash in it may name a path.
	kindText
)

// pathKeys are the tool-input fields that hold one path.
var pathKeys = map[string]bool{
	"filepath": true, "notebookpath": true, "path": true, "paths": true,
	"file": true, "files": true, "target": true, "targetfile": true,
	"dir": true, "directory": true, "cwd": true, "workdir": true,
	"workingdirectory": true, "absolutepath": true, "filename": true,
}

// textKeys are the tool-input fields that hold text, not a path.
var textKeys = map[string]bool{
	"pattern": true, "query": true, "regex": true, "regexp": true, "search": true,
	"searchterm": true, "q": true, "text": true, "content": true, "contents": true,
	"oldstring": true, "newstring": true, "prompt": true, "description": true,
	"message": true, "instruction": true, "instructions": true, "replacement": true,
}

// searchTools are the tools that look through the working folder when the
// call names no other place.
var searchTools = map[string]bool{
	"glob": true, "grep": true, "ls": true, "list": true, "listdir": true,
	"listdirectory": true, "search": true, "find": true, "rg": true,
	"ripgrep": true, "filesearch": true, "grepsearch": true,
}

func normalizeKey(key string) string {
	key = strings.ToLower(key)
	return strings.NewReplacer("_", "", "-", "").Replace(key)
}

// kindOfField classifies the tool-input field key of tool. The pattern of a
// Glob names entries under the folder it searches, so it is a path there.
func kindOfField(tool, key string) fieldKind {
	key = normalizeKey(key)
	switch {
	case key == "glob", key == "pattern" && normalizeKey(tool) == "glob":
		return kindPath
	case pathKeys[key]:
		return kindPath
	case textKeys[key]:
		return kindText
	}
	return kindCommand
}

// inputField is one string of a tool input with the field it comes from. A
// command given as an argument vector is one field: argv holds its elements.
type inputField struct {
	key  string
	text string
	argv []string
}

// collectFields lists the strings of a tool input with their fields, path
// fields first (see inputKeys), up to maxInputStrings. A list of strings under
// a command field is an argument vector; the element after a shell -c option
// is a command line of its own.
func collectFields(tool string, value any, key string, depth int, out *[]inputField) {
	if depth > maxInputDepth || len(*out) >= maxInputStrings {
		return
	}
	switch v := value.(type) {
	case string:
		*out = append(*out, inputField{key: key, text: v})
	case []string:
		items := make([]any, len(v))
		for i, text := range v {
			items[i] = text
		}
		collectFields(tool, items, key, depth, out)
	case []any:
		vector := kindOfField(tool, key) == kindCommand
		var argv []string
		previous := ""
		for _, item := range v {
			text, isText := item.(string)
			switch {
			case !isText:
				collectFields(tool, item, key, depth+1, out)
			case len(*out) >= maxInputStrings:
				return
			case vector && !isShellScriptFlag(previous):
				argv = append(argv, text)
			default:
				*out = append(*out, inputField{key: key, text: text})
			}
			previous = text
		}
		if len(argv) > 0 {
			*out = append(*out, inputField{key: key, argv: argv})
		}
	case map[string]any:
		for _, name := range inputKeys(v) {
			collectFields(tool, v[name], name, depth+1, out)
		}
	}
}

// word is one word of a command line and the role it has in it.
type word struct {
	text string
	// segment numbers the simple command the word belongs to.
	segment int
	// command is set for the word that names the program of a command, or a
	// wrapper that runs one (sudo, env).
	command bool
	// redirect is set for the target of a redirection.
	redirect bool
	// skipBare is set when the word is not a path operand unless it has a
	// slash: a program name, a search pattern, an option value.
	skipBare bool
}

// wrapperWords run the command that follows them, or put it in a block.
var wrapperWords = map[string]bool{
	"sudo": true, "doas": true, "env": true, "time": true, "nohup": true,
	"nice": true, "ionice": true, "exec": true, "command": true, "builtin": true,
	"xargs": true, "timeout": true, "stdbuf": true, "setsid": true, "watch": true,
	"if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "!": true, "{": true,
}

func isSegmentBreak(r rune) bool {
	switch r {
	case 0x3b, 0x7c, 0x26, 0x28, 0x29, 0x0a, 0x60:
		return true
	}
	return false
}

// shellWords splits a command line into words as the shell does for quotes
// and escaped spaces, keeping command operators out of the words (an operator
// ends a word, so does a space, a comma and an equals sign). first is set when
// the first word names a program; segment is the number of its command.
func shellWords(value string, first bool, segment int) []word {
	var words []word
	var current strings.Builder
	var quote rune
	atCommand, afterWrapper, assignValue, redirectNext := first, false, false, false
	flush := func(sep rune) {
		if current.Len() > 0 {
			w := word{text: current.String(), segment: segment}
			current.Reset()
			switch {
			case assignValue:
				assignValue = false
			case redirectNext:
				w.redirect, redirectNext = true, false
			case atCommand && afterWrapper && strings.HasPrefix(w.text, "-") && len(w.text) > 1:
			case atCommand && sep == 0x3d:
				assignValue = true
			case atCommand:
				w.command = true
				if wrapperWords[strings.ToLower(w.text)] {
					afterWrapper = true
				} else {
					atCommand = false
				}
			}
			words = append(words, w)
		}
		switch {
		case isSegmentBreak(sep):
			segment++
			atCommand, afterWrapper, assignValue, redirectNext = true, false, false, false
		case sep == 0x3c || sep == 0x3e:
			redirectNext = true
		}
	}
	chars := []rune(value)
	for i := 0; i < len(chars); i++ {
		ch := chars[i]
		if ch == 0x5c && quote != 0x27 && i+1 < len(chars) {
			next := chars[i+1]
			if next == 0x20 || next == 0x09 || next == 0x22 || next == 0x27 {
				current.WriteRune(next)
				i++
				continue
			}
		}
		if ch == 0x22 || ch == 0x27 {
			if quote == 0 {
				quote = ch
				continue
			}
			if quote == ch {
				quote = 0
				continue
			}
		}
		if quote == 0 && isCommandSeparator(ch) {
			// 2>&1 duplicates a descriptor; it does not start a command.
			if ch == 0x26 && i > 0 && (chars[i-1] == 0x3c || chars[i-1] == 0x3e) {
				flush(0)
				continue
			}
			flush(ch)
			continue
		}
		current.WriteRune(ch)
	}
	flush(0)
	return words
}

// commandWords reads a command line, or an argument vector, into words with
// their roles. cwdSearch is set when a command in it searches the working
// folder because it names no other place (ls, grep -r).
func commandWords(text string, argv []string) (words []word, cwdSearch bool) {
	if argv == nil {
		words = shellWords(text, true, 0)
		return words, markOperands(words)
	}
	for i, arg := range argv {
		// The first element names the program; each later one is more words
		// of its command line, none of them a program.
		segment := 0
		if len(words) > 0 {
			segment = words[len(words)-1].segment
		}
		words = append(words, shellWords(arg, i == 0, segment)...)
	}
	return words, markOperands(words)
}

// isShellScriptFlag reports whether arg is the option that makes a shell run
// the next argument as a command line (-c, -lc).
func isShellScriptFlag(arg string) bool {
	return len(arg) >= 2 && arg[0] == 0x2d && arg[1] != 0x2d && strings.HasSuffix(arg, "c")
}

// runnerWords start another command from words, so what a command prints may
// be used as a path operand by it (echo name | xargs cat).
var runnerWords = map[string]bool{
	"xargs": true, "parallel": true, "eval": true, "source": true, ".": true,
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"fish": true, "pwsh": true, "powershell": true, "cmd": true,
}

// commandProfile says how a program uses its words when they are not paths.
type commandProfile struct {
	// firstIsPattern: the first operand is a pattern or program, unless a
	// pattern option (patternLetters, patternLong) gave it.
	firstIsPattern bool
	patternLetters string
	patternLong    []string
	// valueLetters and valueLong are options that take a value that is not a
	// path to read.
	valueLetters string
	valueLong    []string
	// readsCwd: with no operand the program looks through the working folder
	// (always, or with a recursive option).
	readsCwd  bool
	recursive bool
	// text: the operands only print (echo).
	text bool
	// expression: the operands end at the first option (find).
	expression bool
}

var grepFlags = commandProfile{
	firstIsPattern: true, patternLetters: "ef", patternLong: []string{"regexp", "file"},
	valueLetters: "ABCmdD",
	valueLong: []string{
		"regexp", "file", "include", "exclude", "exclude-dir", "exclude-from", "max-count",
		"after-context", "before-context", "context", "directories", "devices", "label", "binary-files",
	},
	readsCwd: true, recursive: true,
}

var commandProfiles = map[string]commandProfile{
	"grep": grepFlags, "egrep": grepFlags, "fgrep": grepFlags, "zgrep": grepFlags,
	"rg": {
		firstIsPattern: true, patternLetters: "ef", patternLong: []string{"regexp", "file"},
		valueLetters: "gtTABCmjMEr",
		valueLong: []string{
			"regexp", "file", "glob", "iglob", "type", "type-not", "max-count", "after-context",
			"before-context", "context", "threads", "replace", "max-depth", "max-filesize", "encoding", "pre", "ignore-file",
		},
		readsCwd: true,
	},
	"ag":  {firstIsPattern: true, patternLetters: "f", valueLetters: "ABCGgm", readsCwd: true},
	"ack": {firstIsPattern: true, patternLetters: "f", valueLetters: "ABCgm", readsCwd: true},
	"sed": {
		firstIsPattern: true, patternLetters: "ef", patternLong: []string{"expression", "file"},
		valueLetters: "l", valueLong: []string{"expression", "file", "line-length"},
	},
	"awk":    {firstIsPattern: true, patternLetters: "f", patternLong: []string{"file"}, valueLetters: "Fv", valueLong: []string{"file", "assign", "field-separator"}},
	"gawk":   {firstIsPattern: true, patternLetters: "f", patternLong: []string{"file"}, valueLetters: "Fv", valueLong: []string{"file", "assign", "field-separator"}},
	"mawk":   {firstIsPattern: true, patternLetters: "f", valueLetters: "Fv"},
	"find":   {readsCwd: true, expression: true},
	"ls":     {readsCwd: true},
	"dir":    {readsCwd: true},
	"vdir":   {readsCwd: true},
	"tree":   {readsCwd: true, valueLetters: "IPLo"},
	"du":     {readsCwd: true},
	"echo":   {text: true},
	"printf": {text: true},
}

// findValueFlags are the tests and options of find whose value is not a path.
var findValueFlags = []string{
	"-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-wholename", "-iwholename",
	"-lname", "-ilname", "-type", "-xtype", "-perm", "-user", "-group", "-size", "-mtime",
	"-atime", "-ctime", "-mmin", "-amin", "-cmin", "-maxdepth", "-mindepth", "-fstype",
}

func programName(text string) string {
	text = strings.ToLower(text)
	if i := strings.LastIndexAny(text, "/\\"); i >= 0 {
		text = text[i+1:]
	}
	return strings.TrimSuffix(text, ".exe")
}

// markOperands marks the words that are not path operands (the program of a
// command, search patterns, option values, what echo prints) and reports
// whether a command searches the working folder with no place named.
func markOperands(words []word) (cwdSearch bool) {
	runner := false
	for _, w := range words {
		if w.command && runnerWords[programName(w.text)] {
			runner = true
		}
	}
	for start := 0; start < len(words); {
		end := start
		for end < len(words) && words[end].segment == words[start].segment {
			end++
		}
		if markSegment(words[start:end], runner) {
			cwdSearch = true
		}
		start = end
	}
	return cwdSearch
}

func markSegment(segment []word, runner bool) bool {
	verb := -1
	for i := range segment {
		if !segment[i].command {
			break
		}
		segment[i].skipBare = true
		verb = i
	}
	if verb < 0 {
		return false
	}
	profile, ok := commandProfiles[programName(segment[verb].text)]
	if !ok {
		return false
	}
	rest := segment[verb+1:]
	if profile.text {
		if !runner {
			for i := range rest {
				if !rest[i].redirect {
					rest[i].skipBare = true
				}
			}
		}
		return false
	}
	patternGiven, operands, recursive, expressionStarted, endOfOptions := false, 0, false, false, false
	for i := 0; i < len(rest); i++ {
		w := &rest[i]
		if w.redirect {
			continue
		}
		isOption := !endOfOptions && len(w.text) > 1 && w.text[0] == 0x2d
		if w.text == "--" {
			endOfOptions = true
			continue
		}
		skipNext := func() {
			if i+1 < len(rest) {
				rest[i+1].skipBare = true
				i++
			}
		}
		switch {
		case isOption && profile.expression:
			expressionStarted = expressionStarted || !slices.Contains([]string{"-H", "-L", "-P"}, w.text)
			if slices.Contains(findValueFlags, w.text) {
				skipNext()
			}
		case isOption && strings.HasPrefix(w.text, "--"):
			name := strings.TrimPrefix(w.text, "--")
			recursive = recursive || name == "recursive" || name == "dereference-recursive"
			if slices.Contains(profile.patternLong, name) {
				patternGiven = true
			}
			if slices.Contains(profile.valueLong, name) {
				skipNext()
			}
		case isOption:
			letters := w.text[1:]
			recursive = recursive || strings.ContainsAny(letters, "rR")
			last := letters[len(letters)-1:]
			if strings.Contains(profile.patternLetters, last) {
				patternGiven = true
				skipNext()
			} else if strings.Contains(profile.valueLetters, last) {
				skipNext()
			}
		case profile.firstIsPattern && !patternGiven:
			patternGiven = true
			w.skipBare = true
		case !profile.expression || !expressionStarted:
			operands++
		}
	}
	return profile.readsCwd && operands == 0 && (!profile.recursive || recursive)
}

// searchesWorkingFolder reports whether a call of tool searches the working
// folder: it is a search tool and no path field names another place.
func searchesWorkingFolder(tool string, fields []inputField) bool {
	if !searchTools[normalizeKey(tool)] {
		return false
	}
	for _, f := range fields {
		if kindOfField(tool, f.key) == kindPath && strings.TrimSpace(f.text) != "" &&
			normalizeKey(f.key) != "glob" && normalizeKey(f.key) != "pattern" && normalizeKey(f.key) != "cwd" {
			return false
		}
	}
	return true
}

// hasBlank reports whether value holds a space or a tab.
func hasBlank(value string) bool { return strings.ContainsAny(value, " \t") }

// mayNamePath reports whether a word may name a path: one with a slash always
// may, a slash-free one unless its role makes it a word.
func (w word) mayNamePath() bool {
	return !w.skipBare || strings.ContainsAny(w.text, "/\\")
}

func wordTexts(words []word) []string {
	texts := make([]string, len(words))
	for i, w := range words {
		texts[i] = w.text
	}
	return texts
}
