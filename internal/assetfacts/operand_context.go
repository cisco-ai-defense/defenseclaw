// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"strings"
)

// A tool input is read as paths by three plain rules.
//
//  1. A field a tool uses for a path (Read file_path, Grep and Glob path, a
//     Glob pattern) is one path, judged whole as typed, spaces and tabs
//     included.
//  2. A shell command is read one simple command at a time. When the program
//     of a command only reads or copies (cat, grep, find, cp, sed, python,
//     and the same names behind sudo, env, command, xargs), every word after
//     it, option values included, may name a path.
//  3. Any other program (echo, printf, git) has paths only in the words with
//     a slash in them; its slash-free words are paths only in the strict tier,
//     and only where they name an existing entry of the working folder.
//
// A slash-free word is a path only when it names an existing entry of the
// working folder (see skillFolderRefs), so a word that names nothing stays a
// word in every tier.

type fieldKind int

const (
	// kindCommand is a field that holds a shell command line or an argument
	// vector.
	kindCommand fieldKind = iota
	// kindPath is a field that holds one path.
	kindPath
	// kindText is a field that holds a pattern, a query or other text: only a
	// word with a slash in it may name a path.
	kindText
	// kindOther is a field of a name no rule knows: its text is read as a
	// command line, with every word a path where it names an existing entry.
	kindOther
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

// commandKeys are the tool-input fields that hold a shell command line.
var commandKeys = map[string]bool{
	"command": true, "cmd": true, "commands": true, "script": true,
	"shellcommand": true, "commandline": true, "argv": true, "args": true,
	"bash": true, "shell": true, "run": true, "exec": true, "execute": true,
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
	case commandKeys[key]:
		return kindCommand
	}
	return kindOther
}

// isCommandField reports whether the text of a field of this kind is a shell
// command line.
func (k fieldKind) isCommandField() bool { return k == kindCommand || k == kindOther }

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
		vector := kindOfField(tool, key).isCommandField()
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

// word is one word of a command line.
type word struct {
	text string
	// segment numbers the simple command the word belongs to.
	segment int
	// redirect is set for the target of a redirection.
	redirect bool
	// eqAfter is set for a word that ended at an equals sign (NAME=, --opt=);
	// value for the word that follows it.
	eqAfter, value bool
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
// ends a word, so does a space, a comma and an equals sign). segment is the
// number of the command the first word belongs to; a command operator starts
// the next one.
func shellWords(value string, segment int) []word {
	var words []word
	var current strings.Builder
	var quote rune
	redirectNext, afterEquals := false, false
	flush := func(sep rune) {
		if current.Len() > 0 {
			words = append(words, word{
				text: current.String(), segment: segment,
				redirect: redirectNext, eqAfter: sep == 0x3d, value: afterEquals,
			})
			current.Reset()
			redirectNext, afterEquals = false, sep == 0x3d
		}
		switch {
		case isSegmentBreak(sep):
			segment++
			afterEquals, redirectNext = false, false
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

// isShellScriptFlag reports whether arg is the option that makes a shell run
// the next argument as a command line (-c, -lc).
func isShellScriptFlag(arg string) bool {
	return len(arg) >= 2 && arg[0] == 0x2d && arg[1] != 0x2d && strings.HasSuffix(arg, "c")
}

// wrapperWords run the command that follows them, or put it in a block.
var wrapperWords = map[string]bool{
	"sudo": true, "doas": true, "env": true, "time": true, "nohup": true,
	"nice": true, "ionice": true, "exec": true, "command": true, "builtin": true,
	"xargs": true, "parallel": true, "timeout": true, "stdbuf": true, "setsid": true, "watch": true,
	"if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "!": true, "{": true,
}

// wrapperValueLetters and wrapperValueLong are the options of a wrapper that
// take the next word as their value, so that word is not the program.
var wrapperValueLetters = map[string]string{
	"sudo": "ughpCDRTUrtc", "doas": "uC", "env": "uCSP", "nice": "n", "ionice": "cnpPu",
	"timeout": "sk", "stdbuf": "ioe", "xargs": "aEILnPsd", "time": "fo", "watch": "n", "exec": "a",
	"parallel": "jaNnSIL",
}

var wrapperValueLong = map[string][]string{
	"sudo": {"user", "group", "host", "prompt", "close-from", "chdir", "chroot", "role", "type", "other-user", "command-timeout"},
	"env":  {"unset", "chdir", "split-string"}, "nice": {"adjustment"}, "ionice": {"class", "classdata", "pid"},
	"timeout": {"signal", "kill-after"}, "stdbuf": {"input", "output", "error"},
	"xargs": {"arg-file", "delimiter", "eof", "max-args", "max-lines", "max-procs", "max-chars", "replace"},
	"time":  {"format", "output"}, "watch": {"interval"}, "parallel": {"jobs", "arg-file", "max-args", "delimiter"},
}

// readerPrograms read or copy the files named by their words (all of them,
// the pattern or script of a search included, since an option can make that
// word a file), so each word may name a path.
var readerPrograms = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true, "tac": true, "nl": true, "bat": true,
	"grep": true, "egrep": true, "fgrep": true, "zgrep": true, "rg": true, "ag": true, "ack": true,
	"find": true, "ls": true, "dir": true, "vdir": true, "tree": true, "du": true,
	"cp": true, "mv": true, "rsync": true, "scp": true, "tar": true, "zip": true, "unzip": true,
	"gzip": true, "gunzip": true, "zcat": true, "bzcat": true, "xzcat": true, "7z": true, "ar": true, "cpio": true,
	"sed": true, "awk": true, "gawk": true, "mawk": true, "sort": true, "uniq": true, "wc": true,
	"diff": true, "cmp": true, "comm": true, "xxd": true, "od": true, "hexdump": true, "strings": true,
	"file": true, "stat": true, "cut": true, "paste": true, "tr": true, "rev": true, "fold": true,
	"fmt": true, "column": true, "jq": true, "yq": true, "base64": true, "readlink": true, "realpath": true,
	"sha256sum": true, "shasum": true, "md5sum": true, "cksum": true,
	"python": true, "python3": true, "node": true, "ruby": true, "perl": true,
	"vi": true, "vim": true, "view": true, "nano": true, "emacs": true, "code": true, "open": true,
	"cd": true, "pushd": true, "source": true, ".": true,
	"type": true, "gc": true, "get-content": true, "select-string": true, "sls": true, "findstr": true,
	"copy": true, "xcopy": true, "robocopy": true, "move": true, "get-childitem": true, "gci": true,
}

// shellPrograms run a command line given to them with a script option (-c,
// /c, -Command); the rest of the line is judged as a command of its own.
var shellPrograms = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true,
	"pwsh": true, "powershell": true, "cmd": true,
}

// cwdSearchPrograms look through the working folder when no word names
// another place; the grep family only with a recursive option.
var cwdSearchPrograms = map[string]bool{
	"ls": true, "dir": true, "vdir": true, "tree": true, "du": true, "find": true,
	"rg": true, "ag": true, "ack": true, "grep": true, "egrep": true, "fgrep": true, "zgrep": true,
}

var recursiveGrep = map[string]bool{"grep": true, "egrep": true, "fgrep": true, "zgrep": true}

// maxShellDepth bounds the command lines read inside command lines (sh -c,
// eval).
const maxShellDepth = 4

func programName(text string) string {
	text = strings.ToLower(text)
	if i := strings.LastIndexAny(text, "/\\"); i >= 0 {
		text = text[i+1:]
	}
	return strings.TrimSuffix(text, ".exe")
}

// simpleCommand is one command of a command line: its program with the
// wrappers (sudo -u root, env X=1, xargs -n1) taken off, the words around it,
// and whether a wrapper reads the line it runs from its input.
type simpleCommand struct {
	program string
	// programWord is the program as written: a path to it has a slash.
	programWord string
	// before holds the words in front of the program that are not wrappers:
	// assignments, option values of the wrappers, redirection targets.
	before []word
	args   []word
	feeds  bool
}

func parseSimpleCommand(seg []word) simpleCommand {
	var c simpleCommand
	i := 0
	for i < len(seg) {
		w := seg[i]
		if w.redirect || w.eqAfter || w.value {
			c.before = append(c.before, w)
			i++
			continue
		}
		name := programName(w.text)
		if !wrapperWords[name] {
			c.program, c.programWord, c.args = name, w.text, seg[i+1:]
			return c
		}
		c.feeds = c.feeds || name == "xargs" || name == "parallel"
		i++
		for i < len(seg) {
			o := seg[i]
			if o.redirect || o.eqAfter || o.value {
				c.before = append(c.before, o)
				i++
				continue
			}
			if len(o.text) < 2 || o.text[0] != 0x2d {
				break
			}
			i++
			if o.text == "--" {
				break
			}
			if wrapperOptionTakesValue(name, o.text) && i < len(seg) {
				c.before = append(c.before, seg[i])
				i++
			}
		}
		if name == "timeout" && i < len(seg) {
			i++
		}
	}
	return c
}

func wrapperOptionTakesValue(wrapper, option string) bool {
	if strings.HasPrefix(option, "--") {
		for _, long := range wrapperValueLong[wrapper] {
			if option == "--"+long {
				return true
			}
		}
		return false
	}
	letters := wrapperValueLetters[wrapper]
	return letters != "" && strings.ContainsRune(letters, rune(option[len(option)-1]))
}

// commandPathWords reads a command line, or an argument vector, and returns
// the words that may name a path under the rules above, and whether a command
// in it searches dir because it names no other place (ls, grep -r). strict
// reads the slash-free words of any program as paths.
func commandPathWords(text string, argv []string, dir string, strict bool, depth int) (paths []string, cwdSearch bool) {
	var words []word
	if argv == nil {
		words = shellWords(text, 0)
	} else {
		for _, arg := range argv {
			segment := 0
			if len(words) > 0 {
				segment = words[len(words)-1].segment
			}
			words = append(words, shellWords(arg, segment)...)
		}
	}
	var commands []simpleCommand
	for start := 0; start < len(words); {
		end := start
		for end < len(words) && words[end].segment == words[start].segment {
			end++
		}
		commands = append(commands, parseSimpleCommand(words[start:end]))
		start = end
	}
	// The words a command prints are the operands of a later command that
	// reads its line from its input (echo name | xargs cat).
	lastFeed := -1
	for i, c := range commands {
		if c.feeds {
			lastFeed = i
		}
	}
	for i, c := range commands {
		more, search := c.pathWords(dir, strict || i < lastFeed, depth)
		paths = append(paths, more...)
		cwdSearch = cwdSearch || search
	}
	return paths, cwdSearch
}

// pathWords lists the words of the command that may name a path. all reads
// every word of any program as one.
func (c simpleCommand) pathWords(dir string, all bool, depth int) (paths []string, cwdSearch bool) {
	for _, w := range c.before {
		paths = append(paths, w.text)
	}
	if strings.ContainsAny(c.programWord, "/\\") {
		paths = append(paths, c.programWord)
	}
	switch {
	case readerPrograms[c.program]:
		for _, w := range c.args {
			paths = append(paths, w.text)
			paths = append(paths, attachedOptionValues(w.text)...)
		}
	case shellPrograms[c.program]:
		inner, rest, ok := shellScript(c.program, c.args)
		if ok && depth < maxShellDepth {
			more, search := commandPathWords(inner, nil, dir, all, depth+1)
			paths, cwdSearch = append(paths, more...), search
			for _, w := range rest {
				paths = append(paths, w.text)
			}
			break
		}
		for _, w := range c.args {
			paths = append(paths, w.text)
		}
	case c.program == "eval" && depth < maxShellDepth:
		texts := make([]string, len(c.args))
		for i, w := range c.args {
			texts[i] = w.text
		}
		more, search := commandPathWords(strings.Join(texts, " "), nil, dir, all, depth+1)
		paths, cwdSearch = append(paths, more...), search
	case c.program == "for" || c.program == "select":
		listed := false
		for _, w := range c.args {
			if listed {
				paths = append(paths, w.text)
			}
			listed = listed || w.text == "in"
		}
	default:
		listed := false
		for _, w := range c.args {
			listed = listed || w.text == ":::"
			if all || listed || strings.ContainsAny(w.text, "/\\") {
				paths = append(paths, w.text)
			}
		}
	}
	for _, w := range c.args {
		if w.redirect && !readerPrograms[c.program] {
			paths = append(paths, w.text)
		}
	}
	return paths, cwdSearch || c.searchesFolder(dir)
}

// attachedOptionValues are the values glued to a short option (-frules is
// -f rules): the part after each letter.
func attachedOptionValues(text string) []string {
	if len(text) < 3 || len(text) > 64 || text[0] != 0x2d || text[1] == 0x2d {
		return nil
	}
	var values []string
	for i := 2; i < len(text); i++ {
		values = append(values, text[i:])
	}
	return values
}

// shellScript finds the command line a shell is told to run: the word after
// -c for a POSIX shell, the rest of the line after /c or -Command for cmd and
// PowerShell. rest holds the words that come after a POSIX script.
func shellScript(program string, args []word) (script string, rest []word, ok bool) {
	for i, w := range args {
		lower := strings.ToLower(w.text)
		switch {
		case program == "cmd" && (lower == "/c" || lower == "/k"),
			(program == "pwsh" || program == "powershell") && (lower == "-command" || lower == "-c"):
			texts := make([]string, 0, len(args)-i-1)
			for _, t := range args[i+1:] {
				texts = append(texts, t.text)
			}
			return strings.Join(texts, " "), nil, len(texts) > 0
		case isShellScriptFlag(w.text) && program != "cmd" && program != "pwsh" && program != "powershell":
			if i+1 >= len(args) {
				return "", nil, false
			}
			return args[i+1].text, args[i+2:], true
		}
	}
	return "", nil, false
}

// searchesFolder reports whether the command looks through the working folder
// because no word names another place.
func (c simpleCommand) searchesFolder(dir string) bool {
	if !cwdSearchPrograms[c.program] {
		return false
	}
	recursive := !recursiveGrep[c.program]
	for _, w := range c.args {
		switch {
		case w.redirect:
		case strings.HasPrefix(w.text, "--"):
			recursive = recursive || w.text == "--recursive" || w.text == "--dereference-recursive"
		case len(w.text) > 1 && w.text[0] == 0x2d:
			recursive = recursive || strings.ContainsAny(w.text[1:], "rR")
		case w.text == "." || w.text == ".." || strings.HasPrefix(w.text, "~") || strings.HasPrefix(w.text, "$") ||
			strings.ContainsAny(w.text, "/\\") || namesEntryIn(dir, w.text):
			return false
		}
	}
	return recursive
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

func wordTexts(words []word) []string {
	texts := make([]string, len(words))
	for i, w := range words {
		texts[i] = w.text
	}
	return texts
}
