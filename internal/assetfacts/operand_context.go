// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// A tool input is read as paths by three plain rules.
//
//  1. A field a tool uses for a path (Read file_path, Grep and Glob path, a
//     Glob pattern) is one path, judged whole as typed, spaces and tabs
//     included.
//  2. A word of a command line with a slash in it is a path, whatever the
//     program; an argument vector element with a slash is one path whole.
//  3. A word without a slash is a path only as the name of an existing entry
//     that leads into a skill folder (a link to one, or an entry of a folder
//     inside one). The line is not split into operands for this: the check is
//     whether the text of the call holds the name of such an entry at all.
//     With a word that reads, copies, writes or runs (readerWords) it is a
//     path in every tier; without one only in the strict tier. A name is
//     matched as a substring of the text as typed and with quotes and
//     backslashes taken out, without regard to case. In the balanced tiers
//     the word that reads must be a word of a command that runs, and a
//     lookup, the body of a function nothing names and the pattern of a
//     grep or rg are left out of the scan (live_reading.go).
//
// The entries read are those of the working folder and of each folder the
// line names with a path (entryScan).

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

// splitWords splits a command line into words at blanks and at the characters
// that end a command or start a redirection or a substitution. Quotes are
// removed. A backslash before a blank or a quote makes it part of the word;
// with posix a backslash before any character does (the shell reads a\b as
// ab), without it a backslash is kept (a Windows path separator). A comma and
// an equals sign do not split: they are characters of file names.
func splitWords(value string, posix bool) []string {
	var words []string
	var current strings.Builder
	var quote rune
	flush := func() {
		if current.Len() > 0 {
			words = append(words, current.String())
			current.Reset()
		}
	}
	chars := []rune(value)
	for i := 0; i < len(chars); i++ {
		ch := chars[i]
		switch {
		case ch == 0x5c && quote != 0x27 && i+1 < len(chars):
			next := chars[i+1]
			if posix || next == 0x20 || next == 0x09 || next == 0x22 || next == 0x27 {
				current.WriteRune(next)
				i++
				continue
			}
			current.WriteRune(ch)
		case (ch == 0x22 || ch == 0x27) && (quote == 0 || quote == ch):
			if quote == 0 {
				quote = ch
			} else {
				quote = 0
			}
		case quote == 0 && strings.ContainsRune(" \t\r\n;|&()<>`", ch):
			flush()
		default:
			current.WriteRune(ch)
		}
	}
	flush()
	return words
}

// slashWords lists the words of a command line that have a slash in them,
// each spelled as the shell reads it (with and without backslash escapes) and
// also split at the commas and equals signs that may join a value to an
// option (--file=/x/y, NAME=/x/y). Such a word is a path in every tier.
func slashWords(value string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(word string) {
		if strings.ContainsAny(word, "/\\") && !seen[word] {
			seen[word] = true
			out = append(out, word)
		}
	}
	for _, posix := range []bool{false, true} {
		for _, word := range splitWords(value, posix) {
			add(word)
			if strings.ContainsAny(word, "=,") {
				for _, part := range strings.FieldsFunc(word, func(r rune) bool { return r == 0x3d || r == 0x2c }) {
					add(part)
				}
			}
		}
	}
	return out
}

// isShellScriptFlag reports whether arg is the option that makes a shell run
// the next argument as a command line (-c, -lc).
func isShellScriptFlag(arg string) bool {
	return len(arg) >= 2 && arg[0] == 0x2d && arg[1] != 0x2d && strings.HasSuffix(arg, "c")
}

// The words of a command line that read, copy, write, search or run what their
// operands name, in three groups.
const (
	readerList = `cat head tail less more tac nl bat grep egrep fgrep zgrep rg ag ack find ls dir vdir tree du
cp mv rsync scp tar zip unzip gzip gunzip zcat bzcat xzcat 7z ar cpio sed awk gawk mawk sort uniq wc
diff cmp comm xxd od hexdump strings file stat cut paste tr rev fold fmt column jq yq base64
readlink realpath sha256sum shasum md5sum cksum python python3 node ruby perl vi vim view nano
emacs code open cd pushd source read mapfile readarray type gc get-content select-string sls findstr
copy xcopy robocopy move get-childitem gci get-item gi get-itemproperty`
	writerList = `tee dd install ln rm rmdir touch truncate chmod chown chgrp mkdir unlink shred patch sponge mklink
del erase rd ren rename set-content add-content out-file copy-item cpi move-item mi remove-item ri`
	// runnerList are the shells, evaluators and wrappers that run another
	// command.
	runnerList = `sh bash zsh dash ksh fish pwsh powershell cmd eval sudo doas env xargs parallel command builtin exec
time nohup nice ionice timeout stdbuf setsid watch`
)

func wordSet(lists ...string) map[string]bool {
	set := map[string]bool{}
	for _, list := range lists {
		for _, word := range strings.Fields(list) {
			set[word] = true
		}
	}
	return set
}

// readerWords are all three groups: a command line that holds the name of a
// protected link and one of them may use it.
var readerWords = wordSet(readerList, writerList, runnerList)

// folderReaders are the programs that read, copy or search the files of the
// folder they run in when no operand names another place: the readers, less
// the words that move the shell or read its own input.
var folderReaders = func() map[string]bool {
	set := wordSet(readerList)
	for _, name := range strings.Fields("cd pushd source read mapfile readarray type") {
		delete(set, name)
	}
	return set
}()

var (
	// runnerShells run the command line of their -c option, or a script file.
	runnerShells = wordSet("sh bash zsh dash ksh fish pwsh powershell cmd")
	// runnerWrappers run the command that follows their own options.
	runnerWrappers = wordSet("sudo doas env xargs parallel command builtin exec time nohup nice ionice timeout stdbuf setsid watch")
	evalWord       = wordSet("eval")
)

func programName(text string) string {
	text = strings.ToLower(text)
	if i := strings.LastIndexAny(text, "/\\"); i >= 0 {
		text = text[i+1:]
	}
	return strings.TrimSuffix(text, ".exe")
}

// textForms are the spellings of a command line the name check reads: as
// typed, and with the quote, escape and caret characters taken out (c\at,
// 'cat' and nee\dle read as cat and needle). They are lower case: the file
// systems of Windows and macOS do not tell the case of a name.
func textForms(line string) []string {
	lower := strings.ToLower(line)
	plain := strings.NewReplacer(`\`, "", `'`, "", `"`, "", "^", "", "`", "").Replace(lower)
	if plain == lower {
		return []string{lower}
	}
	return []string{lower, plain}
}

// safeRedirect matches the redirections that read or write no file of a
// call: a duplicated descriptor and the null device.
var safeRedirect = regexp.MustCompile(`[0-9&]?>>?\s*/dev/null|[0-9]*>&[0-9-]+|&>>?\s*/dev/null`)

// holdsReaderWord reports whether the command line holds one of the readerWords
// as a word of its own, a read redirection (<, a write: >) or the dot command.
func holdsReaderWord(forms []string) bool {
	for _, form := range forms {
		for _, word := range strings.FieldsFunc(form, func(r rune) bool {
			return !isWordRune(r)
		}) {
			if readerWords[word] {
				return true
			}
		}
		for _, word := range strings.FieldsFunc(form, func(r rune) bool { return strings.ContainsRune(" \t\r\n;|&()", r) }) {
			if word == "." {
				return true
			}
		}
		if strings.ContainsAny(safeRedirect.ReplaceAllString(form, " "), "<>") {
			return true
		}
	}
	return false
}

// isWordRune is a character of a program name: a lower-case letter, a digit,
// a hyphen or an underscore.
func isWordRune(r rune) bool {
	return r >= 0x61 && r <= 0x7a || r >= 0x30 && r <= 0x39 || r == 0x2d || r == 0x5f
}

// maxRunnerDepth bounds the command lines read inside command lines (sh -c,
// eval); past it the line cannot be told.
const maxRunnerDepth = 8

// runsFolderReader reports whether a command runs a program that reads, copies
// or searches the folder it runs in (folderReaders: ls, find, cat, cp, grep,
// ...), whatever its other words are: the working folder is held or denied,
// and a reader started there may read it. The line is read with the shell
// parser, so only a word in the place of a program is a program: text inside
// quotes, an argument or a redirection target never starts one. The program
// is read behind the wrappers (sudo, env, xargs, nice, ...) and inside sh -c
// and eval. Where the line cannot be told (it does not parse, a program is
// named by an expansion or a pattern, runners nest past maxRunnerDepth) the
// answer is cannotTell. An argument vector is one command.
func runsFolderReader(line string, argv []string, cannotTell bool) bool {
	if argv != nil {
		words := make([]commandWord, len(argv))
		for i, element := range argv {
			words[i] = commandWord{text: element, names: []string{programName(element)}}
		}
		return wordsRunReader(words, 0, cannotTell)
	}
	return textRunsReader(line, 0, cannotTell)
}

func textRunsReader(text string, depth int, cannotTell bool) bool {
	if depth > maxRunnerDepth {
		return cannotTell
	}
	file, ok := shellparse.Parse(text)
	if !ok {
		return cannotTell
	}
	called := calledFunctions(file)
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if decl, ok := node.(*syntax.FuncDecl); ok {
			// A definition runs nothing; its body runs where the function is called.
			return called[decl.Name.Value]
		}
		if call, ok := node.(*syntax.CallExpr); ok && !found && len(call.Args) > 0 {
			words := make([]commandWord, len(call.Args))
			for i, arg := range call.Args {
				words[i] = readCommandWord(arg)
			}
			found = wordsRunReader(words, depth, cannotTell)
		}
		return !found
	})
	return found
}

// calledFunctions are the functions the command line defines and names as a
// word of a command that runs (a call, an argument of eval, trap, time, ...).
// A function nothing names never runs, so the commands of its body are not
// commands of the line. A name found only inside the body of a function that
// is itself not named does not count, so the answer is a fixed point. A
// command that runs a program named by an expansion (reader=f; "$reader") or
// hands one to eval may call any function: then every function is called.
func calledFunctions(file *syntax.File) map[string]bool {
	defined := map[string]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if decl, ok := node.(*syntax.FuncDecl); ok {
			defined[decl.Name.Value] = true
		}
		return true
	})
	called := map[string]bool{}
	for changed := len(defined) > 0; changed; {
		changed = false
		syntax.Walk(file, func(node syntax.Node) bool {
			switch n := node.(type) {
			case *syntax.FuncDecl:
				return called[n.Name.Value]
			case *syntax.CallExpr:
				if runsByValue(n.Args) {
					for name := range defined {
						if !called[name] {
							called[name] = true
							changed = true
						}
					}
				}
				for _, arg := range n.Args {
					text := readCommandWord(arg).text
					for _, token := range append(strings.FieldsFunc(text, func(r rune) bool { return strings.ContainsRune(" \t\r\n;|&()<>", r) }), text) {
						if defined[token] && !called[token] {
							called[token] = true
							changed = true
						}
					}
				}
			}
			return true
		})
	}
	return called
}

// runsByValue reports whether a simple command runs a program, or a command
// line, that its words do not spell: its program is an expansion, or it is a
// wrapper, shell or eval with an expansion among its words.
func runsByValue(args []*syntax.Word) bool {
	words := make([]commandWord, len(args))
	for i, arg := range args {
		words[i] = readCommandWord(arg)
	}
	if len(words) == 0 {
		return false
	}
	if words[0].dynamic {
		return true
	}
	if words[0].isOneOf(runnerWrappers) || words[0].isOneOf(runnerShells) || words[0].isOneOf(evalWord) || words[0].isOneOf(wordSet("trap")) {
		return slices.ContainsFunc(words[1:], func(word commandWord) bool { return word.dynamic })
	}
	return false
}

// commandWord is one word of a simple command as the parser read it.
type commandWord struct {
	// text is the word with its quotes and escapes taken out.
	text string
	// names are the program names the word may spell: read as the shell does,
	// and with a backslash kept as a path separator (a Windows path).
	names []string
	// dynamic is set for a word that holds an expansion or a pattern: its
	// value is not in the text.
	dynamic bool
	// start and end are the byte offsets of the word in the parsed text.
	start, end int
}

func (w commandWord) isOneOf(set map[string]bool) bool {
	return slices.ContainsFunc(w.names, func(name string) bool { return set[name] })
}

func (w commandWord) isOption() bool { return strings.HasPrefix(w.text, "-") }

func readCommandWord(word *syntax.Word) commandWord {
	var raw, text strings.Builder
	out := commandWord{start: int(word.Pos().Offset()), end: int(word.End().Offset())}
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			raw.WriteString(p.Value)
			text.WriteString(unescapeLit(p.Value, false))
			if p.Value != "[" && strings.ContainsAny(p.Value, "*?[{") {
				out.dynamic = true
			}
		case *syntax.SglQuoted:
			raw.WriteString(p.Value)
			text.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				if lit, ok := inner.(*syntax.Lit); ok {
					raw.WriteString(lit.Value)
					text.WriteString(unescapeLit(lit.Value, true))
				} else {
					out.dynamic = true
				}
			}
		default:
			out.dynamic = true
		}
	}
	out.text = text.String()
	out.names = []string{programName(raw.String())}
	if name := programName(out.text); name != out.names[0] {
		out.names = append(out.names, name)
	}
	return out
}

// unescapeLit takes the backslash escapes out of a literal: any character in
// the open, only the ones that stay special inside double quotes.
func unescapeLit(value string, quoted bool) string {
	if !strings.Contains(value, "\\") {
		return value
	}
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == 0x5c && i+1 < len(value) && (!quoted || strings.IndexByte("$`\"\\\n", value[i+1]) >= 0) {
			i++
		}
		out.WriteByte(value[i])
	}
	return out.String()
}

func wordsRunReader(words []commandWord, depth int, cannotTell bool) bool {
	for i := 0; i < len(words); i++ {
		word := words[i]
		switch {
		case word.dynamic:
			return cannotTell
		case word.isOneOf(folderReaders):
			return true
		case word.isOneOf(runnerShells), word.isOneOf(evalWord):
			return shellRunsReader(word, words[i+1:], depth, cannotTell)
		case word.isOneOf(runnerWrappers):
			next, queryOnly := skipWrapperOptions(word, words, i+1)
			if queryOnly {
				return false
			}
			i = next - 1
		default:
			return false
		}
	}
	return false
}

// optionSpec names the options of a wrapper that take their value from the
// next word: short letters (a cluster of letters ends in one, -nu root) and
// long names (--unset NAME). The word after such an option is a value, whatever
// it spells (env -u cat, sudo -u cat).
type optionSpec struct {
	short string
	long  []string
}

var wrapperValueOptions = map[string]optionSpec{
	"env":      {"uC", []string{"unset", "chdir"}},
	"sudo":     {"CDRTUgprtu", []string{"close-from", "chdir", "chroot", "command-timeout", "other-user", "group", "prompt", "role", "type", "user", "host"}},
	"doas":     {"uC", nil},
	"xargs":    {"EILPadns", []string{"arg-file", "delimiter", "max-args", "max-procs", "max-lines", "max-chars"}},
	"parallel": {"jnNLSa", nil},
	"nice":     {"n", []string{"adjustment"}},
	"ionice":   {"cnpPu", []string{"class", "classdata", "pid", "pgid", "uid"}},
	"timeout":  {"sk", []string{"signal", "kill-after"}},
	"stdbuf":   {"ioe", []string{"input", "output", "error"}},
	"watch":    {"n", []string{"interval"}},
	"time":     {"fo", []string{"format", "output"}},
	"exec":     {"a", nil},
}

// takesValue reports whether the option, as one word, takes the next word as
// its value: a long option without an attached =value, a short option that
// ends its cluster.
func (s optionSpec) takesValue(option string) bool {
	if strings.HasPrefix(option, "--") {
		name, _, attached := strings.Cut(option[2:], "=")
		return !attached && slices.Contains(s.long, name)
	}
	letters := option[1:]
	for j := 0; j < len(letters); j++ {
		if strings.IndexByte(s.short, letters[j]) >= 0 {
			return j == len(letters)-1
		}
	}
	return false
}

// queriesCommand reports whether the wrapper only looks a command up
// (command -v, command -V) and runs nothing.
func queriesCommand(wrapper commandWord, option string) bool {
	return wrapper.isOneOf(wordSet("command")) && !strings.HasPrefix(option, "--") && strings.ContainsAny(option[1:], "vV")
}

// skipWrapperOptions returns the index of the program a wrapper runs: the
// options of the wrapper, the value of an option that takes one, the word
// after any other option, a variable assignment and a number (timeout 5) come
// first. queryOnly is set where the wrapper runs no program.
func skipWrapperOptions(wrapper commandWord, words []commandWord, from int) (next int, queryOnly bool) {
	var spec optionSpec
	for _, name := range wrapper.names {
		if known, ok := wrapperValueOptions[name]; ok {
			spec = known
		}
	}
	afterOption := false
	i := from
	for ; i < len(words); i++ {
		word := words[i]
		if !word.dynamic && word.isOption() {
			if queriesCommand(wrapper, word.text) {
				return len(words), true
			}
			if spec.takesValue(word.text) {
				i++
				afterOption = false
				continue
			}
		}
		if word.dynamic || word.isOneOf(folderReaders) || word.isOneOf(runnerShells) || word.isOneOf(runnerWrappers) || word.isOneOf(evalWord) {
			break
		}
		assignment := strings.Contains(word.text, "=")
		number := word.text != "" && word.text[0] >= 0x30 && word.text[0] <= 0x39
		if !word.isOption() && !afterOption && !assignment && !number {
			break
		}
		afterOption = word.isOption() && !assignment
	}
	return i, false
}

// shellRunsReader reads the command line a shell or eval is given: the word
// after -c, the rest of the line after /c, /k or -Command, the joined words of
// eval. A shell given a script file runs what it holds, so it is a reader.
func shellRunsReader(shell commandWord, rest []commandWord, depth int, cannotTell bool) bool {
	script := func(from []commandWord) bool {
		texts := make([]string, len(from))
		for i, word := range from {
			if word.dynamic {
				return cannotTell
			}
			texts[i] = word.text
		}
		return textRunsReader(strings.Join(texts, " "), depth+1, cannotTell)
	}
	if shell.isOneOf(evalWord) {
		return script(rest)
	}
	for i, word := range rest {
		switch flag := strings.ToLower(word.text); {
		case flag == "/c", flag == "/k", flag == "-command":
			return script(rest[i+1:])
		case !word.dynamic && isShellScriptFlag(word.text):
			if i+1 < len(rest) {
				return script(rest[i+1 : i+2])
			}
			// The line follows as a field of its own.
			return false
		}
	}
	for _, word := range rest {
		if word.dynamic && cannotTell || !word.dynamic && !word.isOption() {
			return true
		}
	}
	return false
}

// maxListedEntries bounds the entries read from one folder, and
// maxNamedFolders the folders besides the working folder a command line may
// name.
const (
	maxListedEntries = 8192
	maxNamedFolders  = 64
	maxNamedWords    = 256
)

// entryScan finds the entries of a folder, and the skill folders they lead
// into, whose names a command line holds. It is made for one call: the
// listings and the answers are kept.
type entryScan struct {
	home, account string
	listed        map[string]listing
	resolved      map[string][]FolderRef
	// cut is set when folders stopped at its room.
	cut bool
}

type listing struct {
	names    []string
	complete bool
}

func newEntryScan(home, account string) *entryScan {
	return &entryScan{home: home, account: account, listed: map[string]listing{}, resolved: map[string][]FolderRef{}}
}

func (s *entryScan) entries(dir string) listing {
	if l, ok := s.listed[dir]; ok {
		return l
	}
	var l listing
	if filepath.IsAbs(dir) && readableTarget(dir) {
		if f, err := fsOpen(dir); err == nil {
			names, _ := f.Readdirnames(maxListedEntries + 1)
			f.Close()
			l = listing{names: names, complete: len(names) <= maxListedEntries}
		}
	}
	s.listed[dir] = l
	return l
}

// folders lists the skill folders reached by the entries of the working
// folder, and of each folder the command line names with a path, whose names
// the command line holds anywhere in its text, whatever the words around them
// are. The name of an entry is what the shell is given, however the line is
// split, quoted or run, so no reading of the line can hide it. A folder too
// large to list is read word by word. It stops reading entries once it has
// room folders (and sets cut): a call that names more is judged as one that
// was cut.
func (s *entryScan) folders(line, cwd string, room int) []FolderRef {
	if room <= 0 {
		s.cut = true
		return nil
	}
	forms := textForms(line)
	dirs := []string{cwd}
	named := slashWords(line)
	for i, word := range splitWords(line, true) {
		// A word with no slash that is a folder of the working folder
		// (cd sub; cat name) names that folder too.
		if strings.ContainsAny(word, "/\\") {
			continue
		}
		name, placed := driveRelativeName(word, cwd)
		if placed && i < maxNamedWords {
			named = append(named, "./"+name)
		}
	}
	for _, word := range named {
		for _, dir := range s.namedFolders(word, cwd) {
			if len(dirs) <= maxNamedFolders && !slices.Contains(dirs, dir) {
				dirs = append(dirs, dir)
			}
		}
	}
	var refs []FolderRef
	for _, dir := range dirs {
		l := s.entries(dir)
		names := l.names
		if !l.complete {
			names = nil
			for _, word := range splitWords(line, true) {
				if !strings.ContainsAny(word, "/\\") {
					if name, placed := driveRelativeName(word, cwd); placed && namesEntryIn(dir, name) {
						names = append(names, name)
					}
				}
			}
		}
		for _, name := range names {
			lower := strings.ToLower(name)
			if lower == "" || !slices.ContainsFunc(forms, func(form string) bool { return strings.Contains(form, lower) }) {
				continue
			}
			if len(refs) >= room {
				s.cut = true
				return refs
			}
			refs = append(refs, s.reached(filepath.Join(dir, name))...)
		}
	}
	return refs
}

// driveRelativeName gives the entry name a slash-free word of a command line
// names in the working folder cwd. A word with a drive in front and nothing
// else (D:lnk) is relative to the working folder of that drive, as the system
// reads it: the name after the drive when the drive is the drive of cwd. On
// another drive the working folder is not in the hook event, so the word
// cannot be placed: it is recorded as a path whose links are unproven
// (UnprovenLinkNote), as the same word with a slash in it is, and reports
// placed false. A word with no drive is its own name.
func driveRelativeName(word, cwd string) (name string, placed bool) {
	volume := filepath.VolumeName(word)
	if volume == "" {
		return word, true
	}
	if strings.EqualFold(volume, filepath.VolumeName(cwd)) {
		return word[len(volume):], true
	}
	if UnprovenLinkNote != nil {
		UnprovenLinkNote()
	}
	return "", false
}

// reached lists the skill folders the entry at path leads into.
func (s *entryScan) reached(path string) []FolderRef {
	if refs, ok := s.resolved[path]; ok {
		return refs
	}
	refs := skillFolderRefs(path, s.home, "", s.account)
	for i := range refs {
		refs[i].BareOperand = true
	}
	s.resolved[path] = refs
	return refs
}

// namedFolders lists the folders a path word of the command line leads to: the
// path itself where it is a folder, and the folder that holds it.
func (s *entryScan) namedFolders(word, cwd string) []string {
	path := filepath.FromSlash(trimExtendedPrefix(strings.ReplaceAll(word, "\\", "/")))
	path = expandHome(path, s.home, s.account)
	if strings.HasPrefix(path, "~") || strings.Contains(path, "$") {
		return nil
	}
	path = placeIn(path, cwd)
	var out []string
	for _, dir := range []string{filepath.Clean(path), filepath.Dir(filepath.Clean(path))} {
		if readableTarget(dir) {
			if info, err := fsStat(dir); err == nil && info.IsDir() {
				out = append(out, dir)
			}
		}
	}
	return out
}

// expandHome spells a leading ~/, ~caller/, $HOME/ or ${HOME}/ with the home
// folder.
func expandHome(path, home, caller string) string {
	path = filepath.ToSlash(path)
	if home == "" {
		return filepath.FromSlash(path)
	}
	prefixes := []string{"~/", "$HOME/", "${HOME}/"}
	if caller != "" && !strings.ContainsAny(caller, "/\\") {
		prefixes = append([]string{"~" + caller + "/"}, prefixes...)
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return filepath.FromSlash(filepath.ToSlash(home) + "/" + strings.TrimPrefix(path, prefix))
		}
	}
	return filepath.FromSlash(path)
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
