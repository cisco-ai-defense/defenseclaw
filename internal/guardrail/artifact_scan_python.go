// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Python path rules describe a write, not a mention. Keep the original byte
// offsets for finding locations while ignoring comments and docstrings.
var pythonAssignment = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z_0-9]*)\s*=`)
var pythonWriteMethod = regexp.MustCompile(`\.(?:write_text|write_bytes|unlink|rmdir|rename|touch)\s*\(`)
var pythonModuleWrite = regexp.MustCompile(`\b(?:os\.(?:remove|unlink|rename|replace|truncate|rmdir|removedirs)|shutil\.(?:move|rmtree|copy|copy2|copyfile|copytree))\s*\(`)
var pythonWriteOpen = regexp.MustCompile(`\bopen\s*\([^\n)]*,\s*["'][rbtU]*[wax+]`)
var pythonPathCall = regexp.MustCompile(`\bPath\s*\(`)
var pythonName = regexp.MustCompile(`[A-Za-z_][A-Za-z_0-9]*`)

// pythonPathWriteMatch returns the first match of rule, a path, that a write
// call acts on. The path may sit in a string; the write call must start in
// code (MaskPythonStrings), since a call spelled in a string or in the
// literal text of an f-string runs nothing, unless the code may run a string
// (PythonStringsMayRun), when the masked text counts whole as before.
// script is the absolute path of the file, "" when it is not known: Python
// imports from the script's directory first.
func pythonPathWriteMatch(rule *regexp.Regexp, source, script string) []int {
	code := MaskPythonCommentsAndDocstrings(source)
	calls := MaskPythonStrings(source)
	dir, self := "", ""
	if script != "" {
		dir, self = filepath.Split(script)
		dir = filepath.Clean(dir)
	}
	if pythonStringsMayRun(calls, dir, self) {
		calls = code
	}
	lines := strings.Split(code, "\n")
	callLines := strings.Split(calls, "\n")
	if len(callLines) != len(lines) {
		callLines = lines
	}
	for _, hit := range rule.FindAllStringIndex(code, -1) {
		lineNo := strings.Count(code[:hit[0]], "\n")
		if lineNo >= len(lines) {
			continue
		}
		lineStart := hit[0] - strings.LastIndex(code[:hit[0]], "\n") - 1
		line := lines[lineNo]
		if pythonLineWritesPath(line, callLines[lineNo], lineStart, hit[1]-hit[0]) {
			return hit
		}
		assign := pythonAssignment.FindStringSubmatch(line)
		if len(assign) != 2 || strings.Index(line, "=") > lineStart {
			continue
		}
		// A path assigned to a name is a write when a later statement uses
		// that name as the path argument. This covers Path.home()/"name"
		// followed by open(target, "a"), the common skill-script form.
		for offset, later := range lines[lineNo+1:] {
			if pythonLineWritesName(later, callLines[lineNo+1+offset], assign[1]) {
				return hit
			}
		}
	}
	return nil
}

// pythonLineWritesPath reports whether a write call on line acts on the
// path at column. calls is the line with its string text blanked
// (MaskPythonStrings): a write call must start in code.
func pythonLineWritesPath(line, calls string, column, width int) bool {
	if column < 0 || column+width > len(line) || len(calls) != len(line) {
		return false
	}
	// The path must be inside the argument list, not elsewhere on a line
	// that happens to have another write call.
	for _, re := range []*regexp.Regexp{pythonModuleWrite, pythonWriteOpen} {
		for _, call := range re.FindAllStringIndex(line, -1) {
			if pythonCodeAt(line, calls, call[0]) && pythonCallContains(line, call[0], column, column+width) {
				return true
			}
		}
	}
	// pathlib's mutation methods act on the preceding Path object.
	for _, path := range pythonPathCall.FindAllStringIndex(line, -1) {
		end := pythonCallEnd(line, path[1]-1)
		if end >= column+width && column >= path[1] && pythonCodeAt(line, calls, path[0]) &&
			pythonWriteMethod.MatchString(strings.TrimSpace(calls[end+1:])) {
			return true
		}
	}
	return false
}

// pythonLineWritesName reports whether a write call in the code of line
// (calls, the line with its string text blanked) acts on the variable name.
func pythonLineWritesName(line, calls, name string) bool {
	if len(calls) != len(line) {
		return false
	}
	for _, re := range []*regexp.Regexp{pythonModuleWrite, pythonWriteOpen} {
		for _, call := range re.FindAllStringIndex(line, -1) {
			if !pythonCodeAt(line, calls, call[0]) {
				continue
			}
			end := pythonCallEnd(line, strings.IndexByte(line[call[0]:], '(')+call[0])
			if end > call[0] && containsPythonName(calls[call[0]:end], name) {
				return true
			}
		}
	}
	for _, method := range pythonWriteMethod.FindAllStringIndex(line, -1) {
		if pythonCodeAt(line, calls, method[0]) && containsPythonName(calls[:method[0]], name) {
			return true
		}
	}
	return false
}

// pythonCodeAt reports whether text[i] is code: MaskPythonStrings kept it.
func pythonCodeAt(text, calls string, i int) bool {
	return i >= 0 && i < len(text) && i < len(calls) && text[i] != ' ' && calls[i] == text[i]
}

func containsPythonName(text, name string) bool {
	for _, pos := range pythonName.FindAllStringIndex(text, -1) {
		if text[pos[0]:pos[1]] == name {
			return true
		}
	}
	return false
}

func pythonCallContains(line string, callStart, matchStart, matchEnd int) bool {
	openRel := strings.IndexByte(line[callStart:], '(')
	if openRel < 0 {
		return false
	}
	open := callStart + openRel
	end := pythonCallEnd(line, open)
	return end >= matchEnd && matchStart > open
}

func pythonCallEnd(line string, open int) int {
	if open < 0 || open >= len(line) || line[open] != '(' {
		return -1
	}
	depth := 0
	var quote byte
	escaped := false
	for i := open; i < len(line); i++ {
		switch c := line[i]; {
		case quote != 0:
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// MaskPythonCommentsAndDocstrings blanks the comments and the triple-quoted
// strings of Python source in place, so matches keep their offsets: they can
// mention paths without executing a write. An f- or t-string runs the
// expressions of its replacement fields, so those are kept and its literal
// text is blanked: the text around the fields, the literal text of a format
// spec (f"{x:spec}", whose nested fields run), a conversion (!r) and a
// self-documenting "=" (f"{x=}"). Source whose strings the scan cannot
// follow (an unclosed string or field, nesting past pythonMaxStringNesting) is
// returned unmasked: blanking from a wrong string boundary could hide code.
func MaskPythonCommentsAndDocstrings(source string) string {
	out := []byte(source)
	for i := 0; i < len(out); {
		switch out[i] {
		case '#':
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case '\'', '"':
			var exprs [][2]int
			end, ok := pythonStringEnd(out, i, 0, &exprs)
			if !ok {
				return source
			}
			if pythonTripleQuoteAt(out, i) {
				// Blank the literal text around the field expressions, which run.
				from := i
				for _, expr := range exprs {
					blankPythonText(out[from:expr[0]])
					from = expr[1]
				}
				blankPythonText(out[from:end])
			}
			i = end
		default:
			i++
		}
	}
	return string(out)
}

// MaskPythonStrings blanks the comments of Python source and the text of
// every string literal in place, quotes included, keeping the expressions of
// the replacement fields of f- and t-strings (whose own strings are blanked
// too; format spec text is literal text): what is left is the code that
// runs. A call spelled inside a string, or in the literal text of a one-line
// f-string, is data, not a call. Source whose strings the scan cannot follow
// is returned unmasked (fail closed).
func MaskPythonStrings(source string) string {
	out := []byte(source)
	if !maskPythonStrings(out, 0, len(out), 0) {
		return source
	}
	return string(out)
}

func maskPythonStrings(out []byte, from, to, depth int) bool {
	for i := from; i < to; {
		switch out[i] {
		case '#':
			for i < to && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case '\'', '"':
			var exprs [][2]int
			end, ok := pythonStringEnd(out, i, depth, &exprs)
			if !ok || end > to {
				return false
			}
			text := i
			for _, expr := range exprs {
				blankPythonText(out[text:expr[0]])
				if !maskPythonStrings(out, expr[0], expr[1], depth+1) {
					return false
				}
				text = expr[1]
			}
			blankPythonText(out[text:end])
			i = end
		default:
			i++
		}
	}
	return true
}

// pythonStringRunFragments are the names (lower case, matched inside an
// identifier) through which code can turn string text into code that runs,
// or reach a string that does not run: dynamic evaluation and name lookup,
// child processes, serializers that call, introspection of code, frames and
// docstrings, the program's own command line, and a file the code writes,
// renames, links, moves, unpacks or fetches into place (and may import or
// run later: os.symlink(staged, "json.py") puts a module before the
// standard library).
var pythonStringRunFragments = []string{
	"exec", "eval", "compile", "getattr", "attrgetter", "methodcaller",
	"globals", "locals", "vars", "__dict__", "__import__", "importlib",
	"import_module", "builtins", "runpy", "pkgutil", "pydoc", "loader",
	"subprocess", "system", "popen", "spawn", "startfile", "createprocess",
	"winapi", "ctypes", "cffi", "marshal", "pickle", "shelve", "yaml",
	"interact", "timeit", "profile", "trace", "breakpoint", "doc", "__code__",
	"co_consts", "co_code", "frame", "inspect", "modules", "subclasses",
	"__base", "argv", "cmdline", "commandline", "procargs", "psutil",
	"sysctl", "linecache", "source", "write", "open", "dump", "copy",
	"logging", "handler", "rename", "replace", "link", "move", "extract",
	"unpack", "retrieve", "mkfifo", "mknod",
}

// pythonStringRunNames are short names matched whole.
var pythonStringRunNames = map[string]bool{
	"code": true, "pty": true, "pdb": true, "bdb": true, "gc": true, "mro": true,
}

// PythonStringsMayRun reports whether code, Python source masked with
// MaskPythonStrings, may run or read the text of one of its strings or
// docstrings. dir is the directory Python puts first on sys.path when it
// runs the code (the working directory for python -c, the script's own
// directory for a script), or "" when it is not known.
//
// A module an import loads may run any string of the program: a file such as
// subprocess.py, json.py or helper.py on sys.path reads the program's
// docstring through sys.modules["__main__"] and its command line through
// sys.orig_argv. Every program may import, with or without an import
// statement: the interpreter imports on its own ("a".encode("idna") imports
// stringprep and re, help() imports pydoc), first from dir. So the strings
// count unless every import loads only standard-library code
// (pythonImportPathOrdinary): every module an import statement names is in
// the standard library, dir is known and holds nothing an import can load,
// and nothing moves the import path. An "import" the scan cannot read as a
// statement counts, and so does any non-ASCII byte in code: Python reads
// identifiers in NFKC form, so a fullwidth ｅｘｅｃ is exec and import ｊｓｏｎ imports
// json, names this scan cannot match. A name of pythonStringRunFragments or
// pythonStringRunNames in code counts too. A name an import binds does not
// count when the program uses no name that statement binds. Nor does a
// variable of the program's own (source = 1, def doc(x), f(write=True)): a
// plain name, not an attribute, that is not a builtin or a module dunder
// (exec, open, __doc__) and that no import may bind (named in an import, or
// any "from m import *") holds only a value that code this scan reads
// computed, so the name reaches no sink that code does not name.
func PythonStringsMayRun(code, dir string) bool {
	return pythonStringsMayRun(code, dir, "")
}

// pythonStringsMayRun is PythonStringsMayRun for a script named self in dir:
// its own file is the code the scan reads, not a module beside it.
func pythonStringsMayRun(code, dir, self string) bool {
	for i := 0; i < len(code); i++ {
		if code[i] >= utf8.RuneSelf {
			return true
		}
	}
	names := pythonName.FindAllStringIndex(code, -1)
	var statements, unused [][2]int
	imported, star := map[string]bool{}, false
	for _, statement := range pythonImports(code) {
		text := code[statement.span[0]:statement.span[1]]
		if !pythonImportsStandardLibrary(text) {
			return true
		}
		statements = append(statements, statement.span)
		if statement.bound == nil {
			star = true
		} else if !pythonNamesUsed(code, names, statement.bound, statement.span[0], statement.span[1]) {
			unused = append(unused, statement.span)
		}
		for _, name := range pythonName.FindAllString(text, -1) {
			imported[name] = true
		}
	}
	within := func(name []int, spans [][2]int) bool {
		return slices.ContainsFunc(spans, func(span [2]int) bool {
			return name[0] >= span[0] && name[1] <= span[1]
		})
	}
	for _, name := range names {
		word := code[name[0]:name[1]]
		if word == "import" && !within(name, statements) {
			return true // from.m import x, or another form the scan does not read
		}
		if !pythonStringRunName(strings.ToLower(word)) || within(name, unused) {
			continue
		}
		if !star && !imported[word] && pythonProgramVariable(code, name[0], word) {
			continue
		}
		return true
	}
	// Read last: it reads dir.
	return !pythonImportPathOrdinary(code, dir, self)
}

// pythonStandardModules are the top-level public modules of the standard
// library (sys.stdlib_module_names of Python 3.12, less the modules Python
// 3.13 removed and tomllib, which Python 3.10 lacks, plus __future__), less
// site and zipimport, which load code from any directory or archive they are
// given (site.addsitedir runs the import lines of a .pth file there). A
// missing one would be looked up past the standard library, in
// site-packages; so would a module only one platform ships (winreg on
// Linux), the same residual as any installed module.
var pythonStandardModules = func() map[string]bool {
	set := map[string]bool{"__future__": true}
	for _, name := range strings.Fields(`abc antigravity argparse array ast
		asyncio atexit base64 bdb binascii bisect builtins bz2 cProfile calendar
		cmath cmd code codecs codeop collections colorsys compileall concurrent
		configparser contextlib contextvars copy copyreg csv ctypes curses
		dataclasses datetime dbm decimal difflib dis doctest email encodings
		ensurepip enum errno faulthandler fcntl filecmp fileinput fnmatch
		fractions ftplib functools gc genericpath getopt getpass gettext glob
		graphlib grp gzip hashlib heapq hmac html http idlelib imaplib
		importlib inspect io ipaddress itertools json keyword linecache locale
		logging lzma mailbox marshal math mimetypes mmap modulefinder msvcrt
		multiprocessing netrc nt ntpath nturl2path numbers opcode operator
		optparse os pathlib pdb pickle pickletools pkgutil platform plistlib
		poplib posix posixpath pprint profile pstats pty pwd py_compile pyclbr
		pydoc pydoc_data pyexpat queue quopri random re readline reprlib
		resource rlcompleter runpy sched secrets select selectors shelve shlex
		shutil signal smtplib socket socketserver sqlite3 sre_compile
		sre_constants sre_parse ssl stat statistics string stringprep struct
		subprocess symtable sys sysconfig syslog tabnanny tarfile tempfile
		termios textwrap this threading time timeit tkinter token tokenize trace
		traceback tracemalloc tty turtle turtledemo types typing unicodedata
		unittest urllib uuid venv warnings wave weakref webbrowser winreg
		winsound wsgiref xml xmlrpc zipapp zipfile zlib zoneinfo`) {
		set[name] = true
	}
	return set
}()

// pythonImportsStandardLibrary reports whether statement, an import
// statement, is an absolute import of standard-library modules only
// (import json, import os.path as p, from pathlib import Path). A relative
// import, "from m import *" or a shape the scan cannot read is not.
func pythonImportsStandardLibrary(statement string) bool {
	if _, ok := pythonImportBindings(statement); !ok {
		return false
	}
	words := strings.Fields(strings.NewReplacer("(", " ", ")", " ", ",", " , ", "\\", " ").Replace(statement))
	var modules []string
	switch {
	case len(words) >= 4 && words[0] == "from" && slices.Contains(words[2:], "import"):
		if strings.HasPrefix(words[1], ".") || slices.Contains(words, "*") {
			return false
		}
		modules = append(modules, words[1])
	case len(words) >= 2 && words[0] == "import":
		for items := words[1:]; len(items) > 0; {
			end := slices.Index(items, ",")
			if end < 0 {
				end = len(items)
			}
			modules = append(modules, items[0])
			if end == len(items) {
				break
			}
			items = items[end+1:]
		}
	default:
		return false
	}
	for _, module := range modules {
		if !pythonStandardModules[strings.SplitN(module, ".", 2)[0]] {
			return false
		}
	}
	return len(modules) > 0
}

// pythonImportPathOrdinary reports whether an import of code, by a
// statement or by the interpreter itself, loads only standard-library code.
// A standard-library module imports others in turn, so any module of dir can
// shadow one of them: dir must be known, absolute and hold nothing an import
// can load (pythonDirectoryMayLoadCode). PYTHONPATH or PYTHONHOME in the
// environment puts other directories first, and code that may change
// sys.path, a package's search path or the import hooks, or the working
// directory an -c program imports from (os.chdir), loads from anywhere
// (pythonImportPathMoves).
func pythonImportPathOrdinary(code, dir, self string) bool {
	return dir != "" && filepath.IsAbs(dir) &&
		os.Getenv("PYTHONPATH") == "" && os.Getenv("PYTHONHOME") == "" &&
		!pythonImportPathMoves(code) &&
		!pythonDirectoryMayLoadCode(dir, self)
}

// pythonImportPathMoves reports whether code may change where an import
// looks or what it finds there: pythonImportPathChange matches, or code
// reaches the sys module other than through one of pythonSysAttributes
// (pythonSysEscapes).
func pythonImportPathMoves(code string) bool {
	return pythonImportPathChange.MatchString(code) || pythonSysEscapes(code)
}

// pythonImportPathChange matches code that may move the import path under a
// name other than sys: a package's search path (__path__, the
// submodule_search_locations of its spec), the __self__ of a module's
// function (sys.exit.__self__ is sys), and a change of the directory an -c
// program imports from (chdir, fchdir, chroot).
var pythonImportPathChange = regexp.MustCompile(
	`\b(?:f?chdir|chroot|__path__|submodule_search_locations|__self__)\b`)

// pythonSysAttributes are the attributes of sys that neither hold nor change
// the import system: the program's streams, exit and exception state, and
// facts about the interpreter. Any other attribute may (path, meta_path,
// path_hooks, path_importer_cache, modules, pycache_prefix, implementation,
// a frame, a hook, remote_exec, or one a later Python adds).
var pythonSysAttributes = func() map[string]bool {
	set := map[string]bool{}
	for _, name := range strings.Fields(`abiflags api_version argv
		base_exec_prefix base_prefix builtin_module_names byteorder copyright
		dont_write_bytecode exc_info exception exec_prefix executable exit flags
		float_info float_repr_style getallocatedblocks getdefaultencoding
		getfilesystemencodeerrors getfilesystemencoding getrecursionlimit
		getrefcount getsizeof getswitchinterval getwindowsversion hash_info
		hexversion int_info intern is_finalizing last_exc maxsize maxunicode
		orig_argv platform platlibdir prefix ps1 ps2 setrecursionlimit
		setswitchinterval stderr stdin stdlib_module_names stdout thread_info
		version version_info warnoptions winver`) {
		set[name] = true
	}
	return set
}()

// pythonSysEscapes reports whether code reaches the sys module other than to
// read or set one of pythonSysAttributes (sys.exit, os.sys.version): through
// any other attribute (sys.path, os.sys.meta_path), or as a value (s = sys,
// f(sys), [sys][0], (sys).path, import sys as s, from sys import path),
// through which code may move the import path under a name no pattern of the
// path's own finds. An import statement that binds sys as sys (import sys,
// from os import sys) is not a use.
func pythonSysEscapes(code string) bool {
	imports := pythonImports(code)
	for _, name := range pythonName.FindAllStringIndex(code, -1) {
		if code[name[0]:name[1]] != "sys" {
			continue
		}
		next := pythonSkipBlank(code, name[1])
		if i := slices.IndexFunc(imports, func(statement pythonImport) bool {
			return name[0] >= statement.span[0] && name[1] <= statement.span[1]
		}); i >= 0 {
			if !slices.Contains(imports[i].bound, "sys") || pythonName.FindString(code[next:]) == "as" {
				return true
			}
			continue
		}
		if next >= len(code) || code[next] != '.' {
			return true
		}
		from := pythonSkipBlank(code, next+1)
		attr := pythonName.FindStringIndex(code[from:])
		if attr == nil || attr[0] != 0 || !pythonSysAttributes[code[from:from+attr[1]]] {
			return true
		}
	}
	return false
}

// pythonSkipBlank returns the offset of the first byte of code from i on
// that is not white space or a line continuation.
func pythonSkipBlank(code string, i int) int {
	for i < len(code) && strings.IndexByte(" \t\r\n\f\\", code[i]) >= 0 {
		i++
	}
	return i
}

// Bounds of pythonDirectoryMayLoadCode, which runs on the hook path.
const (
	pythonDirMaxEntries     = 256
	pythonPackageMaxEntries = 1024
)

// pythonDirectoryMayLoadCode reports whether dir may hold code an import
// loads: a source, bytecode or extension module (.py, .pyw, .pyc, .pyo,
// .pyd, .so in any case; a .zip or .egg too), a regular package (a
// directory with a module's name that holds an __init__ file of any kind),
// or a link, which may name any of these. A directory that cannot be read,
// or that holds more entries than the scan reads (pythonDirMaxEntries in
// dir, pythonPackageMaxEntries across its package-named directories), may
// hold one. self, when not "", is the scanned script's own file name.
func pythonDirectoryMayLoadCode(dir, self string) bool {
	entries, ok := pythonReadDir(dir, pythonDirMaxEntries)
	if !ok {
		return true
	}
	budget := pythonPackageMaxEntries
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case self != "" && name == self && entry.Type().IsRegular():
		case entry.Type()&fs.ModeSymlink != 0, pythonLoadableFile(name):
			return true
		case entry.IsDir() && pythonModuleName(name):
			inner, ok := pythonReadDir(filepath.Join(dir, name), budget)
			if !ok {
				return true
			}
			budget -= len(inner)
			for _, file := range inner {
				if strings.HasPrefix(strings.ToLower(file.Name()), "__init__.") {
					return true
				}
			}
		}
	}
	return false
}

// pythonReadDir reads at most limit entries of dir; it reports false when
// dir cannot be read or holds more.
func pythonReadDir(dir string, limit int) ([]fs.DirEntry, bool) {
	if limit <= 0 {
		return nil, false
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	return entries, len(entries) <= limit && (err == nil || errors.Is(err, io.EOF))
}

// pythonLoadableFile reports a file name an import may load as a module.
func pythonLoadableFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".py", ".pyw", ".pyc", ".pyo", ".pyd", ".so", ".zip", ".egg":
		return true
	}
	return false
}

// pythonModuleName reports a directory name an import may name: an ASCII
// identifier, or any name with a non-ASCII byte (Python reads identifiers
// in NFKC form).
func pythonModuleName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= utf8.RuneSelf:
			return true
		case c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
		case '0' <= c && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// pythonProgramVariable reports whether the name word at code[at] is a plain
// name (not an attribute, x.source) that is not a builtin or a module dunder.
func pythonProgramVariable(code string, at int, word string) bool {
	if strings.HasPrefix(word, "__") || pythonBuiltins[word] {
		return false
	}
	i := at
	for i > 0 && strings.IndexByte(" \t\r\n\\", code[i-1]) >= 0 {
		i--
	}
	return i == 0 || code[i-1] != '.'
}

// pythonBuiltins are the names of the builtins module (Python 3.14, with the
// Windows-only WindowsError and the names site adds); dunders are left out,
// since no dunder counts as a program variable.
var pythonBuiltins = func() map[string]bool {
	set := map[string]bool{}
	for _, name := range strings.Fields(`ArithmeticError AssertionError
		AttributeError BaseException BaseExceptionGroup BlockingIOError
		BrokenPipeError BufferError BytesWarning ChildProcessError
		ConnectionAbortedError ConnectionError ConnectionRefusedError
		ConnectionResetError DeprecationWarning EOFError Ellipsis
		EncodingWarning EnvironmentError Exception ExceptionGroup False
		FileExistsError FileNotFoundError FloatingPointError FutureWarning
		GeneratorExit IOError ImportError ImportWarning IndentationError
		IndexError InterruptedError IsADirectoryError KeyError
		KeyboardInterrupt LookupError MemoryError ModuleNotFoundError
		NameError None NotADirectoryError NotImplemented NotImplementedError
		OSError OverflowError PendingDeprecationWarning PermissionError
		ProcessLookupError PythonFinalizationError RecursionError
		ReferenceError ResourceWarning RuntimeError RuntimeWarning
		StopAsyncIteration StopIteration SyntaxError SyntaxWarning
		SystemError SystemExit TabError TimeoutError True TypeError
		UnboundLocalError UnicodeDecodeError UnicodeEncodeError UnicodeError
		UnicodeTranslateError UnicodeWarning UserWarning ValueError Warning
		WindowsError ZeroDivisionError _IncompleteInputError abs aiter all
		anext any ascii bin bool breakpoint bytearray bytes callable chr
		classmethod compile complex copyright credits delattr dict dir
		divmod enumerate eval exec exit filter float format frozenset
		getattr globals hasattr hash help hex id input int isinstance
		issubclass iter len license list locals map max memoryview min next
		object oct open ord pow print property quit range repr reversed
		round set setattr slice sorted staticmethod str sum super tuple
		type vars zip`) {
		set[name] = true
	}
	return set
}()

func pythonStringRunName(name string) bool {
	if pythonStringRunNames[name] {
		return true
	}
	for _, fragment := range pythonStringRunFragments {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return false
}

// pythonImport is an import statement of code: its span, and the names it
// binds, nil when the scan cannot list them ("from m import *").
type pythonImport struct {
	span  [2]int
	bound []string
}

// pythonImports returns the import statements of code (strings blanked). A
// statement ends at a newline, ";" or ":" outside brackets ("if x: import
// y").
func pythonImports(code string) []pythonImport {
	var imports []pythonImport
	depth, start := 0, 0
	for i := 0; i <= len(code); i++ {
		if i < len(code) {
			switch c := code[i]; c {
			case '(', '[', '{':
				depth++
				continue
			case ')', ']', '}':
				depth = max(depth-1, 0)
				continue
			case '\n', ';', ':':
				if depth > 0 || c == '\n' && i > 0 && code[i-1] == '\\' {
					continue
				}
			default:
				continue
			}
		}
		if words := strings.Fields(code[start:i]); len(words) > 0 && (words[0] == "import" || words[0] == "from") {
			bound, _ := pythonImportBindings(code[start:i])
			imports = append(imports, pythonImport{span: [2]int{start, i}, bound: bound})
		}
		start = i + 1
	}
	return imports
}

// pythonImportBindings returns the names an import statement binds, and
// false when statement is not an import or binds unknown names.
func pythonImportBindings(statement string) ([]string, bool) {
	words := strings.Fields(strings.NewReplacer("(", " ", ")", " ", ",", " , ", "\\", " ").Replace(statement))
	var items []string
	switch {
	case len(words) >= 2 && words[0] == "import":
		items = words[1:]
	case len(words) >= 4 && words[0] == "from" && slices.Contains(words[2:], "import"):
		items = words[slices.Index(words, "import")+1:]
	default:
		return nil, false
	}
	var bound []string
	for len(items) > 0 {
		end := slices.Index(items, ",")
		if end < 0 {
			end = len(items)
		}
		item := items[:end]
		switch {
		case len(item) == 1:
			bound = append(bound, strings.SplitN(item[0], ".", 2)[0])
		case len(item) == 3 && item[1] == "as":
			bound = append(bound, item[2])
		default:
			return nil, false
		}
		if end == len(items) {
			break
		}
		items = items[end+1:]
		if len(items) == 0 {
			return nil, false // a trailing comma
		}
	}
	for _, name := range bound {
		if name == "*" || !pythonName.MatchString(name) || pythonName.FindString(name) != name {
			return nil, false
		}
	}
	return bound, len(bound) > 0
}

// pythonNamesUsed reports whether a name of bound appears in code outside
// code[from:to].
func pythonNamesUsed(code string, names [][]int, bound []string, from, to int) bool {
	for _, name := range names {
		if name[0] >= from && name[1] <= to {
			continue
		}
		if slices.Contains(bound, code[name[0]:name[1]]) {
			return true
		}
	}
	return false
}

// blankPythonText blanks text in place, newlines kept.
func blankPythonText(text []byte) {
	for j, c := range text {
		if c != '\n' {
			text[j] = ' '
		}
	}
}

// pythonMaxStringNesting bounds strings inside replacement fields inside
// strings (f"{f'{x}'}").
const pythonMaxStringNesting = 32

func pythonTripleQuoteAt(src []byte, i int) bool {
	return i+2 < len(src) && src[i+1] == src[i] && src[i+2] == src[i]
}

// pythonFormatString reports whether the string literal whose quote is at
// src[i] has an f or t prefix (f"x", rf'x', t"""x"""), whose fields run.
func pythonFormatString(src []byte, i int) bool {
	start := i
	for start > 0 && start > i-2 && pythonLetter(src[start-1]) {
		start--
	}
	if start > 0 && (pythonLetter(src[start-1]) || src[start-1] == '_' ||
		src[start-1] >= '0' && src[start-1] <= '9') {
		return false // the end of a longer name, not a prefix
	}
	switch strings.ToLower(string(src[start:i])) {
	case "f", "fr", "rf", "t", "tr", "rt":
		return true
	}
	return false
}

func pythonLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// pythonStringEnd returns the offset just past the string literal whose
// opening quote is at src[i], following the replacement fields of an f- or
// t-string, whose expressions may hold strings with the same quotes
// (Python 3.12). When exprs is not nil, the span of the expression of each
// replacement field of this string, and of each field nested in a format spec,
// is appended to it in order (pythonFieldEnd): the code of the string.
func pythonStringEnd(src []byte, i, depth int, exprs *[][2]int) (int, bool) {
	if depth > pythonMaxStringNesting {
		return 0, false
	}
	quote, triple, format := src[i], pythonTripleQuoteAt(src, i), pythonFormatString(src, i)
	j := i + 1
	if triple {
		j = i + 3
	}
	for j < len(src) {
		c := src[j]
		switch {
		case c == '\\':
			if format && j+1 < len(src) && src[j+1] == '{' {
				j++ // a backslash does not escape a field
				continue
			}
			j += 2
			continue
		case c == quote && !triple:
			return j + 1, true
		case c == quote && pythonTripleQuoteAt(src, j):
			return j + 3, true
		case c == '\n' && !triple:
			return 0, false
		case format && c == '{':
			if j+1 < len(src) && src[j+1] == '{' {
				j += 2
				continue
			}
			end, ok := pythonFieldEnd(src, j+1, depth+1, exprs)
			if !ok {
				return 0, false
			}
			j = end
			continue
		}
		j++
	}
	return 0, false
}

// pythonFieldEnd returns the offset just past the "}" that closes the
// replacement field whose expression starts at src[j]. When exprs is not nil,
// it appends the span of the expression (pythonFieldExpression) and of the
// expressions of the fields nested in its format spec.
func pythonFieldEnd(src []byte, j, depth int, exprs *[][2]int) (int, bool) {
	start, brackets, conversion := j, 0, -1
	for j < len(src) {
		switch src[j] {
		case '\'', '"':
			end, ok := pythonStringEnd(src, j, depth, nil)
			if !ok {
				return 0, false
			}
			j = end
			continue
		case '#':
			for j < len(src) && src[j] != '\n' {
				j++
			}
			continue
		case '(', '[', '{':
			brackets++
		case ')', ']':
			brackets--
		case '!':
			if brackets == 0 && conversion < 0 && (j+1 >= len(src) || src[j+1] != '=') {
				conversion = j // !r, !s or !a: text, not code
			}
		case '}':
			if brackets == 0 {
				pythonFieldExpression(src, start, conversion, j, exprs)
				return j + 1, true
			}
			brackets--
		case ':':
			if brackets == 0 {
				pythonFieldExpression(src, start, conversion, j, exprs)
				return pythonFormatSpecEnd(src, j+1, depth, exprs)
			}
		}
		j++
	}
	return 0, false
}

// pythonFieldExpression appends to exprs (when not nil) the span of the
// expression of a replacement field from src[start] to its conversion, or to
// end when it has none, less a self-documenting "=" (f"{x=}" prints the text
// "x="; x= is not an assignment).
func pythonFieldExpression(src []byte, start, conversion, end int, exprs *[][2]int) {
	if exprs == nil {
		return
	}
	if conversion >= 0 {
		end = conversion
	}
	last := end
	for last > start && strings.IndexByte(" \t\r\n", src[last-1]) >= 0 {
		last--
	}
	if last > start && src[last-1] == '=' && (last-1 == start || strings.IndexByte("=!<>", src[last-2]) < 0) {
		end = last - 1
	}
	*exprs = append(*exprs, [2]int{start, end})
}

// pythonFormatSpecEnd returns the offset just past the "}" that closes a
// field whose format spec (literal text with nested fields) starts at src[j],
// appending the expressions of the nested fields to exprs (when not nil).
func pythonFormatSpecEnd(src []byte, j, depth int, exprs *[][2]int) (int, bool) {
	for j < len(src) {
		switch src[j] {
		case '{':
			end, ok := pythonFieldEnd(src, j+1, depth+1, exprs)
			if !ok {
				return 0, false
			}
			j = end
			continue
		case '}':
			return j + 1, true
		}
		j++
	}
	return 0, false
}
