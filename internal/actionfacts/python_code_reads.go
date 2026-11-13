// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"regexp"
	"strings"
)

// pythonCallee matches a call in Python code: a dotted name and its open
// parenthesis (open(, os.replace(, sys.stdout.write(, p.read_text().
var pythonCallee = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*)\s*\(`)

// pythonWriteCalls are the Python calls that write, remove, rename, link or
// change a file, or run code or another program the reader does not see.
var pythonWriteCalls = map[string]bool{
	"write": true, "writelines": true, "unlink": true, "remove": true, "removedirs": true,
	"rmdir": true, "rmtree": true, "rename": true, "renames": true, "move": true,
	"truncate": true, "touch": true, "mkdir": true, "makedirs": true, "mkdtemp": true,
	"mkstemp": true, "chmod": true, "lchmod": true, "chown": true, "lchown": true,
	"link": true, "link_to": true, "hardlink_to": true, "system": true, "popen": true,
	"Popen": true, "run": true, "call": true, "getoutput": true, "getstatusoutput": true,
	"eval": true, "exec": true, "compile": true, "__import__": true, "import_module": true,
	"getattr": true, "setattr": true, "dump": true, "save": true, "savez": true,
	"savetxt": true, "tofile": true, "utime": true, "mkfifo": true, "mknod": true,
	"setxattr": true, "removexattr": true, "chflags": true, "lchflags": true, "kill": true,
	"killpg": true, "fork": true, "forkpty": true, "startfile": true, "write_text": true,
	"write_bytes": true, "NamedTemporaryFile": true, "TemporaryFile": true,
	"TemporaryDirectory": true, "connect": true, "unpack_archive": true,
	"make_archive": true, "extract": true, "extractall": true, "urlretrieve": true,
	"breakpoint": true,
}

// pythonImport matches an import statement: import a, b.c as d / from a.b
// import c.
var pythonImport = regexp.MustCompile(`(?m)(?:^|;)\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|import\s+([^;\n#]+))`)

// pythonReadModules are standard-library modules a read-only script uses.
// python -c and python - put the working directory first on sys.path, so a
// module the standard library does not have may be a file planted there
// that runs anything; one it does have is not looked up there first for
// the ones Python loads at startup, and the rest are judged as their names.
var pythonReadModules = map[string]bool{
	"os": true, "sys": true, "json": true, "pathlib": true, "hashlib": true, "re": true, "io": true,
	"codecs": true, "collections": true, "itertools": true, "functools": true, "base64": true,
	"binascii": true, "string": true, "textwrap": true, "datetime": true, "time": true, "math": true,
	"statistics": true, "pprint": true, "tomllib": true, "configparser": true, "csv": true,
	"glob": true, "fnmatch": true, "stat": true, "platform": true, "getpass": true, "copy": true,
	"typing": true, "dataclasses": true, "enum": true, "operator": true, "difflib": true,
	"struct": true, "zlib": true, "gzip": true, "bz2": true, "lzma": true, "unicodedata": true,
	"shlex": true, "locale": true, "plistlib": true, "uuid": true, "ast": true, "pwd": true, "grp": true,
}

// pythonWritePrefixes are name prefixes of more such calls (copyfile,
// copytree, execv, spawnl, symlink_to, to_csv, check_output, writeFile).
var pythonWritePrefixes = []string{"copy", "exec", "spawn", "symlink", "to_", "check_", "write"}

// PythonCodeOnlyReads reports Python code that writes nothing: it opens files
// only to read them (open, io.open, codecs.open, Path.open and FileIO with no
// mode or a read mode, os.open with O_RDONLY alone) and makes none of the
// calls that write, remove, rename, link or change a file or run other code
// (pythonWriteCalls). str.replace (two arguments), copy.copy and
// copy.deepcopy, dict.copy and sys.stdout/sys.stderr.write print or copy
// values, not files. A name in a string or a comment counts as a call: the
// check errs to "may write". Code that names ctypes or the builtins table
// may write by a route the check does not follow.
func PythonCodeOnlyReads(code string) bool {
	if code == "" || strings.Contains(code, "ctypes") || strings.Contains(code, "__builtins__") ||
		strings.Contains(code, "globals()") || strings.Contains(code, "os.environ[") && strings.Contains(code, "PYTHON") {
		return false
	}
	for _, match := range pythonImport.FindAllStringSubmatch(code, -1) {
		names := []string{match[1]}
		if match[1] == "" {
			names = nil
			for _, part := range strings.Split(match[2], ",") {
				if fields := strings.Fields(part); len(fields) > 0 {
					names = append(names, fields[0])
				}
			}
		}
		for _, name := range names {
			if top, _, _ := strings.Cut(strings.Trim(name, "()"), "."); !pythonReadModules[top] {
				return false
			}
		}
	}
	for _, match := range pythonCallee.FindAllStringSubmatchIndex(code, -1) {
		callee := strings.Join(strings.Fields(strings.ReplaceAll(code[match[2]:match[3]], ".", " . ")), "")
		// A method of a value (line.replace, d.copy, Path(x).open): the
		// callee is dotted or follows an expression.
		method := strings.Contains(callee, ".") || match[2] > 0 && code[match[2]-1] == '.'
		args, ok := pythonCallArguments(code, match[1])
		if !ok {
			return false
		}
		name := callee[strings.LastIndexByte(callee, '.')+1:]
		switch {
		case name == "open" || name == "FileIO" || name == "fdopen":
			if !pythonOpenReads(callee, method, args) {
				return false
			}
		case name == "replace":
			// str.replace(old, new); os.replace(src, dst) and
			// Path.replace(target) rename.
			if callee == "os.replace" || callee == "replace" || len(args) < 2 {
				return false
			}
		case name == "deepcopy" || name == "copy" && len(args) <= 1 && callee != "shutil.copy":
		case name == "write" && (callee == "sys.stdout.write" || callee == "sys.stderr.write"):
		case pythonWriteCalls[name]:
			return false
		default:
			for _, prefix := range pythonWritePrefixes {
				if strings.HasPrefix(name, prefix) {
					return false
				}
			}
		}
	}
	return true
}

// pythonOpenReads judges one open call: the builtin (and io.open, codecs.open)
// reads the mode as its second argument, Path.open as its first, os.fdopen as
// its second, os.open its flags.
func pythonOpenReads(callee string, method bool, args []string) bool {
	switch {
	case callee == "os.open":
		return len(args) == 2 && strings.TrimSpace(args[1]) == "os.O_RDONLY"
	case callee == "open" || callee == "io.open" || callee == "codecs.open" || callee == "builtins.open" ||
		callee == "FileIO" || callee == "io.FileIO" || callee == "os.fdopen" || callee == "fdopen":
		return pythonReadMode(args, 1)
	case method || strings.HasSuffix(callee, ".open"):
		return pythonReadMode(args, 0)
	}
	return false
}

// pythonReadMode reports open arguments whose mode (the positional at index,
// or mode=) is absent or a literal read mode, with no opener of its own.
func pythonReadMode(args []string, index int) bool {
	mode, positional := "", 0
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		if key, value, keyword := strings.Cut(arg, "="); keyword && pythonIdentifier(strings.TrimSpace(key)) {
			switch strings.TrimSpace(key) {
			case "mode":
				mode = strings.TrimSpace(value)
			case "opener":
				return false
			}
			continue
		}
		if strings.HasPrefix(arg, "*") {
			return false
		}
		if positional == index {
			mode = arg
		}
		positional++
	}
	if mode == "" {
		return true
	}
	if len(mode) < 2 || mode[0] != mode[len(mode)-1] || mode[0] != '\'' && mode[0] != '"' {
		return false
	}
	return strings.Trim(mode[1:len(mode)-1], "rbtU") == ""
}

func pythonIdentifier(text string) bool {
	if text == "" {
		return false
	}
	for index, char := range text {
		letter := char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
		digit := index > 0 && char >= '0' && char <= '9'
		if !letter && !digit {
			return false
		}
	}
	return true
}

// pythonCallArguments splits the arguments of the call whose open
// parenthesis ends at start, at top-level commas, through strings and
// nested brackets. ok is false when the call does not close.
func pythonCallArguments(code string, start int) (args []string, ok bool) {
	depth, from := 0, start
	for index := start; index < len(code); index++ {
		switch char := code[index]; char {
		case '\'', '"':
			end, closed := pythonStringEnd(code, index)
			if !closed {
				return nil, false
			}
			index = end
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				if text := strings.TrimSpace(code[from:index]); text != "" || len(args) > 0 {
					args = append(args, text)
				}
				return args, char == ')'
			}
			depth--
		case ',':
			if depth == 0 {
				args = append(args, code[from:index])
				from = index + 1
			}
		case '#':
			for index < len(code) && code[index] != '\n' {
				index++
			}
		}
	}
	return nil, false
}

// pythonStringEnd returns the index of the quote that closes the string
// literal opening at start (a triple quote included).
func pythonStringEnd(code string, start int) (int, bool) {
	quote := code[start : start+1]
	if strings.HasPrefix(code[start:], strings.Repeat(quote, 3)) {
		quote = strings.Repeat(quote, 3)
	}
	for index := start + len(quote); index < len(code); index++ {
		if code[index] == '\\' {
			index++
			continue
		}
		if strings.HasPrefix(code[index:], quote) {
			return index + len(quote) - 1, true
		}
		if len(quote) == 1 && code[index] == '\n' {
			return 0, false
		}
	}
	return 0, false
}
