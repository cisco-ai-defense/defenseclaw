// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"strings"
)

// CG-EXEC-001 (GAP-0056) keeps the substring rule of 1.0.8 as its match:
// every os.system, subprocess.call, exec(, child_process.exec, eval( and
// system( it reported is a candidate (cgExecBasePattern, unchanged). A
// candidate is dropped only when it is proven benign:
//   - a longer name that only ends in exec, eval or system (parseEval(,
//     ast.literal_eval(, createFlysystem(), other than the Ruby *_eval of a
//     string, jQuery globalEval and PHP shell_exec/pcntl_exec;
//   - a method of a plain receiver (a dotted chain of names) that is not a
//     module or global object that runs commands or code (re.exec(s),
//     model.eval(), platform.system(), db.exec(sql)), a RegExp literal's
//     exec (/x/g.exec(s)), or a method call with nothing to run
//     (self.eval());
//   - a Ruby *_eval given a block (class_eval(&blk));
//   - subprocess.call of a literal list or tuple whose element 0 is a string
//     literal and whose argv is proven benign (cgExecBenignArgv);
//   - subprocess.call_count and a quoted 'subprocess.call' (names, not calls).
//
// Anything the reader cannot prove benign stays reported: a variable,
// f-string, concatenation, function reference, non-literal element 0,
// receiver expression or an unparsed form. So the rule reports a subset of
// the substring rule's lines, plus the Ruby *_eval heredoc and string forms
// and the NFKC spellings (cgExecView), and a missed spelling can no longer
// lose one of the substring rule's true positives.
const (
	cgExecBasePattern = `(?i)(os\.system|subprocess\.call|exec\(|child_process\.exec|eval\(|system\()`
	// cgExecRubyEvalForms are the Ruby *_eval calls without "eval(" that
	// evaluate a string: a heredoc, a string literal, or a space before "(".
	cgExecRubyEvalForms = `(?:instance|class|module)_eval(?:\s*(?:<<|['"%])|\s+\()`
	// cgExecScanLimit bounds how far one candidate is read; a longer form
	// is not proven benign.
	cgExecScanLimit = 4096
)

var cgExecPattern = regexp.MustCompile(cgExecBasePattern + `|` + cgExecRubyEvalForms)

// cgExecReportsLine reports whether any candidate at locs in line (the
// cgExecView of a source line) is not proven benign. What is read once per
// line is read here, so a line costs time linear in its length.
func cgExecReportsLine(line string, locs [][]int) bool {
	childProcess := len(locs) > 0 && cgExecChildProcessLine.MatchString(line)
	for _, loc := range locs {
		if cgExecReports(line, loc, childProcess) {
			return true
		}
	}
	return false
}

// cgExecReports reports whether the candidate at loc in line is not proven
// benign; childProcess is whether the line names child_process or shelljs.
func cgExecReports(line string, loc []int, childProcess bool) bool {
	t := strings.ToLower(line[loc[0]:loc[1]])
	switch {
	case strings.HasPrefix(t, "os.system"), strings.HasPrefix(t, "child_process.exec"):
		return true
	case t == "subprocess.call":
		return !cgExecBenignSubprocessCall(line, loc[0], loc[1])
	case strings.Contains(t, "_eval") && !strings.HasSuffix(t, "eval("):
		// A heredoc, a string, or "_eval (": a block is "_eval (&blk)".
		return !(strings.HasSuffix(t, "(") && cgExecRubyBlockArgs(line[loc[1]:]))
	}
	return !cgExecBenignNameCall(line, loc[0], loc[1], t[:len(t)-1], childProcess)
}

// cgExecReportsNonEval reports whether line holds a reported candidate other
// than an eval: the vuln scanner reports eval() itself (GAP-1595).
func cgExecReportsNonEval(line string) bool {
	locs := cgExecPattern.FindAllStringIndex(line, -1)
	childProcess := len(locs) > 0 && cgExecChildProcessLine.MatchString(line)
	for _, loc := range locs {
		if !strings.Contains(strings.ToLower(line[loc[0]:loc[1]]), "eval") && cgExecReports(line, loc, childProcess) {
			return true
		}
	}
	return false
}

func cgExecIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// cgExecRubyBlockArgs reports whether the arguments after "(" are a block
// or empty (class_eval(&blk), instance_eval()).
func cgExecRubyBlockArgs(args string) bool {
	args = strings.TrimLeft(args, " \t")
	return strings.HasPrefix(args, "&") || strings.HasPrefix(args, ")")
}

func cgExecWordSet(words string) map[string]bool {
	set := map[string]bool{}
	for _, w := range strings.Fields(words) {
		set[w] = true
	}
	return set
}

// cgExecRiskyReceivers are, by method, the modules and global objects whose
// exec, eval or system runs a command or code string.
var cgExecRiskyReceivers = map[string]map[string]bool{
	"eval": cgExecWordSet(`builtins __builtins__ kernel binding toplevel_binding window globalthis global self top parent
		frames defaultview contentwindow`),
	"exec":   cgExecWordSet(`builtins __builtins__ kernel process child_process childprocess cp shell shelljs os posix nt`),
	"system": cgExecWordSet(`os posix nt kernel process builtins __builtins__`),
}

// cgExecRegexpLiteralEnd is the end of a JavaScript RegExp literal before
// ".exec(": "/" and its flags.
var cgExecRegexpLiteralEnd = regexp.MustCompile(`/[dgimsuyv]*$`)

// cgExecChildProcessLine names a module whose handle, under any name, has
// an exec that runs a command string.
var cgExecChildProcessLine = regexp.MustCompile(`(?i)child_process|shelljs`)

// cgExecBenignNameCall reports whether the exec(, eval( or system( call
// spelled name at line[start:end] is proven benign.
func cgExecBenignNameCall(line string, start, end int, name string, childProcess bool) bool {
	j := start
	for j > 0 && start-j < cgExecScanLimit && cgExecIdentByte(line[j-1]) {
		j--
	}
	word := line[j:start]
	if j > 0 && line[j-1] == '\\' && word != "" && strings.IndexByte("nrt", word[0]) >= 0 {
		// "\nexec(" in a string literal: the call starts after the escape.
		word, j = word[1:], j+1
	}
	if word == "$" && (j == 0 || line[j-1] != '.') {
		return false // a PHP variable function: $exec($cmd)
	}
	if word != "" {
		full := strings.ToLower(word) + name
		for _, risky := range []string{"instance_eval", "class_eval", "module_eval"} {
			if strings.HasSuffix(full, risky) {
				return cgExecRubyBlockArgs(line[end:])
			}
		}
		for _, risky := range []string{"globaleval", "shell_exec", "pcntl_exec"} {
			if strings.HasSuffix(full, risky) {
				return false
			}
		}
		return true
	}
	if j == 0 || line[j-1] != '.' {
		return false // a bare call, Foo::exec(, $this->exec(
	}
	if strings.HasPrefix(strings.TrimLeft(line[end:], " \t"), ")") {
		return true // a method call with nothing to run: model.eval()
	}
	if name == "exec" && cgExecRegexpLiteralEnd.MatchString(line[max(0, j-1-16):j-1]) && strings.Count(line[max(0, j-1-256):j-1], "/") >= 2 {
		return true // RegExp.prototype.exec: /x/g.exec(s)
	}
	if j >= 2 && line[j-2] == '?' {
		return false // window?.eval(
	}
	k := j - 1
	for k > 0 && j-k < cgExecScanLimit && (cgExecIdentByte(line[k-1]) || line[k-1] == '.') {
		k--
	}
	recv := line[k : j-1]
	if recv == "" || strings.HasPrefix(recv, ".") || strings.Contains(recv, "..") {
		return false
	}
	if k > 0 && strings.IndexByte(")]}'\"`/>:?\\", line[k-1]) >= 0 {
		return false // a receiver expression: __import__('os').system(, frames[0].eval(
	}
	if name == "exec" && childProcess {
		return false // import('child_process').then(m => m.exec(cmd))
	}
	risky := cgExecRiskyReceivers[name]
	for _, part := range strings.Split(strings.ToLower(recv), ".") {
		if risky[part] {
			return false
		}
	}
	return true
}

// cgExecInterpreters are programs that run a command or code string they
// are given, and the runners that hand one on. A string element that names
// one in any word (also env -S 'node -p' or '--split-string=node -e') keeps
// a subprocess.call reported, unless cgExecBenignScriptRun proves the
// interpreter runs a script file.
var cgExecInterpreters = cgExecWordSet(`sh bash zsh dash ksh mksh pdksh fish csh tcsh ash yash busybox cmd powershell pwsh
	python pythonw py pypy ipython perl ruby irb jruby php node nodejs deno bun ts-node tsx lua luajit tclsh wish
	osascript rscript julia awk gawk mawk nawk jshell jjs groovy scala kotlin elixir iex erl escript racket guile
	sbcl clisp ghci runghc runhaskell swift wscript cscript mshta rundll regsvr expect qjs d8 rhino
	ssh su sudo doas runas runuser xargs watch tmux screen script parallel gnome-terminal xterm konsole wt start
	docker podman kubectl nsenter chroot unshare firejail setsid systemd-run flatpak-spawn sandbox-exec wsl`)

// cgExecWrappers run the program named in a later element.
var cgExecWrappers = cgExecWordSet(`env sudo doas nice ionice timeout command nohup stdbuf taskset chrt setsid runuser su sg
	firejail unshare chroot nsenter xvfb-run time exec builtin strace ltrace valgrind systemd-run flatpak-spawn
	sandbox-exec faketime proxychains proxychains4 torsocks caffeinate wsl wt start runas xargs watch tmux screen
	ssh script parallel docker podman kubectl busybox catchsegv`)

// cgExecProgramWord is a program word: a name, an optional version, an
// optional "-suffix" and ".exe" (python3.12, pwsh-preview, php8.3.exe).
var cgExecProgramWord = regexp.MustCompile(`^([a-z]+(?:-[a-z]+)?)(?:\d[\d.]*)?(?:-[a-z]+)?(?:\.exe)?$`)

// cgExecGenericCodeFlag is an element that passes inline code or a command
// string to whatever program reads it (-c, -Ic, -e, -le, /c, --eval,
// -Command, -EncodedCommand).
var cgExecGenericCodeFlag = regexp.MustCompile(`(?i)^(?:-[a-z]*[ce]|/c|--eval(?:=.*)?|-command|-encodedcommand|-commandwithargs|-cwa)$`)

// cgExecProgram returns the program a word names, lowercased, without its
// path, version and .exe.
func cgExecProgram(word string) string {
	word = strings.ToLower(word)
	if i := strings.LastIndexAny(word, `/\`); i >= 0 {
		word = word[i+1:]
	}
	if cgExecInterpreters[word] || cgExecWrappers[word] {
		return word
	}
	m := cgExecProgramWord.FindStringSubmatch(word)
	if m == nil {
		return word
	}
	if cgExecInterpreters[m[1]] || cgExecWrappers[m[1]] {
		return m[1]
	}
	if i := strings.IndexByte(m[1], '-'); i > 0 {
		return m[1][:i]
	}
	return m[1]
}

// cgExecSplitFlag is a short option cluster that ends in s, joined with its
// value (env -S'node -p', -Snode).
var cgExecSplitFlag = regexp.MustCompile(`(?i)^-[a-z]*s(.+)$`)

// cgExecNamesInterpreter reports whether a string names an interpreter or
// runner in any word.
func cgExecNamesInterpreter(s string) bool {
	for _, w := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == '=' || r == ',' || r == ';' }) {
		if strings.HasPrefix(w, "-") {
			m := cgExecSplitFlag.FindStringSubmatch(w)
			if m == nil {
				continue
			}
			w = m[1]
		}
		if cgExecInterpreters[cgExecProgram(w)] {
			return true
		}
	}
	return false
}

// cgExecStringLiteral returns the content of a Python string literal that
// is the whole element (r, b and u prefixes; not an f-string).
func cgExecStringLiteral(e string) (string, bool) {
	i := 0
	for i < len(e) && i < 2 && strings.IndexByte("rRbBuU", e[i]) >= 0 {
		i++
	}
	if i >= len(e) || (e[i] != '\'' && e[i] != '"') {
		return "", false
	}
	q := e[i]
	for k := i + 1; k < len(e); k++ {
		switch e[k] {
		case '\\':
			k++
		case q:
			if k != len(e)-1 {
				return "", false
			}
			return e[i+1 : k], true
		}
	}
	return "", false
}

// cgExecSplitTopLevel reads s from just after an opening bracket to its
// closing bracket: the top-level elements and the index after the closer.
func cgExecSplitTopLevel(s string, closer byte) ([]string, int, bool) {
	var elems []string
	depth, from := 0, 0
	var quote byte
	for i := 0; i < len(s) && i < cgExecScanLimit; i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
				continue
			}
			if c != closer {
				return nil, 0, false
			}
			if e := strings.TrimSpace(s[from:i]); e != "" {
				elems = append(elems, e)
			}
			return elems, i + 1, true
		case ',':
			if depth == 0 {
				elems = append(elems, strings.TrimSpace(s[from:i]))
				from = i + 1
			}
		}
	}
	return nil, 0, false
}

// cgExecShellKeyword finds shell= (other than shell=False) or executable=.
var cgExecShellKeyword = regexp.MustCompile(`(?i)\bexecutable\s*=|\bshell\s*=\s*(?:[^f\s]|f(?:[^a]|a(?:[^l]|l(?:[^s]|s(?:[^e]|e\w))))|$)`)

// cgExecBenignSubprocessCall reports whether the subprocess.call name at
// line[start:end] is proven benign: subprocess.call_count, a quoted
// 'subprocess.call', or a call of a literal list or tuple that closes on
// the line with no shell= or executable= argument, whose element 0 is a
// string literal and whose argv cgExecBenignArgv proves benign.
func cgExecBenignSubprocessCall(line string, start, end int) bool {
	rest := line[end:]
	if rest != "" && cgExecIdentByte(rest[0]) {
		return true // subprocess.call_count
	}
	if rest != "" && (rest[0] == '\'' || rest[0] == '"') && start > 0 && line[start-1] == rest[0] {
		return true // mock.patch('subprocess.call')
	}
	rest = strings.TrimLeft(rest, " \t")
	if !strings.HasPrefix(rest, "(") {
		return false // a function reference: to_thread(subprocess.call, ...)
	}
	rest = strings.TrimLeft(rest[1:], " \t")
	if rest == "" {
		return false
	}
	var closer byte
	switch rest[0] {
	case '[':
		closer = ']'
	case '(':
		closer = ')'
	default:
		return false
	}
	elems, after, ok := cgExecSplitTopLevel(rest[1:], closer)
	if !ok || len(elems) == 0 {
		return false
	}
	tail := strings.TrimLeft(rest[1+after:], " \t")
	switch {
	case strings.HasPrefix(tail, ")"):
	case strings.HasPrefix(tail, ","):
		kw, _, ok := cgExecSplitTopLevel(tail[1:], ')')
		if !ok {
			return false // left open: shell=True can follow on the next line
		}
		for _, k := range kw {
			if cgExecShellKeyword.MatchString(k) {
				return false
			}
		}
	default:
		return false // ['sudo'] + argv
	}
	argv := make([]cgExecArg, len(elems))
	for i, e := range elems {
		argv[i].s, argv[i].lit = cgExecStringLiteral(e)
	}
	return argv[0].lit && cgExecBenignArgv(argv)
}

// cgExecArg is one argv element: a string literal, or an expression (lit
// false) whose value is not known.
type cgExecArg struct {
	s   string
	lit bool
}

// cgExecBenignArgv reports whether argv (element 0 a literal) is proven
// benign: env's own options and -S string are read and the command it runs
// is checked instead; a python, perl, ruby, php, node or deno that runs a
// script file with only known non-code options passes; otherwise no literal
// names an interpreter, shell or runner, none is a code flag, and a wrapper
// (sudo, nice) has only literals.
func cgExecBenignArgv(argv []cgExecArg) bool {
	prog := cgExecProgram(argv[0].s)
	if prog == "env" {
		return cgExecBenignEnv(argv[1:])
	}
	if cgExecScriptOptions[prog] != nil {
		return cgExecBenignScriptRun(prog, argv)
	}
	wrapper := cgExecWrappers[prog]
	for _, a := range argv {
		if !a.lit {
			if wrapper {
				return false // sudo, then a program chosen at run time
			}
			continue
		}
		if cgExecGenericCodeFlag.MatchString(strings.TrimSpace(a.s)) || cgExecNamesInterpreter(a.s) {
			return false
		}
	}
	return true
}

// cgExecBenignEnv reads env's options (-i, -0, -v, -u NAME, -C DIR,
// NAME=VALUE, -S STRING in any spelling) and checks the command after them.
func cgExecBenignEnv(args []cgExecArg) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.lit {
			return false // env, then a program chosen at run time
		}
		s := a.s
		switch {
		case s == "--":
			return cgExecBenignCommand(nil, args[i+1:])
		case s == "-u" || s == "-C" || s == "--unset" || s == "--chdir":
			i++
			if i < len(args) && !args[i].lit {
				return false
			}
		case strings.HasPrefix(s, "--split-string="):
			return cgExecBenignCommand(strings.Fields(strings.TrimPrefix(s, "--split-string=")), args[i+1:])
		case s == "--split-string":
			if i+1 >= len(args) || !args[i+1].lit {
				return false
			}
			return cgExecBenignCommand(strings.Fields(args[i+1].s), args[i+2:])
		case strings.HasPrefix(s, "--"):
			if strings.Contains(s, "split") {
				return false
			}
		case strings.HasPrefix(s, "-"):
			if k := strings.IndexAny(s, "sS"); k > 0 && strings.Trim(s[1:k], "iv0") == "" {
				if k+1 < len(s) {
					return cgExecBenignCommand(strings.Fields(s[k+1:]), args[i+1:])
				}
				if i+1 >= len(args) || !args[i+1].lit {
					return false
				}
				return cgExecBenignCommand(strings.Fields(args[i+1].s), args[i+2:])
			}
			if strings.Trim(s[1:], "iv0") != "" {
				return false // an env option this reader does not know
			}
		case strings.Contains(s, "="):
		default:
			return cgExecBenignCommand(nil, args[i:])
		}
	}
	return true // env alone prints the environment
}

// cgExecBenignCommand checks the command words (from an env -S string)
// followed by the remaining argv elements.
func cgExecBenignCommand(words []string, rest []cgExecArg) bool {
	argv := make([]cgExecArg, 0, len(words)+len(rest))
	for _, w := range words {
		if strings.Contains(w, "=") && len(argv) == 0 {
			continue // NAME=VALUE inside the -S string
		}
		argv = append(argv, cgExecArg{s: w, lit: true})
	}
	argv = append(argv, rest...)
	if len(argv) == 0 {
		return true
	}
	if !argv[0].lit || strings.HasPrefix(argv[0].s, "-") {
		return false
	}
	return cgExecBenignArgv(argv)
}

// cgExecScriptOptions are, per interpreter, the options that pass no code:
// with only these before a script file (or a version flag alone), the
// interpreter runs a file, not a string. A pattern ending in "+" takes the
// next element as its value.
var cgExecScriptOptions = map[string]*regexp.Regexp{
	"python": regexp.MustCompile(`^(?:-[bBdEhiIOPqsSuvVx]+|-[WX].+|-[WX]\+|--version|--help)$`),
	"py":     regexp.MustCompile(`^(?:-[bBdEhiIOPqsSuvVx]+|-[WX].+|-[WX]\+|-\d[\d.]*(?:-\d+)?|--version|--help)$`),
	"pypy":   regexp.MustCompile(`^(?:-[bBdEhiIOPqsSuvVx]+|-[WX].+|-[WX]\+|--version|--help)$`),
	"perl":   regexp.MustCompile(`^(?:-[wWXTtUv]+|-[IM][^\s-].*|-version|--version|-V)$`),
	"ruby":   regexp.MustCompile(`^(?:-[wWv]+|-W\d|-[EIr][^\s-].*|-[EIr]\+|-version|--version)$`),
	"php":    regexp.MustCompile(`^(?:-[nqHv]+|-[dc][^\s-].*|-d\+|--version|--ini|--no-php-ini)$`),
	"node":   regexp.MustCompile(`^(?:-v|--version|--inspect(?:-brk|-wait)?(?:=\S*)?|--print-bytecode|--enable-source-maps|--max-old-space-size=\d+|--no-warnings|--no-deprecation|--trace-warnings|--expose-gc|--experimental-[a-z-]+|--stack-size=\d+)$`),
	"nodejs": regexp.MustCompile(`^(?:-v|--version|--inspect(?:-brk|-wait)?(?:=\S*)?|--print-bytecode|--enable-source-maps|--max-old-space-size=\d+|--no-warnings|--no-deprecation|--trace-warnings|--expose-gc|--experimental-[a-z-]+|--stack-size=\d+)$`),
	"deno":   regexp.MustCompile(`^(?:-v|-V|--version|-A|--allow-[a-z-]+(?:=\S*)?|-q|--quiet|--unstable(?:-[a-z-]+)?|--watch|--check)$`),
}

// cgExecDenoFileCommands are the deno subcommands that run or read files.
var cgExecDenoFileCommands = cgExecWordSet(`run task fmt test lint check compile install info doc bench cache upgrade`)

// cgExecBenignScriptRun reports whether an interpreter at argv[0] runs a
// script file (or only prints its version) with known non-code options:
// python3 script.py, python3 -m pip, perl -Ilib x.pl, php8.2 artisan, node
// server.js, deno run main.ts. Code flags, -, stdin and data: URLs are not.
func cgExecBenignScriptRun(prog string, argv []cgExecArg) bool {
	opts := cgExecScriptOptions[prog]
	i := 1
	if prog == "deno" {
		for i < len(argv) && argv[i].lit && opts.MatchString(argv[i].s) {
			i++
		}
		if i == len(argv) {
			return true // deno --version
		}
		if !argv[i].lit || !cgExecDenoFileCommands[argv[i].s] {
			return false // deno eval, deno repl
		}
		i++
	}
	for ; i < len(argv); i++ {
		a := argv[i]
		if !a.lit {
			return false
		}
		if a.s == "-m" && strings.HasPrefix(prog, "p") && prog != "php" && prog != "perl" {
			i++ // python -m module: the module runs, not a string
			if i >= len(argv) || !argv[i].lit || strings.HasPrefix(argv[i].s, "-") {
				return false
			}
			return cgExecBenignScriptArgs(argv[i+1:])
		}
		if strings.HasPrefix(a.s, "-") {
			if a.s == "-" || !opts.MatchString(a.s) {
				if opts.MatchString(a.s+"+") && i+1 < len(argv) && argv[i+1].lit {
					i++
					continue
				}
				return false
			}
			continue
		}
		if strings.Contains(strings.ToLower(a.s), "data:") || a.s == "" {
			return false
		}
		return cgExecBenignScriptArgs(argv[i+1:])
	}
	return true // only version or help options
}

// cgExecBenignScriptArgs checks the arguments after a script file: no code
// flag and no interpreter named in a literal.
func cgExecBenignScriptArgs(args []cgExecArg) bool {
	for _, a := range args {
		if a.lit && (cgExecGenericCodeFlag.MatchString(strings.TrimSpace(a.s)) || cgExecNamesInterpreter(a.s)) {
			return false
		}
	}
	return true
}
