// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// UnprovenReasonKey carries a bounded parser uncertainty class to the audit
// record. The value is a short, fixed class name, never command or filesystem
// data. It is not positive evidence of a protected write.
const UnprovenReasonKey = "\x00unproven-write"

var unprovenReasonTitles = map[string]string{
	"trap":                 "A trap handler can write a protected file",
	"function":             "A called function can write a protected file",
	"dynamic-command":      "A dynamic command can write a protected file",
	"dynamic-argument":     "A dynamic argument can select a protected file",
	"eval-source":          "Evaluated or sourced code can write a protected file",
	"interpreter-path":     "Interpreter file effects cannot be proved safe for the protected path",
	"interpreter-argument": "An interpreter has a dynamic argument after writable code",
	"shell-parse":          "A shell parse error leaves a protected write unproved",
	"copy-directory":       "A copy into a directory can select a protected file",
	"cdpath":               "CDPATH can select a directory containing a protected file link",
	"nested-shell":         "A nested shell or shell script can write a protected file",
}

// UnprovenWriteTitle gives the operator the class that prevented a proof.
func UnprovenWriteTitle(reason string) string {
	return unprovenReasonTitles[reason]
}

// IsUnprovenWriteTitle recognizes only fixed, product-authored class titles.
// Callers may show these titles without exposing command text or path data.
func IsUnprovenWriteTitle(title string) bool {
	for _, known := range unprovenReasonTitles {
		if title == known {
			return true
		}
	}
	return false
}

var (
	unprovenPathToken  = regexp.MustCompile(`[A-Za-z0-9_./~*?\[\]-]+`)
	unprovenQuotedPath = []*regexp.Regexp{
		regexp.MustCompile(`'([^']+)'`),
		regexp.MustCompile(`"([^"]+)"`),
	}
	unprovenWriter          = regexp.MustCompile(`\b(?:open|openSync|sysopen|FileIO|writeFile\w*|appendFile\w*|File\.write|File\.binwrite|IO\.write|write_text|write_bytes|copy\w*|createWriteStream|truncate|rename|replace|move|unlink|remove)\s*\(`)
	safeNodeRead            = regexp.MustCompile(`^require\(['"]fs['"]\)\.readFile(?:Sync)?\(['"][^'"]+['"](?:,\s*\(\)=>\{\})?\)$`)
	safeNodeCopy            = regexp.MustCompile(`^require\(['"]fs['"]\)\.copyFile(?:Sync)?\(['"][^'"]+['"],\s*['"]([^'"]+)['"](?:,\s*\(\)=>\{\})?\)$`)
	safeNodeWriteData       = regexp.MustCompile(`^require\(['"]fs['"]\)\.(?:writeFileSync|appendFileSync)\((['"][^'"]+['"]),\s*(['"][^'"]+['"])\)$`)
	safePythonRead          = regexp.MustCompile(`^(?:import io;\s*)?(?:io\.)?(?:FileIO|open)\(['"][^'"]+['"],\s*['"]r['"]\)\.read\(\)$`)
	safePythonOSRead        = regexp.MustCompile(`^import os;\s*os\.open\((['"][^'"]+['"]),\s*os\.O_RDONLY\)$`)
	safePythonOpenWrite     = regexp.MustCompile(`^open\(`)
	safePythonSeparate      = regexp.MustCompile(`^open\((['"][^'"]+['"]),\s*['"]r['"]\);\s*open\((['"][^'"]+['"]),\s*['"]a['"]\)$`)
	safePythonPathWrite     = regexp.MustCompile(`^(?:from\s+pathlib\s+import\s+Path;\s*|import\s+pathlib;\s*)?(?:pathlib\.)?Path\(\s*['"]([^'"]+)['"]\s*\)\.write_(?:text|bytes)\s*\(`)
	literalPathHomeJoinOpen = regexp.MustCompile(`\b(?:pathlib\.)?Path\.home\(\)\.joinpath\(\s*['"]([^'"]+)['"]\s*\)\.open\s*\(`)
	awkBoundedAssignPrefix  = regexp.MustCompile(`^\s*BEGIN\s*\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"\\]+)"\s*;\s*print\s+"(?:\\.|[^"\\])*"\s*>>\s*$`)
	safePythonPrint         = regexp.MustCompile(`^print\((.+)\)$`)
	safeRubyRead            = regexp.MustCompile(`^File\.read\(['"][^'"]+['"]\)$`)
	safeRubyOpenRead        = regexp.MustCompile(`^File\.open\((['"][^'"]+['"]),\s*['"]r['"]\)\s*\{\s*\|f\|\s*puts f\.read\s*\}$`)
	safePerlLocalCopy       = regexp.MustCompile(`^sub copy \{ return 1 \};\s*copy\(['"][^'"]+['"],\s*['"][^'"]+['"]\)$`)
)

// UnprovenProtectedWrite is the boundary between exact write extraction and
// execution forms it cannot model. It returns a class only if the command has
// such a form and a path in its bounded text can reach a protected file. A
// dynamic interpreter write operand can name the protected file directly.
func UnprovenProtectedWrite(command, cwd, home string) string {
	return unprovenProtectedWriteDepth(command, cwd, home, 0)
}

func unprovenProtectedWriteDepth(command, cwd, home string, depth int) string {
	if command == "" || home == "" || !filepath.IsAbs(cwd) || len(command) > MaxPayloadBytes {
		return ""
	}
	if depth >= 4 {
		if protectedReachFromText(command, cwd, home) {
			return "dynamic-command"
		}
		return ""
	}
	if !strings.ContainsAny(command, "$#*?[\\>;|&\n") &&
		!strings.Contains(command, "trap") && !strings.Contains(command, "eval") &&
		!strings.Contains(command, "source") && !strings.Contains(command, "cd ") &&
		!strings.Contains(command, "cd\t") && !strings.Contains(command, "function ") &&
		!strings.Contains(command, "function\t") && !strings.Contains(command, ". ") &&
		!strings.Contains(command, ".\t") &&
		!strings.Contains(command, "python") && !strings.Contains(command, "node") &&
		!strings.Contains(command, "ruby") && !strings.Contains(command, "perl") &&
		!strings.Contains(command, "awk") &&
		!strings.Contains(command, "()") && !shellScriptInvocation(command) {
		return ""
	}
	file, ok := parseShell(command)
	if !ok {
		if unprovenShellParseWrite(command, cwd, home) {
			return "shell-parse"
		}
		return ""
	}
	reachable := false
	called := calledFunctions(file, home)
	reachText := command
	if strings.Contains(command, "()") || strings.Contains(command, "function ") {
		reachText = reachableShellWords(file, called, home)
	}
	checkReach := func() bool {
		if !reachable {
			reachable = samePathName(cwd, home) || samePathName(cwd, filepath.Join(home, ".ssh")) ||
				protectedReachFromText(reachText, cwd, home)
		}
		return reachable
	}
	reason := ""
	set := func(class string, dynamicPath bool) {
		if reason == "" && (dynamicPath || checkReach()) {
			reason = class
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if reason != "" {
			return false
		}
		if redirect, ok := node.(*syntax.Redirect); ok && redirect.Word != nil {
			switch redirect.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
				if _, fixed := StaticWord(redirect.Word, home); !fixed {
					if !provenBoundedRedirect(file, redirect, cwd, home) {
						var target strings.Builder
						runtimeExpansion := false
						syntax.Walk(redirect.Word, func(part syntax.Node) bool {
							switch part.(type) {
							case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ProcSubst:
								runtimeExpansion = true
							}
							return !runtimeExpansion
						})
						if syntax.NewPrinter().Print(&target, redirect.Word) != nil ||
							protectedReachFromText(target.String(), cwd, home) ||
							runtimeExpansion && checkReach() {
							set("dynamic-argument", true)
						}
					}
				}
			}
			return true
		}
		if function, ok := node.(*syntax.FuncDecl); ok {
			if function.Name == nil || !called[function.Name.Value] {
				return false
			}
			if functionBodyMayWrite(function.Body, cwd, home) {
				set("function", false)
			}
			return true
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		program, static := staticProgramWord(call.Args[0], home)
		if !static {
			set("dynamic-command", false)
			return true
		}
		program = programBase(program)
		if slicesContainsString([]string{"awk", "gawk", "mawk", "nawk"}, program) {
			if awkCallUnproven(call, cwd, home) {
				set("dynamic-argument", true)
			}
			return true
		}
		if program == "trap" {
			set("trap", false)
			return true
		}
		if program == "eval" || program == "source" || program == "." {
			for _, argument := range call.Args[1:] {
				if _, ok := StaticWord(argument, home); !ok {
					set("eval-source", true)
					return true
				}
			}
			if (program == "source" || program == ".") && len(call.Args) >= 2 {
				if name, ok := StaticWord(call.Args[1], home); ok {
					if content, ok := readIndirectSource(name, cwd); ok && protectedReachFromText(content, cwd, home) {
						set("eval-source", true)
						return true
					}
				}
			}
			set("eval-source", false)
			return true
		}
		if program == "cd" {
			if cdPathProtectedReach(call, file, cwd, home) {
				set("cdpath", true)
			}
			return true
		}
		if slicesContainsString([]string{"nice", "timeout", "nohup", "env", "command", "exec", "xargs"}, program) {
			words := make([]string, 0, len(call.Args))
			for _, arg := range call.Args {
				word, fixed := StaticWord(arg, home)
				if !fixed {
					break
				}
				words = append(words, word)
			}
			if len(words) < len(call.Args) {
				// Dynamic words after a complete interpreter program are
				// its argv; they cannot move a proved ordinary destination.
				if unprovenWriter.MatchString(command) && !provedOrdinaryInterpreterPrefix(words, cwd, home) {
					set("dynamic-argument", true)
				}
				return true
			}
			if program == "xargs" {
				if len(literalPipelineOperands(file, called, cwd, home, depth)) == 0 &&
					unprovenWriter.MatchString(command) {
					set("dynamic-argument", true)
				}
				return true
			}
			if code, language, found := wrappedInterpreterCode(words); found {
				if class, dynamic := unprovenInterpreterCode(code, language, cwd, home, false); class != "" {
					set(class, dynamic)
					return true
				}
				for _, destination := range literalInterpreterWrites(code, language, cwd, home) {
					if protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
						set("dynamic-argument", true)
						return true
					}
				}
				if !interpreterProtectedUseSafe(code, language, cwd, home) && protectedReachFromText(code, cwd, home) {
					set("interpreter-path", true)
				}
				return true
			}
			if len(literalProgramOperands(words, nil, cwd, home, depth, false)) == 0 &&
				unprovenWriter.MatchString(command) {
				set("dynamic-argument", true)
			}
			return true
		}
		if posixShellProgram(program) {
			words := make([]string, 0, len(call.Args))
			for _, arg := range call.Args {
				word, fixed := StaticWord(arg, home)
				if !fixed {
					set("dynamic-argument", false)
					return true
				}
				words = append(words, word)
			}
			if body, ok := shellCommandBodyIndex(words); ok {
				if nested := unprovenProtectedWriteDepth(words[body], cwd, home, depth+1); nested != "" {
					set(nested, true)
				} else if shellArgvIncomplete(program) && shellBodyProtectedWrite(words[body], cwd, home) {
					// Zsh runs its startup files before the -c body, so argv
					// alone cannot certify the action. A static write to a
					// protected path in the visible body fails closed.
					set("nested-shell", true)
				}
				return true
			}
			// No -c program word: a script file, stdin (-s), or an option
			// the proof does not know. A small regular script under cwd is
			// read and inspected like the interpreter branch; otherwise the
			// shell's visible words fail closed when they reach a protected
			// path, because the contents it will run are not bounded here.
			if script, ok := shellScriptOperand(words); ok {
				if content, read := readIndirectSource(script, cwd); read {
					if nested := unprovenProtectedWriteDepth(content, cwd, home, depth+1); nested != "" {
						set(nested, true)
					} else if shellBodyProtectedWrite(content, cwd, home) {
						set("nested-shell", true)
					}
					return true
				}
			}
			if protectedReachFromText(command, cwd, home) {
				set("nested-shell", true)
			}
			return true
		}
		if program == "python" || strings.HasPrefix(program, "python3") ||
			program == "node" || program == "nodejs" || program == "ruby" || program == "perl" {
			language := program
			if language == "nodejs" {
				language = "node"
			}
			code, codeIndex, fixed := interpreterCodeOperand(call, language, home)
			if !fixed {
				// Unknown options, code operands and script files cannot
				// certify the destination of a protected alias named by the
				// call. A small regular script under cwd is also inspected.
				if len(call.Args) >= 2 {
					if script, static := StaticWord(call.Args[1], home); static {
						if content, ok := readIndirectSource(script, cwd); ok {
							if class, dynamic := unprovenInterpreterCode(content, language, cwd, home, !pythonCallSetsImportPath(call)); class != "" {
								set(class, dynamic)
							}
							if protectedReachFromText(content, cwd, home) &&
								!interpreterProtectedUseSafe(content, language, cwd, home) {
								set("interpreter-path", true)
							}
						}
					}
				}
				set("interpreter-path", false)
				return true
			}
			if fixed && unprovenWriter.MatchString(code) {
				if class, dynamic := unprovenInterpreterCode(code, language, cwd, home, !pythonCallSetsImportPath(call)); class != "" {
					set(class, dynamic)
				}
				// A dynamic argument can steer code through argv, unless
				// the whole program is a proved write to a fixed ordinary
				// destination; a protected name in its data is not a path.
				if !interpreterProtectedUseSafe(code, language, cwd, home) {
					for _, argument := range call.Args[codeIndex+1:] {
						if _, ok := StaticWord(argument, home); !ok {
							set("interpreter-argument", false)
							break
						}
					}
				}
			}
			// Source scanning recognizes selected write APIs, but a fixed
			// interpreter script can invoke any other API. When it names a
			// protected alias, only the small read/source-only forms below
			// establish that the alias cannot be a write destination.
			if fixed && reason == "" && !interpreterProtectedUseSafe(code, language, cwd, home) &&
				checkReach() {
				set("interpreter-path", true)
			}
			return true
		}
		if !slicesContainsString(dataPrograms, program) {
			if slicesContainsString([]string{"cp", "gcp", "mv", "gmv", "install"}, program) && len(call.Args) > 1 {
				if _, ok := StaticWord(call.Args[len(call.Args)-1], home); !ok {
					if destination, bounded := boundedCommandDestination(file, call, home); bounded {
						if protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
							set("dynamic-argument", true)
						}
						return true
					}
					set("dynamic-argument", true)
					return true
				}
			}
			if slicesContainsString([]string{"tee", "touch", "truncate"}, program) {
				for _, argument := range call.Args[1:] {
					if _, ok := StaticWord(argument, home); !ok {
						set("dynamic-argument", false)
						return true
					}
				}
			}
			for _, argument := range call.Args[1:] {
				if _, ok := StaticWord(argument, home); !ok {
					set("dynamic-argument", false)
					break
				}
			}
		}
		return true
	})
	return reason
}

// Recoverable syntax errors may leave executable calls and redirects in the
// syntax tree. Check those effects before discarding the failed parse.
func unprovenShellParseWrite(command, cwd, home string) bool {
	if len(command) > MaxPayloadBytes {
		return true // Beyond the command proof bound, effects are unknown.
	}
	file, _ := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.RecoverErrors(8)).Parse(strings.NewReader(command), "")
	if file == nil {
		return strings.Contains(command, ">") ||
			unprovenWriter.MatchString(command) && protectedReachFromText(command, cwd, home)
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	unknown := false
	calls := 0
	called := calledFunctions(file, home)
	syntax.Walk(file, func(node syntax.Node) bool {
		if unknown {
			return false
		}
		if declaration, ok := node.(*syntax.FuncDecl); ok {
			return declaration.Name != nil && called[declaration.Name.Value]
		}
		if call, ok := node.(*syntax.CallExpr); ok {
			calls++
			if calls > 256 {
				unknown = true
				return false
			}
			var rendered strings.Builder
			if syntax.NewPrinter().Print(&rendered, call) != nil {
				unknown = true
				return false
			}
			prefix := rendered.String()
			if unprovenProtectedWriteDepth(prefix, cwd, home, 0) != "" {
				unknown = true
				return false
			}
			for _, operand := range literalWriteOperandsDepth(prefix, cwd, home, 0) {
				if protectedReachPath(operand, protected, ssh) {
					unknown = true
					return false
				}
			}
			words := make([]string, len(call.Args))
			for i, arg := range call.Args {
				var fixed bool
				words[i], fixed = StaticWord(arg, home)
				if !fixed {
					return true // The unproven call check above handles dynamic operands.
				}
			}
			// A direct cp target is normally an ActionFacts path. The failed
			// whole-command parse discarded that fact, so recover its call as
			// a standalone command (the wrapped proof also extracts cp).
			for _, operand := range literalProgramOperands(words, nil, cwd, home, 1, false) {
				if protectedReachPath(operand, protected, ssh) {
					unknown = true
					return false
				}
			}
		}
		redirect, ok := node.(*syntax.Redirect)
		if !ok || redirect.Word == nil {
			return true
		}
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
		default:
			return true
		}
		path, fixed := StaticWord(redirect.Word, home)
		if !fixed || protectedReachPath(OperandPath(path, cwd), protected, ssh) {
			unknown = true
		}
		return !unknown
	})
	return unknown
}

// awkCallUnproven reports an awk call whose program text has an output this
// proof cannot name, or whose file or command effects depend on a word the
// shell computes. The words are read as awk reads them: options, then one
// program (unless -f or -e supplied it), then operands. Only program text is
// awk code. A -v or -F value, an operand and a var=value assignment are data,
// however much they look like code. After an option this proof does not know,
// any later word can be the program, so each one is checked as a program. A
// dynamic program with a visible file output, a dynamic program file, or any
// dynamic word after an unknown option is unproved. A dynamic
// operand or -v value is an input file or a var=value assignment, so it
// matters only when the program has an unproved output or command effect (or
// the program text is unknown).
func awkCallUnproven(call *syntax.CallExpr, cwd, home string) bool {
	var programs []string
	programKnown, programSupplied, options := true, false, true
	dynamicOperand, unknownOption := false, false
	// addProgram records fixed program text and reports an unproved output.
	addProgram := func(code string) bool {
		programs = append(programs, code)
		return awkUnprovenOutput(code, cwd, home)
	}
	args := call.Args[1:]
	for i := 0; i < len(args); i++ {
		word, fixed := StaticWord(args[i], home)
		if unknownOption && fixed && awkUnprovenOutput(word, cwd, home) {
			return true
		}
		if options && !fixed {
			// An option with an attached computed value, such as -vn="$N".
			switch awkDynamicOptionName(args[i]) {
			case "v":
				dynamicOperand = true
				continue
			case "F":
				continue
			case "f", "e":
				return true
			}
		}
		if !options || !fixed || word == "-" || !strings.HasPrefix(word, "-") {
			if !programSupplied {
				programSupplied, options = true, false
				if !fixed {
					rendered, ok := awkDynamicProgram(args[i], cwd, home)
					if !ok {
						return true
					}
					programs = append(programs, rendered)
				} else if addProgram(word) {
					return true
				}
				continue
			}
			if options && !fixed {
				return true // A computed word where an option can stand may be any option.
			}
			options = false
			dynamicOperand = dynamicOperand || !fixed
			continue
		}
		if word == "--" {
			options = false
			continue
		}
		name, value, attached := awkOptionValue(word)
		if name == "" {
			unknownOption = unknownOption || !slicesContainsString(awkHarmlessFlags, word)
			continue
		}
		valueFixed := true
		if !attached {
			if i+1 >= len(args) {
				return true
			}
			i++
			value, valueFixed = StaticWord(args[i], home)
			if unknownOption && valueFixed && awkUnprovenOutput(value, cwd, home) {
				return true
			}
		}
		switch name {
		case "f":
			if !valueFixed {
				return true
			}
			programSupplied = true
			if content, ok := readIndirectSource(value, cwd); ok {
				programs = append(programs, content)
			} else {
				programKnown = false
			}
		case "e":
			programSupplied = true
			if !valueFixed {
				rendered, ok := awkDynamicProgram(args[i], cwd, home)
				if !ok {
					return true
				}
				programs = append(programs, rendered)
			} else if addProgram(value) {
				return true
			}
		case "v":
			dynamicOperand = dynamicOperand || !valueFixed
		}
	}
	// A program supplied by -f runs even when every input operand is fixed.
	// The file may be unreadable or may write through a protected link; neither
	// case becomes safe merely because awk was given no dynamic argument.
	if !programKnown {
		return true
	}
	for _, program := range programs {
		if awkUnprovenOutput(program, cwd, home) || awkCommandEffect(program) {
			return true
		}
	}
	return dynamicOperand && unknownOption
}

// Flags that take no value and add no file or command effect. Every other
// option (gawk -o, -p, -d, -D, -i, -l, ...) leaves the program unknown.
var awkHarmlessFlags = []string{"--posix", "-P", "--traditional", "--compat", "--sandbox", "-S",
	"-b", "--characters-as-bytes", "-n", "--non-decimal-data", "-N", "--use-lc-numeric",
	"-M", "--bignum", "-O", "--optimize", "-s", "--no-optimize", "-r", "--re-interval"}

// awkOptionValue names a value option (f, e, v or F) and its attached value.
func awkOptionValue(word string) (name, value string, attached bool) {
	for _, option := range []struct{ short, long, name string }{
		{"-f", "--file", "f"}, {"-e", "--source", "e"}, {"-v", "--assign", "v"}, {"-F", "--field-separator", "F"},
	} {
		switch {
		case word == option.short || word == option.long:
			return option.name, "", false
		case strings.HasPrefix(word, option.long+"="):
			return option.name, word[len(option.long)+1:], true
		case strings.HasPrefix(word, option.short) && !strings.HasPrefix(word, "--"):
			return option.name, word[len(option.short):], true
		}
	}
	return "", "", false
}

// awkDynamicOptionName names the value option of a computed word whose
// literal first part is that option, so its value is attached.
func awkDynamicOptionName(word *syntax.Word) string {
	if word == nil || len(word.Parts) < 2 {
		return ""
	}
	literal, ok := word.Parts[0].(*syntax.Lit)
	if !ok {
		return ""
	}
	name, _, _ := awkOptionValue(literal.Value)
	return name
}

// awkDynamicProgram checks visible file effects in an inline program with a
// shell expansion. A shell word's outer quotes are syntax, not AWK source.
// Exposed file output is unproved because the expansion can change its target.
func awkDynamicProgram(word *syntax.Word, cwd, home string) (string, bool) {
	if word == nil || len(word.Parts) != 1 {
		return "", false
	}
	quoted, ok := word.Parts[0].(*syntax.DblQuoted)
	if !ok {
		return "", false
	}
	var rendered strings.Builder
	for _, part := range quoted.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			value := part.Value
			for i := 0; i < len(value); i++ {
				if value[i] == '\\' && i+1 < len(value) {
					switch value[i+1] {
					case '"', '\\', '$':
						i++
						rendered.WriteByte(value[i])
						continue
					}
				}
				rendered.WriteByte(value[i])
			}
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp:
			rendered.WriteByte('X')
		default:
			return "", false
		}
	}
	text := rendered.String()
	if !strings.Contains(text, "{") || !strings.Contains(text, "}") {
		return "", false
	}
	output, unsafe, _ := awkOutputProof(text, cwd, home)
	if output || unsafe || awkCommandEffect(text) {
		return "", false
	}
	return text, true
}

// awkCommandEffect reports awk code that runs a command (a pipe, system(),
// or a gawk @ directive that loads more code). Strings, regular expression
// literals and comments are data; || is a logical operator.
func awkCommandEffect(code string) bool {
	previous := byte('{')
	for i := 0; i < len(code); i++ {
		c := code[i]
		if awkBlank(code, &i) {
			continue
		}
		if end, found, ok := awkDataEnd(code, i, previous); found {
			if !ok {
				return true
			}
			if c != '#' {
				previous = code[end]
			}
			i = end
			continue
		}
		switch {
		case c == '|':
			if i+1 < len(code) && code[i+1] == '|' {
				i++
			} else {
				return true
			}
		case c == '@':
			return true
		case awkWordByte(c) && (c < '0' || c > '9'):
			start := i
			for i+1 < len(code) && awkWordByte(code[i+1]) {
				i++
			}
			if code[start:i+1] == "system" {
				return true
			}
		}
		previous = code[i]
	}
	return false
}

func awkWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// awkBlank steps over a blank or a backslash-newline continuation. Awk reads
// both as a blank: neither ends a statement nor opens a literal.
func awkBlank(code string, i *int) bool {
	switch code[*i] {
	case ' ', '\t', '\r':
		return true
	case '\\':
		next := *i + 1
		if next < len(code) && code[next] == '\r' {
			next++
		}
		if next < len(code) && code[next] == '\n' {
			*i = next
			return true
		}
	}
	return false
}

// awkDataEnd finds the awk data that starts at code[i]: a string, a regular
// expression literal (a slash where awk cannot divide, after the previous
// significant byte) or a comment. It returns the index of the data's last
// byte; a comment ends before its newline, which still ends the statement.
// found is false when code[i] starts no data. ok is false when the data has
// no end awk accepts, so the program does not run as this scan reads it.
func awkDataEnd(code string, i int, previous byte) (end int, found, ok bool) {
	switch c := code[i]; {
	case c == '"':
		for j := i + 1; j < len(code); j++ {
			switch code[j] {
			case '\\':
				j++
			case '"':
				return j, true, true
			}
		}
		return len(code) - 1, true, false
	case c == '#':
		if newline := strings.IndexByte(code[i:], '\n'); newline >= 0 {
			return i + newline - 1, true, true
		}
		return len(code) - 1, true, true
	case c == '/' && strings.IndexByte("(,{};!~&|\n?:=}", previous) >= 0:
		end, ok := awkRegexEnd(code, i)
		return end, true, ok
	}
	return i, false, true
}

// awkRegexEnd returns the index of the slash that closes the regular
// expression literal opening at code[start]. A slash inside a bracket
// expression belongs to it, as gawk and mawk read it; an awk that ends the
// literal there rejects its unclosed bracket and runs nothing. [:class:],
// [.symbol.] and [=equivalent=] close with their own pair, not the first ].
// ok is false for a literal that does not close on its line.
func awkRegexEnd(code string, start int) (int, bool) {
	bracket := false
	for i := start + 1; i < len(code); i++ {
		c := code[i]
		switch {
		case c == '\n':
			return i, false
		case c == '\\':
			if i+1 < len(code) && code[i+1] == '\n' {
				return i + 1, false
			}
			i++
		case bracket && c == '[' && i+1 < len(code) && strings.IndexByte(":.=", code[i+1]) >= 0:
			closer := string(code[i+1]) + "]"
			if end := strings.Index(code[i+2:], closer); end >= 0 && !strings.Contains(code[i+2:i+2+end], "\n") {
				i += 2 + end + 1
			}
		case bracket && c == ']':
			bracket = false
		case c == '[':
			bracket = true
			if i+1 < len(code) && code[i+1] == '^' {
				i++
			}
			if i+1 < len(code) && code[i+1] == ']' {
				i++
			}
		case !bracket && c == '/':
			return i, true
		}
	}
	return len(code) - 1, false
}

// provedOrdinaryInterpreterPrefix reports wrapper words that end with a
// complete inline interpreter program which is a proved write to a fixed
// ordinary destination; later dynamic words can only be its argv.
func provedOrdinaryInterpreterPrefix(words []string, cwd, home string) bool {
	code, language, found := wrappedInterpreterCode(words)
	if !found {
		return false
	}
	class, _ := unprovenInterpreterCode(code, language, cwd, home, false)
	return class == "" && interpreterProtectedUseSafe(code, language, cwd, home)
}

// An awk print redirect opens a file. A quoted target is named by the
// literal operand extractor; an expression after > cannot be named here.
// Strings, regular expression literals and comments are data, so a > inside
// one is not a redirect. A print statement continues past a newline after a
// comma, && or ||, and past a backslash-newline.
func awkUnprovenOutput(code, cwd, home string) bool {
	_, unsafe, _ := awkOutputProof(code, cwd, home)
	return unsafe
}

// awkOutputProof records file output as well as unproved destinations. A
// literal target is checked against protected links even when a later AWK
// input operand is dynamic and the literal operand extractor cannot run.
func awkOutputProof(code, cwd, home string) (output, unsafe bool, literals []string) {
	printing := false
	previous := byte('{')
	for i := 0; i < len(code); i++ {
		c := code[i]
		if awkBlank(code, &i) {
			continue
		}
		if end, found, ok := awkDataEnd(code, i, previous); found {
			if !ok {
				return output, true, literals
			}
			if c != '#' {
				previous = code[end]
			}
			i = end
			continue
		}
		before := previous
		previous = c
		if c == '\n' && strings.IndexByte(",&|", before) >= 0 {
			previous = before
			continue
		}
		if c == ';' || c == '{' || c == '}' || c == '\n' {
			printing = false
			continue
		}
		if awkWordByte(c) && (c < '0' || c > '9') {
			start := i
			for i+1 < len(code) && awkWordByte(code[i+1]) {
				i++
			}
			previous = code[i]
			word := code[start : i+1]
			if word == "print" || word == "printf" {
				printing = true
			}
			continue
		}
		if c != '>' || !printing {
			continue
		}
		output = true
		if i+1 < len(code) && code[i+1] == '>' {
			i++
		}
		for i+1 < len(code) && (code[i+1] == ' ' || code[i+1] == '\t') {
			i++
		}
		if i+1 >= len(code) {
			return output, true, literals
		}
		if code[i+1] == '"' || code[i+1] == '\'' {
			quote := code[i+1]
			end := i + 2
			value := ""
			for end < len(code) && code[end] != quote {
				if code[end] == '\\' {
					return output, true, literals // Escape semantics need an interpreter proof.
				}
				end++
			}
			if end >= len(code) {
				return output, true, literals
			}
			value = code[i+2 : end]
			// AWK concatenates adjacent quoted literals before opening the
			// redirection target. Keep the whole target as one proof operand.
			for quote == '"' {
				next := end + 1
				for next < len(code) && (code[next] == ' ' || code[next] == '\t') {
					next++
				}
				if next >= len(code) || code[next] != '"' {
					break
				}
				start := next + 1
				next = start
				for next < len(code) && code[next] != '"' {
					if code[next] == '\\' {
						return output, true, literals
					}
					next++
				}
				if next >= len(code) {
					return output, true, literals
				}
				value += code[start:next]
				end = next
			}
			if quote == '"' {
				literals = append(literals, value)
			}
			if quote == '"' && protectedReachPath(OperandPath(value, cwd),
				newProtectedFiles(home), filepath.Join(home, ".ssh")) {
				return output, true, literals
			}
			for end+1 < len(code) && (code[end+1] == ' ' || code[end+1] == '\t') {
				end++
			}
			if end+1 < len(code) && code[end+1] != ';' && code[end+1] != '}' &&
				code[end+1] != '\n' && code[end+1] != '#' {
				return output, true, literals // A later expression changes the opened target.
			}
		} else {
			start := i + 1
			end := start
			for end < len(code) && ((code[end] >= 'a' && code[end] <= 'z') ||
				(code[end] >= 'A' && code[end] <= 'Z') || code[end] == '_') {
				end++
			}
			if end == start || end < len(code) && code[end] != ' ' && code[end] != '\t' && code[end] != ';' && code[end] != '}' {
				return output, true, literals
			}
			value, fixed := awkFixedAssignment(code[:start], code[start:end])
			if !fixed || protectedReachPath(OperandPath(value, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
				return output, true, literals
			}
		}
	}
	return output, false, literals
}

func awkFixedAssignment(prefix, name string) (string, bool) {
	// Only this complete BEGIN prefix has no intervening call or statement
	// that can change the variable or the filesystem before the redirect.
	match := awkBoundedAssignPrefix.FindStringSubmatch(prefix)
	if len(match) != 3 || match[1] != name {
		return "", false
	}
	return match[2], true
}

func wrappedInterpreterCode(words []string) (code, language string, found bool) {
	for i, word := range words {
		program := programBase(word)
		switch {
		case program == "python" || strings.HasPrefix(program, "python3"):
			if code, ok := pythonLiteralCode(words[i:]); ok {
				return code, "python", true
			}
		case program == "node" || program == "nodejs" || program == "ruby" || program == "perl":
			if i+2 < len(words) && words[i+1] == "-e" {
				if program == "nodejs" {
					program = "node"
				}
				return words[i+2], program, true
			}
		}
	}
	return "", "", false
}

// A quoted value fixed by the preceding printf assignment is already a
// complete redirect proof. Its literal '*' must not be treated as a glob.
func provenBoundedRedirect(file *syntax.File, redirect *syntax.Redirect, cwd, home string) bool {
	if len(file.Stmts) != 2 || len(file.Stmts[1].Redirs) != 1 || file.Stmts[1].Redirs[0] != redirect {
		return false
	}
	name, value, ok := boundedPrintfAssignment(file.Stmts[0], home)
	if !ok || !boundedWordUses(redirect.Word, name) || boundedWordPattern(redirect.Word, name, value) {
		return false
	}
	target, known := boundedWord(redirect.Word, home, name, value)
	return known && target != "" && !protectedReachPath(OperandPath(target, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh"))
}

func interpreterProtectedUseSafe(code, language, cwd, home string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return true
	}
	commentOnly := true
	for _, line := range strings.Split(code, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			commentOnly = false
			break
		}
	}
	if commentOnly {
		return true
	}
	if language == "python" || strings.HasPrefix(language, "python3") {
		if pythonInertTripleStringProgram(code) {
			return true
		}
		if match := safePythonPrint.FindStringSubmatch(code); match != nil && pythonLiteralData(match[1]) {
			return true
		}
		if safePythonRead.MatchString(code) {
			return true
		}
		if match := safePythonOSRead.FindStringSubmatch(code); match != nil {
			_, ok := literalString(match[1])
			return ok
		}
		if match := safePythonSeparate.FindStringSubmatch(code); match != nil {
			destination, ok := literalString(match[2])
			if ok && !protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
				return true
			}
		}
		if safePythonOpenWrite.MatchString(code) {
			openCall, complete := literalBoundedCall(code, len("open"))
			openArgs := literalCallArgs(openCall)
			if complete && len(openArgs) == 2 {
				destination, pathOK := literalString(openArgs[0])
				mode, modeOK := literalString(openArgs[1])
				prefixEnd := len("open") + len(openCall)
				if pathOK && modeOK && literalWriteMode(mode) &&
					strings.HasPrefix(code[prefixEnd:], ".write(") {
					writeCall, writeOK := literalBoundedCall(code, prefixEnd+len(".write"))
					writeArgs := literalCallArgs(writeCall)
					if writeOK && len(writeArgs) == 1 && pythonLiteralData(writeArgs[0]) &&
						strings.Trim(strings.TrimSpace(code[prefixEnd+len(".write")+len(writeCall):]), "; ") == "" &&
						!protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
						return true
					}
				}
			}
		}
		if match := safePythonPathWrite.FindStringSubmatchIndex(code); match != nil {
			call, complete := literalBoundedCall(code, match[1]-1)
			args := literalCallArgs(call)
			if complete && len(args) == 1 {
				dataOK := pythonLiteralData(args[0])
				destination := code[match[2]:match[3]]
				if dataOK && strings.Trim(strings.TrimSpace(code[match[1]-1+len(call):]), "; ") == "" &&
					!protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
					return true
				}
			}
		}
		return false
	}
	switch language {
	case "node":
		if safeNodeRead.MatchString(code) {
			return true
		}
		if match := safeNodeCopy.FindStringSubmatch(code); match != nil {
			return !protectedReachPath(OperandPath(match[1], cwd), newProtectedFiles(home), filepath.Join(home, ".ssh"))
		}
		if match := safeNodeWriteData.FindStringSubmatch(code); match != nil {
			destination, ok := literalString(match[1])
			_, dataOK := literalString(match[2])
			return ok && dataOK && !protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh"))
		}
	case "ruby":
		return safeRubyRead.MatchString(code) || safeRubyOpenRead.MatchString(code)
	case "perl":
		return safePerlLocalCopy.MatchString(code)
	}
	return false
}

// pythonLiteralData proves one Python string literal is inert data. The
// prefixes are those Python accepts (u, r, b, f and t, alone or in their
// legal pairs, in either case). An f- or t-string is data only when it has no
// replacement field: every brace is doubled. A backslash does not escape a
// brace, so f"\{x}" still evaluates x and is not data.
func pythonLiteralData(value string) bool {
	value = strings.TrimSpace(value)
	quoteAt := strings.IndexAny(value, `'"`)
	if quoteAt < 0 {
		return false
	}
	prefix := strings.ToLower(value[:quoteAt])
	if !slicesContainsString([]string{"", "u", "r", "b", "br", "rb", "f", "fr", "rf", "t", "tr", "rt"}, prefix) {
		return false
	}
	template := strings.ContainsAny(prefix, "ft")
	value = value[quoteAt:]
	if len(value) < 2 || value[0] != value[len(value)-1] {
		return false
	}
	quote := value[0]
	for i := 1; i < len(value)-1; i++ {
		switch value[i] {
		case '\\':
			if template && i+1 < len(value)-1 && (value[i+1] == '{' || value[i+1] == '}') {
				continue
			}
			i++
			if i >= len(value)-1 {
				return false
			}
		case quote:
			return false
		case '{', '}':
			if !template {
				continue
			}
			if i+1 < len(value)-1 && value[i+1] == value[i] {
				i++
				continue
			}
			return false
		}
	}
	return true
}

// boundedCommandDestination handles a single assignment or a single called
// function whose literal argument fixes the copy destination. No intervening
// statement can change the value or the directory in either shape.
func boundedCommandDestination(file *syntax.File, call *syntax.CallExpr, home string) (string, bool) {
	if len(file.Stmts) != 2 || len(call.Args) < 2 {
		return "", false
	}
	last := call.Args[len(call.Args)-1]
	if file.Stmts[1].Cmd == call {
		if name, value, ok := boundedSimpleAssignment(file.Stmts[0], home); ok {
			return boundedWord(last, home, name, value)
		}
		if name, value, ok := boundedBasenameAssignment(file.Stmts[0], home); ok {
			return boundedWord(last, home, name, value)
		}
	}
	function, ok := file.Stmts[0].Cmd.(*syntax.FuncDecl)
	if !ok || function.Name == nil || function.Body == nil {
		return "", false
	}
	body, ok := function.Body.Cmd.(*syntax.Block)
	if !ok || len(body.Stmts) != 1 || body.Stmts[0].Cmd != call {
		return "", false
	}
	invoke, ok := file.Stmts[1].Cmd.(*syntax.CallExpr)
	if !ok || len(invoke.Args) < 2 || len(invoke.Assigns) != 0 || len(file.Stmts[1].Redirs) != 0 {
		return "", false
	}
	name, static := StaticWord(invoke.Args[0], home)
	if !static || name != function.Name.Value {
		return "", false
	}
	for position, argument := range invoke.Args[1:] {
		value, ok := StaticWord(argument, home)
		if !ok {
			return "", false
		}
		if result, ok := boundedWord(last, home, strconv.Itoa(position+1), value); ok {
			return result, true
		}
	}
	return "", false
}

func boundedBasenameAssignment(stmt *syntax.Stmt, home string) (name, value string, ok bool) {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return "", "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 0 || len(call.Assigns) != 1 {
		return "", "", false
	}
	assignment := call.Assigns[0]
	if assignment.Name == nil || assignment.Value == nil || len(assignment.Value.Parts) != 1 {
		return "", "", false
	}
	part := assignment.Value.Parts[0]
	if quoted, ok := part.(*syntax.DblQuoted); ok && len(quoted.Parts) == 1 {
		part = quoted.Parts[0]
	}
	substitution, ok := part.(*syntax.CmdSubst)
	if !ok || len(substitution.Stmts) != 1 {
		return "", "", false
	}
	basename, ok := substitution.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(basename.Args) != 2 || len(basename.Assigns) != 0 || len(substitution.Stmts[0].Redirs) != 0 {
		return "", "", false
	}
	program, static := StaticWord(basename.Args[0], home)
	if !static || program != "basename" {
		return "", "", false
	}
	path, static := StaticWord(basename.Args[1], home)
	if !static || path == "" || strings.ContainsAny(path, "\x00\r\n") {
		return "", "", false
	}
	return assignment.Name.Value, filepath.Base(path), true
}

func reachableShellWords(file *syntax.File, called map[string]bool, home string) string {
	var text strings.Builder
	syntax.Walk(file, func(node syntax.Node) bool {
		if function, ok := node.(*syntax.FuncDecl); ok {
			return function.Name != nil && called[function.Name.Value]
		}
		if word, ok := node.(*syntax.Word); ok {
			if value, static := StaticWord(word, home); static {
				text.WriteString(value)
			} else {
				_ = syntax.NewPrinter().Print(&text, word)
			}
			text.WriteByte(' ')
			return false
		}
		return true
	})
	return text.String()
}

func slicesContainsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func functionBodyMayWrite(body *syntax.Stmt, cwd, home string) bool {
	mayWrite := false
	syntax.Walk(body, func(node syntax.Node) bool {
		if redirect, ok := node.(*syntax.Redirect); ok {
			switch redirect.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
				mayWrite = true
			}
		}
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			program, static := StaticWord(call.Args[0], home)
			program = programBase(program)
			if program == "python" || strings.HasPrefix(program, "python3") ||
				program == "node" || program == "nodejs" || program == "ruby" || program == "perl" {
				code, _, fixed := interpreterCodeOperand(call, program, home)
				if !fixed || len(literalInterpreterWrites(code, program, cwd, home)) > 0 {
					mayWrite = true
				} else if class, _ := unprovenInterpreterCode(code, program, cwd, home, !pythonCallSetsImportPath(call)); class != "" {
					mayWrite = true
				}
			} else if !static || !slicesContainsString(dataPrograms, program) &&
				!slicesContainsString([]string{":", "true", "false", "pwd"}, program) {
				mayWrite = true
			}
		}
		return !mayWrite
	})
	return mayWrite
}

func interpreterCodeOperand(call *syntax.CallExpr, program, home string) (string, int, bool) {
	words := make([]string, len(call.Args))
	for i, word := range call.Args {
		var ok bool
		words[i], ok = StaticWord(word, home)
		if !ok {
			return "", 0, false
		}
		if (program == "node" || program == "ruby" || program == "perl") && i == 2 && words[1] == "-e" {
			return words[2], 2, true
		}
		if (program == "python" || strings.HasPrefix(program, "python3")) && words[i] == "-c" && i+1 < len(words) {
			code, ok := StaticWord(call.Args[i+1], home)
			return code, i + 1, ok
		}
	}
	return "", 0, false
}

var (
	pythonReceiverName   = regexp.MustCompile(`(?:^|[^\w.])([A-Za-z_]\w*)\s*\.\s*write_(?:text|bytes)\s*\($`)
	pythonPathAssignment = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=\s*(?:pathlib\.)?Path(?:\.home\(\)(?:\s*/\s*['"][^'"\\]*['"])*|\(\s*['"]([^'"\\]+)['"]\s*\))$`)
)

// pythonStringWriterText reports writer call text outside executable code.
func pythonStringWriterText(code string) bool {
	for _, location := range unprovenWriter.FindAllStringIndex(code, -1) {
		if !pythonExecutableCodePosition(code, location[0]) {
			return true
		}
	}
	return false
}

// pythonReboundReceiver resolves the receiver of name.write_text( ending at
// call when the program before it is a straight line of simple statements:
// pathlib imports and Path assignments only, the last binding of name being
// a literal Path("..."). Any other statement (a call, a link, a chdir, a
// compound statement) can change what the name or a relative path refers
// to, so the receiver stays unresolved.
func pythonReboundReceiver(code string, call int, home string) (string, bool) {
	receiver := pythonReceiverName.FindStringSubmatchIndex(code[:call])
	if receiver == nil {
		return "", false
	}
	name, prefix := code[receiver[2]:receiver[3]], code[:receiver[2]]
	if strings.ContainsAny(prefix, "\n\r\\#") {
		return "", false
	}
	destination, bound := "", false
	for _, statement := range strings.Split(prefix, ";") {
		switch statement = strings.TrimSpace(statement); statement {
		case "", "from pathlib import Path", "import pathlib", `f"""{`:
		default:
			match := pythonPathAssignment.FindStringSubmatch(statement)
			if match != nil {
				if match[1] == name {
					destination, bound = match[2], match[2] != ""
					if !bound {
						destination, bound = pythonHomePathAssignment(statement, home)
					}
				}
				continue
			}
			variable, expression, assigned := strings.Cut(statement, "=")
			if !assigned || strings.TrimSpace(variable) != name {
				return "", false
			}
			expression = strings.TrimSpace(expression)
			if !strings.HasPrefix(expression, "Path(") && !strings.HasPrefix(expression, "pathlib.Path(") {
				return "", false
			}
			open := strings.IndexByte(expression, '(')
			call, ok := literalBoundedCall(expression, open)
			if !ok || call != expression[open:] {
				return "", false
			}
			args := literalCallArgs(call)
			if len(args) != 1 {
				return "", false
			}
			if destination, bound = literalPythonString(args[0]); !bound {
				return "", false
			}
		}
	}
	return destination, bound
}

func pythonHomePathAssignment(statement, home string) (string, bool) {
	if home == "" {
		return "", false
	}
	_, expression, assigned := strings.Cut(statement, "=")
	if !assigned {
		return "", false
	}
	expression = strings.TrimSpace(expression)
	for _, prefix := range []string{"Path.home()", "pathlib.Path.home()"} {
		if !strings.HasPrefix(expression, prefix) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(expression, prefix))
		path := home
		parts := 0
		for rest != "" {
			if rest[0] != '/' {
				return "", false
			}
			rest = strings.TrimSpace(rest[1:])
			if len(rest) < 2 || rest[0] != '\'' && rest[0] != '"' {
				return "", false
			}
			quote := rest[0]
			end := strings.IndexByte(rest[1:], quote)
			if end < 0 {
				return "", false
			}
			part := rest[1 : end+1]
			if part == "" || filepath.IsAbs(part) || strings.ContainsAny(part, "\\\x00") || part == ".." || strings.HasPrefix(part, "../") {
				return "", false
			}
			path = filepath.Join(path, part)
			parts++
			rest = strings.TrimSpace(rest[end+2:])
		}
		return path, parts > 0
	}
	return "", false
}

// PythonInertTextMasked is supplied by guardrail, which imports hookpaths.
// With no callback, every byte remains potentially executable.
var PythonInertTextMasked func(code, cwd string) string

func pythonCallSetsImportPath(call *syntax.CallExpr) bool {
	for _, assignment := range call.Assigns {
		if assignment.Name == nil {
			return true
		}
		if assignment.Name.Value == "PYTHONPATH" || assignment.Name.Value == "PYTHONHOME" {
			return true
		}
	}
	return false
}

func unprovenInterpreterCode(code, language, cwd, home string, maskInert bool) (string, bool) {
	if len(code) > 16<<10 {
		return "interpreter-path", true
	}
	scan := code
	if maskInert && PythonInertTextMasked != nil &&
		(language == "python" || strings.HasPrefix(language, "python3")) {
		if masked := PythonInertTextMasked(code, cwd); len(masked) == len(code) {
			scan = masked
		}
	}
	if (language == "python" || strings.HasPrefix(language, "python3")) &&
		scan == code && pythonStringWriterText(code) {
		// A local module, import-path override or an executable string can
		// run writer text that otherwise looks like inert Python data.
		return "interpreter-path", true
	}
	if language == "python" || strings.HasPrefix(language, "python3") {
		for _, location := range literalCopyCall.FindAllStringIndex(scan, -1) {
			if scan != code && !pythonExecutableCodePosition(code, location[0]) {
				continue
			}
			api := strings.TrimSuffix(code[location[0]:location[1]], "(")
			if api != "shutil.copy" && api != "shutil.copy2" {
				continue
			}
			call, ok := literalBoundedCall(code, location[1]-1)
			if !ok {
				return "interpreter-path", true
			}
			args := literalCallArgs(call)
			dst := literalCallArgument(args, 1, "dst")
			name, ok := literalString(dst)
			if !ok {
				return "interpreter-path", true
			}
			if info, err := os.Stat(OperandPath(name, cwd)); err == nil && info.IsDir() {
				destination := OperandPath(name, cwd)
				protected := newProtectedFiles(home)
				ssh := filepath.Join(home, ".ssh")
				source, sourceOK := literalString(literalCallArgument(args, 0, "src"))
				if !sourceOK {
					if protectedReachPath(destination, protected, ssh) {
						return "copy-directory", true
					}
					directory, err := os.Open(destination)
					if err != nil {
						return "copy-directory", true
					}
					entries, err := directory.Readdirnames(257)
					_ = directory.Close()
					if err != nil && err != io.EOF || len(entries) > 256 {
						return "copy-directory", true
					}
					for _, entry := range entries {
						if protectedReachPath(filepath.Join(destination, entry), protected, ssh) {
							return "copy-directory", true
						}
					}
					continue
				}
				// shutil.copy/copy2 choose the basename of src when dst is
				// a directory. Inspect that child, including a linked dst.
				child := OperandPath(filepath.Base(source), destination)
				if protectedReachPath(child, protected, ssh) {
					return "copy-directory", true
				}
			}
		}
	}
	for _, location := range unprovenWriter.FindAllStringIndex(scan, -1) {
		if (language == "python" || strings.HasPrefix(language, "python3")) &&
			scan != code && !pythonExecutableCodePosition(code, location[0]) {
			continue
		}
		call, ok := literalBoundedCall(code, location[1]-1)
		if !ok {
			return "interpreter-path", true
		}
		args := literalCallArgs(call)
		if len(args) == 0 {
			return "interpreter-path", true
		}
		name := code[location[0] : location[1]-1]
		if language == "python" || strings.HasPrefix(language, "python3") {
			if name == "write_text" || name == "write_bytes" {
				// The first call argument is data. The file is the Path
				// receiver, which must have a fixed ordinary destination.
				fixedReceiver := false
				for _, match := range literalPathWrite.FindAllStringSubmatchIndex(code, -1) {
					if match[1] == location[1] {
						fixedReceiver = true
						break
					}
				}
				if !fixedReceiver {
					destination, bound := pythonReboundReceiver(code, location[1], home)
					if !bound || protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
						return "interpreter-path", true
					}
				}
				continue
			}
			if name == "open" && location[0] > 0 && code[location[0]-1] == '.' &&
				strings.Contains(code[:location[0]], "Path.home()") && len(args) > 0 {
				if mode, ok := literalString(args[0]); ok && literalWriteMode(mode) {
					safePath := false
					for _, match := range literalPathHomeJoinOpen.FindAllStringSubmatchIndex(code, -1) {
						if match[1] != location[1] {
							continue
						}
						relative := code[match[2]:match[3]]
						if !filepath.IsAbs(relative) && !strings.Contains(relative, "..") {
							destination := OperandPath(relative, home)
							if !protectedReachPath(destination, newProtectedFiles(home), filepath.Join(home, ".ssh")) {
								safePath = true
							}
						}
						break
					}
					if safePath {
						continue
					}
					return "interpreter-path", true
				}
			}
		}
		if slicesContainsString([]string{"truncate", "rename", "replace", "move", "unlink", "remove", "sysopen", "IO.write"}, name) {
			pathArgs := args[:1]
			if name == "sysopen" && len(args) >= 2 {
				pathArgs = args[1:2]
			} else if (name == "rename" || name == "replace" || name == "move") && len(args) >= 2 {
				pathArgs = args[:2]
			}
			for _, arg := range pathArgs {
				if _, ok := literalString(arg); !ok {
					return "interpreter-path", true
				}
			}
			return "interpreter-path", false
		}
		if strings.HasPrefix(name, "copy") || name == "copy" {
			if len(args) < 2 {
				return "interpreter-path", true
			}
			if _, ok := literalString(args[1]); !ok {
				return "interpreter-path", true
			}
			continue
		}
		if name == "open" || name == "openSync" || name == "FileIO" {
			pathArg, modeArg := args[0], ""
			if language == "perl" && len(args) >= 3 {
				pathArg, modeArg = args[2], args[1]
			} else if len(args) >= 2 {
				modeArg = args[1]
			}
			if (language == "python" || strings.HasPrefix(language, "python3")) && strings.HasSuffix(code[:location[0]], "os.") {
				if !literalOSWriteFlags(modeArg) {
					continue
				}
			} else if mode, ok := literalString(modeArg); !ok || !literalWriteMode(mode) {
				continue
			}
			if _, ok := literalString(pathArg); !ok {
				return "interpreter-path", true
			}
			continue
		}
		if _, ok := literalString(args[0]); !ok {
			return "interpreter-path", true
		}
	}
	return "", false
}

// posixShellProgram reports a POSIX-family shell whose -c body or script file
// the bounded proof inspects. fish is excluded because its grammar differs.
func posixShellProgram(program string) bool {
	switch program {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh":
		return true
	}
	return false
}

// shellArgvIncomplete reports a shell whose invocation argv cannot, on its own,
// certify the complete action. Zsh runs its system and user startup files
// before any -c body, script or stdin, and no flag disables all of them, so a
// static body write must still fail closed. bash, sh, dash, ksh and mksh are
// modeled by actionfacts from argv.
func shellArgvIncomplete(program string) bool {
	return program == "zsh"
}

// shellScriptInvocation reports a command that runs a POSIX shell with a
// script-file operand. It keeps such commands out of the fast-path skip so the
// shell branch can read and inspect the script, matching the awk -f rule. It
// only runs after the cheaper substring filters, so the field scan is bounded
// to otherwise-simple commands.
func shellScriptInvocation(command string) bool {
	fields := strings.Fields(command)
	index := 0
	for index < len(fields) && !strings.HasPrefix(fields[index], "-") && strings.ContainsRune(fields[index], '=') {
		index++ // leading NAME=value environment assignments
	}
	if index >= len(fields) || !posixShellProgram(programBase(fields[index])) {
		return false
	}
	for _, word := range fields[index+1:] {
		if word != "--" && !strings.HasPrefix(word, "-") {
			return true
		}
	}
	return false
}

// shellScriptOperand returns the first word a shell would run as a script
// file: the first operand that does not begin with '-'. Option values are
// conservatively treated as candidate operands, because reading the wrong
// small local file only adds a bounded, fail-closed inspection.
func shellScriptOperand(words []string) (string, bool) {
	for _, word := range words[1:] {
		if word == "--" {
			continue
		}
		if !strings.HasPrefix(word, "-") {
			return word, true
		}
	}
	return "", false
}

// shellBodyProtectedWrite reports a statically resolvable write operand in a
// shell program whose destination reaches a protected file. It covers shells
// and shell scripts that actionfacts does not model from argv, so a plain
// redirect or literal writer to a protected link in the body fails closed.
// Unresolvable (dynamic) writes are handled by the recursive walk instead.
func shellBodyProtectedWrite(code, cwd, home string) bool {
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	operands, _, _ := ShellWriteOperands(code, cwd, home)
	operands = append(operands, LiteralWriteOperands(code, cwd, home)...)
	for _, operand := range operands {
		if protectedReachPath(OperandPath(operand, cwd), protected, ssh) {
			return true
		}
	}
	return false
}

func protectedReachFromText(command, cwd, home string) bool {
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	seen := map[string]bool{}
	text := strings.ReplaceAll(strings.ReplaceAll(command, "${HOME}/", home+"/"), "$HOME/", home+"/")
	for _, quoted := range unprovenQuotedPath {
		matches := quoted.FindAllStringSubmatch(text, 257)
		if len(matches) > 256 {
			return true
		}
		for _, match := range matches {
			if len(match[1]) > MaxWriteTargetPathBytes || unprovenPathToken.FindString(match[1]) == match[1] {
				continue
			}
			candidate := match[1]
			if candidate == "~" || strings.HasPrefix(candidate, "~/") {
				candidate = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(candidate, "~"), "/"))
			}
			if protectedReachTextPath(OperandPath(candidate, cwd), protected, ssh) {
				return true
			}
		}
	}
	tokens := unprovenPathToken.FindAllString(text, 513)
	if len(tokens) > 512 {
		return true // The path reach scan itself exceeded its proof bound.
	}
	for _, token := range tokens {
		if seen[token] || len(token) > MaxWriteTargetPathBytes || token == "." || token == ".." {
			continue
		}
		seen[token] = true
		if strings.ContainsAny(token, "*?[]") {
			if boundedProtectedGlobReach(token, cwd, protected, ssh) {
				return true
			}
			continue
		}
		if token == "~" || strings.HasPrefix(token, "~/") {
			// A bare ~ is the home itself (GAP-1093).
			token = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(token, "~"), "/"))
		}
		if protectedReachTextPath(OperandPath(token, cwd), protected, ssh) {
			return true
		}
	}
	return false
}

func boundedProtectedGlobReach(pattern, cwd string, protected protectedFiles, ssh string) bool {
	parent, base := filepath.Dir(pattern), filepath.Base(pattern)
	if _, err := filepath.Match(base, ""); err != nil {
		return false // An incomplete URL bracket is not a shell glob.
	}
	if strings.ContainsAny(parent, "*?[") {
		return true
	}
	directory, err := os.Open(OperandPath(parent, cwd))
	if err != nil {
		return false
	}
	names, err := directory.Readdirnames(4097)
	_ = directory.Close()
	if err != nil && err != io.EOF || len(names) > 4096 {
		return true
	}
	for _, name := range names {
		if matched, _ := filepath.Match(base, name); matched &&
			protectedReachPath(OperandPath(name, OperandPath(parent, cwd)), protected, ssh) {
			return true
		}
	}
	return false
}

func protectedReachPath(path string, protected protectedFiles, ssh string) bool {
	resolved, ok := ResolveWriteTarget(path)
	if !ok {
		return false
	}
	if protected.has(resolved) || samePathName(resolved, ssh) {
		return true
	}
	if mapped, ok := protected.target(resolved); ok && protected.has(mapped) {
		return true
	}
	return false
}

// The user's home is a reachability clue for unmodelled code: relative
// interpreter paths and shell state can enter its protected subdirectories.
// Exact write destinations still use protectedReachPath, so a literal
// ordinary child of home is not mistaken for the protected file.
func protectedReachTextPath(path string, protected protectedFiles, ssh string) bool {
	resolved, ok := ResolveWriteTarget(path)
	return ok && samePathName(resolved, filepath.Dir(ssh)) || protectedReachPath(path, protected, ssh)
}

func cdPathProtectedReach(call *syntax.CallExpr, file *syntax.File, cwd, home string) bool {
	if len(call.Args) != 2 {
		return false
	}
	path, ok := StaticWord(call.Args[1], home)
	if !ok || cdBypassesSearchPath(path) || path == "" || strings.HasPrefix(path, "-") {
		return false
	}
	selected := OperandPath(path, filepath.Join(home, ".ssh"))
	info, err := os.Stat(selected)
	if err != nil || !info.IsDir() {
		return false
	}
	protected := newProtectedFiles(home)
	var rendered strings.Builder
	if syntax.NewPrinter().Print(&rendered, file) != nil {
		return false
	}
	operands, _, _ := ShellWriteOperands(rendered.String(), cwd, home)
	operands = append(operands, LiteralWriteOperands(rendered.String(), cwd, home)...)
	for _, operand := range operands {
		if relative, err := filepath.Rel(cwd, operand); err == nil && relative != "." && !strings.HasPrefix(relative, "..") {
			if protectedReachPath(OperandPath(relative, selected), protected, filepath.Join(home, ".ssh")) {
				return true
			}
		}
	}
	return false
}
