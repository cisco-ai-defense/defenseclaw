// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"path/filepath"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// boundedProgramAssignment recognizes one literal assignment immediately
// before an executed command. Other shell assignments need runtime expansion.
func boundedProgramAssignment(file *syntax.File, home string) (name, value string) {
	if len(file.Stmts) != 2 || file.Stmts[0].Background || file.Stmts[0].Negated {
		return "", ""
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 0 || len(call.Assigns) != 1 || len(file.Stmts[0].Redirs) != 0 {
		return "", ""
	}
	assignment := call.Assigns[0]
	if assignment.Name == nil || assignment.Value == nil {
		return "", ""
	}
	value, ok = StaticWord(assignment.Value, home)
	if !ok || value == "" || strings.ContainsAny(value, "/\x00\r\n") {
		return "", ""
	}
	return assignment.Name.Value, value
}

func simpleShellParameter(word *syntax.Word) string {
	if word == nil || len(word.Parts) != 1 {
		return ""
	}
	part := word.Parts[0]
	if quoted, ok := part.(*syntax.DblQuoted); ok && len(quoted.Parts) == 1 {
		part = quoted.Parts[0]
	}
	param, ok := part.(*syntax.ParamExp)
	if !ok || param.Param == nil || param.Excl || param.Length || param.Index != nil ||
		param.Slice != nil || param.Repl != nil || param.Exp != nil || len(param.Modifiers) != 0 {
		return ""
	}
	return param.Param.Value
}

// literalProgramOperands descends only through launchers with known argument
// positions. An unknown option does not turn an option value into a program.
func literalProgramOperands(words []string, stmt *syntax.Stmt, cwd, home string, depth int, allowFileRead bool) []string {
	return literalProgramOperandsKnown(words, stmt, cwd, home, depth, allowFileRead, nil, nil)
}

func literalProgramOperandsKnown(words []string, stmt *syntax.Stmt, cwd, home string, depth int, allowFileRead bool, environment actionValues, include func(string) bool) []string {
	for wrapper := 0; wrapper < 8 && len(words) > 0; wrapper++ {
		program := programBase(words[0])
		switch program {
		case "env":
			index := 1
			environment = maps.Clone(environment)
			for index < len(words) {
				word := words[index]
				switch {
				case word == "--":
					index++
					goto nextProgram
				case word == "-i" || word == "--ignore-environment":
					environment = nil
					index++
				case word == "-v" || word == "--debug":
					index++
				case word == "-u" || word == "--unset":
					if index+1 < len(words) {
						delete(environment, words[index+1])
					}
					index += 2
				case strings.HasPrefix(word, "--unset="):
					delete(environment, strings.TrimPrefix(word, "--unset="))
					index++
				case strings.HasPrefix(word, "-u") && len(word) > 2:
					delete(environment, word[2:])
					index++
				case word == "-C" || word == "--chdir":
					if index+1 >= len(words) {
						return nil
					}
					cwd = OperandPath(words[index+1], cwd)
					index += 2
				case strings.HasPrefix(word, "--chdir="):
					cwd = OperandPath(strings.TrimPrefix(word, "--chdir="), cwd)
					index++
				case strings.HasPrefix(word, "-C") && len(word) > 2:
					cwd = OperandPath(word[2:], cwd)
					index++
				case strings.Contains(word, "=") && !strings.HasPrefix(word, "-"):
					name, value, _ := strings.Cut(word, "=")
					if environment == nil {
						environment = actionValues{}
					}
					environment[name] = value
					index++
				case strings.HasPrefix(word, "-"):
					return nil
				default:
					goto nextProgram
				}
			}
		nextProgram:
			if index >= len(words) {
				return nil
			}
			words = words[index:]
		case "command":
			index := 1
			for index < len(words) && strings.HasPrefix(words[index], "-") {
				if words[index] == "--" {
					index++
					break
				}
				if words[index] != "-p" {
					return nil
				}
				index++
			}
			words = words[index:]
		case "builtin", "nohup", "busybox", "time":
			if len(words) < 2 || words[1] == "--help" || words[1] == "--version" {
				return nil
			}
			if words[1] == "--" {
				words = words[2:]
			} else if strings.HasPrefix(words[1], "-") {
				return nil
			} else {
				words = words[1:]
			}
		case "exec":
			index := 1
			for index < len(words) && strings.HasPrefix(words[index], "-") {
				switch words[index] {
				case "--":
					index++
					goto execDone
				case "-a":
					// exec -a NAME: a missing name leaves no program to read.
					if index+1 >= len(words) {
						return nil
					}
					index += 2
				case "-c", "-l":
					index++
				default:
					return nil
				}
			}
		execDone:
			words = words[index:]
		case "nice":
			index := 1
			if index < len(words) && (words[index] == "-n" || words[index] == "--adjustment") {
				index++
				if index >= len(words) || !literalInteger(words[index]) {
					return nil
				}
				index++
			} else if index < len(words) && strings.HasPrefix(words[index], "--adjustment=") {
				if !literalInteger(strings.TrimPrefix(words[index], "--adjustment=")) {
					return nil
				}
				index++
			} else if index < len(words) && strings.HasPrefix(words[index], "-n") {
				if !literalInteger(words[index][2:]) {
					return nil
				}
				index++
			}
			words = words[index:]
		case "timeout":
			index := 1
			for index < len(words) && strings.HasPrefix(words[index], "-") {
				if words[index] == "--" {
					index++
					break
				}
				if words[index] != "--foreground" && words[index] != "--preserve-status" && words[index] != "-v" {
					return nil
				}
				index++
			}
			if index+1 >= len(words) || !literalDuration(words[index]) {
				return nil
			}
			words = words[index+1:]
		case "sh", "bash", "dash", "ash", "zsh", "ksh":
			if body, ok := shellCommandBodyIndex(words); ok {
				var operands []string
				if redirects, parsed, _ := ShellWriteOperands(words[body], cwd, home); parsed {
					operands = append(operands, redirects...)
				}
				writes, _ := literalWriteOperandsWithParsedKnown(words[body], cwd, home, depth+1, nil, environment, include)
				operands = append(operands, writes...)
				if len(words) >= body+2 {
					operands = append(operands, literalPositionalShellRedirects(words[body], words[body+1:], cwd, home)...)
				}
				return operands
			}
			if allowFileRead {
				if script, ok := shellScriptOperand(words); ok {
					operands, _ := literalLocalShellScriptOperands(script, cwd, home, depth)
					return operands
				}
			}
			return nil
		case "eval":
			if include == nil || len(words) < 2 || len(words) > 8 {
				return nil
			}
			body := strings.Join(words[1:], " ")
			writes, _ := literalWriteOperandsWithParsedKnown(body, cwd, home, depth+1, nil, environment, include)
			return writes
		case "find":
			operands := literalFindOperands(words, cwd, home, depth)
			if include != nil {
				operands = append(operands, knownFindChangeOperands(words, cwd)...)
			}
			return operands
		case ".", "source":
			if allowFileRead {
				return literalSourceFileOperands(words, cwd, home, depth)
			}
			return nil
		case "make", "gmake":
			if allowFileRead {
				return literalMakeRecipeOperands(words, cwd, home, depth)
			}
			return nil
		case "git":
			if allowFileRead {
				return literalGitSSHCommandOperands(words, cwd, home, depth)
			}
			return nil
		case "xargs":
			return nil // A producer must prove the replacement text first.
		default:
			if allowFileRead && strings.HasSuffix(program, ".sh") {
				if operands, read := literalLocalShellScriptOperands(words[0], cwd, home, depth); read {
					return operands
				}
			}
			operands := directLiteralProgramOperands(words, stmt, cwd, home, allowFileRead)
			// An interpreter child whose code no reader proves read-only is handed
			// its argument paths as possible writes (rel-1-0-10:GAP-0365).
			for _, name := range actionfacts.InlineCodeHandedWords(words) {
				operands = append(operands, OperandPath(name, cwd))
			}
			if include != nil {
				operands = append(operands, knownEntryChangeOperands(words, cwd)...)
			}
			return operands
		}
	}
	return nil
}

// literalLocalShellScriptOperands is the write operands of the script a shell
// or a .sh program runs, and whether the script was read.
func literalLocalShellScriptOperands(script, cwd, home string, depth int) ([]string, bool) {
	content, read := readActionScript(script, cwd)
	if !read {
		return nil, false
	}
	writes, _, _ := ShellWriteOperands(content, cwd, home)
	return append(writes, literalWriteOperandsDepth(content, cwd, home, depth+1)...), true
}

func literalInteger(value string) bool {
	_, err := strconv.Atoi(value)
	return err == nil
}

func literalDuration(value string) bool {
	value = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(value, "s"), "m"), "h"), "d")
	if value == "" {
		return false
	}
	_, err := strconv.ParseFloat(value, 64)
	return err == nil
}

func directLiteralProgramOperands(words []string, stmt *syntax.Stmt, cwd, home string, allowFileRead bool) []string {
	if len(words) == 0 {
		return nil
	}
	program := programBase(words[0])
	add := func(names []string) []string {
		for i, name := range names {
			names[i] = OperandPath(name, cwd)
		}
		return names
	}
	switch {
	case program == "python" || strings.HasPrefix(program, "python3") || program == "perl" || program == "ruby" || program == "node" || program == "nodejs":
		if program == "python" || strings.HasPrefix(program, "python3") {
			if code, ok := pythonLiteralCode(words); ok {
				return add(literalInterpreterWrites(code, "python", cwd, home))
			}
		}
		if code, language, ok := literalInlineProgram(words); ok {
			return add(literalInterpreterWrites(code, language, cwd, home))
		}
		if program == "python" || strings.HasPrefix(program, "python3") {
			if stmt != nil && (len(words) == 1 || len(words) >= 2 && words[1] == "-") {
				for _, redirect := range stmt.Redirs {
					if code, ok := literalQuotedHereDocument(redirect); ok {
						return add(literalInterpreterWrites(code, "python", cwd, home))
					}
				}
			}
		}
	case program == "awk" || program == "gawk" || program == "mawk" || program == "nawk":
		var names []string
		for _, code := range awkInlineProgramText(words) {
			_, _, targets := awkOutputProof(code, cwd, home)
			names = append(names, targets...)
		}
		if allowFileRead {
			for i := 1; i < len(words); i++ {
				option, value, attached := awkOptionValue(words[i])
				if option != "f" {
					continue
				}
				if !attached {
					i++
					if i >= len(words) {
						break
					}
					value = words[i]
				}
				if !actionScriptInsideCWD(value, cwd) {
					continue
				}
				if code, read := readIndirectSource(value, cwd); read {
					_, _, targets := awkOutputProof(code, cwd, home)
					names = append(names, targets...)
				}
			}
		}
		return add(names)
	case program == "sed" || program == "gsed":
		var names []string
		for _, name := range sedInPlaceFiles(words) {
			if sedFollowsInPlaceLinks(words) || sedParentProtected(name, cwd, home) {
				names = append(names, name)
			}
		}
		return add(names)
	case program == "cp" || program == "gcp":
		if len(words) < 3 {
			// cp with fewer than two operands fails on its own and writes
			// nothing (GAP-2528).
			return nil
		}
		for _, option := range words[1:] {
			if option == "--recursive" || strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "--") &&
				(strings.ContainsAny(option, "rR")) {
				return nil // A recursive copy is judged by its directory scope.
			}
		}
		for _, source := range words[1 : len(words)-1] {
			if strings.HasPrefix(source, "-") {
				continue
			}
			if info, err := pathStat(OperandPath(source, cwd)); err == nil && info.IsDir() {
				return nil // A recursive directory copy has its own scope proof.
			}
			break
		}
		if dest := cpDestination(words[1:], makeStatic(len(words)-1), cwd); dest != "" {
			return []string{dest}
		}
	case program == "tee" || program == "gtee":
		var names []string
		for _, word := range words[1:] {
			if word == "--" {
				continue
			}
			if strings.HasPrefix(word, "-") {
				continue
			}
			names = append(names, word)
		}
		return add(names)
	case program == "dd" || program == "gdd":
		// dd writes its of= operand; with several, GNU dd uses the last,
		// so each is listed (GAP-0228).
		var names []string
		for _, word := range words[1:] {
			if output, ok := strings.CutPrefix(word, "of="); ok && output != "" {
				names = append(names, output)
			}
		}
		return add(names)
	case program == "truncate" || program == "gtruncate":
		// truncate FILE... rewrites every file operand; -s and -r take a
		// value (GAP-0228: a brace operand is read as its fixed words).
		var names []string
		for i := 1; i < len(words); i++ {
			switch word := words[i]; {
			case word == "--":
				names = append(names, words[i+1:]...)
				return add(names)
			case word == "-s" || word == "-r" || word == "--size" || word == "--reference":
				i++
			case strings.HasPrefix(word, "-"):
			default:
				names = append(names, word)
			}
		}
		return add(names)
	case program == "ln":
		if len(words) >= 3 && !strings.HasPrefix(words[len(words)-1], "-") {
			return add([]string{words[len(words)-1]})
		}
	case program == "tar":
		var directory string
		var member string
		for i := 1; i < len(words); i++ {
			switch word := words[i]; {
			case word == "-C" || word == "--directory":
				if i+1 >= len(words) {
					return nil
				}
				directory = words[i+1]
				i++
			case strings.HasPrefix(word, "--directory="):
				directory = strings.TrimPrefix(word, "--directory=")
			case word == "-f" || word == "--file":
				i++
			case strings.HasPrefix(word, "-"):
				continue
			default:
				member = word
			}
		}
		if directory != "" && member != "" && !strings.ContainsAny(member, "*?[") {
			target := OperandPath(member, OperandPath(directory, cwd))
			if protectedReachPath(target, newProtectedFiles(home), filepath.Join(home, ".ssh")) {
				return []string{target}
			}
		}
		// An extraction whose -C directory reaches ~/.ssh writes each
		// member there, through any link to it (GAP-2515): a member that
		// reaches a protected file is the write, and an extraction that
		// names no member, or a pattern, writes members the archive
		// chooses into the keys directory.
		if destination, members, extract, ok := tarScan(words[1:], makeStatic(len(words)-1), cwd); ok && extract &&
			OperandPath(destination, cwd) != cwd &&
			protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
			destination = OperandPath(destination, cwd)
			if len(members) == 0 {
				return []string{destination}
			}
			var targets []string
			for _, name := range members {
				target := OperandPath(name, destination)
				if strings.ContainsAny(name, "*?[") ||
					protectedReachPath(target, newProtectedFiles(home), filepath.Join(home, ".ssh")) {
					targets = append(targets, target)
				}
			}
			return targets
		}
	}
	return nil
}

// awkInlineProgramText keeps option data and input operands out of the source
// scanner. A -f file is separate code; the literal extractor examines only
// program text present in the tool call.
func awkInlineProgramText(words []string) []string {
	programs, _ := awkProgramWords(words)
	return programs
}

// awkProgramSupplied reports an awk argv whose words already hold the whole
// program: an inline program operand, or a -f / -e option. A later word is
// then an input operand, an assignment or another -f program, none of which
// changes the program text already read (GAP-2172, GAP-0498).
func awkProgramSupplied(words []string) bool {
	_, supplied := awkProgramWords(words)
	return supplied
}

func awkProgramWords(words []string) ([]string, bool) {
	options, supplied := true, false
	var programs []string
	for i := 1; i < len(words); i++ {
		word := words[i]
		if options && word == "--" {
			options = false
			continue
		}
		if options && word != "-" && strings.HasPrefix(word, "-") {
			name, value, attached := awkOptionValue(word)
			if name == "" {
				if slicesContainsString(awkHarmlessFlags, word) {
					continue
				}
				return nil, false
			}
			if !attached {
				i++
				if i >= len(words) {
					return nil, false
				}
				value = words[i]
			}
			if name == "f" || name == "e" {
				supplied = true
				if name == "e" {
					programs = append(programs, value)
				}
			}
			continue
		}
		if !supplied {
			programs = append(programs, word)
			supplied = true
		}
		options = false
	}
	return programs, supplied
}

// AWKReadsProgramFile reports a shell command with an awk call that reads its
// program from a file (-f FILE, -fFILE, --file=FILE). The user's hook reads
// that file and lists its print targets; a gateway that cannot read it
// (ProtectHome) judges the hook's list (GAP-2178, GAP-0508).
func AWKReadsProgramFile(command string) bool {
	if command == "" || len(command) > MaxPayloadBytes || !strings.Contains(command, "awk") {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if found || !ok || len(call.Args) < 2 {
			return !found
		}
		program, static := StaticWord(call.Args[0], "")
		if !static {
			return true
		}
		switch programBase(program) {
		case "awk", "gawk", "mawk", "nawk":
		default:
			return true
		}
		for _, arg := range call.Args[1:] {
			word, static := StaticWord(arg, "")
			if !static {
				continue
			}
			if word == "--" {
				break
			}
			if name, _, _ := awkOptionValue(word); name == "f" {
				found = true
				break
			}
		}
		return !found
	})
	return found
}

// literalInlineProgram returns the inline code of a perl, ruby or node call
// and its language, past the interpreter's other options (perl -w or
// -MFile::Copy, a -we cluster, perl -E, node -r x), so an option before the
// code does not hide its writes. perl runs "use Module;" before the code for
// each -MModule option; that use is put in front of the code here, so an
// API the module exports is read as it is with an in-code use
// (rel-1-0-2:GAP-0429).
func literalInlineProgram(words []string) (code, language string, ok bool) {
	if len(words) < 3 {
		return "", "", false
	}
	language = actionInterpreterKind(words[0])
	if language != "perl" && language != "ruby" && language != "node" {
		return "", "", false
	}
	code, ok = actionInterpreterInlineCode(words, 0)
	if !ok {
		return "", "", false
	}
	if language == "perl" {
		var uses strings.Builder
		for j := 1; j+1 < len(words) && !actionWindowsInterpreterCodeOption(language, words[j]); j++ {
			module, attached := strings.CutPrefix(words[j], "-M")
			if !attached {
				continue
			}
			if module == "" {
				j++
				module = words[j]
			}
			if name, _, _ := strings.Cut(module, "="); name != "" && !strings.HasPrefix(name, "-") {
				uses.WriteString("use " + name + ";\n")
			}
		}
		code = uses.String() + code
	}
	return code, language, true
}

// pythonLiteralCode accepts only fixed no-argument switches before -c.
// A script name or an option with an operand ends this proof.
func pythonLiteralCode(words []string) (string, bool) {
	for index := 1; index < len(words) && index <= 8; index++ {
		switch words[index] {
		case "-I", "-E", "-s", "-S", "-B", "-u", "-q", "-O", "-OO":
			continue
		case "-c":
			if index+1 < len(words) {
				return words[index+1], true
			}
		}
		return "", false
	}
	return "", false
}

func fixedInterpreterCodePrefix(words []string) bool {
	if len(words) >= 2 {
		switch programBase(words[0]) {
		case "awk", "gawk", "mawk", "nawk":
			return awkProgramSupplied(words)
		}
	}
	if len(words) < 3 {
		return false
	}
	program := programBase(words[0])
	if program == "python" || strings.HasPrefix(program, "python3") {
		_, ok := pythonLiteralCode(words)
		return ok
	}
	return (program == "node" || program == "nodejs" || program == "ruby" || program == "perl") && words[1] == "-e"
}

func literalQuotedHereDocument(redirect *syntax.Redirect) (string, bool) {
	if redirect == nil || redirect.Hdoc == nil || redirect.Word == nil ||
		redirect.Op != syntax.Hdoc && redirect.Op != syntax.DashHdoc {
		return "", false
	}
	quoted := false
	for _, part := range redirect.Word.Parts {
		switch part.(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted:
			quoted = true
		}
	}
	if !quoted {
		return "", false
	}
	var code strings.Builder
	for _, part := range redirect.Hdoc.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			return "", false
		}
		code.WriteString(lit.Value)
	}
	return code.String(), true
}

func literalFindOperands(words []string, cwd, home string, depth int) []string {
	if len(words) < 5 || strings.HasPrefix(words[1], "-") {
		return nil
	}
	subject := words[1]
	start := 2
	if subject == "." && len(words) >= 7 && words[2] == "-name" &&
		words[3] != "" && !strings.ContainsAny(words[3], "/*?[]\\") {
		subject = "./" + words[3]
		start = 4
	}
	target := OperandPath(subject, cwd)
	if _, err := pathLstat(target); err != nil {
		return nil
	}
	for i := start; i < len(words); i++ {
		if words[i] != "-exec" || i+2 >= len(words) {
			continue
		}
		end := i + 1
		for end < len(words) && words[end] != ";" && words[end] != "+" {
			end++
		}
		if end == len(words) || end == i+1 {
			return nil
		}
		child := append([]string(nil), words[i+1:end]...)
		for j := range child {
			child[j] = strings.ReplaceAll(child[j], "{}", subject)
		}
		return literalProgramOperands(child, nil, cwd, home, depth+1, false)
	}
	return nil
}

func literalPositionalShellRedirects(command string, arguments []string, cwd, home string) []string {
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	var operands []string
	syntax.Walk(file, func(node syntax.Node) bool {
		if _, declaration := node.(*syntax.FuncDecl); declaration {
			return false
		}
		redirect, ok := node.(*syntax.Redirect)
		if !ok || redirect.Word == nil {
			return true
		}
		index, err := strconv.Atoi(simpleShellParameter(redirect.Word))
		if err != nil || index < 0 || index >= len(arguments) || arguments[index] == "" || strings.HasPrefix(arguments[index], "-") {
			return true
		}
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
			operands = append(operands, OperandPath(arguments[index], cwd))
		}
		return true
	})
	return operands
}

func literalPipelineOperands(file *syntax.File, called map[string]bool, cwd, home string, depth int) []string {
	var operands []string
	syntax.Walk(file, func(node syntax.Node) bool {
		if declaration, isFunction := node.(*syntax.FuncDecl); isFunction {
			return declaration.Name != nil && (called[declaration.Name.Value] || called[knownUnshadowed(declaration.Name.Value)])
		}
		binary, ok := node.(*syntax.BinaryCmd)
		if !ok || binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll {
			return true
		}
		left, leftOK := binary.X.Cmd.(*syntax.CallExpr)
		right, rightOK := binary.Y.Cmd.(*syntax.CallExpr)
		if !leftOK || !rightOK {
			return true
		}
		getWords := func(call *syntax.CallExpr) ([]string, bool) {
			words := make([]string, len(call.Args))
			for i, word := range call.Args {
				var ok bool
				words[i], ok = StaticWord(word, home)
				if !ok {
					return nil, false
				}
			}
			return words, true
		}
		producer, valid := getWords(left)
		consumer, consumerOK := getWords(right)
		if !valid || !consumerOK || len(producer) == 0 || len(consumer) < 4 ||
			producer[0] != "printf" || consumer[0] != "xargs" {
			return true
		}
		value := ""
		if len(producer) == 2 && !strings.Contains(producer[1], "%") {
			value = producer[1]
		} else if len(producer) == 3 && (producer[1] == "%s" || producer[1] == "%s\n") {
			value = producer[2]
		}
		if value == "" || strings.ContainsAny(value, "\x00\r\n \t") {
			return true
		}
		index, replacement := 1, ""
		if (consumer[index] == "-I" || consumer[index] == "--replace") && len(consumer) > index+1 {
			replacement = consumer[index+1]
			index += 2
		} else if strings.HasPrefix(consumer[index], "-I") {
			replacement = consumer[index][2:]
			index++
		} else if strings.HasPrefix(consumer[index], "--replace=") {
			replacement = strings.TrimPrefix(consumer[index], "--replace=")
			index++
		}
		if replacement == "" || index >= len(consumer) {
			return true
		}
		child := append([]string(nil), consumer[index:]...)
		for i := range child {
			child[i] = strings.ReplaceAll(child[i], replacement, value)
		}
		operands = append(operands, literalProgramOperands(child, nil, cwd, home, depth+1, false)...)
		return true
	})
	return operands
}

func literalGeneratedScriptOperands(file *syntax.File, cwd, home string, depth int) []string {
	if depth >= 4 || len(file.Stmts) != 2 {
		return nil
	}
	producer, producerOK := file.Stmts[0].Cmd.(*syntax.CallExpr)
	consumer, consumerOK := file.Stmts[1].Cmd.(*syntax.CallExpr)
	if !producerOK || !consumerOK || len(producer.Args) != 2 || len(consumer.Args) != 2 ||
		len(file.Stmts[0].Redirs) != 1 || len(file.Stmts[1].Redirs) != 0 {
		return nil
	}
	name, nameOK := StaticWord(producer.Args[0], home)
	script, scriptOK := StaticWord(producer.Args[1], home)
	source, sourceOK := StaticWord(consumer.Args[0], home)
	sourceName, sourceNameOK := StaticWord(consumer.Args[1], home)
	output := file.Stmts[0].Redirs[0]
	outputName, outputOK := StaticWord(output.Word, home)
	if !nameOK || name != "printf" || !scriptOK || script == "" ||
		strings.ContainsAny(script, "%\\\x00\r") ||
		!sourceOK || source != "." && source != "source" || !sourceNameOK ||
		output.Op != syntax.RdrOut || !outputOK ||
		filepath.Clean(OperandPath(sourceName, cwd)) != filepath.Clean(OperandPath(outputName, cwd)) {
		return nil
	}
	redirects, parsed, _ := ShellWriteOperands(script, cwd, home)
	if !parsed {
		return nil
	}
	return append(redirects, literalWriteOperandsDepth(script, cwd, home, depth+1)...)
}

// entryChangeOptions is the option grammar of a command that removes,
// renames or changes the mode, owner or times of its operands. short lists
// the short options that take a value; long maps each long option to 1 when
// it takes a value and 2 when its value is optional (only the --name=value
// form). target names the options whose value is the directory that
// receives the entries. A value of any other option is read, not changed.
type entryChangeOptions struct {
	short, target string
	long          map[string]int
	// leading: the first operand is a mode or owner, unless a reference
	// file stands in for it.
	leading bool
	// lastOnly: the command reads its sources and changes only its last
	// operand, unless it names a target directory or creates directories.
	lastOnly bool
}

var (
	entryChangeOwnerOptions = entryChangeOptions{leading: true, long: map[string]int{
		"changes": 0, "dereference": 0, "no-dereference": 0, "from": 1, "no-preserve-root": 0,
		"preserve-root": 0, "quiet": 0, "silent": 0, "reference": 1, "recursive": 0, "verbose": 0, "help": 0, "version": 0,
	}}
	entryChangeGrammars = map[string]entryChangeOptions{
		"rm": {long: map[string]int{
			"force": 0, "interactive": 2, "one-file-system": 0, "no-preserve-root": 0, "preserve-root": 2,
			"recursive": 0, "dir": 0, "verbose": 0, "help": 0, "version": 0,
		}},
		"unlink": {long: map[string]int{"help": 0, "version": 0}},
		"rmdir":  {long: map[string]int{"ignore-fail-on-non-empty": 0, "parents": 0, "verbose": 0, "help": 0, "version": 0}},
		"chmod": {leading: true, long: map[string]int{
			"changes": 0, "silent": 0, "quiet": 0, "verbose": 0, "no-preserve-root": 0, "preserve-root": 0,
			"reference": 1, "recursive": 0, "help": 0, "version": 0,
		}},
		"chown": entryChangeOwnerOptions,
		"chgrp": entryChangeOwnerOptions,
		"shred": {short: "ns", long: map[string]int{
			"force": 0, "iterations": 1, "random-source": 1, "remove": 2, "size": 1, "exact": 0, "zero": 0,
			"verbose": 0, "help": 0, "version": 0,
		}},
		"mv": {short: "St", target: "t", long: map[string]int{
			"backup": 2, "force": 0, "interactive": 0, "no-clobber": 0, "no-copy": 0, "strip-trailing-slashes": 0,
			"suffix": 1, "target-directory": 1, "no-target-directory": 0, "update": 2, "verbose": 0, "context": 0,
			"exchange": 0, "debug": 0, "help": 0, "version": 0,
		}},
		"touch": {short: "drt", long: map[string]int{
			"date": 1, "no-create": 0, "no-dereference": 0, "reference": 1, "time": 1, "help": 0, "version": 0,
		}},
		"install": {short: "gmoSt", target: "t", lastOnly: true, long: map[string]int{
			"backup": 2, "compare": 0, "directory": 0, "group": 1, "mode": 1, "owner": 1, "preserve-timestamps": 0,
			"strip": 0, "strip-program": 1, "suffix": 1, "target-directory": 1, "no-target-directory": 0,
			"verbose": 0, "preserve-context": 0, "context": 2, "debug": 0, "help": 0, "version": 0,
		}},
	}
)

// entryChangeLongOption resolves a long option name, or its unambiguous
// prefix, the way getopt_long does.
func entryChangeLongOption(long map[string]int, name string) (string, int, bool) {
	if kind, ok := long[name]; ok {
		return name, kind, true
	}
	match, kind, matches := "", 0, 0
	for option, optionKind := range long {
		if strings.HasPrefix(option, name) {
			match, kind, matches = option, optionKind, matches+1
		}
	}
	return match, kind, matches == 1
}

// chmodModeWord reports a chmod mode written like an option (-w, -x+r).
func chmodModeWord(word string) bool {
	return len(word) > 1 && strings.HasPrefix(word, "-") && strings.Trim(word, "rwxXstugoa,+-=01234567") == ""
}

// knownEntryChangeOperands lists the operands a command changes without
// writing content: it removes or renames the entry, or changes its mode,
// owner or times. The known-environment reader judges these operands like
// writer targets, so a protected file named through a known value is read
// the same as the literal name. The options are read with the grammar of
// the command, so a value an option only reads (a reference file, a random
// source) and the leading mode or owner are not listed.
func knownEntryChangeOperands(words []string, cwd string) []string {
	if len(words) < 2 {
		return nil
	}
	program := programBase(words[0])
	if program == "sed" || program == "gsed" {
		names := sedInPlaceFiles(words)
		for i, name := range names {
			names[i] = OperandPath(name, cwd)
		}
		return names
	}
	grammar, ok := entryChangeGrammars[program]
	if !ok {
		// The GNU g-prefixed names of a BSD system.
		program = strings.TrimPrefix(program, "g")
		if grammar, ok = entryChangeGrammars[program]; !ok {
			return nil
		}
	}
	var operands, targets []string
	reference, directories, mode := false, false, false
	for i := 1; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "--":
			operands = append(operands, words[i+1:]...)
			i = len(words)
		case program == "chmod" && !mode && !reference && chmodModeWord(word):
			// GNU chmod takes -w and the like as its mode operand.
			mode = true
		case strings.HasPrefix(word, "--"):
			name, value, attached := strings.Cut(word[2:], "=")
			option, kind, known := entryChangeLongOption(grammar.long, name)
			if !known {
				continue
			}
			if kind == 1 && !attached && i+1 < len(words) {
				i++
				value = words[i]
			}
			switch option {
			case "reference":
				reference = true
			case "directory":
				directories = true
			case "target-directory":
				targets = append(targets, value)
			}
		case len(word) > 1 && strings.HasPrefix(word, "-"):
			for j := 1; j < len(word); j++ {
				letter := word[j : j+1]
				if !strings.Contains(grammar.short, letter) {
					if program == "install" && letter == "d" {
						directories = true
					}
					continue
				}
				value := word[j+1:]
				if value == "" && i+1 < len(words) {
					i++
					value = words[i]
				}
				if strings.Contains(grammar.target, letter) {
					targets = append(targets, value)
				}
				if program == "touch" && letter == "r" {
					reference = true
				}
				break
			}
		default:
			operands = append(operands, word)
		}
	}
	if grammar.leading && !mode && !reference && len(operands) > 0 {
		operands = operands[1:]
	}
	if grammar.lastOnly && !directories {
		if len(targets) > 0 {
			operands = nil
		} else if len(operands) > 1 {
			operands = operands[len(operands)-1:]
		}
	}
	operands = append(operands, targets...)
	for i, name := range operands {
		operands[i] = OperandPath(name, cwd)
	}
	return operands
}

// knownFindChangeOperands lists the start points of a find that removes
// or changes what it finds, through -delete or an -exec entry change.
func knownFindChangeOperands(words []string, cwd string) []string {
	var roots []string
	index := 1
	for index < len(words) && !strings.HasPrefix(words[index], "-") && words[index] != "(" && words[index] != "!" {
		roots = append(roots, words[index])
		index++
	}
	var operands []string
	for i := index; i < len(words); i++ {
		switch words[i] {
		case "-delete":
			for _, root := range roots {
				operands = append(operands, OperandPath(root, cwd))
			}
		case "-exec", "-execdir", "-ok", "-okdir":
			end := i + 1
			for end < len(words) && words[end] != ";" && words[end] != "+" {
				end++
			}
			for _, root := range roots {
				child := append([]string(nil), words[i+1:end]...)
				for j := range child {
					child[j] = strings.ReplaceAll(child[j], "{}", root)
				}
				operands = append(operands, knownEntryChangeOperands(child, cwd)...)
			}
			i = end
		}
	}
	return operands
}
