// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
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
	for wrapper := 0; wrapper < 8 && len(words) > 0; wrapper++ {
		program := programBase(words[0])
		switch program {
		case "env":
			index := 1
			for index < len(words) {
				word := words[index]
				switch {
				case word == "--":
					index++
					goto nextProgram
				case word == "-i" || word == "--ignore-environment" || word == "-v" || word == "--debug":
					index++
				case word == "-u" || word == "--unset":
					index += 2
				case strings.HasPrefix(word, "--unset=") || strings.HasPrefix(word, "-u") && len(word) > 2:
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
				operands = append(operands, literalWriteOperandsDepth(words[body], cwd, home, depth+1)...)
				if len(words) >= body+3 {
					operands = append(operands, literalPositionalShellRedirects(words[body], words[body+2], cwd, home)...)
				}
				return operands
			}
			if allowFileRead {
				if script, ok := shellScriptOperand(words); ok && actionScriptInsideCWD(script, cwd) {
					return literalLocalShellScriptOperands(script, cwd, home, depth)
				}
			}
			return nil
		case "find":
			return literalFindOperands(words, cwd, home, depth)
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
			if allowFileRead && strings.HasSuffix(program, ".sh") && actionScriptInsideCWD(words[0], cwd) {
				return literalLocalShellScriptOperands(words[0], cwd, home, depth)
			}
			return directLiteralProgramOperands(words, stmt, cwd, home, allowFileRead)
		}
	}
	return nil
}

func literalLocalShellScriptOperands(script, cwd, home string, depth int) []string {
	content, read := readIndirectSource(script, cwd)
	if !read {
		return nil
	}
	writes, _, _ := ShellWriteOperands(content, cwd, home)
	return append(writes, literalWriteOperandsDepth(content, cwd, home, depth+1)...)
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
		if len(words) >= 3 && (program == "perl" || program == "ruby" || program == "node" || program == "nodejs") && words[1] == "-e" {
			language := program
			if language == "nodejs" {
				language = "node"
			}
			return add(literalInterpreterWrites(words[2], language, cwd, home))
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
			return nil // A cp with no destination writes nothing (GAP-2528).
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
			if info, err := os.Stat(OperandPath(source, cwd)); err == nil && info.IsDir() {
				return nil // A recursive directory copy has its own scope proof.
			}
			break
		}
		if dest := cpDestination(words[1:], makeStatic(len(words)-1), cwd); dest != "" {
			return []string{dest}
		}
	case program == "tee":
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
	if _, err := os.Lstat(target); err != nil {
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

func literalPositionalShellRedirects(command, value, cwd, home string) []string {
	file, ok := parseShell(command)
	if !ok || value == "" || strings.HasPrefix(value, "-") {
		return nil
	}
	var operands []string
	syntax.Walk(file, func(node syntax.Node) bool {
		if _, declaration := node.(*syntax.FuncDecl); declaration {
			return false
		}
		redirect, ok := node.(*syntax.Redirect)
		if !ok || redirect.Word == nil || simpleShellParameter(redirect.Word) != "1" {
			return true
		}
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
			operands = append(operands, OperandPath(value, cwd))
		}
		return true
	})
	return operands
}

func literalPipelineOperands(file *syntax.File, called map[string]bool, cwd, home string, depth int) []string {
	var operands []string
	syntax.Walk(file, func(node syntax.Node) bool {
		if declaration, isFunction := node.(*syntax.FuncDecl); isFunction {
			return declaration.Name != nil && called[declaration.Name.Value]
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
