// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"mvdan.cc/sh/v3/syntax"
)

// actionProtectedTargetMention is independent of a program's operand roles.
// A resolved protected path in a writable command is enough for the action
// decision; commands with no such path continue through the existing proof.
func actionProtectedTargetMention(command, cwd, home string) bool {
	return actionProtectedTargetMentionDepth(command, cwd, home, 0)
}

func actionProtectedTargetMentionDepth(command, cwd, home string, depth int) bool {
	if command == "" || home == "" || len(command) > MaxPayloadBytes || depth >= 8 {
		return false
	}
	if actionWindowsHome(home) {
		return actionWindowsTargetMention(command, cwd, home, depth)
	}
	if !filepath.IsAbs(cwd) {
		return false
	}
	file, parsed := parseShell(command)
	if depth == 0 && parsed && (actionOnlySSHDirectoryNavigation(file, cwd, home) || actionKnownReadOnlyShell(file, home)) {
		return false
	}
	if parsed && actionPosixNestedShellMention(file, cwd, home, depth) {
		return true
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	check := func(value string) bool {
		if len(value) == 0 || len(value) > MaxWriteTargetPathBytes {
			return false
		}
		if strings.HasPrefix(value, "~/") {
			value = filepath.Join(home, value[2:])
		}
		if strings.ContainsAny(value, "*?[]") {
			return false // A pattern in source text is not a resolved pathname.
		}
		return protectedReachPath(OperandPath(value, cwd), protected, ssh)
	}
	if parsed {
		values := actionValues{"HOME": home, "PWD": cwd}
		found := false
		syntax.Walk(file, func(node syntax.Node) bool {
			if found {
				return false
			}
			stmt, ok := node.(*syntax.Stmt)
			if !ok {
				return true
			}
			actionUpdateValues(stmt, values, cwd, home)
			for _, redir := range stmt.Redirs {
				if redir.Word != nil {
					if value, known := actionWordValue(redir.Word, values, cwd, home); known && check(value) {
						found = true
						return false
					}
				}
			}
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
				for _, word := range call.Args {
					if value, known := actionWordValue(word, values, cwd, home); known && check(value) {
						found = true
						return false
					}
				}
			}
			return true
		})
		if found {
			return true
		}
	}
	text := actionMaskLiteralDollars(command)
	text = strings.ReplaceAll(strings.ReplaceAll(text, "${HOME}/", home+"/"), "$HOME/", home+"/")
	for _, token := range unprovenPathToken.FindAllString(text, -1) {
		if check(token) {
			return true
		}
	}
	return false
}

func actionPosixNestedShellMention(file *syntax.File, cwd, home string, depth int) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		for i, word := range call.Args {
			program, static := staticProgramWord(word, home)
			if !static {
				continue
			}
			base := programBase(program)
			if base == "env" {
				for j := i + 1; j+1 < len(call.Args); j++ {
					option, optionStatic := StaticWord(call.Args[j], home)
					if !optionStatic || option != "-S" && option != "--split-string" {
						continue
					}
					if child, childStatic := StaticWord(call.Args[j+1], home); childStatic &&
						actionProtectedTargetMentionDepth(child, cwd, home, depth+1) {
						found = true
						return false
					}
				}
			}
			if !posixShellProgram(base) && base != "ash" {
				continue
			}
			for j := i + 1; j+1 < len(call.Args); j++ {
				option, static := StaticWord(call.Args[j], home)
				if !static || !strings.HasPrefix(option, "-") {
					break
				}
				if option == "-o" {
					j++ // This option consumes the next shell setting.
					continue
				}
				if option == "-c" || len(option) > 2 && !strings.HasPrefix(option, "--") &&
					!strings.ContainsAny(option, "=/") && strings.Contains(option[1:], "c") {
					if child, static := StaticWord(call.Args[j+1], home); static &&
						actionProtectedTargetMentionDepth(child, cwd, home, depth+1) {
						found = true
					}
					break
				}
			}
		}
		return !found
	})
	return found
}

// Literal and escaped dollar signs are not home variables in the outer shell.
func actionMaskLiteralDollars(command string) string {
	var masked strings.Builder
	masked.Grow(len(command))
	var quote byte
	escaped := false
	for i := 0; i < len(command); i++ {
		c := command[i]
		escapedNow := escaped
		switch {
		case escaped:
			escaped = false
		case c == '\\' && quote != '\'':
			escaped = true
		case c == '\'' && quote == 0:
			quote = '\''
		case c == '\'' && quote == '\'':
			quote = 0
		case c == '"' && quote == 0:
			quote = '"'
		case c == '"' && quote == '"':
			quote = 0
		}
		if c == '$' && (escapedNow || quote == '\'') {
			masked.WriteByte('@')
		} else {
			masked.WriteByte(c)
		}
	}
	return masked.String()
}

func actionKnownReadOnlyShell(file *syntax.File, home string) bool {
	seen, safe := false, true
	syntax.Walk(file, func(node syntax.Node) bool {
		if !safe {
			return false
		}
		switch node.(type) {
		case *syntax.Redirect, *syntax.FuncDecl, *syntax.DeclClause:
			safe = false
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		if len(call.Args) == 0 || len(call.Assigns) != 0 {
			safe = false
			return false
		}
		program, known := staticProgramWord(call.Args[0], home)
		if !known {
			safe = false
			return false
		}
		seen = true
		switch programBase(program) {
		case "cat", "type", "head", "tail", "less", "grep", "sha256sum", "ls", "dir", "stat", "wc", "readlink", "diff", "cmp", "file", "test", "[":
		case "git":
			if len(call.Args) < 2 {
				safe = false
				break
			}
			subcommand, fixed := StaticWord(call.Args[1], home)
			safe = fixed && subcommand == "status"
		default:
			safe = false
		}
		return safe
	})
	return seen && safe
}

func actionOnlySSHDirectoryNavigation(file *syntax.File, cwd, home string) bool {
	if len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 0 {
		return false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return false
	}
	program, known := staticProgramWord(call.Args[0], home)
	if !known || programBase(program) != "cd" && programBase(program) != "pushd" {
		return false
	}
	return actionPosixSSHDirectoryNavigation(call.Args, cwd, home)
}

func actionPosixSSHDirectoryNavigation(args []*syntax.Word, cwd, home string) bool {
	var targetWord *syntax.Word
	if len(args) == 3 {
		option, known := StaticWord(args[1], home)
		if !known || option != "--" {
			return false
		}
		targetWord = args[2]
	} else if len(args) == 2 {
		targetWord = args[1]
	} else {
		return false
	}
	if wordHasCommandSubstitution(targetWord) {
		return false
	}
	value, known := actionWordValue(targetWord, actionValues{"HOME": home, "PWD": cwd}, cwd, home)
	if !known {
		return false
	}
	target, resolved := ResolveWriteTarget(OperandPath(value, cwd))
	ssh, sshResolved := ResolveWriteTarget(filepath.Join(home, ".ssh"))
	return resolved && sshResolved && samePathName(target, ssh)
}

func actionWindowsTargetMention(command, cwd, home string, depth int) bool {
	if depth >= 8 || len(command) > MaxPayloadBytes {
		return false
	}
	// The argument to PowerShell -Command is parsed again by the child shell.
	// Quotes that are literal in the outer command do not stop expansion there.
	rawWords, rawOK := actionWindowsWords(command)
	if rawOK {
		for i := 0; i+2 < len(rawWords); i++ {
			program := strings.TrimSuffix(strings.ToLower(programBase(rawWords[i])), ".exe")
			if program == "env" {
				for j := i + 1; j+1 < len(rawWords); j++ {
					if rawWords[j] == ";" || rawWords[j] == "|" || rawWords[j] == "&" {
						break
					}
					if (rawWords[j] == "-S" || rawWords[j] == "--split-string") &&
						actionWindowsTargetMention(rawWords[j+1], cwd, home, depth+1) {
						return true
					}
				}
			}
			if program != "pwsh" && program != "powershell" {
				continue
			}
			for j := i + 1; j+1 < len(rawWords); j++ {
				if rawWords[j] == ";" || rawWords[j] == "|" || rawWords[j] == "&" {
					break
				}
				if strings.EqualFold(rawWords[j], "-command") || strings.EqualFold(rawWords[j], "-c") {
					if actionWindowsTargetMention(rawWords[j+1], cwd, home, depth+1) {
						return true
					}
					break
				}
			}
		}
	}
	// PowerShell does not expand variables inside single quoted literals.
	// Preserve the literal pathname there while keeping its dollar sign from
	// being mistaken for a resolvable home variable.
	var normalized strings.Builder
	normalized.Grow(len(command))
	singleQuoted := false
	for i := 0; i < len(command); i++ {
		if command[i] == '\'' {
			singleQuoted = !singleQuoted
		}
		if singleQuoted && command[i] == '$' {
			normalized.WriteByte('@')
		} else {
			normalized.WriteByte(command[i])
		}
	}
	words, ok := actionWindowsWords(normalized.String())
	if !ok || len(words) == 0 || actionKnownReadOnlyWindows(words, cwd, home) {
		return false
	}
	for i := 0; i+1 < len(words); i++ {
		if !strings.EqualFold(words[i], "-encodedcommand") && !strings.EqualFold(words[i], "-enc") {
			continue
		}
		encoded, err := base64.StdEncoding.DecodeString(words[i+1])
		if err != nil || len(encoded) == 0 || len(encoded)%2 != 0 {
			continue
		}
		letters := make([]uint16, len(encoded)/2)
		for j := range letters {
			letters[j] = uint16(encoded[2*j]) | uint16(encoded[2*j+1])<<8
		}
		if actionWindowsTargetMention(string(utf16.Decode(letters)), cwd, home, depth+1) {
			return true
		}
	}
	for _, statement := range actionWindowsResolvedStatements(words, cwd, home) {
		for _, word := range statement {
			if actionWindowsWordMentionsTarget(word, cwd, home) {
				return true
			}
		}
	}
	for _, word := range words {
		if actionWindowsWordMentionsTarget(word, cwd, home) {
			return true
		}
	}
	return false
}

func actionKnownReadOnlyWindows(words []string, cwd, home string) bool {
	if actionWindowsSSHDirectoryNavigation(words, cwd, home) {
		return true
	}
	seen, start := false, 0
	for i, word := range words {
		if actionWindowsRedirectOperator(word) != "" {
			return false
		}
		if word != ";" && word != "|" && word != "||" && word != "&" && word != "&&" {
			continue
		}
		if !actionKnownReadOnlyWindowsStatement(words[start:i]) {
			return false
		}
		seen, start = true, i+1
	}
	return (seen || start < len(words)) && actionKnownReadOnlyWindowsStatement(words[start:])
}

func actionKnownReadOnlyWindowsStatement(words []string) bool {
	if len(words) == 0 {
		return false
	}
	for _, word := range words {
		if strings.Contains(word, "$(") || strings.Contains(word, "`") {
			return false // A nested command or escaped syntax is not a plain read.
		}
	}
	call := strings.ToLower(words[0])
	if strings.HasPrefix(call, "[system.io.file]::readall") || strings.HasPrefix(call, "[io.file]::readall") {
		return true
	}
	program := strings.TrimSuffix(strings.ToLower(programBase(words[0])), ".exe")
	switch program {
	case "cat", "type", "get-content", "get-childitem", "get-item", "get-acl", "get-filehash", "resolve-path", "test-path", "select-string", "select-object", "grep", "head", "tail", "less", "sha256sum", "wc", "dir", "ls", "stat", "readlink", "diff", "cmp", "file", "findstr":
		return true
	case "git":
		return len(words) > 1 && strings.EqualFold(words[1], "status")
	}
	return false
}

func actionWindowsSSHDirectoryNavigation(words []string, cwd, home string) bool {
	if len(words) == 0 {
		return false
	}
	program := strings.TrimSuffix(strings.ToLower(programBase(words[0])), ".exe")
	if program != "cd" && program != "pushd" && program != "set-location" && program != "push-location" {
		return false
	}
	if len(words) == 3 {
		option := strings.ToLower(words[1])
		if option != "-path" && option != "-literalpath" &&
			(option != "--" || program != "cd" && program != "pushd") {
			return false
		}
		words = words[2:]
	} else if len(words) == 2 {
		words = words[1:]
	} else {
		return false
	}
	target, resolved := actionWindowsPath(words[0], cwd, home)
	ssh, sshResolved := actionWindowsPath(strings.TrimRight(home, `\/`)+`/.ssh`, cwd, home)
	return resolved && sshResolved && target == ssh
}

func actionWindowsWordMentionsTarget(word, cwd, home string) bool {
	check := func(candidate string) bool {
		candidate = strings.ReplaceAll(candidate, "`", "")
		resolved, ok := actionWindowsPath(candidate, cwd, home)
		if !ok {
			return actionWindowsUnresolvedUnderSSH(candidate, cwd, home)
		}
		root, ok := actionWindowsPath(home, cwd, home)
		if !ok {
			return false
		}
		if resolved == root+"/.ssh" {
			return true
		}
		protected, _ := actionWindowsProtected(candidate, cwd, home, false)
		return protected
	}
	if check(word) {
		return true
	}
	for _, field := range strings.FieldsFunc(word, func(r rune) bool {
		return strings.ContainsRune(" \t\r\n'\"(),;|&<>{}=", r)
	}) {
		if check(field) {
			return true
		}
		if colon := strings.IndexByte(field, ':'); colon > 1 && field[0] == '-' && check(field[colon+1:]) {
			return true
		}
	}
	return false
}

// An unresolved leaf under .ssh is still a protected-directory use. Keep
// this lexical fallback scoped to that directory; other unknown paths audit.
func actionWindowsUnresolvedUnderSSH(value, cwd, home string) bool {
	value = strings.ReplaceAll(strings.TrimSpace(value), `\`, "/")
	lower := strings.ToLower(value)
	for _, prefix := range []string{"%userprofile%", "%homedrive%%homepath%", "$env:userprofile", "${env:userprofile}", "$home", "${home}", "~"} {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") {
			value = strings.ReplaceAll(home, `\`, "/") + value[len(prefix):]
			break
		}
	}
	if !actionWindowsHome(value) {
		value = strings.TrimRight(strings.ReplaceAll(cwd, `\`, "/"), "/") + "/" + value
	}
	root := strings.ToLower(path.Clean(strings.ReplaceAll(home, `\`, "/"))) + "/.ssh/"
	return strings.HasPrefix(strings.ToLower(path.Clean(value)), root)
}
