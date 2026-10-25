// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf16"

	"mvdan.cc/sh/v3/syntax"
)

// actionProtectedTargetMention is independent of a program's operand roles.
// A resolved protected path in a writable command is enough for the action
// decision; commands with no such path continue through the existing proof.
func actionProtectedTargetMention(command, cwd, home string) bool {
	return actionProtectedTargetMentionDepth(command, cwd, home, 0, false)
}

// ActionStateTargetMention applies the same independent target scan to the
// active DefenseClaw security state, without attributing it to SSH keys.
func ActionStateTargetMention(command, cwd, home string) bool {
	return actionProtectedTargetMentionDepth(command, cwd, home, 0, true)
}

func actionProtectedTargetMentionDepth(command, cwd, home string, depth int, stateOnly bool) bool {
	if command == "" || home == "" || len(command) > MaxPayloadBytes || depth >= 8 {
		return false
	}
	if actionWindowsHome(home) {
		return actionWindowsTargetMention(command, cwd, home, depth, stateOnly)
	}
	if !filepath.IsAbs(cwd) && (!actionPosixWindowsHome(home) || !path.IsAbs(cwd)) {
		return false
	}
	file, parsed := parseShell(command)
	if depth == 0 && parsed && (actionOnlySSHDirectoryNavigation(file, cwd, home) || actionKnownReadOnlyShell(file, home)) {
		return false
	}
	if parsed && actionPosixNestedShellMention(file, cwd, home, depth, stateOnly) {
		return true
	}
	protected := newProtectedFiles(home)
	check := func(value string) bool {
		if len(value) == 0 || len(value) > MaxWriteTargetPathBytes {
			return false
		}
		if strings.HasPrefix(value, "~/") {
			if actionPosixWindowsHome(home) {
				value = path.Join(home, value[2:])
			} else {
				value = filepath.Join(home, value[2:])
			}
		}
		if strings.ContainsAny(value, "*?[]") {
			if stateOnly {
				return false
			}
			if actionPosixWindowsHome(home) {
				return actionPosixWindowsProtectedGlob(value, cwd, home)
			}
			return actionProtectedFileGlobReach(value, cwd, protected)
		}
		if actionPosixWindowsHome(home) {
			if stateOnly {
				return actionPosixWindowsStatePath(value, cwd, home)
			}
			return actionPosixWindowsProtected(value, cwd, home)
		}
		operand := OperandPath(value, cwd)
		if stateOnly {
			return actionProtectedStatePath(operand, home)
		}
		return actionProtectedFileReach(operand, protected)
	}
	if parsed {
		values := actionValues{"HOME": home, "PWD": cwd}
		found := false
		checkWord := func(word *syntax.Word) bool {
			value, known := actionWordValue(word, values, cwd, home)
			activeGlob := actionWordHasUnquotedGlob(word, command)
			if !known && activeGlob {
				value, known = actionWordValueWithGlob(word, values, cwd, home, true)
			}
			return known && (!strings.ContainsAny(value, "*?[]") || activeGlob) && check(value)
		}
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
				if redir.Word != nil && checkWord(redir.Word) {
					found = true
					return false
				}
			}
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
				for _, word := range call.Args {
					if checkWord(word) {
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
	text := actionMaskLiteralMetacharacters(command)
	text = strings.ReplaceAll(strings.ReplaceAll(text, "${HOME}/", home+"/"), "$HOME/", home+"/")
	for _, token := range unprovenPathToken.FindAllString(text, -1) {
		if strings.ContainsAny(token, "*?[]") && (parsed || !strings.ContainsAny(token, "/\\")) {
			continue // Shell case labels and patch text are not argv glob operands.
		}
		if check(token) {
			return true
		}
	}
	return false
}

// A Windows hook may receive a POSIX-dialect command from WSL or another
// shell with a POSIX active home. The host filesystem cannot resolve those
// names, so compare only their bounded lexical protected-target spelling.
func actionPosixWindowsHome(home string) bool {
	return runtime.GOOS == "windows" && strings.HasPrefix(home, "/") && !strings.HasPrefix(home, "//")
}

func actionPosixWindowsPath(value, cwd, home string) string {
	if value == "~" {
		value = home
	} else if strings.HasPrefix(value, "~/") {
		value = path.Join(home, value[2:])
	}
	if !path.IsAbs(value) {
		value = path.Join(cwd, value)
	}
	return path.Clean(value)
}

func actionPosixWindowsProtected(value, cwd, home string) bool {
	resolved := actionPosixWindowsPath(value, cwd, home)
	ssh := path.Join(home, ".ssh")
	for _, name := range AuthorizedKeysFiles {
		if resolved == path.Join(ssh, name) {
			return true
		}
	}
	return false
}

func actionPosixWindowsProtectedGlob(value, cwd, home string) bool {
	resolved := actionPosixWindowsPath(value, cwd, home)
	parent, base := path.Split(resolved)
	if strings.ContainsAny(parent, "*?[") {
		return false
	}
	if path.Clean(parent) != path.Join(home, ".ssh") {
		return false
	}
	for _, name := range AuthorizedKeysFiles {
		if matched, _ := path.Match(base, name); matched {
			return true
		}
	}
	return false
}

// A directory mention alone is not a protected-file mention. The write proof
// separately retains its directory-as-destination rule.
func actionProtectedFileReach(operand string, protected protectedFiles) bool {
	resolved, ok := ResolveWriteTarget(operand)
	if !ok {
		return false
	}
	if protected.has(resolved) {
		return true
	}
	mapped, ok := protected.target(resolved)
	return ok && protected.has(mapped)
}

// Expand only a bounded literal parent and match files, not the .ssh directory.
func actionProtectedFileGlobReach(pattern, cwd string, protected protectedFiles) bool {
	parent, base := filepath.Dir(pattern), filepath.Base(pattern)
	if _, err := filepath.Match(base, ""); err != nil || strings.ContainsAny(parent, "*?[") {
		return false
	}
	directory, err := os.Open(OperandPath(parent, cwd))
	if err != nil {
		return false
	}
	names, err := directory.Readdirnames(4097)
	_ = directory.Close()
	if err != nil && err != io.EOF || len(names) > 4096 {
		return false
	}
	for _, name := range names {
		if matched, _ := filepath.Match(base, name); matched &&
			actionProtectedFileReach(OperandPath(name, OperandPath(parent, cwd)), protected) {
			return true
		}
	}
	return false
}

func actionPosixWindowsStatePath(value, cwd, home string) bool {
	resolved := actionPosixWindowsPath(value, cwd, home)
	return actionProtectedStateRelative(strings.TrimPrefix(resolved, path.Clean(home)+"/"))
}

// State protection is scoped to the active home and the security-state names
// owned by the semantic detector. Project-local .defenseclaw files and the
// product's diagnostic logs are ordinary work.
func actionProtectedStateRelative(relative string) bool {
	if !strings.HasPrefix(relative, ".defenseclaw/") {
		return false
	}
	state := strings.TrimPrefix(relative, ".defenseclaw/")
	switch state {
	case ".env", "config.yaml", "confidence_policy.yaml", "guardrail_runtime.json",
		"device.key", "picked_connector", "custom-providers.json", "audit.db",
		"audit.db-wal", "audit.db-shm", "judge.db", "judge.db-wal",
		"judge.db-shm", "judge_bodies.db", "judge_bodies.db-wal", "judge_bodies.db-shm":
		return true
	}
	for _, prefix := range []string{"cache/", "policies/", "quarantine/", "receipts/", "registries/"} {
		if strings.HasPrefix(state, prefix) && len(state) > len(prefix) {
			return true
		}
	}
	return false
}

func actionProtectedStatePath(value, home string) bool {
	resolved, ok := ResolveWriteTarget(value)
	if !ok {
		return false
	}
	activeHome, ok := ResolveWriteTarget(home)
	if !ok {
		return false
	}
	relative, err := filepath.Rel(activeHome, resolved)
	return err == nil && actionProtectedStateRelative(filepath.ToSlash(relative))
}

func actionPosixNestedShellMention(file *syntax.File, cwd, home string, depth int, stateOnly bool) bool {
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
						actionProtectedTargetMentionDepth(child, cwd, home, depth+1, stateOnly) {
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
						actionProtectedTargetMentionDepth(child, cwd, home, depth+1, stateOnly) {
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

// Quoted or escaped dollar signs and glob characters do not expand in the
// outer shell. Nested shell bodies are checked separately above.
func actionMaskLiteralMetacharacters(command string) string {
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
		if c == '$' && (escapedNow || quote == '\'') ||
			strings.ContainsRune("*?[]", rune(c)) && (escapedNow || quote != 0) {
			masked.WriteByte('@')
		} else {
			masked.WriteByte(c)
		}
	}
	return masked.String()
}

func actionWordHasUnquotedGlob(word *syntax.Word, command string) bool {
	start, end := int(word.Pos().Offset()), int(word.End().Offset())
	return start >= 0 && end <= len(command) && start < end &&
		strings.ContainsAny(actionMaskLiteralMetacharacters(command[start:end]), "*?[]")
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
		case "cat", "type", "head", "tail", "grep", "sha256sum", "ls", "dir", "stat", "wc", "readlink", "diff", "cmp", "file", "test", "[":
		case "less":
			for _, arg := range call.Args[1:] {
				option, known := StaticWord(arg, home)
				if !known || actionLessWritesFile(option) {
					safe = false
					break
				}
			}
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

func actionLessWritesFile(option string) bool {
	return option == "-o" || option == "-O" ||
		strings.HasPrefix(option, "-o") && !strings.HasPrefix(option, "--") ||
		strings.HasPrefix(option, "-O") ||
		strings.HasPrefix(option, "--log-file")
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
	if actionPosixWindowsHome(home) {
		return actionPosixWindowsPath(value, cwd, home) == path.Join(home, ".ssh")
	}
	target, resolved := ResolveWriteTarget(OperandPath(value, cwd))
	ssh, sshResolved := ResolveWriteTarget(filepath.Join(home, ".ssh"))
	return resolved && sshResolved && samePathName(target, ssh)
}

func actionWindowsTargetMention(command, cwd, home string, depth int, stateOnly bool) bool {
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
						actionWindowsTargetMention(rawWords[j+1], cwd, home, depth+1, stateOnly) {
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
					if actionWindowsTargetMention(rawWords[j+1], cwd, home, depth+1, stateOnly) {
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
		if actionWindowsTargetMention(string(utf16.Decode(letters)), cwd, home, depth+1, stateOnly) {
			return true
		}
	}
	for _, statement := range actionWindowsResolvedStatements(words, cwd, home) {
		for _, word := range statement {
			if actionWindowsWordMentionsTarget(word, cwd, home, stateOnly) {
				return true
			}
		}
	}
	for _, word := range words {
		if actionWindowsWordMentionsTarget(word, cwd, home, stateOnly) {
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
	call := strings.ToLower(words[0])
	if strings.HasPrefix(call, "[system.io.file]::readall") || strings.HasPrefix(call, "[io.file]::readall") {
		return len(words) == 1 && strings.Count(call, "(") == 1 &&
			strings.Count(call, ")") == 1 && strings.HasSuffix(call, ")")
	}
	for _, word := range words {
		if strings.ContainsAny(word, "(`") || strings.Contains(word, "@{") {
			return false // A nested command or escaped syntax is not a plain read.
		}
		for i := 0; i < len(word); i++ {
			if word[i] == '{' && (i == 0 || word[i-1] != '$') {
				return false // Scriptblocks and calculated properties execute commands.
			}
		}
	}
	program := strings.TrimSuffix(strings.ToLower(programBase(words[0])), ".exe")
	switch program {
	case "cat", "type", "get-content", "get-childitem", "get-item", "get-acl", "get-filehash", "resolve-path", "test-path", "select-string", "select-object", "grep", "head", "tail", "sha256sum", "wc", "dir", "ls", "stat", "readlink", "diff", "cmp", "file", "findstr":
		return true
	case "less":
		for _, option := range words[1:] {
			if actionLessWritesFile(option) {
				return false
			}
		}
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

func actionWindowsWordMentionsTarget(word, cwd, home string, stateOnly bool) bool {
	check := func(candidate string) bool {
		candidate = strings.ReplaceAll(candidate, "`", "")
		if strings.ContainsAny(candidate, "*?[]") {
			return !stateOnly && actionWindowsProtectedGlobReach(candidate, cwd, home)
		}
		resolved, ok := actionWindowsPath(candidate, cwd, home)
		if !ok {
			if stateOnly {
				return false
			}
			return actionWindowsUnresolvedUnderSSH(candidate, cwd, home)
		}
		root, ok := actionWindowsPath(home, cwd, home)
		if !ok {
			return false
		}
		if stateOnly {
			return strings.HasPrefix(resolved, root+"/") &&
				actionProtectedStateRelative(strings.TrimPrefix(resolved, root+"/"))
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

func actionWindowsProtectedGlobReach(pattern, cwd, home string) bool {
	pattern = strings.ReplaceAll(pattern, `\`, "/")
	parent, base := path.Split(pattern)
	if parent == "" {
		parent = "."
	}
	if _, err := path.Match(base, ""); err != nil || strings.ContainsAny(parent, "*?[") {
		return false
	}
	resolved, ok := actionWindowsPath(strings.TrimSuffix(parent, "/"), cwd, home)
	if !ok {
		return false
	}
	root, ok := actionWindowsPath(home, cwd, home)
	if !ok || resolved != root+"/.ssh" {
		return false
	}
	if runtime.GOOS == "windows" && actionProtectedFileGlobReach(
		filepath.Join(filepath.FromSlash(resolved), base), cwd, newProtectedFiles(home)) {
		return true
	}
	for _, name := range AuthorizedKeysFiles {
		if matched, _ := path.Match(strings.ToLower(base), name); matched {
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
