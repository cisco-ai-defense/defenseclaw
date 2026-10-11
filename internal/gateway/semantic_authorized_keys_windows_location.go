// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"mvdan.cc/sh/v3/syntax"
)

// A Windows hook reports native cwd and home even when the tool runs Git Bash.
// Keep this proof independent of the operating system running the Go tests.
func trustedWindowsLocationAuthorizedKeysWrite(input actionfacts.Input) bool {
	if input.Command == "" || len(input.Command) > 64<<10 ||
		!windowsLocationAbsolute(input.ActiveHome) || !windowsLocationAbsolute(input.CWD) {
		return false
	}
	return trustedWindowsPOSIXLocationWrite(input) ||
		trustedWindowsNativeLocationWrite(input, actionfacts.DialectPowerShell) ||
		trustedWindowsNativeLocationWrite(input, actionfacts.DialectCMD) ||
		trustedWindowsCMDWrapperLocationWrite(input)
}

// A Bash-labeled Windows tool can invoke cmd explicitly. The outer shell does
// not execute cd; cmd does, so prove the location change in the inner command.
func trustedWindowsCMDWrapperLocationWrite(input actionfacts.Input) bool {
	command := strings.TrimSpace(input.Command)
	lower := strings.ToLower(command)
	for _, prefix := range []string{"cmd /d /c ", "cmd.exe /d /c "} {
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		body := strings.TrimSpace(command[len(prefix):])
		if len(body) >= 2 && body[0] == '"' && body[len(body)-1] == '"' {
			body = body[1 : len(body)-1]
		}
		if body == "" || strings.ContainsAny(body, "\r\n") {
			return false
		}
		input.Command = body
		input.DialectHint = actionfacts.DialectCMD
		return trustedWindowsNativeLocationWrite(input, actionfacts.DialectCMD)
	}
	return false
}

func windowsLocationAbsolute(value string) bool {
	value = strings.ReplaceAll(value, `\`, "/")
	return len(value) >= 3 && value[1] == ':' && value[2] == '/' ||
		len(value) >= 4 && value[0] == '/' && value[2] == '/' &&
			(value[1] >= 'a' && value[1] <= 'z' || value[1] >= 'A' && value[1] <= 'Z') ||
		strings.HasPrefix(value, "//")
}

func windowsLocationCanonical(value string) string {
	value = strings.ToLower(strings.ReplaceAll(value, `\`, "/"))
	if strings.HasPrefix(value, "//?/unc/") {
		value = "//" + strings.TrimPrefix(value, "//?/unc/")
	} else if strings.HasPrefix(value, "//?/") {
		value = strings.TrimPrefix(value, "//?/")
	}
	if len(value) >= 4 && value[0] == '/' && value[2] == '/' &&
		value[1] >= 'a' && value[1] <= 'z' {
		value = value[1:2] + ":" + value[2:]
	}
	if strings.HasPrefix(value, "//") {
		return "/" + path.Clean(value)
	}
	return path.Clean(value)
}

func windowsLocationResolve(value, current string, input actionfacts.Input, dialect actionfacts.Dialect) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n`") {
		return "", false
	}
	value = strings.ReplaceAll(value, `\`, "/")
	lower := strings.ToLower(value)
	var prefixes []string
	switch dialect {
	case actionfacts.DialectPOSIX, actionfacts.DialectPowerShell:
		prefixes = append(prefixes, "~")
	}
	switch dialect {
	case actionfacts.DialectPOSIX:
		prefixes = append(prefixes, "$home", "${home}")
	case actionfacts.DialectPowerShell:
		prefixes = append(prefixes, "$home", "${home}", "$env:userprofile", "${env:userprofile}")
	case actionfacts.DialectCMD:
		prefixes = append(prefixes, "%userprofile%", "%homedrive%%homepath%")
	}
	expanded := false
	for _, prefix := range prefixes {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") {
			value = strings.ReplaceAll(input.ActiveHome, `\`, "/") + value[len(prefix):]
			expanded = true
			break
		}
	}
	if !expanded && strings.ContainsAny(strings.TrimPrefix(value, "//?/"), "$%*?[]") {
		return "", false
	}
	for _, component := range strings.Split(value, "/") {
		if component == ".." {
			return "", false // do not clean across a junction or symbolic link
		}
	}
	if !windowsLocationAbsolute(value) {
		if strings.Contains(value, ":") {
			return "", false // drive-relative and provider paths need runtime state
		}
		value = current + "/" + value
	}
	return windowsLocationCanonical(value), true
}

func windowsLocationAuthorizedKeys(target string, input actionfacts.Input) bool {
	target = windowsLocationCanonical(target)
	home := windowsLocationCanonical(input.ActiveHome)
	for _, name := range []string{"authorized_keys", "authorized_keys2"} {
		protected := windowsLocationCanonical(home + "/.ssh/" + name)
		if target == protected {
			return true
		}
		// On real Windows, file identity also covers an 8.3 or UNC spelling
		// of an existing directory. Synthetic tests use the path comparison.
		if runtime.GOOS == "windows" && path.Base(target) == name {
			gotDir, err1 := os.Stat(filepath.FromSlash(path.Dir(target)))
			homeDir, err2 := os.Stat(filepath.FromSlash(path.Dir(protected)))
			if err1 == nil && err2 == nil && os.SameFile(gotDir, homeDir) {
				return true
			}
		}
	}
	return false
}

func windowsLocationFlatten(stmt *syntax.Stmt, out *[]*syntax.Stmt) bool {
	if stmt == nil || stmt.Background || stmt.Negated {
		return false
	}
	if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok {
		return binary.Op == syntax.AndStmt &&
			windowsLocationFlatten(binary.X, out) &&
			windowsLocationFlatten(binary.Y, out)
	}
	if _, ok := stmt.Cmd.(*syntax.CallExpr); !ok {
		return false
	}
	*out = append(*out, stmt)
	return true
}

func trustedWindowsPOSIXLocationWrite(input actionfacts.Input) bool {
	if input.DialectHint != "" && input.DialectHint != actionfacts.DialectPOSIX {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(input.Command), "")
	if err != nil || len(file.Stmts) == 0 || len(file.Stmts) > 16 {
		return false
	}
	var statements []*syntax.Stmt
	for _, stmt := range file.Stmts {
		if !windowsLocationFlatten(stmt, &statements) {
			return false
		}
	}
	if len(statements) < 2 || len(statements) > 16 {
		return false
	}
	current := windowsLocationCanonical(input.CWD)
	var stack []string
	changed := false
	for _, stmt := range statements {
		call := stmt.Cmd.(*syntax.CallExpr)
		if len(call.Assigns) != 0 || len(call.Args) == 0 {
			return false
		}
		program, ok := hookpaths.StaticWord(call.Args[0], input.ActiveHome)
		if !ok {
			return false
		}
		switch strings.ToLower(program) {
		case "cd", "pushd":
			if len(call.Args) > 2 {
				return false
			}
			directory := input.ActiveHome
			if len(call.Args) == 2 {
				directory, ok = hookpaths.StaticWord(call.Args[1], input.ActiveHome)
				if !ok {
					return false
				}
			}
			next, ok := windowsLocationResolve(directory, current, input, actionfacts.DialectPOSIX)
			if !ok {
				return false
			}
			if strings.EqualFold(program, "pushd") {
				stack = append(stack, current)
			}
			current, changed = next, true
			continue
		case "popd":
			if len(call.Args) != 1 || len(stack) == 0 {
				return false
			}
			current, stack = stack[len(stack)-1], stack[:len(stack)-1]
			changed = true
			continue
		}
		if !changed {
			continue
		}
		for _, redirect := range stmt.Redirs {
			switch redirect.Op {
			case syntax.RdrOut, syntax.RdrClob, syntax.AppOut, syntax.AppClob,
				syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
			default:
				continue
			}
			target, ok := hookpaths.StaticWord(redirect.Word, input.ActiveHome)
			if !ok {
				continue
			}
			resolved, ok := windowsLocationResolve(target, current, input, actionfacts.DialectPOSIX)
			if ok && windowsLocationAuthorizedKeys(resolved, input) {
				return true
			}
		}
	}
	return false
}

type windowsLocationToken struct {
	text         string
	singleQuoted bool
}

// Only literal command tokens can contribute to this proof.
func windowsLocationSegments(command string) ([][]windowsLocationToken, bool) {
	var segments [][]windowsLocationToken
	var tokens []windowsLocationToken
	var word strings.Builder
	var quote byte
	single := false
	flush := func() {
		if word.Len() > 0 {
			tokens = append(tokens, windowsLocationToken{word.String(), single})
			word.Reset()
			single = false
		}
	}
	finish := func() {
		flush()
		if len(tokens) > 0 {
			segments = append(segments, tokens)
			tokens = nil
		}
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				if c == '`' {
					return nil, false
				}
				word.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			if word.Len() > 0 {
				return nil, false
			}
			quote = c
			single = c == '\''
		case ' ', '\t':
			flush()
		case ';', '|':
			finish()
		case '&':
			if i+1 >= len(command) || command[i+1] != '&' {
				return nil, false
			}
			finish()
			i++
		case '>':
			flush()
			if i+1 < len(command) && command[i+1] == '>' {
				tokens = append(tokens, windowsLocationToken{text: ">>"})
				i++
			} else {
				tokens = append(tokens, windowsLocationToken{text: ">"})
			}
		case '<', '\r', '\n', '`':
			return nil, false
		default:
			word.WriteByte(c)
		}
	}
	if quote != 0 {
		return nil, false
	}
	finish()
	return segments, len(segments) > 0 && len(segments) <= 16
}

func windowsLocationDirectory(tokens []windowsLocationToken, dialect actionfacts.Dialect, home string) (string, bool) {
	program := strings.ToLower(tokens[0].text)
	if len(tokens) == 1 {
		return home, dialect != actionfacts.DialectCMD && program != "pushd"
	}
	index := 1
	if dialect == actionfacts.DialectCMD && strings.EqualFold(tokens[index].text, "/d") {
		index++
	}
	if index >= len(tokens) {
		return "", false
	}
	if strings.EqualFold(tokens[index].text, "-Path") ||
		strings.EqualFold(tokens[index].text, "-LiteralPath") {
		index++
	}
	if index+1 != len(tokens) || tokens[index].singleQuoted &&
		strings.Contains(tokens[index].text, "$") {
		return "", false
	}
	return tokens[index].text, true
}

func windowsLocationWriteTarget(tokens []windowsLocationToken, dialect actionfacts.Dialect) (string, bool) {
	program := strings.ToLower(tokens[0].text)
	if dialect == actionfacts.DialectCMD {
		for i := 1; i+1 < len(tokens); i++ {
			if tokens[i].text == ">" || tokens[i].text == ">>" {
				return tokens[i+1].text, true
			}
		}
		return "", false
	}
	if program != "add-content" && program != "set-content" && program != "out-file" {
		// PowerShell redirections write independently of the command.
		for i := 1; i+1 < len(tokens); i++ {
			if tokens[i].text == ">" || tokens[i].text == ">>" {
				return tokens[i+1].text, true
			}
		}
		return "", false
	}
	for _, token := range tokens {
		if strings.EqualFold(token.text, "-WhatIf") || strings.EqualFold(token.text, "-Confirm") {
			return "", false
		}
	}
	for i := 1; i+1 < len(tokens); i++ {
		if strings.EqualFold(tokens[i].text, "-Path") ||
			strings.EqualFold(tokens[i].text, "-LiteralPath") ||
			strings.EqualFold(tokens[i].text, "-FilePath") {
			if tokens[i+1].singleQuoted && strings.Contains(tokens[i+1].text, "$") {
				return "", false
			}
			return tokens[i+1].text, true
		}
	}
	for _, token := range tokens[1:] {
		if !strings.HasPrefix(token.text, "-") {
			if token.singleQuoted && strings.Contains(token.text, "$") {
				return "", false
			}
			return token.text, true
		}
	}
	return "", false
}

func trustedWindowsNativeLocationWrite(input actionfacts.Input, dialect actionfacts.Dialect) bool {
	if input.DialectHint != dialect {
		return false
	}
	segments, ok := windowsLocationSegments(input.Command)
	if !ok || len(segments) < 2 {
		return false
	}
	current := windowsLocationCanonical(input.CWD)
	var stack []string
	changed := false
	for _, tokens := range segments {
		program := strings.ToLower(tokens[0].text)
		switch program {
		case "cd", "set-location", "push-location", "pushd", "pop-location", "popd":
			if dialect == actionfacts.DialectCMD &&
				program != "cd" && program != "pushd" && program != "popd" {
				return false
			}
			if program == "pop-location" || program == "popd" {
				if len(tokens) != 1 || len(stack) == 0 {
					return false
				}
				current, stack = stack[len(stack)-1], stack[:len(stack)-1]
				changed = true
				continue
			}
			directory, ok := windowsLocationDirectory(tokens, dialect, input.ActiveHome)
			if !ok {
				return false
			}
			next, ok := windowsLocationResolve(directory, current, input, dialect)
			if !ok {
				return false
			}
			if program == "push-location" || program == "pushd" {
				stack = append(stack, current)
			}
			current, changed = next, true
			continue
		}
		if !changed {
			continue
		}
		target, ok := windowsLocationWriteTarget(tokens, dialect)
		if !ok {
			continue
		}
		resolved, ok := windowsLocationResolve(target, current, input, dialect)
		if ok && windowsLocationAuthorizedKeys(resolved, input) {
			return true
		}
	}
	return false
}
