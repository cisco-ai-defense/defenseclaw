// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// windowsCommandFindings recognizes Windows-native command forms that cannot
// be represented safely by a flat substring regexp. It performs lexical
// normalization only: input is never decoded, expanded, or executed.
func windowsCommandFindings(text, toolName string) []RuleFinding {
	command, dialect, ok := windowsCommandText(text, toolName)
	if !ok {
		return windowsSensitivePathFindings(text, toolName, false)
	}

	pipeline, dialect := unwrapWindowsCommand(command, dialect, 0)
	var segments []string
	for _, stage := range pipeline {
		segments = append(segments, windowsStatements(stage, dialect)...)
	}
	findings := make([]RuleFinding, 0, 4)
	seen := make(map[string]bool)
	add := func(id, title, severity string, confidence float64, tags ...string) {
		if seen[id] {
			return
		}
		seen[id] = true
		findings = append(findings, RuleFinding{
			RuleID: id, Title: title, Severity: severity, Confidence: confidence,
			Evidence: sanitizeEvidence(command), Tags: tags,
		})
	}

	for _, segment := range segments {
		tokens := windowsTokens(segment, dialect)
		if len(tokens) == 0 {
			continue
		}
		name := windowsExecutableName(tokens[0])
		args := tokens[1:]

		if isPowerShellRemoveItem(name) && hasPowerShellSwitch(args, "recurse", "r") && hasPowerShellSwitch(args, "force", "fo") {
			add("CMD-WIN-REMOVE-ITEM-RF", "PowerShell recursive forced deletion", "CRITICAL", 0.98, "destructive", "windows")
		}
		if (name == "rmdir" || name == "rd") && hasWindowsSwitch(args, "s") && hasWindowsSwitch(args, "q") {
			add("CMD-WIN-RMDIR-SQ", "cmd recursive quiet directory deletion", "CRITICAL", 0.98, "destructive", "windows")
		}
		if name == "reg" && windowsPersistenceRegistryKey(args) {
			add("CMD-WIN-REG-PERSIST", "Windows registry persistence modification", "CRITICAL", 0.97, "persistence", "windows")
		}

		if windowsCommandCanReadSensitivePath(name) {
			for _, f := range windowsSensitivePathFindings(strings.Join(args, " "), toolName, true) {
				if !seen[f.RuleID] {
					seen[f.RuleID] = true
					findings = append(findings, f)
				}
			}
		}
	}

	for i := 0; i+1 < len(pipeline); i++ {
		leftStatements := windowsStatements(pipeline[i], dialect)
		rightStatements := windowsStatements(pipeline[i+1], dialect)
		if len(leftStatements) != 1 || len(rightStatements) != 1 {
			continue
		}
		left, right := windowsTokens(leftStatements[0], dialect), windowsTokens(rightStatements[0], dialect)
		if len(left) == 0 || len(right) == 0 {
			continue
		}
		if isPowerShellWebRequest(windowsExecutableName(left[0])) && isPowerShellExpression(windowsExecutableName(right[0])) {
			add("CMD-WIN-IWR-IEX", "PowerShell download piped to expression execution", "CRITICAL", 0.99, "execution", "download-exec", "windows")
		}
	}

	return findings
}

type windowsShellDialect uint8

const (
	windowsDialectUnknown windowsShellDialect = iota
	windowsDialectPowerShell
	windowsDialectCMD
)

func windowsCommandText(text, toolName string) (string, windowsShellDialect, bool) {
	name := strings.ToLower(strings.TrimSpace(toolName))
	dialect := windowsDialectUnknown
	switch name {
	case "cmd", "cmd.exe":
		dialect = windowsDialectCMD
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		dialect = windowsDialectPowerShell
	case "bash", "shell", "shell_command", "terminal", "run_command", "run_shell_command", "runshellcommand", "run_terminal_cmd", "execute", "execute_command", "exec", "command":
	default:
		return "", dialect, false
	}

	var object map[string]interface{}
	if json.Unmarshal([]byte(text), &object) == nil {
		for _, key := range []string{"command", "cmd", "script", "input"} {
			if value, ok := object[key].(string); ok && strings.TrimSpace(value) != "" {
				return value, dialect, true
			}
			if values, ok := object[key].([]interface{}); ok {
				argv := make([]string, 0, len(values))
				for _, raw := range values {
					value, ok := raw.(string)
					if !ok {
						return "", dialect, false
					}
					argv = append(argv, quoteWindowsArg(value))
				}
				if len(argv) > 0 {
					return strings.Join(argv, " "), dialect, true
				}
			}
		}
		return "", dialect, false
	}
	return text, dialect, strings.TrimSpace(text) != ""
}

func quoteWindowsArg(value string) string {
	if value == "" || strings.IndexFunc(value, unicode.IsSpace) >= 0 || strings.ContainsAny(value, "|;&") {
		return `'` + strings.ReplaceAll(value, `'`, `''`) + `'`
	}
	return value
}

func unwrapWindowsCommand(command string, dialect windowsShellDialect, depth int) ([]string, windowsShellDialect) {
	command = stripPowerShellComments(command, dialect)
	segments := windowsSegments(command, dialect)
	if depth >= 3 || len(segments) != 1 {
		return segments, dialect
	}
	tokens := windowsTokens(segments[0], dialect)
	if len(tokens) < 3 {
		return segments, dialect
	}
	name := windowsExecutableName(tokens[0])
	if name == "powershell" || name == "pwsh" {
		for i := 1; i < len(tokens)-1; i++ {
			arg := strings.ToLower(tokens[i])
			if arg == "-command" || arg == "-c" {
				return unwrapWindowsCommand(strings.Join(tokens[i+1:], " "), windowsDialectPowerShell, depth+1)
			}
		}
	}
	if name == "cmd" {
		for i := 1; i < len(tokens)-1; i++ {
			if strings.EqualFold(tokens[i], "/c") || strings.EqualFold(tokens[i], "/k") {
				return unwrapWindowsCommand(strings.Join(tokens[i+1:], " "), windowsDialectCMD, depth+1)
			}
		}
	}
	return segments, dialect
}

// windowsSegments splits executable pipeline stages without treating quoted
// documentation or string literals as commands.
func windowsSegments(command string, dialect windowsShellDialect) []string {
	var out []string
	start := 0
	var quote rune
	escaped := false
	runes := []rune(command)
	for i, r := range runes {
		if escaped {
			escaped = false
			continue
		}
		if windowsEscapeRune(r, dialect, quote) {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '|' {
			if part := strings.TrimSpace(string(runes[start:i])); part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	if part := strings.TrimSpace(string(runes[start:])); part != "" {
		out = append(out, part)
	}
	return out
}

func windowsStatements(stage string, dialect windowsShellDialect) []string {
	var out []string
	start := 0
	var quote rune
	escaped := false
	runes := []rune(stage)
	for i, r := range runes {
		if escaped {
			escaped = false
			continue
		}
		if windowsEscapeRune(r, dialect, quote) {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == ';' || r == '&' || r == '\n' || r == '\r' {
			if part := strings.TrimSpace(string(runes[start:i])); part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	if part := strings.TrimSpace(string(runes[start:])); part != "" {
		out = append(out, part)
	}
	return out
}

func windowsTokens(segment string, dialect windowsShellDialect) []string {
	var tokens []string
	var current strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	for _, r := range segment {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if windowsEscapeRune(r, dialect, quote) {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if unicode.IsSpace(r) {
			flush()
			continue
		}
		current.WriteRune(r)
	}
	flush()
	return tokens
}

func windowsEscapeRune(r rune, dialect windowsShellDialect, quote rune) bool {
	switch dialect {
	case windowsDialectPowerShell:
		return r == '`' && quote != '\''
	case windowsDialectCMD:
		return r == '^' && quote == 0
	default:
		return false
	}
}

func stripPowerShellComments(command string, dialect windowsShellDialect) string {
	if dialect != windowsDialectPowerShell {
		return command
	}
	runes := []rune(command)
	var out strings.Builder
	var quote rune
	escaped := false
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if escaped {
			out.WriteRune(r)
			escaped = false
			continue
		}
		if windowsEscapeRune(r, dialect, quote) {
			out.WriteRune(r)
			escaped = true
			continue
		}
		if quote != 0 {
			out.WriteRune(r)
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			out.WriteRune(r)
			continue
		}
		if r == '#' && (i == 0 || unicode.IsSpace(runes[i-1])) {
			for i < len(runes) && runes[i] != '\n' && runes[i] != '\r' {
				i++
			}
			if i < len(runes) {
				out.WriteRune(runes[i])
			}
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

func windowsExecutableName(value string) string {
	value = strings.TrimSpace(strings.Trim(value, "&'\""))
	value = filepath.Base(strings.ReplaceAll(value, `\`, `/`))
	value = strings.ToLower(value)
	return strings.TrimSuffix(value, ".exe")
}

func isPowerShellRemoveItem(name string) bool {
	switch name {
	case "remove-item", "ri", "rm", "del", "erase", "rmdir", "rd":
		return true
	default:
		return false
	}
}

func hasPowerShellSwitch(args []string, names ...string) bool {
	for _, arg := range args {
		arg = strings.ToLower(strings.TrimSpace(arg))
		if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
			continue
		}
		arg = strings.TrimPrefix(arg, "-")
		if name, enabled, found := strings.Cut(arg, ":"); found {
			switch enabled {
			case "$true", "true":
				arg = name
			case "$false", "false":
				continue
			default:
				continue
			}
		}
		for _, name := range names {
			if arg == name || strings.HasPrefix(name, arg) && len(arg) >= 2 {
				return true
			}
		}
	}
	return false
}

func hasWindowsSwitch(args []string, name string) bool {
	for _, arg := range args {
		if strings.EqualFold(strings.TrimSpace(arg), "/"+name) {
			return true
		}
	}
	return false
}

func isPowerShellWebRequest(name string) bool {
	switch name {
	case "invoke-webrequest", "iwr", "invoke-restmethod", "irm", "curl", "wget":
		return true
	default:
		return false
	}
}

func isPowerShellExpression(name string) bool {
	return name == "invoke-expression" || name == "iex"
}

func windowsPersistenceRegistryKey(args []string) bool {
	if len(args) < 2 || !strings.EqualFold(args[0], "add") {
		return false
	}
	key := args[1]
	key = strings.ToLower(strings.Trim(strings.ReplaceAll(key, `/`, `\`), "'\" "))
	aliases := []string{
		"hkey_current_user", "hkcu", "hkey_local_machine", "hklm",
	}
	validRoot := false
	for _, root := range aliases {
		if key == root || key == root+":" || strings.HasPrefix(key, root+`\`) || strings.HasPrefix(key, root+`:\`) {
			key = strings.TrimPrefix(key, root)
			key = strings.TrimPrefix(key, ":")
			validRoot = true
			break
		}
	}
	if !validRoot {
		return false
	}
	key = strings.Trim(key, `\`)
	if key == `software\microsoft\windows\currentversion\run` ||
		key == `software\microsoft\windows\currentversion\runonce` ||
		key == `software\wow6432node\microsoft\windows\currentversion\run` ||
		key == `software\wow6432node\microsoft\windows\currentversion\runonce` {
		return true
	}
	value := windowsRegistryValueName(args[2:])
	if key == `software\microsoft\windows nt\currentversion\winlogon` {
		return value == "shell" || value == "userinit"
	}
	if strings.HasPrefix(key, `system\currentcontrolset\services\`) {
		return value == "imagepath" || value == "servicedll"
	}
	return false
}

func windowsRegistryValueName(args []string) string {
	for i, arg := range args {
		lower := strings.ToLower(strings.TrimSpace(arg))
		if lower == "/v" && i+1 < len(args) {
			return strings.ToLower(strings.Trim(args[i+1], "'\" "))
		}
		if strings.HasPrefix(lower, "/v:") {
			return strings.Trim(strings.TrimPrefix(lower, "/v:"), "'\" ")
		}
	}
	return ""
}

func windowsCommandCanReadSensitivePath(name string) bool {
	switch name {
	case "get-content", "gc", "cat", "type", "more", "copy", "copy-item", "cp", "move", "move-item", "mv", "remove-item", "ri", "rm", "del", "erase", "findstr", "select-string", "certutil":
		return true
	default:
		return false
	}
}

func windowsSensitivePathFindings(text, toolName string, commandContext bool) []RuleFinding {
	tool := strings.ToLower(strings.TrimSpace(toolName))
	if !commandContext {
		switch tool {
		case "read", "read_file", "readfile", "write", "write_file", "writefile", "edit", "edit_file", "multiedit":
		default:
			return nil
		}
		text = windowsFileToolPathText(text)
		if text == "" {
			return nil
		}
	}
	n := strings.ToLower(strings.ReplaceAll(text, `/`, `\`))
	n = strings.ReplaceAll(n, `%userprofile%`, `__userprofile__`)
	n = strings.ReplaceAll(n, `$env:userprofile`, `__userprofile__`)
	n = strings.ReplaceAll(n, `%appdata%`, `__appdata__`)
	n = strings.ReplaceAll(n, `$env:appdata`, `__appdata__`)
	n = strings.ReplaceAll(n, `%localappdata%`, `__localappdata__`)
	n = strings.ReplaceAll(n, `$env:localappdata`, `__localappdata__`)
	n = strings.ReplaceAll(n, `%systemroot%`, `__systemroot__`)
	n = strings.ReplaceAll(n, `%windir%`, `__systemroot__`)
	n = strings.ReplaceAll(n, `$env:systemroot`, `__systemroot__`)
	n = strings.ReplaceAll(n, `$env:windir`, `__systemroot__`)

	seen := make(map[string]bool)
	var findings []RuleFinding
	for _, rule := range windowsSensitivePathRules {
		if !seen[rule.id] && rule.pattern.MatchString(n) {
			seen[rule.id] = true
			findings = append(findings, RuleFinding{
				RuleID: rule.id, Title: rule.title, Severity: rule.severity,
				Confidence: 0.96, Evidence: sanitizeEvidence(text),
				Tags: []string{"credential", "file-sensitive", "windows"},
			})
		}
	}
	return findings
}

type windowsPathRule struct {
	id, title, severity string
	pattern             *regexp.Regexp
}

const windowsPathBoundary = `[\s"',;\}\]\)]`
const windowsPathEnd = `(?:$|` + windowsPathBoundary + `)`
const windowsUserRoot = `(?:[a-z]:\\users\\[^\\"']+|__userprofile__)`
const windowsAppDataRoot = `(?:[a-z]:\\users\\[^\\"']+\\appdata\\(?:roaming|local)|__appdata__|__localappdata__)`
const windowsSystemRoot = `(?:[a-z]:\\windows|__systemroot__)`

var windowsSensitivePathRules = []windowsPathRule{
	{"PATH-WIN-SSH-KEY", "Windows SSH private key access", "CRITICAL", regexp.MustCompile(windowsUserRoot + `\\\.ssh\\id_(?:rsa|ed25519|ecdsa|dsa)` + windowsPathEnd)},
	{"PATH-WIN-AWS-CREDS", "Windows AWS credentials access", "CRITICAL", regexp.MustCompile(windowsUserRoot + `\\\.aws\\credentials` + windowsPathEnd)},
	{"PATH-WIN-KUBE-CONFIG", "Windows Kubernetes credentials access", "CRITICAL", regexp.MustCompile(windowsUserRoot + `\\\.kube\\config` + windowsPathEnd)},
	{"PATH-WIN-GIT-CREDS", "Windows Git credentials access", "CRITICAL", regexp.MustCompile(windowsUserRoot + `\\\.git-credentials` + windowsPathEnd)},
	{"PATH-WIN-NETRC", "Windows netrc credentials access", "CRITICAL", regexp.MustCompile(windowsUserRoot + `\\_netrc` + windowsPathEnd)},
	{"PATH-WIN-CREDENTIAL-MANAGER", "Windows Credential Manager store access", "CRITICAL", regexp.MustCompile(windowsAppDataRoot + `\\microsoft\\credentials(?:\\|$|` + windowsPathBoundary + `)`)},
	{"PATH-WIN-DPAPI", "Windows DPAPI key store access", "CRITICAL", regexp.MustCompile(windowsAppDataRoot + `\\microsoft\\protect(?:\\|$|` + windowsPathBoundary + `)`)},
	{"PATH-WIN-PS-HISTORY", "PowerShell command history access", "CRITICAL", regexp.MustCompile(windowsAppDataRoot + `\\microsoft\\windows\\powershell\\psreadline\\consolehost_history\.txt` + windowsPathEnd)},
	{"PATH-WIN-SAM", "Windows SAM registry hive access", "CRITICAL", regexp.MustCompile(windowsSystemRoot + `\\system32\\config\\sam` + windowsPathEnd)},
	{"PATH-WIN-SECURITY-HIVE", "Windows SECURITY registry hive access", "CRITICAL", regexp.MustCompile(windowsSystemRoot + `\\system32\\config\\security` + windowsPathEnd)},
	{"PATH-WIN-SYSTEM-HIVE", "Windows SYSTEM registry hive access", "CRITICAL", regexp.MustCompile(windowsSystemRoot + `\\system32\\config\\system` + windowsPathEnd)},
}

func windowsFileToolPathText(text string) string {
	var object map[string]interface{}
	if json.Unmarshal([]byte(text), &object) != nil {
		return strings.TrimSpace(text)
	}
	var paths []string
	for _, key := range []string{"path", "file_path", "filePath", "source_path", "sourcePath", "destination_path", "destinationPath"} {
		if value, ok := object[key].(string); ok && strings.TrimSpace(value) != "" {
			paths = append(paths, value)
		}
	}
	return strings.Join(paths, "\n")
}
