// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// actionLiteralIndirectPrivateKeyRead binds only paths written in this command.
// A producer's literal path can reach a pipe reader, and a literal assignment
// or Join-Path can reach a later reader. Evaluated or decoded command text is
// deliberately outside this proof.
func actionLiteralIndirectPrivateKeyRead(command, cwd, home string, dialect actionfacts.Dialect) bool {
	if len(command) > MaxPayloadBytes || strings.Contains(command, "<<") {
		return false
	}
	lower := strings.ToLower(command)
	if !strings.ContainsAny(command, "|=") && !strings.Contains(lower, "join-path") &&
		!strings.Contains(lower, "foreach") && !strings.Contains(lower, "new-psdrive") {
		return false
	}
	if !strings.Contains(lower, "cat") && !strings.Contains(lower, "content") &&
		!strings.Contains(lower, "gc") && !strings.Contains(lower, "type") &&
		!strings.Contains(lower, "head") && !strings.Contains(lower, "tail") &&
		!strings.Contains(lower, "base64") && !strings.Contains(lower, "new-psdrive") {
		return false
	}
	mode := keyReadMode(0)
	if actionWindowsHome(home) {
		mode = keyReadWindows
	}
	for _, grammar := range []actionWindowsGrammar{actionWindowsLiteralDollar, actionWindowsPlainGrammar | actionWindowsLiteralDollar} {
		scan := actionWindowsScan(command, grammar)
		if !scan.ok {
			continue
		}
		values := map[string]string{}
		drives := map[string]string{}
		var producer string
		previousPipe := false
		for start := 0; start < len(scan.words); {
			end := start
			for end < len(scan.words) && !actionIndirectSeparator(scan.words[end]) {
				end++
			}
			words := append([]string(nil), scan.words[start:end]...)
			if len(words) > 0 {
				if name, root, ok := actionIndirectPSDrive(words, values, cwd, home); ok {
					drives[name] = root
				}
				if actionIndirectForeachRead(words, values, cwd, home, mode) {
					return true
				}
				if name, rhs, ok := actionIndirectAssignment(words); ok {
					delete(values, name)
					if value, known := actionIndirectValue(rhs, values, cwd, home); known {
						values[name] = value
					}
				} else {
					words = actionIndirectJoinWords(words, values, cwd, home)
					for i, word := range words {
						if value, ok := actionIndirectDrivePath(word, drives); ok {
							if strings.HasPrefix(word, "${") &&
								actionPrivateKeyReadWords([]string{"cat", value}, cwd, home, mode, 0) {
								return true
							}
							word = value
						}
						if value, ok := actionIndirectValue([]string{word}, values, cwd, home); ok {
							words[i] = value
						}
						if dialect == actionfacts.DialectPowerShell && mode&keyReadWindows == 0 {
							words[i] = strings.ReplaceAll(words[i], `\`, "/")
						}
					}
					if previousPipe && producer != "" && actionIndirectConsumerReads(words, producer, cwd, home, mode, dialect) {
						return true
					}
					if actionPrivateKeyReadWords(actionWindowsReaderWords(words), cwd, home, mode, 0) {
						return true
					}
					producer = actionIndirectProducer(words, cwd, home)
				}
			}
			previousPipe = end < len(scan.words) && scan.words[end] == "|"
			if !previousPipe {
				producer = ""
			}
			start = end + 1
		}
	}
	return false
}

func actionIndirectPSDrive(words []string, values map[string]string, cwd, home string) (string, string, bool) {
	if len(words) < 7 || !strings.EqualFold(words[0], "New-PSDrive") {
		return "", "", false
	}
	fields := map[string]string{}
	for i := 1; i+1 < len(words); i++ {
		if strings.HasPrefix(words[i], "-") {
			fields[strings.ToLower(words[i])] = words[i+1]
			i++
		}
	}
	if !strings.EqualFold(fields["-psprovider"], "FileSystem") || len(fields["-name"]) != 1 {
		return "", "", false
	}
	root, ok := actionIndirectValue([]string{fields["-root"]}, values, cwd, home)
	if !ok {
		return "", "", false
	}
	return strings.ToLower(fields["-name"]), root, true
}

func actionIndirectDrivePath(word string, drives map[string]string) (string, bool) {
	pathWord := strings.TrimSuffix(strings.TrimPrefix(word, "${"), "}")
	if len(pathWord) < 3 || pathWord[1] != ':' || pathWord[2] != '/' && pathWord[2] != '\\' {
		return "", false
	}
	root, ok := drives[strings.ToLower(pathWord[:1])]
	if !ok {
		return "", false
	}
	return strings.TrimRight(root, `/\`) + "/" + strings.TrimLeft(strings.ReplaceAll(pathWord[2:], `\`, "/"), "/"), true
}

func actionIndirectSeparator(word string) bool {
	switch word {
	case ";", "|", "||", "&", "&&":
		return true
	}
	return false
}

func actionIndirectAssignment(words []string) (string, []string, bool) {
	if len(words) >= 3 && words[1] == "=" {
		if name := actionIndirectName(words[0]); name != "" {
			return name, words[2:], true
		}
	}
	if len(words) == 1 {
		if eq := strings.IndexByte(words[0], '='); eq > 0 {
			if name := actionIndirectName(words[0][:eq]); name != "" {
				return name, []string{words[0][eq+1:]}, true
			}
		}
	}
	return "", nil, false
}

func actionIndirectName(word string) string {
	word = strings.TrimPrefix(word, "$")
	word = strings.Trim(word, "{}")
	if !actionShellName(word) {
		return ""
	}
	return strings.ToLower(word)
}

func actionIndirectValue(words []string, values map[string]string, cwd, home string) (string, bool) {
	if len(words) == 4 && strings.EqualFold(words[0], "Join-Path") && words[2] == "-ChildPath" {
		words = []string{words[0], words[1], words[3]}
	}
	if len(words) == 3 && strings.EqualFold(words[0], "Join-Path") {
		parent, ok1 := actionIndirectValue(words[1:2], values, cwd, home)
		child, ok2 := actionIndirectValue(words[2:3], values, cwd, home)
		if ok1 && ok2 && !strings.HasPrefix(child, "/") && !actionWindowsHome(child) {
			return path.Clean(strings.TrimRight(parent, "/") + "/" + child), true
		}
		return "", false
	}
	if len(words) != 1 {
		return "", false
	}
	value := strings.Trim(words[0], "()")
	if value == "" || strings.ContainsAny(value, "\x00\r\n`\"'") {
		return "", false
	}
	if name := strings.TrimPrefix(value, "$"); name != value {
		name = strings.Trim(name, "{}")
		if bound, ok := values[strings.ToLower(name)]; ok {
			return bound, true
		}
	}
	for _, prefix := range []string{"$HOME", "${HOME}", "$home", "${home}"} {
		if value == prefix || strings.HasPrefix(value, prefix+"/") || strings.HasPrefix(value, prefix+`\`) {
			return home + value[len(prefix):], true
		}
	}
	if strings.ContainsAny(value, "$%") {
		return "", false
	}
	if strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		return home + value[1:], true
	}
	return value, true
}

func actionIndirectJoinWords(words []string, values map[string]string, cwd, home string) []string {
	for i := 0; i+2 < len(words); i++ {
		if !strings.EqualFold(strings.TrimPrefix(words[i], "("), "Join-Path") {
			continue
		}
		if value, ok := actionIndirectValue([]string{"Join-Path", words[i+1], strings.TrimSuffix(words[i+2], ")")}, values, cwd, home); ok {
			words = append(words[:i], append([]string{value}, words[i+3:]...)...)
		}
	}
	return words
}

func actionIndirectProducer(words []string, cwd, home string) string {
	if len(words) < 2 {
		return ""
	}
	switch programBase(words[0]) {
	case "ls", "get-childitem", "gci", "dir":
		for _, word := range words[1:] {
			if !strings.HasPrefix(word, "-") && word != "" {
				return word
			}
		}
	}
	return ""
}

func actionIndirectConsumerReads(words []string, source, cwd, home string, mode keyReadMode, dialect actionfacts.Dialect) bool {
	if dialect == actionfacts.DialectPowerShell && mode&keyReadWindows == 0 {
		source = strings.ReplaceAll(source, `\`, "/")
	}
	if !actionPrivateKeyReadWords([]string{"cat", source}, cwd, home, mode, 0) {
		return false
	}
	if len(words) == 0 {
		return false
	}
	switch programBase(words[0]) {
	case "get-content", "gc":
		return actionIndirectBarePSReader(words)
	case "cat", "type":
		return dialect == actionfacts.DialectPowerShell && actionIndirectBarePSReader(words)
	case "xargs":
		for _, word := range words[1:] {
			if strings.HasPrefix(word, "-") || word == "1" {
				continue
			}
			return actionPrivateKeyReadWords([]string{word, source}, cwd, home, mode, 0)
		}
	case "foreach-object", "%":
		for i := 1; i+1 < len(words); i++ {
			if actionPrivateKeyReadWords([]string{words[i], source}, cwd, home, mode, 0) &&
				strings.Trim(words[i+1], "{}") == "$_" {
				return true
			}
		}
	}
	return false
}

// A PowerShell content reader accepts pipeline paths when it has no explicit
// path operand. Only options that do not supply a path are set aside here.
func actionIndirectBarePSReader(words []string) bool {
	for i := 1; i < len(words); i++ {
		switch strings.ToLower(words[i]) {
		case "-raw", "-force", "-wait":
		case "-encoding", "-readcount", "-totalcount", "-tail", "-stream", "-delimiter", "-erroraction":
			i++
			if i >= len(words) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func actionIndirectForeachRead(words []string, values map[string]string, cwd, home string, mode keyReadMode) bool {
	if len(words) < 8 || !strings.EqualFold(words[0], "foreach") || !strings.EqualFold(words[2], "in") {
		return false
	}
	name := actionIndirectName(strings.TrimPrefix(words[1], "("))
	if name == "" {
		return false
	}
	for i := 3; i+1 < len(words); i++ {
		if !strings.EqualFold(words[i], "Get-ChildItem") && !strings.EqualFold(words[i], "gci") && words[i] != "ls" {
			continue
		}
		path, ok := actionIndirectValue([]string{strings.TrimSuffix(words[i+1], ")")}, values, cwd, home)
		if !ok {
			return false
		}
		for j := i + 2; j+1 < len(words); j++ {
			if strings.Trim(words[j+1], "{}") == "$"+name &&
				actionPrivateKeyReadWords([]string{words[j], path}, cwd, home, mode, 0) {
				return true
			}
		}
	}
	return false
}
