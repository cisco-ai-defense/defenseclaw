// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type knownLinkTextEdit struct {
	start, end  int
	replacement string
}

// resolveKnownShellLinkTargets substitutes only bounded command substitutions
// in a top-level ln target whose values are determined by the event cwd or a
// literal printf format. The normalized command then goes through the normal
// link resolver, which proves whether the later write reaches a protected
// file.
func resolveKnownShellLinkTargets(file *syntax.File, command, cwd, home string) (string, bool) {
	if file == nil || !filepath.IsAbs(cwd) {
		return "", false
	}
	var edits []knownLinkTextEdit
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 3 || len(call.Assigns) != 0 {
			return true
		}
		program, static := StaticWord(call.Args[0], home)
		if !static || programBase(program) != "ln" {
			return true
		}
		option, static := StaticWord(call.Args[1], home)
		if !static || option != "-s" && option != "-sf" {
			return true
		}
		target := call.Args[2]
		start, end := int(target.Pos().Offset()), int(target.End().Offset())
		if start < 0 || end <= start || end > len(command) {
			return true
		}
		raw := command[start:end]
		if !strings.Contains(raw, "$(") {
			return true
		}
		callStart := int(call.Pos().Offset())
		if callStart < 0 || callStart > len(command) || strings.TrimSpace(command[:callStart]) != "" {
			return true
		}
		value, resolved := knownLinkShellWord(raw, home)
		if !resolved {
			return true
		}
		edits = append(edits, knownLinkTextEdit{start: start, end: end, replacement: shellQuoteLinkWord(value)})
		return true
	})
	if len(edits) == 0 {
		return "", false
	}
	for i := 1; i < len(edits); i++ {
		for j := i; j > 0 && edits[j].start > edits[j-1].start; j-- {
			edits[j], edits[j-1] = edits[j-1], edits[j]
		}
	}
	var out strings.Builder
	cursor := 0
	for _, edit := range edits {
		if edit.start < cursor || edit.end > len(command) {
			return "", false
		}
		out.WriteString(command[cursor:edit.start])
		out.WriteString(edit.replacement)
		cursor = edit.end
	}
	out.WriteString(command[cursor:])
	return out.String(), true
}

func knownLinkShellWord(raw, home string) (string, bool) {
	word := raw
	if len(word) >= 2 && word[0] == '"' && word[len(word)-1] == '"' {
		word = word[1 : len(word)-1]
	} else if strings.ContainsAny(word, "'") {
		return "", false
	}
	var out strings.Builder
	for len(word) > 0 {
		at := strings.Index(word, "$(")
		if at < 0 {
			if strings.ContainsAny(word, "$`") {
				return "", false
			}
			out.WriteString(word)
			break
		}
		out.WriteString(word[:at])
		rest := word[at+2:]
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			return "", false
		}
		value, ok := knownLinkSubstitution(rest[:end], home)
		if !ok {
			return "", false
		}
		out.WriteString(value)
		word = rest[end+1:]
	}
	value := out.String()
	if value == "" || strings.ContainsAny(value, "*?[") {
		return "", false
	}
	return value, true
}

func knownLinkSubstitution(body, home string) (string, bool) {
	if strings.Join(strings.Fields(body), "") == "cd;pwd" {
		return filepath.Clean(home), filepath.IsAbs(home)
	}
	fields := strings.Fields(body)
	if len(fields) != 2 || fields[0] != "printf" {
		return "", false
	}
	format := fields[1]
	if len(format) < 2 || (format[0] != '\'' && format[0] != '"') || format[len(format)-1] != format[0] {
		return "", false
	}
	format = format[1 : len(format)-1]
	if strings.Contains(format, "%") {
		return "", false
	}
	var out strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '\\' {
			out.WriteByte(format[i])
			continue
		}
		if i+3 >= len(format) || format[i+1] != 'x' {
			return "", false
		}
		value, err := strconv.ParseUint(format[i+2:i+4], 16, 8)
		if err != nil {
			return "", false
		}
		out.WriteByte(byte(value))
		i += 3
	}
	return out.String(), true
}

func shellQuoteLinkWord(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
