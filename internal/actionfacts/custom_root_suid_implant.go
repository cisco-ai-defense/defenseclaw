// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const customRootSUIDMaxSourceBytes = 8 << 10

var (
	customRootSUIDHeredoc   = regexp.MustCompile(`^cat[ \t]+>[ \t]*([^ \t]+)[ \t]+<<'([A-Za-z][A-Za-z0-9_]{0,31})'$`)
	customRootSUIDCompile   = regexp.MustCompile(`^(?:cc|gcc)[ \t]+([^ \t]+)[ \t]+-o[ \t]+([^ \t]+)$`)
	customRootSUIDChown     = regexp.MustCompile(`^chown[ \t]+(?:root:root|0:0)[ \t]+([^ \t]+)$`)
	customRootSUIDChmod     = regexp.MustCompile(`^chmod[ \t]+(0?[0-7]{3,4})[ \t]+([^ \t]+)$`)
	customRootSUIDList      = regexp.MustCompile(`^ls[ \t]+-l[ \t]+([^ \t]+)$`)
	customRootSUIDRun       = regexp.MustCompile(`^su[ \t]+-[ \t]+[A-Za-z_][A-Za-z0-9_-]{0,31}[ \t]+-c[ \t]+'([^']+)'$`)
	customRootSUIDMain      = regexp.MustCompile(`\b(?:int|signed)[ \t\n]+main[ \t\n]*\([^)]*\)[ \t\n]*\{`)
	customRootSUIDSetUID    = regexp.MustCompile(`\bsetuid[ \t\n]*\([ \t\n]*0[ \t\n]*\)`)
	customRootSUIDSetRUID   = regexp.MustCompile(`\bsetresuid[ \t\n]*\([ \t\n]*0[ \t\n]*,[ \t\n]*0[ \t\n]*,[ \t\n]*0[ \t\n]*\)`)
	customRootSUIDInclude   = regexp.MustCompile(`^#include[ \t]+[<][A-Za-z0-9_./]+[>]$`)
	customRootSUIDIncludes  = regexp.MustCompile(`(?m)^[ \t]*#include[^\n]*$`)
	customRootSUIDReturn    = regexp.MustCompile(`\breturn\b`)
	customRootSUIDForbidden = regexp.MustCompile(`\b(?:if|for|while|switch|goto|sizeof|_generic|exit|_exit|abort|longjmp)\b`)
)

// ExactCustomRootSUIDImplant reports a value-free proof for one closed
// same-action grammar. A chmod alone is never sufficient: the proof requires
// literal C source with an effective root transition, compilation from that
// exact source to X, root ownership of X, and a setuid executable mode on X.
func ExactCustomRootSUIDImplant(facts Facts) bool {
	return len(facts.CustomRootSUIDImplants) == 1
}

func projectCustomRootSUIDImplants(input Input) []CustomRootSUIDImplantFact {
	command, ok := exactCustomRootSUIDCommandInput(input)
	if !ok || !exactCustomRootSUIDScript(command) {
		return nil
	}
	return []CustomRootSUIDImplantFact{{}}
}

func exactCustomRootSUIDCommandInput(input Input) (string, bool) {
	if input.Tool != "bash_command" || len(input.Argv) != 0 || len(input.Args) == 0 ||
		len(input.Args) > maxArgsJSONBytes || !utf8.Valid(input.Args) {
		return "", false
	}
	var object struct {
		Keystrokes string       `json:"keystrokes"`
		Duration   *json.Number `json:"duration,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(input.Args))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object.Keystrokes == "" {
		return "", false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return "", false
	}
	if object.Duration != nil {
		duration, err := strconv.ParseFloat(string(*object.Duration), 64)
		if err != nil || duration < 0 || duration > 3600 {
			return "", false
		}
	}
	if input.Command != "" && input.Command != object.Keystrokes {
		return "", false
	}
	return object.Keystrokes, true
}

func exactCustomRootSUIDScript(command string) bool {
	if len(command) > customRootSUIDMaxSourceBytes || !utf8.ValidString(command) ||
		strings.ContainsAny(command, "\r\x00") || !strings.HasSuffix(command, "\n") {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(command, "\n"), "\n")
	if len(lines) < 4 || len(lines) > 96 {
		return false
	}
	opener := customRootSUIDHeredoc.FindStringSubmatch(lines[0])
	if len(opener) != 3 || !exactCustomRootSUIDPath(opener[1]) ||
		path.Ext(opener[1]) != ".c" {
		return false
	}
	end := -1
	for index := 1; index < len(lines); index++ {
		if lines[index] == opener[2] {
			end = index
			break
		}
	}
	if end < 2 || end+1 >= len(lines) {
		return false
	}
	source := strings.Join(lines[1:end], "\n")
	if len(source) > customRootSUIDMaxSourceBytes || !effectiveRootUIDCSource(source) {
		return false
	}
	components := strings.Split(lines[end+1], " && ")
	if len(components) != 3 && len(components) != 4 {
		return false
	}
	compile := customRootSUIDCompile.FindStringSubmatch(components[0])
	owner := customRootSUIDChown.FindStringSubmatch(components[1])
	mode := customRootSUIDChmod.FindStringSubmatch(components[2])
	if len(compile) != 3 || len(owner) != 2 || len(mode) != 3 ||
		compile[1] != opener[1] || !exactCustomRootSUIDPath(compile[2]) ||
		owner[1] != compile[2] || mode[2] != compile[2] ||
		!exactRootSUIDExecutableMode(mode[1]) {
		return false
	}
	if len(components) == 4 {
		listed := customRootSUIDList.FindStringSubmatch(components[3])
		if len(listed) != 2 || listed[1] != compile[2] {
			return false
		}
	}
	if len(lines) == end+2 {
		return true
	}
	if len(lines) != end+3 {
		return false
	}
	run := customRootSUIDRun.FindStringSubmatch(lines[end+2])
	return len(run) == 2 && run[1] == compile[2]
}

func exactCustomRootSUIDPath(value string) bool {
	return staticAbsolutePOSIXPath(value) && path.Clean(value) == value &&
		value != "/" && !strings.ContainsAny(value, " \t$`*?[]{};|&<>()\\\"")
}

func exactRootSUIDExecutableMode(value string) bool {
	mode, err := strconv.ParseUint(value, 8, 16)
	return err == nil && mode&04000 != 0 && mode&0111 != 0
}

// effectiveRootUIDCSource accepts a deliberately small C subset. It removes
// comments and literals, permits only include directives, requires one main
// body without nested blocks or control flow, and requires the root transition
// before return. This excludes comments, strings, disabled preprocessor code,
// dead branches, short-circuit expressions, and helper functions.
func effectiveRootUIDCSource(source string) bool {
	stripped, ok := stripCustomRootSUIDC(source)
	if !ok {
		return false
	}
	for _, line := range strings.Split(stripped, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") &&
			!customRootSUIDInclude.MatchString(trimmed) {
			return false
		}
	}
	code := customRootSUIDIncludes.ReplaceAllString(stripped, "")
	main := customRootSUIDMain.FindStringIndex(code)
	if main == nil || strings.TrimSpace(code[:main[0]]) != "" {
		return false
	}
	body := code[main[1]:]
	if strings.Count(body, "{") != 0 || strings.Count(body, "}") != 1 {
		return false
	}
	close := strings.LastIndex(body, "}")
	if close < 0 || strings.TrimSpace(body[close+1:]) != "" {
		return false
	}
	body = body[:close]
	lower := strings.ToLower(body)
	if customRootSUIDForbidden.MatchString(lower) {
		return false
	}
	if strings.Contains(body, "&&") || strings.Contains(body, "||") ||
		strings.Contains(body, "?") {
		return false
	}
	transition := customRootSUIDSetUID.FindStringIndex(body)
	if transition == nil {
		transition = customRootSUIDSetRUID.FindStringIndex(body)
	}
	if transition == nil {
		return false
	}
	if returned := customRootSUIDReturn.FindStringIndex(body); returned != nil &&
		returned[0] < transition[0] {
		return false
	}
	return true
}

func stripCustomRootSUIDC(source string) (string, bool) {
	var out strings.Builder
	out.Grow(len(source))
	for index := 0; index < len(source); {
		switch {
		case index+1 < len(source) && source[index:index+2] == "//":
			end := strings.IndexByte(source[index+2:], '\n')
			if end < 0 {
				out.WriteString(strings.Repeat(" ", len(source)-index))
				return out.String(), true
			}
			end += index + 2
			out.WriteString(strings.Repeat(" ", end-index))
			index = end
		case index+1 < len(source) && source[index:index+2] == "/*":
			end := strings.Index(source[index+2:], "*/")
			if end < 0 {
				return "", false
			}
			end += index + 4
			for _, character := range source[index:end] {
				if character == '\n' {
					out.WriteByte('\n')
				} else {
					out.WriteByte(' ')
				}
			}
			index = end
		case source[index] == '\'' || source[index] == '"':
			quote := source[index]
			out.WriteByte(' ')
			index++
			closed := false
			for index < len(source) {
				if source[index] == '\n' {
					return "", false
				}
				if source[index] == '\\' {
					if index+1 >= len(source) {
						return "", false
					}
					out.WriteString("  ")
					index += 2
					continue
				}
				out.WriteByte(' ')
				if source[index] == quote {
					index++
					closed = true
					break
				}
				index++
			}
			if !closed {
				return "", false
			}
		default:
			out.WriteByte(source[index])
			index++
		}
	}
	return out.String(), true
}
