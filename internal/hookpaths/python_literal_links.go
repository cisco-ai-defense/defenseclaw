// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
	"mvdan.cc/sh/v3/syntax"
)

var (
	// pythonLiteralLinkCall is one os.link or os.symlink call of inline
	// Python code whose two arguments are plain string literals.
	pythonLiteralLinkCall = lazyregexp.New(`\bos\.(sym)?link\(\s*(?:'([^'"\\\n]*)'|"([^'"\\\n]*)")\s*,\s*(?:'([^'"\\\n]*)'|"([^'"\\\n]*)")\s*\)`)
	// pythonImportsOS is the plain import os statement that makes os the
	// os module.
	pythonImportsOS     = lazyregexp.New(`(?:^|[;\n])[ \t]*import[ \t]+os[ \t]*(?:[;\n]|$)`)
	pythonProgramName   = regexp.MustCompile(`^python(?:3(?:\.[0-9]+)?)?$`)
	pythonInlineOptions = map[string]bool{"-I": true, "-E": true, "-s": true, "-S": true, "-B": true, "-u": true, "-q": true}
)

// addPythonLiteralLinks reads the link text of a command whose only link
// API calls are os.link or os.symlink calls with two string literals, in the
// -c code of a top-level python call that imports os, in a command that does
// not change directory. Each call makes the link that link or ln -s makes
// from the same two operands, so it is recorded as they record it, and a
// write through the new name is judged by the file it names: a project file
// stays an ordinary write, the keys file a protected one
// (rel-1-0-6:GAP-0157). It reports false, and records nothing, for any other
// link text (a computed argument, another link API, a chdir), which keeps the
// opaque reading.
func (l *shellLinks) addPythonLiteralLinks(file *syntax.File, command, cwd, home string) bool {
	if !filepath.IsAbs(cwd) || home == "" || tactics.RunsProgram(command, cdPrograms...) {
		return false
	}
	type literalLink struct {
		source, name string
		symbolic     bool
	}
	var found []literalLink
	var codeWords []*syntax.Word
	for _, stmt := range file.Stmts {
		syntax.Walk(stmt, func(node syntax.Node) bool {
			call, ok := node.(*syntax.CallExpr)
			if !ok || len(call.Args) < 3 || len(call.Assigns) != 0 {
				return true
			}
			program, static := staticProgramWord(call.Args[0], home)
			if !static || !pythonProgramName.MatchString(programBase(program)) {
				return true
			}
			last := len(call.Args) - 1
			for _, option := range call.Args[1 : last-1] {
				if value, static := StaticWord(option, home); !static || !pythonInlineOptions[value] {
					return true
				}
			}
			if option, static := StaticWord(call.Args[last-1], home); !static || option != "-c" {
				return true
			}
			code, static := StaticWord(call.Args[last], home)
			if !static || !opaqueLink.MatchString(code) || !pythonImportsOS.MatchString(code) || strings.Contains(code, "chdir") {
				return true
			}
			rest := pythonLiteralLinkCall.ReplaceAllString(code, " ")
			if opaqueLink.MatchString(rest) {
				return true
			}
			for _, match := range pythonLiteralLinkCall.FindAllStringSubmatch(code, -1) {
				found = append(found, literalLink{source: match[2] + match[3], name: match[4] + match[5], symbolic: match[1] != ""})
			}
			codeWords = append(codeWords, call.Args[last])
			return true
		})
	}
	if len(found) == 0 || opaqueLinkText(file, actionBlankWords(command, codeWords), home) {
		return false
	}
	for _, link := range found {
		if link.source == "" || link.name == "" {
			return false
		}
	}
	for _, link := range found {
		l.record(link.source, link.name, link.symbolic, link.symbolic, cwd)
	}
	return true
}
