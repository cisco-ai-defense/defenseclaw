// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// The mention scan follows the same effective working directory the shell
// uses for later words. A physical directory is retained so a symlink into
// .ssh cannot hide a relative protected name.
func actionPosixAdvanceDirectory(call *syntax.CallExpr, values actionValues, home string, cwd *string, stack *[]string) {
	if len(call.Args) == 0 {
		return
	}
	program, known := actionWordValue(call.Args[0], values, *cwd, home)
	if !known {
		return
	}
	switch programBase(program) {
	case "popd":
		if len(*stack) == 0 {
			return
		}
		*cwd = (*stack)[len(*stack)-1]
		*stack = (*stack)[:len(*stack)-1]
		return
	case "cd", "pushd":
	default:
		return
	}
	index := 1
	if index < len(call.Args) {
		if option, fixed := StaticWord(call.Args[index], home); fixed && option == "--" {
			index++
		}
	}
	if len(call.Args)-index > 1 {
		return
	}
	destination := home
	if index < len(call.Args) {
		var fixed bool
		destination, fixed = actionWordValue(call.Args[index], values, *cwd, home)
		if !fixed || destination == "" {
			return
		}
	}
	if programBase(program) == "pushd" {
		*stack = append(*stack, *cwd)
	}
	if actionPosixWindowsHome(home) {
		*cwd = actionPosixWindowsPath(destination, *cwd, home)
		return
	}
	if resolved, ok := ResolveWriteTarget(OperandPath(destination, *cwd)); ok {
		*cwd = resolved
	} else {
		*cwd = filepath.Clean(OperandPath(destination, *cwd))
	}
}

// An unresolved fragment is target-bearing only when the surrounding syntax
// or current directory puts its possible expansion in the protected class.
// This keeps ordinary project variables out of the protected-target rule.
func actionUnknownWordMayNameKey(word *syntax.Word, cwd, home string) bool {
	if word == nil {
		return false
	}
	var raw strings.Builder
	if syntax.NewPrinter().Print(&raw, word) != nil {
		return false
	}
	value := raw.String()
	if actionWordMaySelectKeyName(word, actionPosixWindowsHome(home)) {
		return true
	}
	if !strings.ContainsAny(value, "$`*?[") {
		return false
	}
	if actionPosixWindowsHome(home) {
		return path.Clean(cwd) == path.Join(home, ".ssh")
	}
	ssh, sshKnown := ResolveWriteTarget(filepath.Join(home, ".ssh"))
	current, cwdKnown := ResolveWriteTarget(cwd)
	return sshKnown && cwdKnown && samePathName(current, ssh) &&
		strings.ContainsAny(value, "$`*?[")
}

func actionWindowsAdvanceDirectory(words []string, home string, cwd *string, stack *[]string) {
	if len(words) == 0 {
		return
	}
	program := strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(words[0], `\`, "/"))), ".exe")
	switch program {
	case "popd", "pop-location":
		if len(*stack) != 0 {
			*cwd = (*stack)[len(*stack)-1]
			*stack = (*stack)[:len(*stack)-1]
		}
		return
	case "cd", "pushd", "set-location", "push-location":
	default:
		return
	}
	index := 1
	if index < len(words) {
		option := strings.ToLower(words[index])
		if option == "--" || option == "-path" || option == "-literalpath" {
			index++
		}
	}
	if len(words)-index > 1 {
		return
	}
	destination := home
	if index < len(words) {
		destination = words[index]
	}
	resolved, known := actionWindowsPath(destination, *cwd, home)
	if !known {
		return
	}
	if program == "pushd" || program == "push-location" {
		*stack = append(*stack, *cwd)
	}
	*cwd = resolved
}

func actionReadOptionMayWrite(option string) bool {
	option = strings.ToLower(option)
	for _, prefix := range []string{"--output", "--out-file", "--outfile", "--log-file", "--in-place", "-output", "-outfile", "-filepath", "-logfile", "-inplace"} {
		if strings.HasPrefix(option, prefix) {
			return true
		}
	}
	return false
}

// An unresolved word names a key file only through a complete path
// component: a literal component equal to a key file name, or a component
// whose unquoted globs or dynamic parts can expand to one. A longer literal
// name that merely contains a key name (authorized_keys.bak) names another
// file and stays audit evidence. A subexpression body that computes the
// component is scanned for a complete key name.
func actionWordMaySelectKeyName(word *syntax.Word, fold bool) bool {
	var component actionKeyComponent
	hit := false
	const (
		unquoted = iota
		doubleQuoted
		singleQuoted
	)
	text := func(value string, mode int) {
		for i := 0; i < len(value) && !hit; i++ {
			c := value[i]
			switch {
			case c == '/':
				hit = component.selects(fold)
				component = actionKeyComponent{}
			case mode == unquoted && c == '\\' && i+1 < len(value):
				i++
				component.literal(value[i])
			case mode == doubleQuoted && c == '\\' && i+1 < len(value) && strings.IndexByte("$`\"\\", value[i+1]) >= 0:
				i++
				component.literal(value[i])
			case mode == unquoted && (c == '*' || c == '?'):
				component.wildcard(string(c))
			case mode == unquoted && c == '[':
				if end := strings.IndexByte(value[i+1:], ']'); end > 0 {
					component.wildcard(value[i : i+end+2])
					i += end + 1
				} else {
					component.literal(c)
				}
			default:
				component.literal(c)
			}
		}
	}
	var parts func([]syntax.WordPart, int)
	parts = func(items []syntax.WordPart, mode int) {
		for _, item := range items {
			if hit {
				return
			}
			switch part := item.(type) {
			case *syntax.Lit:
				text(part.Value, mode)
			case *syntax.SglQuoted:
				text(part.Value, singleQuoted)
			case *syntax.DblQuoted:
				parts(part.Parts, doubleQuoted)
			default:
				component.wildcard("*")
				hit = actionNestedTextNamesKey(item, fold)
			}
		}
	}
	parts(word.Parts, unquoted)
	return hit || component.selects(fold)
}

// actionKeyComponent is one path component as a path.Match pattern.
type actionKeyComponent struct {
	pattern      strings.Builder
	run, longest int
	hasWildcard  bool
}

func (c *actionKeyComponent) literal(b byte) {
	if strings.IndexByte(`*?[\`, b) >= 0 {
		c.pattern.WriteByte('\\')
	}
	c.pattern.WriteByte(b)
	c.run++
	c.longest = max(c.longest, c.run)
}

func (c *actionKeyComponent) wildcard(pattern string) {
	c.pattern.WriteString(pattern)
	c.run, c.hasWildcard = 0, true
}

// A wildcard component needs a literal run of four or more characters: a
// bare "$name" or "${x}s" could expand to any file and stays audit evidence.
func (c *actionKeyComponent) selects(fold bool) bool {
	pattern := c.pattern.String()
	if pattern == "" || c.hasWildcard && c.longest < 4 {
		return false
	}
	if fold {
		pattern = strings.ToLower(pattern)
	}
	for _, name := range AuthorizedKeysFiles {
		if matched, err := path.Match(pattern, name); err == nil && matched {
			return true
		}
	}
	return false
}

var actionNestedToken = regexp.MustCompile(`[A-Za-z0-9_.*?\[\]]+`)

func actionNestedTextNamesKey(node syntax.Node, fold bool) bool {
	var raw strings.Builder
	if syntax.NewPrinter().Print(&raw, node) != nil {
		return false
	}
	for _, token := range actionNestedToken.FindAllString(raw.String(), -1) {
		var component actionKeyComponent
		for i := 0; i < len(token); i++ {
			switch token[i] {
			case '*', '?':
				component.wildcard(token[i : i+1])
			default:
				component.literal(token[i])
			}
		}
		if component.selects(fold) {
			return true
		}
	}
	return false
}
