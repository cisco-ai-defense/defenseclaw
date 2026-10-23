// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A makefile is read whole, so it gets a larger bound than a sourced script:
// ordinary build files often pass the 16 KiB indirect-source limit. A call
// reads at most maxMakeFiles makefiles, includes counted.
const (
	maxMakeSourceBytes int64 = 8 << 20
	maxMakeFiles             = 64
	maxMakeReachFields       = 128
)

var makeWindowsToken = regexp.MustCompile(`[^\s'"<>|;&()=,]+`)

var makeVariableDefinition = regexp.MustCompile(`^(?:override\s+|export\s+)?([A-Za-z_.][A-Za-z0-9_.]*)\s*(?:::=|:=|\?=|\+=|!=|=)\s*(.*)$`)

func actionMakeProgram(word string) bool {
	program := programBase(word)
	return program == "make" || program == "gmake"
}

// actionMakeAssignments returns the NAME=value words a shell puts in the
// environment of one call. A value the hook cannot expand becomes "$", so a
// computed MAKEFILES or MAKEFLAGS stays unresolved.
func actionMakeAssignments(stmt *syntax.Stmt, home string) []string {
	if stmt == nil {
		return nil
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return nil
	}
	env := make([]string, 0, len(call.Assigns))
	for _, assignment := range call.Assigns {
		if assignment.Name == nil {
			continue
		}
		value := ""
		if assignment.Value != nil {
			static, fixed := StaticWord(assignment.Value, home)
			if !fixed {
				static = "$"
			}
			value = static
		}
		env = append(env, assignment.Name.Value+"="+value)
	}
	return env
}

// actionMakeDecision decides a make or gmake call (GAP-0996). The hook sees
// only the call; the recipes it runs write without a visible destination. So
// it reads the makefiles the call runs, wherever they are: -f, --file and
// --makefile operands, else the default GNUmakefile, makefile or Makefile of
// the -C directory, the MAKEFILES list, and the includes they name (searched
// in the make directory, then the -I directories). Makefile text, --eval
// text and command-line variable overrides that reach a protected file or a
// link to one block in action mode. A makefile name the hook cannot resolve
// (an expansion, stdin), or a makefile it cannot read whole (not a regular
// file, unreadable, over maxMakeSourceBytes, more than maxMakeFiles), is an
// unresolved construct of a write-capable call and blocks too. Ordinary
// builds pass: a readable makefile without protected reach, inside or
// outside the work directory, and a missing makefile, which runs no recipe.
// An include name that only make can compute ($(shell ...), a pattern
// substitution) is not followed: a known limit of reading make statically.
func actionMakeDecision(words, env []string, cwd, home string) string {
	call := actionMakeCall{home: home, dir: cwd}
	for _, assignment := range env {
		if reason := call.variable(assignment, true); reason != "" {
			return reason
		}
	}
	if len(words) > 0 {
		if reason := call.options(words[1:], false); reason != "" {
			return reason
		}
	}
	return call.decide()
}

// variable takes one NAME=value from the environment or the command line.
// MAKEFILES (environment only) adds makefiles; MAKEFLAGS adds options. A
// command-line value is also text make runs, so its reach is checked.
func (c *actionMakeCall) variable(assignment string, environment bool) string {
	name, value, _ := strings.Cut(assignment, "=")
	switch name {
	case "MAKEFILES":
		if !environment {
			break
		}
		if actionMakeDynamic(value) {
			return "dynamic-argument"
		}
		c.extra = append(c.extra, strings.Fields(value)...)
	case "MAKEFLAGS", "GNUMAKEFLAGS", "MFLAGS":
		if actionMakeDynamic(value) {
			return "dynamic-argument"
		}
		if reason := c.options(strings.Fields(value), true); reason != "" {
			return reason
		}
	}
	if !environment {
		c.texts = append(c.texts, assignment)
	}
	return ""
}

type actionMakeCall struct {
	home, dir   string
	files       []string // -f operands, read in order
	extra       []string // MAKEFILES entries, read first; a missing one is skipped
	includeDirs []string
	texts       []string // --eval text and variable overrides
	goals       []string // command-line targets
	read        int
	variables   map[string]string
	global      []string // makefile lines outside rules
	rules       []makeRule
}

// options takes make's arguments. Short options may be grouped (-kf x).
// flags is set for a MAKEFLAGS value, whose bare words are option letters.
func (c *actionMakeCall) options(args []string, flags bool) string {
	for i := 0; i < len(args); i++ {
		word := args[i]
		if word == "--" {
			for _, rest := range args[i+1:] {
				if strings.Contains(rest, "=") {
					c.texts = append(c.texts, rest)
				} else if !flags {
					c.goals = append(c.goals, rest)
				}
			}
			return ""
		}
		if !strings.HasPrefix(word, "-") {
			if strings.Contains(word, "=") {
				if reason := c.variable(word, false); reason != "" {
					return reason
				}
			} else if !flags {
				c.goals = append(c.goals, word)
			}
			continue
		}
		var option, value string
		next := false
		if strings.HasPrefix(word, "--") {
			name, inline, hasValue := strings.Cut(word[2:], "=")
			switch name {
			case "file", "makefile":
				option = "f"
			case "directory":
				option = "C"
			case "include-dir":
				option = "I"
			case "eval":
				option = "E"
			case "old-file", "assume-old", "what-if", "new-file", "assume-new":
				option = "o"
			default:
				continue
			}
			value, next = inline, !hasValue
		} else {
			for j := 1; j < len(word); j++ {
				if strings.ContainsRune("fCIEoW", rune(word[j])) {
					option, value = word[j:j+1], word[j+1:]
					next = value == ""
					break
				}
			}
			if option == "" {
				continue
			}
		}
		if next {
			i++
			if i >= len(args) {
				return "dynamic-argument"
			}
			value = args[i]
		}
		if actionMakeDynamic(value) {
			return "dynamic-argument"
		}
		switch option {
		case "f":
			c.files = append(c.files, value)
		case "C":
			dir, ok := c.path(value, c.dir)
			if !ok {
				return "dynamic-argument"
			}
			c.dir = dir
		case "I":
			c.includeDirs = append(c.includeDirs, value)
		case "E":
			c.texts = append(c.texts, value)
		}
	}
	return ""
}

func (c *actionMakeCall) decide() string {
	c.variables = map[string]string{}
	for _, name := range c.extra {
		if reason := c.makefile(name, false); reason != "" {
			return reason
		}
	}
	if len(c.files) == 0 {
		// GNU make runs the first default file that exists.
		for _, name := range []string{"GNUmakefile", "makefile", "Makefile"} {
			path, ok := c.path(name, c.dir)
			if !ok {
				return "dynamic-argument"
			}
			if _, err := os.Lstat(path); err == nil {
				c.files = append(c.files, name)
				break
			} else if !errors.Is(err, fs.ErrNotExist) {
				return "dynamic-argument"
			}
		}
	}
	for _, name := range c.files {
		if name == "-" {
			return "dynamic-argument" // a makefile on stdin
		}
		if reason := c.makefile(name, false); reason != "" {
			return reason
		}
	}
	protected := newProtectedFiles(c.home)
	ssh := filepath.Join(c.home, ".ssh")
	reaches := func(text string) bool {
		for _, form := range []string{"$(HOME)", "${HOME}", "$$HOME", "$$(HOME)", "$${HOME}"} {
			text = strings.ReplaceAll(text, form, filepath.ToSlash(c.home))
		}
		// The reach scan bounds the paths it checks in one text; a long
		// joined source list is checked in parts so its length alone is
		// not a block.
		if actionWindowsHome(c.home) {
			// The reach scan reads POSIX spellings; the shared Windows
			// resolver reads drive, UNC, %USERPROFILE% and ~ spellings.
			for _, token := range makeWindowsToken.FindAllString(text, -1) {
				if protected, _ := actionWindowsProtected(token, c.dir, c.home, false); protected {
					return true
				}
			}
		}
		fields := strings.Fields(text)
		for start := 0; start < len(fields); start += maxMakeReachFields {
			part := strings.Join(fields[start:min(start+maxMakeReachFields, len(fields))], " ")
			if protectedReachFromTextWithFiles(part, c.dir, c.home, protected, ssh, false) {
				return true
			}
		}
		return false
	}
	texts := append(append([]string(nil), c.texts...), c.global...)
	for _, rule := range c.selectedRules() {
		texts = append(texts, rule.lines...)
	}
	for _, text := range texts {
		if reaches(text) {
			return "dynamic-argument"
		}
	}
	return ""
}

// makeRule is one rule of the makefiles a call reads: its header and recipe
// lines, which run only when make builds one of its targets.
type makeRule struct {
	targets, prerequisites, lines []string
}

// selectedRules returns the rules the call can run: those of the goals (the
// command-line targets, else .DEFAULT_GOAL or the first ordinary target) and
// of their prerequisites, plus every pattern or computed rule, which can
// build any of them. A computed goal or prerequisite selects every rule.
func (c *actionMakeCall) selectedRules() []makeRule {
	goals := append([]string(nil), c.goals...)
	if len(goals) == 0 {
		if goal := strings.TrimSpace(actionMakeExpand(c.variables[".DEFAULT_GOAL"], c.variables)); goal != "" {
			goals = strings.Fields(goal)
		}
	}
	if len(goals) == 0 {
	first:
		for _, rule := range c.rules {
			for _, target := range rule.targets {
				if !strings.HasPrefix(target, ".") && !strings.ContainsAny(target, "%$") {
					goals = []string{target}
					break first
				}
			}
		}
	}
	selected := make([]bool, len(c.rules))
	queued := map[string]bool{}
	for len(goals) > 0 {
		goal := goals[0]
		goals = goals[1:]
		if queued[goal] {
			continue
		}
		queued[goal] = true
		if strings.ContainsAny(goal, "$`") {
			return c.rules
		}
		for i, rule := range c.rules {
			for _, target := range rule.targets {
				if target == goal || strings.ContainsAny(target, "%$") {
					if !selected[i] {
						selected[i] = true
						goals = append(goals, rule.prerequisites...)
					}
					break
				}
			}
		}
	}
	var rules []makeRule
	for i, rule := range c.rules {
		if selected[i] {
			rules = append(rules, rule)
		}
	}
	return rules
}

// makefile reads one makefile and the includes it names into the call's
// model. include searches the -I directories when the make directory has no
// such file. Lines outside rules (variables, conditionals, $(shell ...))
// always run; a rule's lines run when make builds one of its targets.
func (c *actionMakeCall) makefile(name string, include bool) string {
	path, ok := c.path(name, c.dir)
	if !ok {
		return "dynamic-argument"
	}
	content, found, readable := actionMakeRead(path)
	if include && !found && !filepath.IsAbs(filepath.FromSlash(name)) {
		for _, dir := range c.includeDirs {
			base, baseOK := c.path(dir, c.dir)
			if !baseOK {
				return "dynamic-argument"
			}
			if path, ok = c.path(name, base); !ok {
				return "dynamic-argument"
			}
			if content, found, readable = actionMakeRead(path); found {
				break
			}
		}
	}
	if !found {
		return "" // a missing makefile runs no recipe
	}
	c.read++
	if !readable || c.read > maxMakeFiles {
		return "dynamic-argument"
	}
	content = strings.ReplaceAll(content, "\\\r\n", " ")
	content = strings.ReplaceAll(content, "\\\n", " ")
	rule := -1
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(line, "\t") {
			if rule >= 0 {
				c.rules[rule].lines = append(c.rules[rule].lines, line)
			} else {
				c.global = append(c.global, line)
			}
			continue
		}
		if match := makeVariableDefinition.FindStringSubmatch(trimmed); match != nil {
			c.variables[match[1]] = strings.TrimSpace(match[2])
			c.global = append(c.global, line)
			rule = -1
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && (fields[0] == "include" || fields[0] == "-include" || fields[0] == "sinclude") {
			c.global = append(c.global, line)
			rule = -1
			if reason := c.includes(fields[1:]); reason != "" {
				return reason
			}
			continue
		}
		header, recipe, _ := strings.Cut(trimmed, ";")
		targets, prerequisites, isRule := strings.Cut(header, ":")
		if !isRule {
			c.global = append(c.global, line) // a directive or conditional
			rule = -1
			continue
		}
		prerequisites = strings.TrimLeft(prerequisites, ":")
		parsed := makeRule{
			targets:       strings.Fields(actionMakeExpand(targets, c.variables)),
			prerequisites: strings.Fields(strings.ReplaceAll(actionMakeExpand(prerequisites, c.variables), "|", " ")),
			lines:         []string{header},
		}
		if recipe != "" {
			parsed.lines = append(parsed.lines, recipe)
		}
		c.rules = append(c.rules, parsed)
		rule = len(c.rules) - 1
	}
	return ""
}

func (c *actionMakeCall) includes(operands []string) string {
	for _, operand := range operands {
		if strings.HasPrefix(operand, "#") {
			break
		}
		operand = actionMakeExpand(operand, c.variables)
		if strings.ContainsAny(operand, "$`") {
			continue // computed by make itself: a documented limit
		}
		names := []string{operand}
		if strings.ContainsAny(operand, "*?[") {
			pattern, ok := c.path(operand, c.dir)
			if !ok {
				return "dynamic-argument"
			}
			matches, err := filepath.Glob(filepath.FromSlash(pattern))
			if err != nil {
				return "dynamic-argument"
			}
			names = matches
		}
		for _, include := range names {
			if reason := c.makefile(include, true); reason != "" {
				return reason
			}
		}
	}
	return ""
}

// actionMakeExpand substitutes the makefile's own static variables into an
// include operand, a few levels deep.
func actionMakeExpand(operand string, variables map[string]string) string {
	for range 4 {
		before := operand
		for name, value := range variables {
			operand = strings.ReplaceAll(operand, "$("+name+")", value)
			operand = strings.ReplaceAll(operand, "${"+name+"}", value)
		}
		if operand == before {
			break
		}
	}
	return operand
}

func actionMakeDynamic(value string) bool {
	return value == "" || strings.ContainsAny(value, "\x00\r\n$`")
}

// path names a makefile or directory for this call: Windows homes use the
// shared Windows resolver; ".." stays in the name, and the read resolves it
// after following links.
func (c *actionMakeCall) path(name, base string) (string, bool) {
	if actionMakeDynamic(name) {
		return "", false
	}
	if actionWindowsHome(c.home) {
		if resolved, ok := actionWindowsPath(name, base, c.home); ok {
			return resolved, true
		}
		// The shared resolver refuses ".." and short names, which need file
		// identity; the read follows them on the file system instead.
		name = strings.ReplaceAll(name, `\`, "/")
		if strings.ContainsAny(name, "%~") || len(name) >= 2 && name[1] == ':' || strings.HasPrefix(name, "/") {
			return "", false
		}
		return strings.TrimRight(strings.ReplaceAll(base, `\`, "/"), "/") + "/" + name, true
	}
	if name == "~" || strings.HasPrefix(name, "~/") {
		name = c.home + name[1:]
	}
	if filepath.IsAbs(name) {
		return name, true
	}
	if !filepath.IsAbs(base) {
		return "", false
	}
	return strings.TrimRight(base, string(filepath.Separator)) + string(filepath.Separator) + name, true
}

// actionMakeRead reads one makefile whole. found is false when nothing
// exists at the name; readable is false when a file exists but is not a
// regular file within maxMakeSourceBytes that the hook can open.
func actionMakeRead(name string) (content string, found, readable bool) {
	real, err := filepath.EvalSymlinks(filepath.FromSlash(name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, true
		}
		return "", true, false
	}
	root, err := os.OpenRoot(filepath.Dir(real))
	if err != nil {
		return "", true, false
	}
	defer root.Close()
	base := filepath.Base(real)
	before, err := root.Lstat(base)
	if err != nil || !before.Mode().IsRegular() || before.Size() > maxMakeSourceBytes {
		return "", true, false
	}
	file, err := root.Open(base)
	if err != nil {
		return "", true, false
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return "", true, false
	}
	data, err := io.ReadAll(io.LimitReader(file, maxMakeSourceBytes+1))
	if err != nil || int64(len(data)) > maxMakeSourceBytes {
		return "", true, false
	}
	return string(data), true, true
}
