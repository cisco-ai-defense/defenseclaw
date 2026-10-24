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
	maxMakeWork        int64 = 32 << 20
	maxMakeQueuedGoals       = 65536
	maxMakeGoalBytes         = 4096
)

var makeWindowsToken = regexp.MustCompile(`[^\s'"<>|;&()=,]+`)

var makeVariableDefinition = regexp.MustCompile(`^(?:override\s+|export\s+)?([A-Za-z_.][A-Za-z0-9_.]*)\s*(:::=|:=|\?=|\+=|!=|=)\s*(.*)$`)

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
// text and selected recipes that reach a protected file or a link to one block
// in action mode. A makefile name or stdin source the hook cannot resolve,
// or a makefile it cannot read whole (not a regular
// file, unreadable, over maxMakeSourceBytes, more than maxMakeFiles), is an
// unresolved construct of a write-capable call and blocks too. Ordinary
// builds pass: a readable makefile without protected reach, inside or
// outside the work directory, and a missing makefile, which runs no recipe.
// An include name that only make can compute ($(shell ...), a pattern
// substitution) is not followed: a known limit of reading make statically.
func actionMakeDecision(words, env []string, cwd, home string, stdin *string) string {
	call := actionMakeCall{home: home, dir: cwd, stdin: stdin}
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
// command-line value is expanded only where a selected recipe uses it.
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
		if c.overrides == nil {
			c.overrides = make(map[string]string)
		}
		c.overrides[name] = value
	}
	return ""
}

type actionMakeCall struct {
	home, dir   string
	files       []string // -f operands, read in order
	extra       []string // MAKEFILES entries, read first; a missing one is skipped
	includeDirs []string
	evals       []string // --eval text, parsed before makefiles
	overrides   map[string]string
	goals       []string // command-line targets
	read        int
	stdin       *string
	variables   map[string]string
	simple      map[string]bool // immediately expanded make variables
	global      []string        // executable parse-time makefile lines
	rules       []makeRule
	work        int64
	overBudget  bool
}

func (c *actionMakeCall) spend(amount int64) bool {
	if amount < 0 || c.work > maxMakeWork-amount {
		c.overBudget = true
		return false
	}
	c.work += amount
	return true
}

func (c *actionMakeCall) expand(text string) string {
	if !c.spend(int64(len(text))) {
		return ""
	}
	expanded, ok := actionMakeExpand(text, c.variables)
	if !ok || !c.spend(int64(len(expanded))) {
		c.overBudget = true
		return ""
	}
	return expanded
}

// options takes make's arguments. Short options may be grouped (-kf x).
// flags is set for a MAKEFLAGS value, whose bare words are option letters.
func (c *actionMakeCall) options(args []string, flags bool) string {
	for i := 0; i < len(args); i++ {
		word := args[i]
		if word == "--" {
			for _, rest := range args[i+1:] {
				if strings.Contains(rest, "=") {
					if reason := c.variable(rest, false); reason != "" {
						return reason
					}
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
		if option == "E" {
			if value == "" || strings.ContainsAny(value, "\x00\r$`") {
				return "dynamic-argument"
			}
		} else if actionMakeDynamic(value) {
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
			c.evals = append(c.evals, value)
		}
	}
	return ""
}

func (c *actionMakeCall) decide() string {
	c.variables = map[string]string{}
	c.simple = map[string]bool{}
	for name, value := range c.overrides {
		c.variables[name] = value
	}
	for _, eval := range c.evals {
		if int64(len(eval)) > maxMakeSourceBytes {
			return "dynamic-argument"
		}
		if reason := c.parseContent(eval); reason != "" {
			return reason
		}
	}
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
		if reason := c.makefile(name, false); reason != "" {
			return reason
		}
	}
	if c.overBudget {
		return "dynamic-argument"
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
	for _, text := range c.global {
		if reaches(text) {
			return "dynamic-argument"
		}
	}
	rules, ok := c.selectedRules()
	if !ok {
		return "dynamic-argument"
	}
	for _, rule := range rules {
		for _, line := range rule.lines {
			text := c.expand(line)
			if c.overBudget {
				return "dynamic-argument"
			}
			copy, copyDir, copyKnown := c.recipeCopy(text, c.dir, 0)
			if copyKnown {
				for _, source := range copy.sources {
					private := actionPrivateReadPath(source, copyDir, c.home)
					if actionWindowsHome(c.home) {
						private, _ = actionWindowsProtected(source, copyDir, c.home, true)
					}
					if private {
						return "dynamic-argument"
					}
				}
			}
			if reaches(text) && (!copyKnown || !c.recipeCopyHasOrdinaryDestination(copy, copyDir)) &&
				!c.recipeUsesProtectedPathAsData(text) {
				return "dynamic-argument"
			}
		}
	}
	return ""
}

// A protected copy source is data when every source is a regular file and
// every destination the transfer can write is ordinary. Unrecognized options
// and launch shapes retain the reach-scan block.
func (c *actionMakeCall) recipeCopyHasOrdinaryDestination(copy cpOperandsResult, dir string) bool {
	if !copy.ok || copy.hard || copy.symbolic || copy.alternateTarget || len(copy.sources) == 0 {
		return false
	}
	for _, source := range copy.sources {
		info, err := os.Lstat(OperandPath(source, dir))
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 && !copy.preserves {
			info, err = os.Stat(OperandPath(source, dir))
		}
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	destination := OperandPath(copy.destination, dir)
	info, err := os.Stat(destination)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	isDir := copy.targetDir || err == nil && info.IsDir()
	if !isDir && len(copy.sources) != 1 {
		return false
	}
	protected := newProtectedFiles(c.home)
	ssh := filepath.Join(c.home, ".ssh")
	ordinary := func(path string) bool {
		if _, ok := ResolveWriteTarget(path); !ok || protectedReachPath(path, protected, ssh) {
			return false
		}
		if actionWindowsHome(c.home) {
			blocked, resolved := actionWindowsProtected(path, dir, c.home, false)
			return resolved && !blocked
		}
		return true
	}
	if !ordinary(destination) {
		return false
	}
	for _, source := range copy.sources {
		target := destination
		if isDir {
			target = OperandPath(filepath.Base(source), destination)
		}
		if !ordinary(target) {
			return false
		}
	}
	return true
}

// recipeCopy follows the literal launch forms the shared action decision can
// inspect. It does not infer a copy merely because "cp" occurs in an argument.
func (c *actionMakeCall) recipeCopy(line, dir string, depth int) (cpOperandsResult, string, bool) {
	if depth >= 8 {
		return cpOperandsResult{}, dir, false
	}
	command := strings.TrimLeft(line, " \t@-+")
	for _, form := range []string{"$(HOME)", "${HOME}", "$$HOME", "$$(HOME)", "$${HOME}"} {
		command = strings.ReplaceAll(command, form, filepath.ToSlash(c.home))
	}
	file, ok := parseShell(command)
	if !ok || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 0 {
		return cpOperandsResult{}, dir, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return cpOperandsResult{}, dir, false
	}
	words := make([]string, len(call.Args))
	for i, word := range call.Args {
		value, static := StaticWord(word, c.home)
		if !static {
			return cpOperandsResult{}, dir, false
		}
		words[i] = value
	}
	for len(words) > 0 {
		if strings.ContainsAny(words[0], `/\`) {
			return cpOperandsResult{}, dir, false // a qualified executable may not be the named system program
		}
		program := programBase(words[0])
		switch program {
		case "cp", "gcp":
			parsed := cpOperands(words[1:], makeStatic(len(words)-1))
			return parsed, dir, parsed.ok
		case "install":
			parsed := makeInstallOperands(words[1:])
			return parsed, dir, parsed.ok
		case "rsync":
			parsed := makeRsyncOperands(words[1:])
			return parsed, dir, parsed.ok
		case "busybox", "toybox", "command", "exec", "time", "nohup", "sudo":
			words = words[1:]
			if len(words) > 0 && words[0] == "--" {
				words = words[1:]
			}
		case "env":
			i := 1
			for i < len(words) {
				word := words[i]
				switch {
				case word == "--", word == "-i", word == "--ignore-environment":
					i++
				case word == "-C" || word == "--chdir":
					if i+1 >= len(words) {
						return cpOperandsResult{}, dir, false
					}
					dir = OperandPath(words[i+1], dir)
					i += 2
				case strings.HasPrefix(word, "--chdir="):
					dir = OperandPath(strings.TrimPrefix(word, "--chdir="), dir)
					i++
				case word == "-S" || word == "--split-string":
					if i+1 >= len(words) || i+2 != len(words) {
						return cpOperandsResult{}, dir, false
					}
					return c.recipeCopy(words[i+1], dir, depth+1)
				case strings.Contains(word, "=") && !strings.HasPrefix(word, "-"):
					if strings.HasPrefix(word, "HOME=") {
						return cpOperandsResult{}, dir, false
					}
					i++
				default:
					goto envChild
				}
			}
		envChild:
			words = words[i:]
		case "nice":
			i := 1
			if i < len(words) && words[i] == "-n" {
				i += 2
			} else if i < len(words) && strings.HasPrefix(words[i], "-n") {
				i++
			}
			if i > len(words) {
				return cpOperandsResult{}, dir, false
			}
			words = words[i:]
		case "timeout":
			if len(words) < 3 {
				return cpOperandsResult{}, dir, false
			}
			words = words[2:]
		case "sh", "bash", "zsh", "dash":
			if index, ok := shellCommandBodyIndex(words); ok && index < len(words) && index == len(words)-1 {
				return c.recipeCopy(words[index], dir, depth+1)
			}
			return cpOperandsResult{}, dir, false
		default:
			return cpOperandsResult{}, dir, false
		}
	}
	return cpOperandsResult{}, dir, false
}

func makeInstallOperands(args []string) cpOperandsResult {
	var operands []string
	var target string
	options := true
	for i := 0; i < len(args); i++ {
		word := args[i]
		if options && word == "--" {
			options = false
			continue
		}
		if !options || !strings.HasPrefix(word, "-") || word == "-" {
			operands = append(operands, word)
			continue
		}
		switch {
		case word == "-t" || word == "--target-directory":
			i++
			if i >= len(args) {
				return cpOperandsResult{}
			}
			target = args[i]
		case strings.HasPrefix(word, "--target-directory="):
			target = strings.TrimPrefix(word, "--target-directory=")
		case word == "-m" || word == "-o" || word == "-g":
			i++
			if i >= len(args) {
				return cpOperandsResult{}
			}
		case word == "-D" || word == "-v" || word == "-C" || word == "-p" || word == "-T" ||
			word == "--compare" || word == "--verbose" || word == "--preserve-timestamps" ||
			strings.HasPrefix(word, "--mode=") || strings.HasPrefix(word, "--owner=") || strings.HasPrefix(word, "--group="):
		default:
			return cpOperandsResult{}
		}
	}
	if target != "" && len(operands) > 0 {
		return cpOperandsResult{sources: operands, destination: target, targetDir: true, ok: true}
	}
	if len(operands) < 2 {
		return cpOperandsResult{}
	}
	return cpOperandsResult{sources: operands[:len(operands)-1], destination: operands[len(operands)-1], ok: true}
}

func makeRsyncOperands(args []string) cpOperandsResult {
	var operands []string
	options := true
	preserves := false
	for _, word := range args {
		if options && word == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(word, "-") {
			if strings.Contains(" --archive --recursive --verbose --dry-run --copy-links --links --perms --times ", " "+word+" ") ||
				len(word) > 1 && word[1] != '-' && strings.Trim(word[1:], "avrlptgoDzcunI") == "" {
				preserves = preserves || word == "--archive" || word == "--links" ||
					len(word) > 1 && word[1] != '-' && strings.ContainsAny(word[1:], "al")
				continue
			}
			return cpOperandsResult{}
		}
		if strings.ContainsAny(word, "\x00\r\n") || strings.Contains(word, ":") &&
			(len(word) < 3 || word[1] != ':' || word[2] != '/' && word[2] != '\\') {
			return cpOperandsResult{} // remote and drive-relative destinations need a separate proof
		}
		operands = append(operands, word)
	}
	if len(operands) < 2 {
		return cpOperandsResult{}
	}
	return cpOperandsResult{sources: operands[:len(operands)-1], destination: operands[len(operands)-1], preserves: preserves, ok: true}
}

// A few known readers and printers can mention a protected path as data while
// writing an ordinary target. The shared shell decision proves their effects.
func (c *actionMakeCall) recipeUsesProtectedPathAsData(line string) bool {
	command := strings.TrimLeft(line, " \t@-+")
	if strings.ContainsAny(command, "$`") {
		return false
	}
	file, ok := parseShell(command)
	if !ok || len(file.Stmts) != 1 {
		return false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	program, fixed := StaticWord(call.Args[0], c.home)
	if !fixed || !strings.Contains(" echo printf cat head tail grep sort wc ", " "+programBase(program)+" ") {
		return false
	}
	for _, redirect := range file.Stmts[0].Redirs {
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
			target, known := StaticWord(redirect.Word, c.home)
			if !known || protectedReachPath(OperandPath(target, c.dir), newProtectedFiles(c.home), filepath.Join(c.home, ".ssh")) {
				return false
			}
		}
	}
	return ActionCommandDecision(command, c.dir, c.home) == ""
}

// makeRule is one rule of the makefiles a call reads. Its recipe lines run
// only when make builds one of its targets.
type makeRule struct {
	targets, prerequisites, lines []string
}

// selectedRules returns the rules the call can run: those of the goals (the
// command-line targets, else .DEFAULT_GOAL or the first ordinary target) and
// of their prerequisites. A pattern rule is selected only when its stem
// matches a requested goal. A computed goal or prerequisite selects every rule.
func (c *actionMakeCall) selectedRules() ([]makeRule, bool) {
	goals := append([]string(nil), c.goals...)
	if len(goals) == 0 {
		if goal := strings.TrimSpace(c.expand(c.variables[".DEFAULT_GOAL"])); goal != "" {
			goals = strings.Fields(goal)
		}
	}
	if c.overBudget {
		return nil, false
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
	if len(goals) > maxMakeQueuedGoals {
		return nil, false
	}
	for _, goal := range goals {
		if len(goal) > maxMakeGoalBytes || !c.spend(int64(len(goal)+1)) {
			return nil, false
		}
	}
	selected := make([]bool, len(c.rules))
	explicit := make(map[string][]int, len(c.rules))
	var patterns []int
	var dynamic []int
	for i, rule := range c.rules {
		for _, target := range rule.targets {
			switch {
			case strings.Contains(target, "$"):
				dynamic = append(dynamic, i)
			case strings.Contains(target, "%"):
				patterns = append(patterns, i)
			default:
				explicit[target] = append(explicit[target], i)
			}
		}
	}
	queued := map[string]bool{}
	for head := 0; head < len(goals); head++ {
		goal := goals[head]
		if queued[goal] {
			continue
		}
		queued[goal] = true
		if strings.ContainsAny(goal, "$`") {
			return c.rules, !c.overBudget
		}
		explicitRecipe := false
		for _, i := range explicit[goal] {
			if len(c.rules[i].lines) > 0 {
				explicitRecipe = true
			}
		}
		candidateCount := len(explicit[goal]) + len(dynamic)
		if !explicitRecipe {
			candidateCount += len(patterns)
		}
		if !c.spend(int64(candidateCount) * 8) {
			return nil, false
		}
		candidates := make([]int, 0, candidateCount)
		candidates = append(candidates, explicit[goal]...)
		candidates = append(candidates, dynamic...)
		if !explicitRecipe {
			candidates = append(candidates, patterns...)
		}
		for _, i := range candidates {
			rule := c.rules[i]
			for _, target := range rule.targets {
				if !c.spend(int64(len(target) + 1)) {
					return nil, false
				}
				stem := ""
				matches := target == goal
				if prefix, suffix, pattern := strings.Cut(target, "%"); pattern && !explicitRecipe && !strings.Contains(suffix, "%") &&
					strings.HasPrefix(goal, prefix) && strings.HasSuffix(goal, suffix) && len(goal) >= len(prefix)+len(suffix) {
					matches = true
					stem = goal[len(prefix) : len(goal)-len(suffix)]
				}
				if matches || strings.Contains(target, "$") {
					selected[i] = true
					if len(goals)+len(rule.prerequisites) > maxMakeQueuedGoals {
						return nil, false
					}
					for _, prerequisite := range rule.prerequisites {
						if !c.spend(int64(len(prerequisite))) {
							return nil, false
						}
						length := len(prerequisite) + strings.Count(prerequisite, "%")*(len(stem)-1)
						if length > maxMakeGoalBytes || !c.spend(int64(length+1)) {
							return nil, false
						}
						goals = append(goals, strings.ReplaceAll(prerequisite, "%", stem))
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
	return rules, !c.overBudget
}

// makefile reads one makefile and the includes it names into the call's
// model. include searches the -I directories when the make directory has no
// such file. Lines outside rules (variables, conditionals, $(shell ...))
// always run; a rule's lines run when make builds one of its targets.
func (c *actionMakeCall) makefile(name string, include bool) string {
	if actionMakeStdinName(name) {
		c.read++
		if c.stdin == nil || c.read > maxMakeFiles || int64(len(*c.stdin)) > maxMakeSourceBytes {
			return "dynamic-argument"
		}
		return c.parseContent(*c.stdin)
	}
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
	return c.parseContent(content)
}

func actionMakeStdinName(name string) bool {
	return name == "-" || name == "/dev/stdin" || name == "/dev/fd/0" ||
		name == "/proc/self/fd/0" || strings.EqualFold(name, "CONIN$")
}

func (c *actionMakeCall) parseContent(content string) string {
	if !c.spend(int64(len(content))) {
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
			_, override := c.overrides[match[1]]
			active := !override || strings.HasPrefix(trimmed, "override ")
			operator, raw := match[2], match[3]
			if operator == "!=" || actionMakeParseTimeCode(raw) &&
				(operator == ":=" || operator == ":::=" || operator == "+=" && c.simple[match[1]] && active) {
				c.global = append(c.global, c.expand(line))
			}
			if active {
				value := strings.TrimSpace(match[3])
				if operator == ":=" || operator == ":::=" {
					value = c.expand(value)
				}
				switch operator {
				case "?=":
					if _, defined := c.variables[match[1]]; !defined {
						c.variables[match[1]] = value
						c.simple[match[1]] = false
					}
				case "+=":
					if c.simple[match[1]] {
						value = c.expand(value)
					}
					combined := len(c.variables[match[1]]) + 1 + len(value)
					if combined > int(maxMakeSourceBytes) || !c.spend(int64(combined)) {
						return "dynamic-argument"
					}
					c.variables[match[1]] = strings.TrimSpace(c.variables[match[1]] + " " + value)
				default:
					c.simple[match[1]] = operator == ":=" || operator == ":::="
					c.variables[match[1]] = value
				}
			}
			rule = -1
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && (fields[0] == "include" || fields[0] == "-include" || fields[0] == "sinclude") {
			c.global = append(c.global, c.expand(line))
			rule = -1
			if reason := c.includes(fields[1:]); reason != "" {
				return reason
			}
			continue
		}
		if strings.HasPrefix(trimmed, "$(shell") || strings.HasPrefix(trimmed, "${shell") ||
			strings.HasPrefix(trimmed, "$(eval") || strings.HasPrefix(trimmed, "${eval") {
			c.global = append(c.global, c.expand(line))
			rule = -1
			continue
		}
		header, recipe, _ := strings.Cut(trimmed, ";")
		targets, prerequisites, isRule := strings.Cut(header, ":")
		if !isRule {
			rule = -1
			continue
		}
		prerequisites = strings.TrimLeft(prerequisites, ":")
		parsed := makeRule{
			targets:       strings.Fields(c.expand(targets)),
			prerequisites: strings.Fields(strings.ReplaceAll(c.expand(prerequisites), "|", " ")),
			lines:         nil,
		}
		if recipe != "" {
			parsed.lines = append(parsed.lines, recipe)
		}
		c.rules = append(c.rules, parsed)
		rule = len(c.rules) - 1
		if c.overBudget {
			return "dynamic-argument"
		}
	}
	if c.overBudget {
		return "dynamic-argument"
	}
	return ""
}

func (c *actionMakeCall) includes(operands []string) string {
	for _, operand := range operands {
		if strings.HasPrefix(operand, "#") {
			break
		}
		operand = c.expand(operand)
		if c.overBudget {
			return "dynamic-argument"
		}
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

// actionMakeExpand substitutes static make variables into an include, goal,
// or recipe operand, a few levels deep.
func actionMakeExpand(operand string, variables map[string]string) (string, bool) {
	for range 4 {
		var expanded strings.Builder
		nextParen, nextBrace := -1, -1
		noParen, noBrace := false, false
		for i := 0; i < len(operand); {
			if operand[i] == '$' && i+1 < len(operand) && (operand[i+1] == '(' || operand[i+1] == '{') {
				close := byte(')')
				if operand[i+1] == '{' {
					close = '}'
				}
				end := -1
				if close == ')' && !noParen {
					if nextParen < i+2 {
						nextParen = strings.IndexByte(operand[i+2:], close)
						if nextParen >= 0 {
							nextParen += i + 2
						} else {
							noParen = true
						}
					}
					end = nextParen
				} else if close == '}' && !noBrace {
					if nextBrace < i+2 {
						nextBrace = strings.IndexByte(operand[i+2:], close)
						if nextBrace >= 0 {
							nextBrace += i + 2
						} else {
							noBrace = true
						}
					}
					end = nextBrace
				}
				if end >= 0 {
					name := operand[i+2 : end]
					if makeStaticVariableName(name) {
						if value, found := variables[name]; found {
							expanded.WriteString(value)
							i = end + 1
							if expanded.Len() > int(maxMakeSourceBytes) {
								return "", false
							}
							continue
						}
					}
				}
			}
			expanded.WriteByte(operand[i])
			i++
			if expanded.Len() > int(maxMakeSourceBytes) {
				return "", false
			}
		}
		if expanded.String() == operand {
			break
		}
		operand = expanded.String()
	}
	return operand, true
}

func makeStaticVariableName(name string) bool {
	return name != "" && !strings.Contains(name, "$")
}

func actionMakeParseTimeCode(text string) bool {
	return strings.Contains(text, "$(shell") || strings.Contains(text, "${shell") ||
		strings.Contains(text, "$(eval") || strings.Contains(text, "${eval")
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
