// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func actionPureMake(command, home string) bool {
	file, ok := parseShell(command)
	if !ok || len(file.Stmts) != 1 {
		return false
	}
	stmt := file.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed || programBase(program) != "make" && programBase(program) != "gmake" {
		return false
	}
	for _, redirect := range stmt.Redirs {
		if redirect.Op != syntax.RdrIn && redirect.Op != syntax.Hdoc && redirect.Op != syntax.DashHdoc {
			return false
		}
	}
	return true
}

// This proof only returns true for a selected recipe with a resolved protected
// write. Missing, unreadable, or complex make input leaves the call to make
// alone: parse uncertainty is audit information, not a protected target.
func actionMakeProtectedRecipe(command, cwd, home string) bool {
	return actionMakeProtectedRecipeDepth(command, cwd, home, 0)
}

// A recipe that runs make again ($(MAKE) -f other.mk) is read the same way,
// to a bounded depth (GAP-0996).
func actionMakeProtectedRecipeDepth(command, cwd, home string, depth int) bool {
	return actionMakeRecipeMatches(command, cwd, home, func(recipe, dir, home string) bool {
		protected := newProtectedFiles(home)
		ssh := filepath.Join(home, ".ssh")
		writes, _, _ := ShellWriteOperands(recipe, dir, home)
		writes = append(writes, LiteralWriteOperands(recipe, dir, home)...)
		for _, path := range writes {
			if protectedReachPath(OperandPath(path, dir), protected, ssh) {
				return true
			}
		}
		return depth < 4 && actionMakeProtectedRecipeDepth(recipe, dir, home, depth+1)
	})
}

// ActionMakePrivateKeyRead reports a selected recipe that reads an active SSH
// private key, independently from the authorized-keys persistence rule.
func ActionMakePrivateKeyRead(command, cwd, home string) bool {
	return actionMakeRecipeMatches(command, cwd, home, ActionPrivateKeyRead)
}

func actionMakeRecipeMatches(command, cwd, home string, matches func(string, string, string) bool) bool {
	if !strings.Contains(command, "make") || !filepath.IsAbs(cwd) {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	feeds := actionMakeStdinFeeds(file, cwd, home)
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok || found {
			return !found
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		for i, word := range call.Args {
			value, fixed := StaticWord(word, home)
			if !fixed {
				return true
			}
			words[i] = value
		}
		if base := programBase(words[0]); base != "make" && base != "gmake" {
			return true
		}
		proof := makeRecipeProof{dir: cwd, home: home}
		for _, assignment := range call.Assigns {
			if assignment.Name == nil || assignment.Value == nil {
				continue
			}
			value, fixed := StaticWord(assignment.Value, home)
			if !fixed {
				continue
			}
			switch assignment.Name.Value {
			case "MAKEFLAGS", "GNUMAKEFLAGS", "MFLAGS":
				proof.options(strings.Fields(value))
			case "MAKEFILES":
				proof.files = append(proof.files, strings.Fields(value)...)
			}
		}
		proof.options(words[1:])
		if proof.stdinFile {
			if content, fixed := actionLiteralHereDocument(stmt); fixed {
				proof.parse(content)
			} else if name := actionStaticStdinFile(stmt, cwd, home); name != "" {
				proof.read(name)
			} else {
				for _, name := range feeds[stmt] {
					proof.read(name)
				}
			}
		}
		found = proof.matches(matches)
		return !found
	})
	return found
}

// actionStaticStdinFile returns the file a static `< FILE` redirect feeds to
// the statement's standard input (the last one wins, as in the shell), or "".
func actionStaticStdinFile(stmt *syntax.Stmt, cwd, home string) string {
	name := ""
	for _, redirect := range stmt.Redirs {
		if redirect.Op != syntax.RdrIn || redirect.Word == nil || redirect.N != nil && redirect.N.Value != "0" {
			continue
		}
		value, fixed := StaticWord(redirect.Word, home)
		if !fixed || value == "" {
			return ""
		}
		name = OperandPath(value, cwd)
	}
	return name
}

// actionMakeStdinFeeds maps each pipeline stage to the files a plain
// `cat FILE...` (or `cat < FILE`) stage before it writes to its standard
// input, so `cat evil.mk | make -f -` reads evil.mk like `make -f - <
// evil.mk` (GAP-0996). Any other feeder, or a cat with options, feeds nothing
// known.
func actionMakeStdinFeeds(file *syntax.File, cwd, home string) map[*syntax.Stmt][]string {
	feeds := make(map[*syntax.Stmt][]string)
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		stages := actionPipeStages(stmt)
		for i := 1; i < len(stages); i++ {
			if names := actionCatFeedFiles(stages[i-1], cwd, home); len(names) != 0 {
				feeds[stages[i]] = names
			}
		}
		return true
	})
	return feeds
}

func actionPipeStages(stmt *syntax.Stmt) []*syntax.Stmt {
	binary, ok := stmt.Cmd.(*syntax.BinaryCmd)
	if !ok || binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll || len(stmt.Redirs) != 0 {
		return []*syntax.Stmt{stmt}
	}
	return append(actionPipeStages(binary.X), actionPipeStages(binary.Y)...)
}

func actionCatFeedFiles(stmt *syntax.Stmt, cwd, home string) []string {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil
	}
	words := make([]string, len(call.Args))
	for i, word := range call.Args {
		value, fixed := StaticWord(word, home)
		if !fixed {
			return nil
		}
		words[i] = value
	}
	if programBase(words[0]) != "cat" {
		return nil
	}
	var names []string
	for _, word := range words[1:] {
		if word == "" || strings.HasPrefix(word, "-") {
			return nil
		}
		names = append(names, OperandPath(word, cwd))
	}
	if len(names) == 0 {
		if name := actionStaticStdinFile(stmt, cwd, home); name != "" {
			names = append(names, name)
		}
	}
	return names
}

type makeRecipeRule struct {
	targets, needs, recipes []string
}

type makeRecipeProof struct {
	dir, home           string
	files, evals, goals []string
	rules               []makeRecipeRule
	stdinFile           bool
	reads, bytes        int
	firstGoal           string
}

func (p *makeRecipeProof) options(args []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			p.goals = append(p.goals, args[i+1:]...)
			return
		}
		option, value := "", ""
		switch {
		case arg == "-f" || arg == "-C" || arg == "--file" || arg == "--makefile" || arg == "--directory" || arg == "--eval":
			option = arg
			if i+1 >= len(args) {
				return
			}
			i++
			value = args[i]
		case strings.HasPrefix(arg, "--file=") || strings.HasPrefix(arg, "--makefile=") ||
			strings.HasPrefix(arg, "--directory=") || strings.HasPrefix(arg, "--eval="):
			option, value, _ = strings.Cut(arg, "=")
		case strings.HasPrefix(arg, "-f") && len(arg) > 2:
			option, value = "-f", arg[2:]
		case strings.HasPrefix(arg, "-C") && len(arg) > 2:
			option, value = "-C", arg[2:]
		case !strings.HasPrefix(arg, "-") && !strings.Contains(arg, "="):
			p.goals = append(p.goals, arg)
		}
		switch option {
		case "-f", "--file", "--makefile":
			if value == "-" || value == "/dev/stdin" || value == "/dev/fd/0" || value == "/proc/self/fd/0" {
				p.stdinFile = true
			} else if value != "" {
				p.files = append(p.files, value)
			}
		case "-C", "--directory":
			if value != "" {
				p.dir = OperandPath(value, p.dir)
			}
		case "--eval":
			p.evals = append(p.evals, value)
		}
	}
}

func (p *makeRecipeProof) matches(match func(string, string, string) bool) bool {
	p.load()
	selected := p.selected()
	for index, rule := range p.rules {
		if !selected[index] {
			continue
		}
		for _, recipe := range rule.recipes {
			recipe = strings.TrimLeft(recipe, " \t@-+")
			// make passes the environment's HOME as a variable and runs
			// $(MAKE) as make (GAP-0996).
			recipe = makeRecipeVariables(p.home).Replace(recipe)
			if match(recipe, p.dir, p.home) {
				return true
			}
		}
	}
	return false
}

// load reads the --eval texts, then the makefiles. It returns the number of
// rules defined before the makefiles: the evals' (after a stdin makefile's).
func (p *makeRecipeProof) load() int {
	for _, content := range p.evals {
		p.parse(content)
	}
	before := len(p.rules)
	if len(p.files) == 0 && !p.stdinFile {
		for _, name := range []string{"GNUmakefile", "makefile", "Makefile"} {
			if _, err := pathLstat(filepath.Join(p.dir, name)); err == nil {
				p.files = append(p.files, name)
				break
			}
		}
	}
	for _, name := range p.files {
		p.read(name)
	}
	return before
}

// selected marks the rules make runs for the goals (the first target when
// there is none) and their prerequisites.
func (p *makeRecipeProof) selected() map[int]bool {
	goals := append([]string(nil), p.goals...)
	if len(goals) == 0 && p.firstGoal != "" {
		goals = append(goals, p.firstGoal)
	}
	selected := make(map[int]bool)
	seen := make(map[string]bool)
	for len(goals) > 0 && len(seen) < 256 {
		goal := goals[0]
		goals = goals[1:]
		if seen[goal] {
			continue
		}
		seen[goal] = true
		exactRecipe := false
		for _, rule := range p.rules {
			for _, target := range rule.targets {
				if target == goal && len(rule.recipes) != 0 {
					exactRecipe = true
				}
			}
		}
		for index, rule := range p.rules {
			for _, target := range rule.targets {
				stem, match := makeRecipeMatch(target, goal)
				if !match || stem != "" && exactRecipe {
					continue
				}
				selected[index] = true
				for _, need := range rule.needs {
					goals = append(goals, strings.ReplaceAll(need, "%", stem))
				}
				break
			}
		}
	}
	return selected
}

// makeEvalDirectives are the makefile directives an --eval text may hold;
// each one reads files, runs code or changes variables when make parses it.
var makeEvalDirectives = map[string]bool{
	"include": true, "-include": true, "sinclude": true, "define": true, "endef": true, "export": true,
	"unexport": true, "override": true, "private": true, "vpath": true, "ifdef": true, "ifndef": true,
	"ifeq": true, "ifneq": true, "else": true, "endif": true, "load": true, "-load": true, "undefine": true,
}

// actionInertMakeEvals returns the --eval words of a static make call when
// every --eval text only defines plain rules (no $ expansion, assignment,
// directive, pattern, special or double-colon target) and the call selects
// none of them: make parses such a text and never runs its recipes, so the
// paths in it are not targets of the call (GAP-2169). Any other call
// returns nil, and its --eval texts are read as before.
func actionInertMakeEvals(call *syntax.CallExpr, cwd, home string) []*syntax.Word {
	if len(call.Assigns) != 0 || len(call.Args) < 2 || !filepath.IsAbs(cwd) {
		return nil
	}
	words, known := actionStaticWords(call.Args, home)
	if !known {
		return nil
	}
	if base := programBase(words[0]); base != "make" && base != "gmake" {
		return nil
	}
	var evals []*syntax.Word
	for i := 1; i < len(words) && words[i] != "--"; i++ {
		text := ""
		switch {
		case strings.HasPrefix(words[i], "--eval="):
			text = strings.TrimPrefix(words[i], "--eval=")
		case words[i] == "--eval" && i+1 < len(words):
			i++
			text = words[i]
		default:
			continue
		}
		if !makeEvalDefinesRulesOnly(text) {
			return nil
		}
		evals = append(evals, call.Args[i])
	}
	if len(evals) == 0 {
		return nil
	}
	proof := makeRecipeProof{dir: cwd, home: home}
	proof.options(words[1:])
	if proof.stdinFile {
		return nil
	}
	evalRules := proof.load()
	for index := range proof.selected() {
		if index < evalRules {
			return nil
		}
	}
	return evals
}

func makeEvalDefinesRulesOnly(text string) bool {
	if strings.ContainsAny(text, "$`\\") {
		return false
	}
	rules := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "\t") {
			if !rules {
				return false
			}
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		head, _, _ := strings.Cut(line, ";")
		targets, rest, rule := strings.Cut(head, ":")
		fields := strings.Fields(targets)
		if !rule || len(fields) == 0 || strings.ContainsAny(head, "=%") || strings.HasPrefix(rest, ":") || makeEvalDirectives[fields[0]] {
			return false
		}
		for _, target := range fields {
			if strings.HasPrefix(target, ".") {
				return false
			}
		}
		rules = true
	}
	return rules
}

func makeRecipeVariables(home string) *strings.Replacer {
	return strings.NewReplacer("$(HOME)", home, "${HOME}", home, "$(MAKE)", "make", "${MAKE}", "make")
}

func makeRecipeMatch(pattern, goal string) (string, bool) {
	if pattern == goal {
		return "", true
	}
	prefix, suffix, hasPattern := strings.Cut(pattern, "%")
	if !hasPattern || strings.Contains(suffix, "%") || !strings.HasPrefix(goal, prefix) ||
		!strings.HasSuffix(goal, suffix) || len(goal) <= len(prefix)+len(suffix) {
		return "", false
	}
	return goal[len(prefix) : len(goal)-len(suffix)], true
}

func (p *makeRecipeProof) read(name string) {
	if p.reads >= 64 || name == "" || strings.ContainsAny(name, "\x00\r\n$`") {
		return
	}
	p.reads++
	path := OperandPath(name, p.dir)
	real, err := pathEvalSymlinks(path)
	if err != nil {
		return
	}
	file, err := pathOpen(real)
	if err != nil {
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
		return
	}
	content, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	if err == nil && len(content) <= 8<<20 {
		p.parse(string(content))
	}
}

func (p *makeRecipeProof) parse(content string) {
	if len(content) > 8<<20 || p.bytes > (32<<20)-len(content) {
		return
	}
	p.bytes += len(content)
	active := -1
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "\t") {
			if active >= 0 {
				p.rules[active].recipes = append(p.rules[active].recipes, line)
			}
			continue
		}
		active = -1
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if fields := strings.Fields(line); len(fields) > 1 &&
			(fields[0] == "include" || fields[0] == "-include" || fields[0] == "sinclude") {
			for _, name := range fields[1:] {
				p.read(name)
			}
			continue
		}
		header, inline, _ := strings.Cut(line, ";")
		targets, needs, rule := strings.Cut(header, ":")
		if !rule || strings.Contains(targets, "=") {
			continue
		}
		parsed := makeRecipeRule{targets: strings.Fields(targets), needs: strings.Fields(strings.ReplaceAll(needs, "|", " "))}
		if inline != "" {
			parsed.recipes = append(parsed.recipes, inline)
		}
		if len(parsed.targets) == 0 {
			continue
		}
		if p.firstGoal == "" && !strings.HasPrefix(parsed.targets[0], ".") {
			p.firstGoal = parsed.targets[0]
		}
		if len(p.rules) >= 65536 {
			return
		}
		p.rules = append(p.rules, parsed)
		active = len(p.rules) - 1
	}
}
