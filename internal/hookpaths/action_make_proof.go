// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"os"
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
		return false
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
			}
		}
		found = proof.matches(matches)
		return !found
	})
	return found
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
			if value == "-" {
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
	for _, content := range p.evals {
		p.parse(content)
	}
	if len(p.files) == 0 && !p.stdinFile {
		for _, name := range []string{"GNUmakefile", "makefile", "Makefile"} {
			if _, err := os.Lstat(filepath.Join(p.dir, name)); err == nil {
				p.files = append(p.files, name)
				break
			}
		}
	}
	for _, name := range p.files {
		p.read(name)
	}
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
	for index, rule := range p.rules {
		if !selected[index] {
			continue
		}
		for _, recipe := range rule.recipes {
			recipe = strings.TrimLeft(recipe, " \t@-+")
			if match(recipe, p.dir, p.home) {
				return true
			}
		}
	}
	return false
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
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return
	}
	file, err := os.Open(real)
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
