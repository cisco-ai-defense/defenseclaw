// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// GitCloneThenRunOrAdHocPush is detection evidence for two source-control
// effects: a git clone whose files the same action then runs (a path named
// inside the clone, or any path run after a cd into it), and a git push to a
// remote given as a URL or user@host:path instead of a configured remote
// name. Neither is an enforcement proof.
func GitCloneThenRunOrAdHocPush(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX {
		return false
	}
	for _, command := range facts.Commands {
		if command.Kind != CommandKindProcess || gitProgram(command) != "git" {
			continue
		}
		if subcommand, rest := gitSubcommand(command.Argv); subcommand == "push" && gitPushNamesAdHocRemote(rest) {
			return true
		}
	}
	return gitCloneThenRunsClonedFile(facts)
}

func gitProgram(command CommandFact) string {
	if len(command.Argv) == 0 {
		return ""
	}
	return path.Base(command.Argv[0])
}

func gitSubcommand(argv []string) (string, []string) {
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		switch {
		case argument == "-C" || argument == "-c" || argument == "--git-dir" || argument == "--work-tree":
			index++
		case strings.HasPrefix(argument, "-"):
		default:
			return argument, argv[index+1:]
		}
	}
	return "", nil
}

func gitPushNamesAdHocRemote(args []string) bool {
	for _, argument := range args {
		if strings.HasPrefix(argument, "-") {
			continue
		}
		return isAdHocGitRemote(argument)
	}
	return false
}

func isAdHocGitRemote(value string) bool {
	if strings.Contains(value, "://") {
		return true
	}
	at, colon := strings.IndexByte(value, '@'), strings.IndexByte(value, ':')
	return at > 0 && colon > at
}

func gitCloneThenRunsClonedFile(facts Facts) bool {
	for index, command := range facts.Commands {
		if command.Kind != CommandKindProcess || gitProgram(command) != "git" {
			continue
		}
		if subcommand, rest := gitSubcommand(command.Argv); subcommand != "clone" {
			continue
		} else if directory := clonedDirectory(rest); directory != "" && runsFileAfterClone(facts, index, directory) {
			return true
		}
	}
	return false
}

func runsFileAfterClone(facts Facts, cloneIndex int, directory string) bool {
	inside := false
	for _, later := range facts.Commands[cloneIndex+1:] {
		if later.Program == "cd" && len(later.Argv) == 2 && cleanRelative(later.Argv[1]) == directory {
			inside = true
			continue
		}
		if inside && cloneBuildRunner(later) {
			return true
		}
		if len(later.Argv) > 0 && strings.HasPrefix(cleanRelative(later.Argv[0]), directory+"/") {
			return true
		}
		for _, candidate := range facts.Paths {
			if candidate.CommandID != later.ID || candidate.Access != PathAccessExecute {
				continue
			}
			if inside || strings.HasPrefix(cleanRelative(candidate.Value), directory+"/") {
				return true
			}
		}
	}
	return false
}

// cloneBuildRunner reports the package and build entry points that execute
// repository-defined scripts: install hooks, Makefile recipes, npm scripts.
func cloneBuildRunner(command CommandFact) bool {
	if len(command.Argv) == 0 {
		return false
	}
	switch path.Base(command.Argv[0]) {
	case "cmake", "pip", "pip3", "python", "python3", "npm", "yarn", "pnpm", "bundle", "cargo", "go", "mvn", "gradle":
		return len(command.Argv) > 1
	case "make":
		return true
	}
	return false
}

func cleanRelative(value string) string {
	return strings.TrimSuffix(strings.TrimPrefix(value, "./"), "/")
}

func clonedDirectory(args []string) string {
	var operands []string
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "-b" || argument == "--branch" || argument == "--depth" || argument == "-o" ||
			argument == "--origin" || argument == "--template" || argument == "-c" || argument == "--config":
			index++
		case strings.HasPrefix(argument, "-"):
		default:
			operands = append(operands, argument)
		}
	}
	switch {
	case len(operands) >= 2:
		return cleanRelative(operands[1])
	case len(operands) == 1:
		name := strings.TrimSuffix(strings.TrimSuffix(operands[0], "/"), ".git")
		if cut := strings.LastIndexAny(name, "/:"); cut >= 0 {
			name = name[cut+1:]
		}
		return name
	}
	return ""
}
