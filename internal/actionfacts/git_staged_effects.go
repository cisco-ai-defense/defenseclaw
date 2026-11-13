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
// inside the clone, or a script or program run by path after a cd into it),
// and a git push to a remote given inline instead of a configured remote
// name. Running a package manager or build tool in the clone (npm install,
// make, go test) is ordinary work and is not a run of the clone's files.
// Neither effect is an enforcement proof.
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

// isAdHocGitRemote reports a push destination given inline instead of as a
// configured remote name, in a form a contributor workflow does not use. The
// two ssh spellings of a remote, user@host:path and ssh://host/path, are one
// case: ad hoc when the host is not a well-known code-hosting service, so a
// self-hosted server reached inline alerts in both forms and a push to a
// forge never does. A URL over another transport (https, git) is ad hoc only
// when its host is a bare public IP address, since a named https remote
// carries a normal authenticated push. Pushes to a fork URL on a forge are
// ordinary and not reported.
func isAdHocGitRemote(value string) bool {
	if scheme := strings.Index(value, "://"); scheme >= 0 {
		host := value[scheme+3:]
		if at := strings.LastIndexByte(host, '@'); at >= 0 {
			host = host[at+1:]
		}
		if cut := strings.IndexAny(host, "/:"); cut >= 0 {
			host = host[:cut]
		}
		switch strings.ToLower(value[:scheme]) {
		case "ssh", "git+ssh", "ssh+git":
			return host != "" && !knownCodeForge(host)
		}
		return parsesAsUntrustedAddress(host)
	}
	at, colon := strings.IndexByte(value, '@'), strings.IndexByte(value, ':')
	if at <= 0 || colon <= at {
		return false
	}
	return !knownCodeForge(value[at+1 : colon])
}

func knownCodeForge(host string) bool {
	switch strings.ToLower(host) {
	case "github.com", "gitlab.com", "bitbucket.org", "ssh.dev.azure.com", "vs-ssh.visualstudio.com",
		"git.sr.ht", "codeberg.org", "source.developers.google.com", "ssh.github.com":
		return true
	}
	return false
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
