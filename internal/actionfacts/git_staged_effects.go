// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"slices"
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
	for index, command := range facts.Commands {
		if command.Kind != CommandKindProcess || gitProgram(command) != "git" {
			continue
		}
		if subcommand, rest := gitSubcommand(command.Argv); subcommand == "push" &&
			gitPushNamesAdHocRemote(rest, gitRemoteDefinitions(facts.Commands[:index+1])) {
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

// gitPushValueOptions are the push options that take a separate value, so the
// value is not the remote.
var gitPushValueOptions = []string{"-o", "--push-option", "--receive-pack", "--exec"}

// gitPushRemote returns the repository operand of a push: the value of --repo,
// or the first operand once options and their values are skipped.
func gitPushRemote(args []string) (string, bool) {
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--repo" && index+1 < len(args):
			return args[index+1], true
		case strings.HasPrefix(argument, "--repo="):
			return strings.TrimPrefix(argument, "--repo="), true
		case strings.HasPrefix(argument, "-"):
			if !strings.Contains(argument, "=") && slices.Contains(gitPushValueOptions, argument) {
				index++
			}
		default:
			return argument, true
		}
	}
	return "", false
}

func gitPushNamesAdHocRemote(args []string, defined map[string]string) bool {
	remote, ok := gitPushRemote(args)
	if !ok {
		return false
	}
	if url, named := defined[remote]; named {
		remote = url
	}
	return isAdHocGitRemote(remote)
}

// gitRemoteDefinitions collects the remotes the action itself defines before
// a push: git remote add or set-url NAME URL, and git -c remote.NAME.url=URL.
// A push by such a name is a push to the inline address under a name.
func gitRemoteDefinitions(commands []CommandFact) map[string]string {
	defined := map[string]string{}
	for _, command := range commands {
		if command.Kind != CommandKindProcess || gitProgram(command) != "git" {
			continue
		}
		for index := 1; index+1 < len(command.Argv) && command.Argv[index] != "remote"; index++ {
			if command.Argv[index] != "-c" {
				continue
			}
			key, value, found := strings.Cut(command.Argv[index+1], "=")
			if name, isURL := remoteURLKey(key); found && isURL {
				defined[name] = value
			}
		}
		if subcommand, rest := gitSubcommand(command.Argv); subcommand == "remote" && len(rest) > 0 &&
			(rest[0] == "add" || rest[0] == "set-url") {
			var operands []string
			for _, argument := range rest[1:] {
				if !strings.HasPrefix(argument, "-") {
					operands = append(operands, argument)
				}
			}
			if len(operands) >= 2 {
				defined[operands[0]] = operands[1]
			}
		}
	}
	return defined
}

// remoteURLKey returns the remote name of a remote.<name>.url or
// remote.<name>.pushurl config key.
func remoteURLKey(key string) (string, bool) {
	rest, ok := strings.CutPrefix(key, "remote.")
	if !ok {
		return "", false
	}
	for _, suffix := range []string{".pushurl", ".url"} {
		if name, found := strings.CutSuffix(rest, suffix); found && name != "" {
			return name, true
		}
	}
	return "", false
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
	// The scp form [user@]host:path: a colon before any slash.
	colon := strings.IndexByte(value, ':')
	if colon <= 0 || strings.ContainsRune(value[:colon], '/') {
		return false
	}
	host := value[:colon]
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	// A single letter is a drive, not a host.
	if len(host) < 2 {
		return false
	}
	return !knownCodeForge(host)
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
		if later.Program == "cd" && len(later.Argv) == 2 {
			target := later.Argv[1]
			switch {
			case cleanRelative(target) == directory:
				inside = true
			case strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~") || strings.HasPrefix(target, ".."):
				inside = false
			}
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
