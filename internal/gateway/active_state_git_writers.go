// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strings"
)

// Option forms that write a named file or directory, which ActionFacts does
// not model as a write target, and git subcommands that rewrite a work tree
// placed on the state (GAP-2485): `install -t ~/.defenseclaw/hooks x`,
// `sort -o ~/.defenseclaw/config.yaml x`, `git --work-tree ~/.defenseclaw
// stash -u` / `checkout -f -- .` / `reset --hard`, and a clean or stash of
// untracked files from the home work tree (`git -C ~ clean -fdx`), which
// takes the state root with it. Reads and project or dotfiles forms stay
// allowed: `install -t ~/.local/bin x`, `sort -o ~/proj/out x`, `git
// --git-dir=~/dotfiles --work-tree=~ checkout -- .vimrc`.

// installStateTarget reports an install whose -t/--target-directory names a
// protected tree, or the state root with a source named like protected state.
func installStateTarget(words []string, home, cwd string) bool {
	var target string
	var sources []string
	optionsDone := false
	for index := 0; index < len(words); index++ {
		word := words[index]
		switch {
		case word == "":
		case optionsDone:
			sources = append(sources, word)
		case word == "--":
			optionsDone = true
		case word == "-t" || word == "--target-directory":
			if index+1 < len(words) {
				index++
				target = words[index]
			}
		case strings.HasPrefix(word, "--target-directory="):
			target = strings.TrimPrefix(word, "--target-directory=")
		case strings.HasPrefix(word, "--"):
		case strings.HasPrefix(word, "-") && len(word) > 1:
			// -m, -o, -g, -S take a value; a cluster ending in one takes
			// the next word, one inside takes the rest.
			for at := 1; at < len(word); at++ {
				switch word[at] {
				case byte(116): // t
					if at+1 < len(word) {
						target = word[at+1:]
					} else if index+1 < len(words) {
						index++
						target = words[index]
					}
					at = len(word)
				case byte(109), byte(111), byte(103), byte(83): // m o g S
					if at+1 == len(word) {
						index++
					}
					at = len(word)
				}
			}
		default:
			sources = append(sources, word)
		}
	}
	if target == "" {
		return false
	}
	tree, root := stateDirectoryOf(target, home, cwd)
	if tree {
		return true
	}
	if !root {
		return false
	}
	for _, source := range sources {
		if stateLandingReached(target, path.Base(strings.TrimRight(source, "/")), home, cwd) {
			return true
		}
	}
	return false
}

// sortStateOutput reports a sort whose -o/--output file is protected state.
func sortStateOutput(words []string, home, cwd string) bool {
	var outputs []string
	for index := 0; index < len(words); index++ {
		word := words[index]
		switch {
		case word == "--":
			index = len(words)
		case word == "--output" || word == "-o":
			if index+1 < len(words) {
				index++
				outputs = append(outputs, words[index])
			}
		case strings.HasPrefix(word, "--output="):
			outputs = append(outputs, strings.TrimPrefix(word, "--output="))
		case strings.HasPrefix(word, "--"):
		case strings.HasPrefix(word, "-") && len(word) > 1:
			for at := 1; at < len(word); at++ {
				switch word[at] {
				case byte(111): // o
					if at+1 < len(word) {
						outputs = append(outputs, word[at+1:])
					} else if index+1 < len(words) {
						index++
						outputs = append(outputs, words[index])
					}
					at = len(word)
				case byte(107), byte(116), byte(83), byte(84): // k t S T take the rest
					if at+1 == len(word) {
						index++
					}
					at = len(word)
				}
			}
		}
	}
	for _, output := range outputs {
		if output != "" && statePatternReaches(output, home, cwd) {
			return true
		}
	}
	return false
}

// gitGlobalValueOptions are the git options before the subcommand whose
// value can be the next word.
var gitGlobalValueOptions = map[string]bool{
	"-C": true, "-c": true, "--work-tree": true, "--git-dir": true, "--namespace": true,
	"--config-env": true, "--super-prefix": true,
}

// gitSubcommandIndex is the index of the git subcommand in words, or -1.
func gitSubcommandIndex(words []string) int {
	for index := 0; index < len(words); index++ {
		word := words[index]
		switch {
		case gitGlobalValueOptions[word]:
			index++
		case word == "" || strings.HasPrefix(word, "-"):
		default:
			return index
		}
	}
	return -1
}

// gitShortOption reports a short option cluster (not after --) holding c.
func gitShortOption(words []string, c byte) bool {
	for _, word := range words {
		if word == "--" {
			return false
		}
		if len(word) > 1 && word[0] == byte(45) && word[1] != byte(45) && strings.IndexByte(word, c) > 0 {
			return true
		}
	}
	return false
}

func gitLongOption(words []string, names ...string) bool {
	for _, word := range words {
		if word == "--" {
			return false
		}
		if slices.Contains(names, word) {
			return true
		}
	}
	return false
}

// gitWorkTreeStateWrite reports a git subcommand that rewrites the files of
// a work tree that is (in) the state, or that removes untracked files from a
// work tree above the state root (the home), which holds the state root.
func gitWorkTreeStateWrite(words []string, home, cwd string) bool {
	sub := gitSubcommandIndex(words)
	if sub < 0 {
		return false
	}
	name, args := words[sub], words[sub+1:]
	base, ok := gitWorkDirectory(words[:sub], home, cwd)
	if !ok {
		return false
	}
	tree, root := stateDirectoryOf(base, home, cwd)
	onState := tree || root
	// Above the state root only a work tree the call names (-C,
	// --work-tree) counts: whether the directory a session or a cd
	// leaves the call in (the home, /tmp) is a git work tree at all is not
	// proven by the command, so `git stash -u` or `cd /tmp && git clean
	// -fdx` from a home session stays allowed (pod check26, BALANCED rule 1).
	named := slices.ContainsFunc(words[:sub], func(word string) bool {
		return word == "-C" || word == "--work-tree" || strings.HasPrefix(word, "--work-tree=")
	})
	stateRoot := strings.TrimRight(home, "/") + "/.defenseclaw"
	above := named && (base == "/" || strings.HasPrefix(stateRoot, strings.TrimRight(base, "/")+"/"))
	stashUntracked := gitShortOption(args, byte(117)) || gitShortOption(args, byte(97)) ||
		gitLongOption(args, "--include-untracked", "--all")
	switch name {
	case "stash":
		action := ""
		for _, word := range args {
			if word != "" && !strings.HasPrefix(word, "-") {
				action = word
				break
			}
		}
		switch action {
		case "", "push", "save":
			return onState || above && stashUntracked
		case "pop", "apply", "branch":
			return onState
		}
	case "clean":
		// Inside the state the clean check above judges it; above it, a
		// forced clean of untracked directories takes the state root.
		return above && !onState && gitCleanForcesAny(args) && !gitCleanDryRunAny(args) &&
			(gitShortOption(args, byte(100)) || gitShortOption(args, byte(120))) &&
			len(gitCleanPathspecs(append([]string{"clean"}, args...))) == 0
	case "checkout", "switch", "restore", "merge", "pull", "rebase", "cherry-pick", "revert",
		"am", "read-tree", "checkout-index", "mv":
		return onState
	case "reset":
		return onState && gitLongOption(args, "--hard", "--merge", "--keep")
	case "rm":
		return onState && !gitLongOption(args, "--cached")
	case "apply":
		return onState && !gitLongOption(args, "--cached", "--check", "--stat", "--numstat", "--summary")
	}
	return false
}

func gitCleanForcesAny(args []string) bool {
	return slices.ContainsFunc(args, gitCleanForces)
}

func gitCleanDryRunAny(args []string) bool {
	return slices.ContainsFunc(args, gitCleanDryRun)
}

// gitWorkDirectory is the work tree of a git call from its words before the
// subcommand: gitCleanDirectory with the subcommand cut off.
func gitWorkDirectory(globals []string, home, cwd string) (string, bool) {
	return gitCleanDirectory(append(slices.Clone(globals), "clean"), home, cwd)
}
