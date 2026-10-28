// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// StateRootSiblingsPrefix + the state root carries the hook client's
// listing, read as the user, of the state root's parent directory:
// StateRootSiblings. A managed gateway runs as a service account that
// cannot list the user's home (_defenseclaw on macOS, ProtectHome on
// Linux), so it reads this fact instead (GAP-2404 pod check20).
const StateRootSiblingsPrefix = "\x00state-root-siblings:"

// StateRootSiblings is "0" when no name in the parent directory of root
// but root's own starts with root's name, in any letter case, and "1"
// when one does or the directory cannot be read. An archive named
// ~/.defenseclaw.zip strips to the state root ("${1%.zip}"), so a find
// that unzips each archive into its stripped name may reach the state
// only when this is "1".
func StateRootSiblings(root string) string {
	root = filepath.Clean(root)
	name := strings.ToLower(filepath.Base(root))
	entries, err := os.ReadDir(filepath.Dir(root))
	if err != nil || name == "." || name == string(filepath.Separator) {
		return "1"
	}
	for _, entry := range entries {
		other := strings.ToLower(entry.Name())
		if other != name && strings.HasPrefix(other, name) {
			return "1"
		}
	}
	return "0"
}

// StateTreeNamePrefix + StateTreeNameKey carries the hook client's answer,
// read as the user, to whether a file or directory of the protected state
// under a root has a name a find -name (or -iname) pattern matches:
// StateTreeHasName. A managed gateway cannot read the home, so its own
// index of the state tree counts every pattern as a match and refused
// every home find with a name test (GAP-2404 pod check20, managed RHEL).
const StateTreeNamePrefix = "\x00state-tree-name:"

// MaxStateTreeNameFacts bounds the name tests one call's map answers.
const MaxStateTreeNameFacts = 8

// ActiveStateProtectedTrees are the directories of the state root whose
// files are protected state (not logs/, backups/ or the uv cache).
var ActiveStateProtectedTrees = []string{
	"cache", "hooks", "installer", "policies", "previous", "quarantine", "receipts", "registries",
}

// activeStateNameWalkLimit bounds one walk of the protected trees; a
// larger state counts as holding every name.
const activeStateNameWalkLimit = 400000

// StateTreeNameKey is the target-map key of StateTreeHasName's answer.
func StateTreeNameKey(root, pattern string, fold bool) string {
	letter := "c"
	if fold {
		letter = "i"
	}
	return StateTreeNamePrefix + filepath.Clean(root) + "\x00" + letter + pattern
}

// StateTreeHasName is "1" when a file or directory of the protected state
// under root (the root's own entries and its protected trees, at any depth)
// has a name pattern matches, or when a tree cannot be read or is over the
// walk bound, and "0" otherwise (a missing root holds no name).
func StateTreeHasName(root, pattern string, fold bool) string {
	if fold {
		pattern = strings.ToLower(pattern)
	}
	match := func(name string) bool {
		if fold {
			name = strings.ToLower(name)
		}
		matched, err := path.Match(pattern, name)
		return err != nil || matched
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return "0"
	}
	if err != nil {
		return "1"
	}
	seen := 0
	for _, entry := range entries {
		if match(entry.Name()) {
			return "1"
		}
		if !entry.IsDir() || !slices.Contains(ActiveStateProtectedTrees, entry.Name()) {
			continue
		}
		found := false
		walkErr := filepath.WalkDir(filepath.Join(root, entry.Name()), func(_ string, item fs.DirEntry, err error) error {
			seen++
			if err != nil || seen > activeStateNameWalkLimit || match(item.Name()) {
				found = true
				return fs.SkipAll
			}
			return nil
		})
		if found || walkErr != nil {
			return "1"
		}
	}
	return "0"
}

// stateTreeNameFacts answers StateTreeHasName for the -name and -iname
// tests of the find commands of facts (MaxStateTreeNameFacts at most).
func stateTreeNameFacts(facts actionfacts.Facts, home string) map[string]string {
	if !filepath.IsAbs(home) {
		return nil
	}
	root := filepath.Join(home, ".defenseclaw")
	out := map[string]string{}
	for _, command := range facts.Commands {
		if !strings.EqualFold(filepath.Base(command.Program), "find") {
			continue
		}
		for index := 0; index+1 < len(command.Argv); index++ {
			test := command.Argv[index]
			if test != "-name" && test != "-iname" {
				continue
			}
			key := StateTreeNameKey(root, command.Argv[index+1], test == "-iname")
			if _, done := out[key]; done {
				continue
			}
			if len(out) >= MaxStateTreeNameFacts {
				return out
			}
			out[key] = StateTreeHasName(root, command.Argv[index+1], test == "-iname")
		}
	}
	return out
}
