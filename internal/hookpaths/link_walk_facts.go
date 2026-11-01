// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path"
	"runtime"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// WalkFactPrefix keys the hook client's walk of one directory spelling a
// command word names, as the kernel walks it (links followed, a `..` after
// a link ascending from the link's target). The value is the physical
// directory. Only a spelling whose physical place differs from its lexical
// one is listed. A managed gateway may not read the user's home
// (ProtectHome, another account), so it places a link-walk operand such as
// `rm -rf dclink/../.defenseclaw/hooks` or `git -C dclink clean -fdx` only
// from these facts (GAP-2569). A fact that does not fit is omitted: the
// gateway reads a missing fact as unknown, as before.
const WalkFactPrefix = "\x00walk:"

const (
	maxWalkFactWords      = 64
	maxWalkFactComponents = 24
	maxWalkFacts          = 32
)

// WalkKey is the key spelling of an absolute slash path: empty and `.`
// components are dropped, `..` components are kept (they are walked, not
// cleaned).
func WalkKey(value string) string {
	parts := strings.Split(value, "/")
	kept := parts[:0]
	for _, part := range parts {
		if part != "" && part != "." {
			kept = append(kept, part)
		}
	}
	return "/" + strings.Join(kept, "/")
}

// LinkWalkFacts walks the static path words of a POSIX shell command (and
// the value of a --name=VALUE option) from cwd and returns a WalkFactPrefix
// fact for every directory prefix whose physical place differs from its
// lexical spelling. Words after the first pattern or expansion are not
// walked.
func LinkWalkFacts(command, cwd, home string) map[string]string {
	if runtime.GOOS == "windows" || !strings.HasPrefix(cwd, "/") {
		return nil
	}
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	var words []string
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if len(words) >= maxWalkFactWords {
				return false
			}
			if word, static := walkFactWord(arg, home); static {
				words = append(words, word)
			}
		}
		return true
	})
	facts := map[string]string{}
	for _, word := range words {
		full := word
		if !strings.HasPrefix(full, "/") {
			full = strings.TrimRight(cwd, "/") + "/" + full
		}
		key := WalkKey(full)
		components := strings.Split(strings.TrimPrefix(key, "/"), "/")
		if len(components) > maxWalkFactComponents {
			components = components[:maxWalkFactComponents]
		}
		for index := range components {
			prefix := "/" + strings.Join(components[:index+1], "/")
			if _, seen := facts[WalkFactPrefix+prefix]; seen {
				continue
			}
			physical, resolved := ResolveWriteTarget(prefix)
			if !resolved || physical == path.Clean(prefix) || len(prefix) > MaxWriteTargetPathBytes {
				continue
			}
			if len(facts) >= maxWalkFacts {
				return facts
			}
			facts[WalkFactPrefix+prefix] = physical
		}
	}
	return facts
}

// walkFactWord is one static word as a path spelling: the value of a
// --name=VALUE option, else the word, up to the first pattern component; an
// option word and an empty word are not paths.
func walkFactWord(arg *syntax.Word, home string) (string, bool) {
	word, static := StaticWord(staticPatternPrefix(arg), home)
	if !static || word == "" {
		return "", false
	}
	if strings.HasPrefix(word, "--") {
		_, value, found := strings.Cut(word, "=")
		if !found || value == "" {
			return "", false
		}
		word = value
	} else if strings.HasPrefix(word, "-") {
		return "", false
	}
	if strings.HasPrefix(word, "~") || strings.ContainsRune(word, 0) {
		return "", false
	}
	return word, true
}

// staticPatternPrefix is word up to the directory before its first
// unquoted pattern character (`dclink/../.defenseclaw/*` gives
// `dclink/../.defenseclaw/`), or word itself when it has none.
func staticPatternPrefix(word *syntax.Word) *syntax.Word {
	if word == nil {
		return nil
	}
	for index, part := range word.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			continue
		}
		at := strings.IndexAny(lit.Value, "*?[")
		if at < 0 {
			continue
		}
		cut := strings.LastIndex(lit.Value[:at], "/")
		if cut < 0 {
			return nil
		}
		parts := append(slices.Clone(word.Parts[:index]), &syntax.Lit{Value: lit.Value[:cut+1]})
		return &syntax.Word{Parts: parts}
	}
	return word
}

// WalkFactTarget places an absolute slash spelling from the client's walk
// facts: the fact for the spelling itself, else the longest walked prefix
// with the rest joined lexically when the rest has no `..` (a `cd dclink;
// cd hooks` directory the client saw only as dclink). ok is false when no
// fact covers it.
func WalkFactTarget(targets map[string]string, spelling string) (string, bool) {
	if len(targets) == 0 || !strings.HasPrefix(spelling, "/") {
		return "", false
	}
	key := WalkKey(spelling)
	if physical, found := targets[WalkFactPrefix+key]; found {
		return physical, strings.HasPrefix(physical, "/")
	}
	components := strings.Split(strings.TrimPrefix(key, "/"), "/")
	for index := len(components) - 1; index >= 1; index-- {
		physical, found := targets[WalkFactPrefix+"/"+strings.Join(components[:index], "/")]
		if !found {
			continue
		}
		rest := components[index:]
		for _, part := range rest {
			if part == ".." {
				return "", false
			}
		}
		if !strings.HasPrefix(physical, "/") {
			return "", false
		}
		return path.Join(append([]string{physical}, rest...)...), true
	}
	return "", false
}
