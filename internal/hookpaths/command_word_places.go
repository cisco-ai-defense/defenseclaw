// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"
)

// LocalCommandWordPlaces places each path word of a POSIX shell command
// (CommandPathWords: the arguments of every simple command, behind any
// wrapper, every file redirect whatever its descriptor, the redirect of a
// loop or a group, the words of a static eval or -c body) in the file system
// the call runs in: Followed with every link followed, Entry with its folders
// followed and its last name kept, as the kernel walks them from cwd
// (resolve, ResolveWriteTarget or a memo of it). A word whose place is the
// one it spells is left out. LinkResolvedCommand spells the command with
// these places, so a call that reaches a file through a link is judged as
// the call that names the file (rel-1-0-10:GAP-1243: command cat key-link,
// echo x > cfg-link and the other shapes were allowed where the plain form
// blocks or alerts). The same places are what a Substrate actor's kit
// reports for its own file system.
//
// The words are placed in the hook's folder: a cd before the word may fail,
// so that folder stays a place the word may name. A relative word is placed
// in the physical folder, and an alias of a top-level folder (/tmp to
// /private/tmp on macOS) is no move of the word. /proc/self/cwd names the
// folder of the shell that opens it, not the gateway's
// (ResolveProcSelfCWDTarget); another process-relative name
// (processRelativeLink) has no place the gateway can name. Each distinct
// word is walked once.
func LocalCommandWordPlaces(command, cwd, home string, resolve func(string) (string, bool)) map[string]CommandWordPlace {
	if command == "" || !filepath.IsAbs(cwd) || resolve == nil {
		return nil
	}
	physicalCWD, ok := resolve(filepath.Clean(cwd))
	if !ok || !filepath.IsAbs(physicalCWD) {
		return nil
	}
	// A place in the physical home is spelled in the home the call names, as
	// every path rule reads it (a home under /var on macOS is /private/var).
	logical := func(place string) string { return place }
	if physicalHome, ok := resolve(filepath.Clean(home)); ok && filepath.IsAbs(physicalHome) && physicalHome != filepath.Clean(home) {
		logical = func(place string) string {
			if rest, found := strings.CutPrefix(place, physicalHome+"/"); found {
				return filepath.Join(home, rest)
			}
			if place == physicalHome {
				return filepath.Clean(home)
			}
			return place
		}
	}
	var places map[string]CommandWordPlace
	seen := map[string]bool{}
	for _, word := range CommandPathWords(command, home) {
		if seen[word.Text] {
			continue
		}
		seen[word.Text] = true
		if word.Program {
			// A program is judged by the name it runs as: a link to it
			// runs it with that name (/bin/sh to dash, python3 to
			// python3.12), and a bare name is looked up in PATH.
			continue
		}
		place, moved := localCommandWordPlace(word.Value, physicalCWD, resolve)
		if !moved {
			continue
		}
		if place.Followed != "" {
			place.Followed = logical(place.Followed)
		}
		if place.Entry != "" {
			place.Entry = logical(place.Entry)
		}
		if places == nil {
			places = map[string]CommandWordPlace{}
		}
		places[word.Text] = place
	}
	return places
}

// localCommandWordPlace is the place of one word value; moved is false when
// it is the place the word spells.
func localCommandWordPlace(value, physicalCWD string, resolve func(string) (string, bool)) (CommandWordPlace, bool) {
	full := value
	if rest, found := strings.CutPrefix(full, "/proc/self/cwd/"); found {
		full = strings.TrimRight(physicalCWD, "/") + "/" + rest
	} else if full == "/proc/self/cwd" {
		full = physicalCWD
	}
	if processRelativeLink(full) {
		return CommandWordPlace{}, false
	}
	if !strings.HasPrefix(full, "/") {
		full = strings.TrimRight(physicalCWD, "/") + "/" + full
	}
	lexical := filepath.Clean(full)
	var place CommandWordPlace
	if followed, ok := resolve(full); ok && filepath.IsAbs(followed) && followed != lexical &&
		!topLevelAlias(lexical, followed, resolve) {
		place.Followed = followed
	}
	if dir, name := filepath.Split(strings.TrimRight(full, "/")); dir != "" && name != "" && name != "." && name != ".." {
		if parent, ok := resolve(dir); ok && filepath.IsAbs(parent) {
			if entry := filepath.Join(parent, name); entry != lexical && !topLevelAlias(lexical, entry, resolve) {
				place.Entry = entry
			}
		}
	}
	return place, place.Followed != "" || place.Entry != ""
}

// topLevelAlias reports a place that differs from lexical only by the link
// of its top-level folder (/tmp/x is /private/tmp/x on macOS): the folder is
// the same for every word that names it, and the word itself moves nowhere.
func topLevelAlias(lexical, place string, resolve func(string) (string, bool)) bool {
	rest := strings.TrimPrefix(lexical, "/")
	first, tail, _ := strings.Cut(rest, "/")
	if first == "" {
		return false
	}
	physical, ok := resolve("/" + first)
	if !ok || physical == "/"+first {
		return false
	}
	if tail == "" {
		return place == physical
	}
	return place == filepath.Join(physical, tail)
}
