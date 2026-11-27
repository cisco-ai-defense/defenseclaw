// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// madeLinks are the links the ln calls of one command make: the absolute
// link name, slash-separated, and the target it stores, placed as the link
// reader places it (a dot-dot kept). The literal write readers ask it before
// they clean a destination's dot-dot, so a write through a link the same
// command makes reaches the place the kernel opens (rel-1-0-10:GAP-2287).
type madeLinks map[string]string

// commandMadeLinks reads the static ln calls of file in the directories the
// statement walk places them in. A command with no ln call costs one scan of
// its text.
func commandMadeLinks(file *syntax.File, command, cwd, home string) madeLinks {
	if file == nil || !strings.Contains(command, "ln") {
		return nil
	}
	// Its own placement: the literal reader's may read the tree before a
	// known-value frame renames it (placedCalls.renamed).
	placed := newPlacedCalls(file, command, cwd, home)
	var made madeLinks
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		first, ok := StaticWord(call.Args[0], home)
		if program := programBase(first); !ok || program != "ln" && program != "gln" {
			return true
		}
		words := make([]string, len(call.Args)-1)
		for i, arg := range call.Args[1:] {
			if words[i], ok = StaticWord(arg, home); !ok {
				return true
			}
		}
		for _, dir := range placed.of(call) {
			var links shellLinks
			if !links.add("ln", words, dir) {
				continue
			}
			for _, alias := range links.aliases {
				if made == nil {
					made = make(madeLinks, 2)
				}
				made[filepath.ToSlash(alias.name)] = filepath.ToSlash(alias.target)
			}
		}
		return true
	})
	return made
}

// linkBeforeStep reports a placed absolute path whose walk passes a link the
// kernel follows before a later step, which a lexical clean would erase: a
// dot-dot that follows a link the command makes or a link on disk (the step
// leaves the link target, not the folder the link is in), or a link the
// command makes to a process link (the place depends on the process that
// writes). Such a path is kept as written, so the write proofs resolve the
// links first (rel-1-0-10:GAP-2287). A path with no dot-dot costs no read
// when the command makes no link.
func (m madeLinks) linkBeforeStep(placed string) bool {
	slashed := filepath.ToSlash(placed)
	if !strings.HasPrefix(slashed, "/") {
		return false
	}
	if len(m) == 0 && !strings.Contains(slashed, "/../") && !strings.HasSuffix(slashed, "/..") {
		return false
	}
	// prefix is the walk so far, "/" and the kept parts; ends holds its
	// length after each kept part. A part in or a step out costs no rebuild,
	// so a long path costs one pass, not a join per part (CHK-T6-2287 H1).
	prefix := make([]byte, 0, len(slashed))
	ends := make([]int, 0, 8)
	var notLink map[string]bool
	for _, part := range strings.Split(slashed, "/")[1:] {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(ends) == 0 {
				continue
			}
			if _, made := m[string(prefix)]; made {
				return true
			}
			// A folder already read is no link: a repeated x/.. reads once.
			if !notLink[string(prefix)] {
				name := string(prefix)
				if info, err := pathLstat(filepath.FromSlash(name)); err == nil && info.Mode()&os.ModeSymlink != 0 {
					return true
				}
				if notLink == nil {
					notLink = make(map[string]bool)
				}
				notLink[name] = true
			}
			ends = ends[:len(ends)-1]
			prefix = prefix[:0]
			if len(ends) != 0 {
				prefix = prefix[:ends[len(ends)-1]]
			}
			continue
		}
		prefix = append(append(prefix, '/'), part...)
		ends = append(ends, len(prefix))
		if len(m) != 0 {
			if target, made := m[string(prefix)]; made && throughProcessLink(target) {
				return true
			}
		}
	}
	return false
}

// DotDotMoveDestinations lists, for the hook config guard, the files the
// static mv, install and rsync calls of command write through a destination
// spelled with a dot-dot, placed as a cp destination is (copyDestinationPath):
// cleaned, unless a process link or a link the dot-dot steps out of decides
// the place. The literal write reader lists these calls only below a process
// link (rel-1-0-10:GAP-2275), and the registration reader walks the raw
// spelling, which fails at a folder that does not exist yet, so a move into
// x/../.claude/settings.json named no hook file while the plain spelling
// did (rel-1-0-10:GAP-2288). The plain spellings stay with those readers.
func DotDotMoveDestinations(command, cwd, home string) []string {
	if !filepath.IsAbs(cwd) || !strings.Contains(command, "..") {
		return nil
	}
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	placed := newPlacedCalls(file, command, cwd, home)
	made := commandMadeLinks(file, command, cwd, home)
	var out []string
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 3 {
			return true
		}
		words := make([]string, len(call.Args))
		for i, arg := range call.Args {
			if words[i], ok = StaticWord(arg, home); !ok {
				return true
			}
		}
		program := programBase(words[0])
		switch program {
		case "mv", "gmv", "install", "ginstall", "rsync":
		default:
			return true
		}
		for _, dir := range placed.of(call) {
			for _, name := range moveWrites(program, words, dir) {
				slashed := filepath.ToSlash(name)
				if !strings.Contains(slashed, "/../") && !strings.HasSuffix(slashed, "/..") {
					continue
				}
				if !throughProcessLink(name) && !made.linkBeforeStep(name) {
					name = filepath.Clean(name)
				}
				if !slices.Contains(out, name) {
					out = append(out, name)
				}
			}
		}
		return true
	})
	return out
}
