// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// actionFindPrivateKeyRead reports a find walk that can hand the SSH folder
// or a private key to a content-reading child. Find patterns match leading
// dots and -path wildcards span slashes, unlike shell pathname expansion.
// The caller has already expanded shell words; no host directory walk is
// needed for the guest actor's absolute workdir (GAP-1025).
func actionFindPrivateKeyRead(words []string, cwd, home string) bool {
	if len(words) < 3 || (programBase(words[0]) != "find" && programBase(words[0]) != "gfind") || !filepath.IsAbs(home) {
		return false
	}
	var starts []string
	i := 1
	for i < len(words) && words[i] != "" && !strings.HasPrefix(words[i], "-") && words[i] != "!" && words[i] != "(" {
		starts = append(starts, OperandPath(words[i], cwd))
		i++
	}
	if len(starts) == 0 {
		starts = []string{cwd}
	}
	var names, paths []string
	contentChild := false
	fileOnly, dirOnly := false, false
	minDepth, maxDepth := 0, -1
	for ; i < len(words); i++ {
		switch words[i] {
		case "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename":
			if i+1 >= len(words) || words[i+1] == "" {
				return false
			}
			if strings.Contains(words[i], "name") && words[i] != "-wholename" && words[i] != "-iwholename" {
				names = append(names, words[i+1])
			} else {
				paths = append(paths, words[i+1])
			}
			i++
		case "-type":
			if i+1 >= len(words) {
				return false
			}
			fileOnly = fileOnly || words[i+1] == "f"
			dirOnly = dirOnly || words[i+1] == "d"
			i++
		case "-maxdepth", "-mindepth":
			if i+1 >= len(words) {
				return false
			}
			depth, err := strconv.Atoi(words[i+1])
			if err != nil || depth < 0 {
				return false
			}
			if words[i] == "-maxdepth" {
				maxDepth = depth
			} else {
				minDepth = depth
			}
			i++
		case "-exec", "-execdir", "-ok", "-okdir":
			end := i + 1
			for end < len(words) && words[end] != ";" && words[end] != "+" {
				end++
			}
			if end == len(words) {
				return false
			}
			// Interactive actions require confirmation and are not read proof (GAP-0522).
			if words[i] == "-exec" || words[i] == "-execdir" {
				contentChild = contentChild || actionFindContentChild(words[i+1:end])
			}
			i = end
		}
	}
	if !contentChild {
		return false
	}
	folder := filepath.Join(home, ".ssh")
	candidates := []string{folder}
	for _, name := range actionPrivateKeyNames {
		candidates = append(candidates, filepath.Join(folder, name))
	}
	for index, candidate := range candidates {
		if index == 0 && fileOnly || index > 0 && dirOnly {
			continue
		}
		matched := true
		for _, pattern := range names {
			if !actionFindPatternMatch(pattern, filepath.Base(candidate)) {
				matched = false
				break
			}
		}
		for _, pattern := range paths {
			if !actionFindPatternMatch(pattern, filepath.ToSlash(candidate)) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		for _, start := range starts {
			rel, err := filepath.Rel(start, candidate)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			depth := 0
			if rel != "." {
				depth = strings.Count(rel, string(filepath.Separator)) + 1
			}
			if depth >= minDepth && (maxDepth < 0 || depth <= maxDepth) {
				return true
			}
		}
	}
	return false
}

func actionFindContentChild(words []string) bool {
	if len(words) == 0 {
		return false
	}
	reader := false
	switch programBase(words[0]) {
	case "cat", "head", "tail", "base64", "less", "more", "grep", "egrep", "fgrep", "rg", "xxd", "od", "hexdump", "strings", "cut", "nl", "tac", "rev", "sort", "uniq", "fold", "fmt", "pr", "paste", "diff", "comm", "awk":
		reader = true
	}
	if !reader {
		return false
	}
	for _, word := range words[1:] {
		if strings.Contains(word, "{}") {
			return true
		}
	}
	return false
}

// GNU find treats slash as an ordinary byte in -path patterns. Replacing it
// with NUL lets path.Match retain its class and escaping rules while making
// its * and ? match across components. -name has no slash to replace.
func actionFindPatternMatch(pattern, candidate string) bool {
	pattern = strings.ReplaceAll(pattern, "/", "\x00")
	candidate = strings.ReplaceAll(candidate, "/", "\x00")
	matched, err := path.Match(pattern, candidate)
	return err == nil && matched
}
