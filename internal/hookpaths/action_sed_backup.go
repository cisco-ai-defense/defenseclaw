// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// sed -i leaves a backup of each file under a name made from the suffix
// (GNU sed: every * of the suffix is the file's base name, a suffix without
// one is appended; a name with a slash is a path). The backup is a rename of
// the original over that name, so a suffix that names a protected file
// replaces it (rel-1-0-10 GAP-0414, HLR3-SFX). The replace-verb proof holds
// only for a bare -i or --in-place; this reads the suffix of every other
// spelling and judges the backup names it makes.

// sedInPlaceSuffix reads the in-place option of one sed argument word. It
// returns the suffix text (empty for a bare -i), whether the word is an
// in-place option at all, and whether the suffix is exact: attached to -i in a
// cluster of flags that take no argument (-i, -ni, -i.bak, -nEi.bak), or after
// --in-place=. A word that is not an option, or an option of another kind, is
// not in-place.
func sedInPlaceSuffix(text string) (suffix string, inPlace bool) {
	if rest, ok := strings.CutPrefix(text, "--in-place"); ok {
		switch {
		case rest == "":
			return "", true
		case strings.HasPrefix(rest, "="):
			return rest[1:], true
		}
		return "", false
	}
	if len(text) < 2 || text[0] != '-' || text[1] == '-' {
		return "", false
	}
	for i := 1; i < len(text); i++ {
		switch text[i] {
		case 'n', 'E', 'r', 's', 'u', 'z':
			continue
		case 'i':
			return text[i+1:], true
		}
		return "", false
	}
	return "", false
}

// sedBackupNames returns the paths sed -i would write a backup of file to for
// suffix. A suffix with a slash is a path: it is read relative to the file's
// directory and to the working directory, both.
func sedBackupNames(file, suffix, cwd string) []string {
	if suffix == "" {
		return nil
	}
	base, dir := filepath.Base(file), filepath.Dir(file)
	name := base + suffix
	if strings.Contains(suffix, "*") {
		name = strings.ReplaceAll(suffix, "*", base)
	}
	if !strings.Contains(name, "/") {
		return []string{filepath.Join(dir, name)}
	}
	if filepath.IsAbs(name) {
		return []string{filepath.Clean(name)}
	}
	return []string{filepath.Join(dir, name), filepath.Join(cwd, name)}
}

// sedBackupReachesProtected reports a sed -i call whose backup name is, or
// replaces, a protected file. A suffix or operand it cannot read exactly is
// reported by UncertainWriteReason, not here.
func sedBackupReachesProtected(command, cwd, home string, memo *TargetMemo) bool {
	if home == "" || !filepath.IsAbs(cwd) || actionWindowsHome(home) ||
		!strings.Contains(command, "sed") || !strings.Contains(command, "-") {
		return false
	}
	file, parsed := parseShell(command)
	if !parsed {
		return false
	}
	values := actionValues{"HOME": home, "PWD": cwd}
	startup := memo.shellStartup()
	options := shellGlobOptionsForCall(command, startup)
	protected := memo.protectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		values["PWD"] = cwd
		actionUpdateValues(stmt, values, cwd, home)
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		program, fixed := staticProgramWord(call.Args[0], home)
		if !fixed || (programBase(program) != "sed" && programBase(program) != "gsed") {
			return true
		}
		var suffixes []string
		var operands []*syntax.Word
		haveScript := false
		for i := 1; i < len(call.Args); i++ {
			word := call.Args[i]
			// The word as the shell passes it (quotes removed; the pattern
			// characters of an unmatched word stay as written).
			fields, err := expand.Fields(resolverConfig(values, cwd), word)
			if err != nil || len(fields) != 1 {
				continue
			}
			text := fields[0]
			if text == "-e" || text == "--expression" || text == "-f" || text == "--file" {
				i++
				haveScript = true
				continue
			}
			if suffix, in := sedInPlaceSuffix(text); in {
				if suffix != "" {
					suffixes = append(suffixes, suffix)
				}
				continue
			}
			if strings.HasPrefix(text, "-") && text != "-" {
				continue
			}
			if !haveScript {
				haveScript = true
				continue
			}
			operands = append(operands, word)
		}
		for _, operand := range operands {
			resolved := resolveWriteWord(operand, values, cwd, options)
			for _, target := range resolved.candidates {
				for _, suffix := range suffixes {
					for _, backup := range sedBackupNames(target, suffix, cwd) {
						if protectedReachPathWith(backup, protected, ssh, memo) {
							found = true
							return false
						}
					}
				}
			}
		}
		return true
	})
	return found
}
