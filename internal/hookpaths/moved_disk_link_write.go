// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"mvdan.cc/sh/v3/syntax"
)

// actionMovedDiskLinkWrite reports a write, among the resolved write
// targets of a command, to the new name of an existing disk link to the
// authorized-keys file or the .ssh directory that a static mv or gmv of the
// same command renames: mv keylink k2; echo x >> k2 writes the keys file.
// The link walk follows only the links the command makes, and a resolved
// write target is read on the disk as it is before the command runs, where
// the new name does not exist yet. The hook client reads this as the user
// (actionConcreteProtectedWrite, ActionDecisionKey), so a managed gateway
// that cannot see the link blocks the write as a per-user gateway does
// (rel-1-0-6:GAP-0045). A move of a link to any other file, a write to
// another name and a move whose operands are not static are not read here.
func actionMovedDiskLinkWrite(command, cwd, home string, writes []string) bool {
	if len(writes) == 0 || home == "" {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	protected := newProtectedFiles(home)
	keysDir := filepath.Join(home, ".ssh")
	placed, placedKnown := topLevelLinkDirectories(file, cwd, home)
	// moved maps a new name to the protected path its link names.
	moved := map[string]string{}
	var backups []movedBackup
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 3 {
			return true
		}
		words := make([]string, 0, len(call.Args))
		for _, word := range call.Args {
			value, static := StaticWord(word, home)
			if !static {
				return true
			}
			words = append(words, value)
		}
		if program := filepath.Base(words[0]); program != "mv" && program != "gmv" {
			return true
		}
		dirs := []string{cwd}
		if placedKnown && len(placed[call]) > 0 {
			dirs = append(dirs, placed[call]...)
		}
		for _, dir := range dirs {
			op, ok := parseRename(words[1:], dir)
			if !ok {
				continue
			}
			for _, source := range op.sources {
				from := absolutePath(source, dir)
				if info, err := os.Lstat(from); err != nil || info.Mode()&os.ModeSymlink == 0 {
					continue
				}
				target, resolved := ResolveWriteTarget(from)
				if !resolved || !protectedReachPath(from, protected, keysDir) {
					continue
				}
				for _, dest := range op.destinations(source) {
					moved[filepath.Clean(dest)] = target
				}
			}
			// A move with a backup option onto an existing link keeps
			// the link as a backup entry beside it (rel-1-0-6:GAP-0144).
			if op.backup && op.dest != "" && op.targetDir == "" && len(op.sources) == 1 {
				dest := absolutePath(op.dest, dir)
				if info, err := os.Lstat(dest); err == nil && info.Mode()&os.ModeSymlink != 0 {
					if protectedReachPath(dest, protected, keysDir) {
						backups = append(backups, movedBackup{dest: dest, suffix: op.suffix})
					}
				}
			}
		}
		return true
	})
	for _, write := range writes {
		path := filepath.Clean(OperandPath(write, cwd))
		for _, backup := range backups {
			if backup.names(path) {
				return true
			}
		}
	}
	if len(moved) == 0 {
		return false
	}
	names := make([]string, 0, len(moved))
	for name := range moved {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, write := range writes {
		path := filepath.Clean(OperandPath(write, cwd))
		for _, name := range names {
			rest, under := cutPathPrefix(path, name)
			if !under {
				continue
			}
			// The new name is the link: a write to it reaches the file or
			// directory the link names; a write below a moved link to the
			// .ssh directory reaches a file in it.
			if rest == "" {
				return true
			}
			if reached := filepath.Join(moved[name], rest); protected.has(reached) || protectedReachPath(reached, protected, keysDir) {
				return true
			}
		}
	}
	return false
}

// movedBackup is the backup entry a mv with a backup option makes of an
// existing destination link to the keys file or the .ssh directory.
type movedBackup struct{ dest, suffix string }

// names reports a write path that is that backup entry or lies below it:
// the destination name with the suffix, with the default ~ or with a
// numbered .~N~ suffix.
func (b movedBackup) names(path string) bool {
	dir, base := filepath.Dir(b.dest), filepath.Base(b.dest)
	for filepath.Dir(path) != dir {
		parent := filepath.Dir(path)
		if parent == path {
			return false
		}
		path = parent
	}
	rest, ok := strings.CutPrefix(filepath.Base(path), base)
	if !ok || rest == "" {
		return false
	}
	return rest == "~" || b.suffix != "" && rest == b.suffix || movedBackupNumbered.MatchString(rest)
}

var movedBackupNumbered = lazyregexp.New(`^\.~[0-9]+~$`)
