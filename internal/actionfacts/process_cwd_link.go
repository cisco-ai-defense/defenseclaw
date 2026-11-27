// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// ProcessCWDLinkSpelling is the path a process opens for name when name
// goes through the process's own working-directory link (/proc/self/cwd or
// /proc/thread-self/cwd) and the process works in dir. The kernel opens the
// link at the working directory itself, so a dot-dot right after it steps
// up from dir, never from the link text: the lexical reading of
// /proc/self/cwd/../.ssh/authorized_keys (/proc/self/.ssh/...) names a file
// no process opens, while dir/../.ssh/authorized_keys is the one it writes.
// The spelling is placed and cleaned the way the plain spelling of the same
// operand is, so every path rule reads it as the plain form
// (rel-1-0-10:GAP-2265). A link of another process or thread (a task link
// names a thread the call cannot show: rel-1-0-10:GAP-2237), a root,
// executable or descriptor link, a name with shell syntax and a relative dir
// give no spelling: their target is not the working directory of this
// command. Nor do the bare link and a name with a dot-dot after one of its
// other components (processCWDLinkRestPlaceable).
func ProcessCWDLinkSpelling(name, dir string) (string, bool) {
	if !strings.HasPrefix(name, "/") || !strings.HasPrefix(dir, "/") ||
		!strings.Contains(name, "cwd") || strings.ContainsAny(name, "$`\\\x00") {
		return "", false
	}
	input := strings.Split(name, "/")
	parts := make([]string, 0, 3)
	for i := 1; i < len(input); i++ {
		switch input[i] {
		case "", ".":
			continue
		case "..":
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
			continue
		}
		parts = append(parts, input[i])
		if len(parts) != 3 || parts[0] != "proc" {
			continue
		}
		// Only the command's own cwd link is placed here; any other entry
		// three deep below /proc ends the search.
		if parts[1] != "self" && parts[1] != "thread-self" || parts[2] != "cwd" {
			return "", false
		}
		rest := input[i+1:]
		if !processCWDLinkRestPlaceable(rest) {
			return "", false
		}
		return path.Join(append([]string{dir}, rest...)...), true
	}
	return "", false
}

// processCWDLinkRestPlaceable reports the part of a name after the cwd link
// that a lexical join below the working directory reads as the kernel does:
// at least one component, and every dot-dot before the first other
// component. A dot-dot right after the link steps up from the working
// directory itself; one after a name steps up from whatever that name is,
// which may be a link the call cannot show, so such a name and the bare link
// keep the reading they had before (rel-1-0-10:GAP-2265 parity: a guest
// write through cwd/../root/../ kept its block only on a Linux gateway).
func processCWDLinkRestPlaceable(rest []string) bool {
	named, any := false, false
	for _, part := range rest {
		switch part {
		case "", ".":
			continue
		case "..":
			if named {
				return false
			}
		default:
			named = true
		}
		any = true
	}
	return any
}
