// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// ProcessCWDLinkSpelling is the path a process opens for name when name
// goes through the process's own working-directory link (/proc/self/cwd,
// /proc/thread-self/cwd or /proc/self/task/<tid>/cwd) and the process works
// in dir. The kernel opens the link at the working directory itself, so a
// dot-dot after it steps up from dir, never from the link text: the lexical
// reading of /proc/self/cwd/../.ssh/authorized_keys (/proc/self/.ssh/...)
// names a file no process opens, while dir/../.ssh/authorized_keys is the one
// it writes. The spelling is placed and cleaned the way the plain spelling
// of the same operand is, so every path rule reads it as the plain form
// (rel-1-0-10:GAP-2265). A link of another process, a root, executable or
// descriptor link, a name with shell syntax and a relative dir give no
// spelling: their target is not the working directory of this command.
func ProcessCWDLinkSpelling(name, dir string) (string, bool) {
	if !strings.HasPrefix(name, "/") || !strings.HasPrefix(dir, "/") ||
		!strings.Contains(name, "cwd") || strings.ContainsAny(name, "$`\\\x00") {
		return "", false
	}
	input := strings.Split(name, "/")
	parts := make([]string, 0, 5)
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
		if len(parts) < 3 || parts[0] != "proc" {
			continue
		}
		own := parts[1] == "self" || parts[1] == "thread-self"
		switch {
		case len(parts) == 3 && own && parts[2] == "cwd",
			len(parts) == 5 && parts[1] == "self" && parts[2] == "task" && allASCIIDigits(parts[3]) && parts[4] == "cwd":
			return path.Join(append([]string{dir}, input[i+1:]...)...), true
		case len(parts) == 3 || len(parts) > 5:
			// Any other entry below /proc/<x> before the link ends the
			// search: only the command's own cwd link is placed here.
			if !(len(parts) == 3 && parts[1] == "self" && parts[2] == "task") {
				return "", false
			}
		case len(parts) == 4 && !allASCIIDigits(parts[3]):
			return "", false
		}
	}
	return "", false
}

func allASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 48 || value[i] > 57 {
			return false
		}
	}
	return true
}
