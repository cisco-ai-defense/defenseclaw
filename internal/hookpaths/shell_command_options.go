// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"
)

// NestedShellBody returns a fixed shell -c body. The shared shell operand
// readers use the same option grammar for nested calls.
func NestedShellBody(words []string) string {
	if len(words) < 3 {
		return ""
	}
	switch filepath.Base(words[0]) {
	case "bash", "sh", "dash", "zsh", "ash", "ksh":
	default:
		return ""
	}
	if index, ok := shellCommandBodyIndex(words); ok {
		return words[index]
	}
	return ""
}

// shellCommandBodyIndex locates a shell's -c program after fixed options.
// Unrecognized options cannot establish an exact child command.
func shellCommandBodyIndex(words []string) (int, bool) {
	for i := 1; i < len(words); i++ {
		option := words[i]
		if option == "-c" {
			return i + 1, i+1 < len(words)
		}
		if option == "--login" || option == "--noprofile" || option == "--norc" || option == "--posix" {
			continue
		}
		if !strings.HasPrefix(option, "-") || strings.HasPrefix(option, "--") || len(option) == 1 {
			return -1, false
		}
		command := false
		for _, flag := range option[1:] {
			switch flag {
			case 'c':
				command = true
			case 'a', 'b', 'e', 'f', 'h', 'i', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'u', 'v', 'x', 'B', 'C', 'E', 'H', 'P', 'T':
			default:
				return -1, false
			}
		}
		if command {
			return i + 1, i+1 < len(words)
		}
	}
	return -1, false
}
