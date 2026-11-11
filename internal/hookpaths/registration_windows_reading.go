// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"slices"
	"strings"
)

// RegistrationWriteReached runs the shared concrete shell mutation reader
// against a caller-supplied registration set and returns the members of that
// set the command provably writes, in the order given. On a Windows host the
// command is read twice, as the protected decision reads it
// (actionWindowsTargetMention): with the POSIX grammar Git Bash uses, and with
// a backslash inside a word read as a path separator
// (registrationWindowsReading). A member either reading reaches is reached.
func RegistrationWriteReached(command, cwd, home string, names []string) []string {
	reached := registrationWriteReachedAs(command, cwd, home, names)
	reading, windows := registrationWindowsReading(command)
	if !windows || len(reached) == len(names) {
		return reached
	}
	more := registrationWriteReachedAs(reading, cwd, home, names)
	if len(more) == 0 {
		return reached
	}
	var merged []string
	for _, name := range names {
		if slices.Contains(reached, name) || slices.Contains(more, name) {
			merged = append(merged, name)
		}
	}
	return merged
}

// RegistrationArchivePossibleReach reports an extraction into a directory
// containing a registration when the archive's entries are not named in the
// command, in either reading of the command on a Windows host. This is a
// possible write; callers choose its profile grade.
func RegistrationArchivePossibleReach(command, cwd, home string, names []string) string {
	if found := registrationArchivePossibleReachAs(command, cwd, home, names); found != "" {
		return found
	}
	if reading, windows := registrationWindowsReading(command); windows {
		return registrationArchivePossibleReachAs(reading, cwd, home, names)
	}
	return ""
}

// registrationWindowsReading returns, on a Windows host, the command with a
// backslash inside a word read as a path separator, so a native path such as
// C:\Users\me\.claude names that folder whichever shell runs the call. It
// reports false off Windows and when that reading is the same text.
func registrationWindowsReading(command string) (string, bool) {
	if runtime.GOOS != "windows" || !strings.Contains(command, `\`) {
		return "", false
	}
	reading := windowsSeparatorSpelling(command)
	return reading, reading != command
}

// windowsSeparatorSpelling replaces with / every backslash between two word
// characters. A backslash next to a blank, a shell operator, a quote or
// another backslash stays an escape, so the \; that ends a find action and an
// escaped blank keep their meaning.
func windowsSeparatorSpelling(command string) string {
	var out strings.Builder
	out.Grow(len(command))
	for i := 0; i < len(command); i++ {
		if command[i] == '\\' && i > 0 && i+1 < len(command) &&
			windowsWordByte(command[i-1]) && windowsWordByte(command[i+1]) {
			out.WriteByte('/')
			continue
		}
		out.WriteByte(command[i])
	}
	return out.String()
}

func windowsWordByte(c byte) bool {
	return strings.IndexByte(" \t\r\n;|&()<>\"'`\\", c) < 0
}
