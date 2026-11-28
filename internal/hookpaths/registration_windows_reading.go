// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// RegistrationWriteReachedBounded is RegistrationWriteReached that also
// reports the caps its pattern expansions hit (actionBoundedGlob) where a
// reader decided on the matches read before the cap and none was a
// registered file: the reading is truncated, which the caller judges at
// least at the unknown tier (the one bound rule, rel-1-0-10:GAP-1468).
//
// spellings keeps the physical spellings of the names for the hook call
// (NewRegistrationSpellings; nil reads them afresh): a caller that reads the
// statements of one call against the same names passes one set.
func RegistrationWriteReachedBounded(command, cwd, home string, names []string, spellings *RegistrationSpellings) (reached []string, truncated bounded.CapSet) {
	truncated = globCutOf(func() { reached = registrationWriteReachedIn(command, cwd, home, names, spellings) })
	return reached, truncated
}

// RegistrationWriteReached runs the shared concrete shell mutation reader
// against a caller-supplied registration set and returns the members of that
// set the command provably writes, in the order given. On a Windows host the
// command is read twice, as the protected decision reads it
// (actionWindowsTargetMention): with the POSIX grammar Git Bash uses, and with
// a backslash inside a word read as a path separator
// (WindowsShellReading). A member either reading reaches is reached.
func RegistrationWriteReached(command, cwd, home string, names []string) []string {
	return registrationWriteReachedIn(command, cwd, home, names, nil)
}

// registrationWriteReachedIn is RegistrationWriteReached with the spellings
// of the call (nil: read afresh); both readings share them.
func registrationWriteReachedIn(command, cwd, home string, names []string, spellings *RegistrationSpellings) []string {
	if spellings == nil {
		spellings = NewRegistrationSpellings()
	}
	reached := registrationWriteReachedAs(command, cwd, home, names, spellings)
	reading, windows := WindowsShellReading(command)
	if !windows || len(reached) == len(names) {
		return reached
	}
	more := registrationWriteReachedAs(reading, cwd, home, names, spellings)
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

// RegistrationFirstWriteReached is the first member of names
// RegistrationWriteReached returns, or "" when it returns none, read only as
// far as that member: a caller that names one reached file does not narrow
// the halves after it (rel-1-0-10:GAP-2271). On a Windows host the second
// reading looks only before the first member the POSIX reading reaches.
func RegistrationFirstWriteReached(command, cwd, home string, names []string) string {
	first := registrationFirstWriteReachedAs(command, cwd, home, names, len(names))
	if reading, windows := WindowsShellReading(command); windows && first != 0 {
		first = min(first, registrationFirstWriteReachedAs(reading, cwd, home, names, first))
	}
	if first < len(names) {
		return names[first]
	}
	return ""
}

// RegistrationArchivePossibleReach reports an extraction into a directory
// containing a registration when the archive's entries are not named in the
// command, in either reading of the command on a Windows host. This is a
// possible write; callers choose its profile grade.
func RegistrationArchivePossibleReach(command, cwd, home string, names []string) string {
	if found := registrationArchivePossibleReachAs(command, cwd, home, names); found != "" {
		return found
	}
	if reading, windows := WindowsShellReading(command); windows {
		return registrationArchivePossibleReachAs(reading, cwd, home, names)
	}
	return ""
}

// WindowsShellReading returns, on a Windows host, the command with a
// backslash inside a word read as a path separator, so a native path such as
// C:\Users\me\.claude names that folder whichever shell runs the call. It
// reports false off Windows and when that reading is the same text. A reader
// that judges a call in this reading too keeps the verdict of either.
func WindowsShellReading(command string) (string, bool) {
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
