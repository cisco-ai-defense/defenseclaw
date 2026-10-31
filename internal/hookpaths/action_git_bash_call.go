// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"regexp"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// actionGitBashSpellings are the spellings only Windows reads in a POSIX
// shell's call: a stream or env: colon, a Cygwin drive root, a launcher of
// another shell or a path or link tool of Windows, and an 8.3 short name.
var actionGitBashSpellings = []string{
	"env:", "::", "/cygdrive/", "~1", "~2", "~3", "~4", "~5", "~6", "~7", "~8", "~9",
	"powershell", "pwsh", "cmd", "wsl", "cygpath", "msys", "mklink", "junction",
	"fsutil", "robocopy", "xcopy", ".exe", ".bat", ".ps1", ".vbs", ".lnk",
}

// actionGitBashWindowsRoots are a backslash other than a shell escape of a
// quote, a dollar, a backquote, a backslash, a newline or a tab (a Windows
// path separator to Git Bash's file functions), a cmd variable (%NAME%), a
// drive-relative word (C:x, C:), a UNC root (//host) and a Git Bash drive
// root (/c/...) at the start of a word, and a stream of a protected name
// (authorized_keys:x), and a Windows home or profile variable Git Bash
// exports ($USERPROFILE, ${APPDATA} ...). A drive path with a slash (C:/...)
// is a path the POSIX reading places on the Windows file system.
var actionGitBashWindowsRoots = regexp.MustCompile("\\\\[^\"'$`\\\\nt\n]|" +
	`%[A-Za-z_][A-Za-z0-9_()]*%|(^|[\s'"=;|&()<>])[A-Za-z]:([^/]|$)|(^|[\s'"=;|&()<>{}])//|` +
	`(^|[\s'"=;|&()<>{}$])/[A-Za-z](/|$|[\s'"])|(?i)(authorized_keys|\.ssh|defenseclaw)[^/\s'"]*:|` +
	`(?i)\$\{?[!#]?(userprofile|homedrive|homepath|appdata|localappdata|programdata|allusersprofile|` +
	`onedrive\w*|public|systemdrive|systemroot|windir)\b`)

// actionGitBashReadsAlone reports a call a POSIX shell runs on a native
// Windows host (Git Bash runs Claude Code's Bash tool; the gateway passes
// the POSIX dialect hint) that the POSIX grammar reads completely there: it
// parses, and it spells nothing only Windows reads (actionGitBashSpellings).
// Such a call is read with the POSIX grammar on the Windows file system
// alone, as Git Bash runs it, so the POSIX rules hold on Windows: a quoted
// word is text, a pattern skips dot names, an uncalled function never runs
// (GAP-1717). The Windows file system still answers for every path: a link,
// a junction, a hard link, a case form or a short name of a protected file
// is the same file (protectedFiles compares file identity). Any other call
// keeps every reading (lead decision on GAP-1504).
func actionGitBashReadsAlone(command, home string, dialect actionfacts.Dialect) bool {
	if dialect != actionfacts.DialectPOSIX || runtime.GOOS != "windows" || !actionWindowsHome(home) ||
		command == "" || len(command) > MaxPayloadBytes {
		return false
	}
	lower := strings.ToLower(command)
	for _, spelling := range actionGitBashSpellings {
		if strings.Contains(lower, spelling) {
			return false
		}
	}
	if actionGitBashWindowsRoots.MatchString(command) {
		return false
	}
	_, parsed := parseShell(command)
	return parsed
}
