// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// ruleReadableHome is the user home the home-relative path rules read in a
// path: /root, /home/<word> and /Users/<word>. A home of another shape (a
// dotted or hyphenated account name, a directory-service name, a home under
// another root) is invisible to those rules, so the same credential file
// that is judged by its name elsewhere would be judged by no rule in it. A
// Windows drive home is never listed here: the rules read the folder names
// in one letter case and Windows reads them in any.
var ruleReadableHome = regexp.MustCompile(`^(?:/root|/home/\w+|/Users/\w+)$`)

// activeHomeAsTilde spells the active home in text as ~, which every
// home-relative path rule reads, when the rules cannot read the home as it
// is. The file the caller owns is then judged by the same rule as the same
// name under a home of the usual shape. Only the home as a whole path prefix
// is respelled: not a longer name, not a path that merely ends in it. A
// drive-letter home is read in the forward-slash spelling the path facts
// give, and compared without regard to letter case, as Windows does.
func activeHomeAsTilde(text, home string) string {
	home = strings.TrimRight(strings.ReplaceAll(home, `\`, "/"), "/")
	windows := actionfacts.DriveLetterPath(home + "/")
	if len(home) < 2 || !windows && (home[0] != '/' || ruleReadableHome.MatchString(home)) {
		return text
	}
	haystack, needle := text, home+"/"
	if windows {
		haystack, needle = asciiLowerPreservingBytes(text), asciiLowerPreservingBytes(needle)
	}
	if !strings.Contains(haystack, needle) {
		return text
	}
	var out strings.Builder
	last := 0
	for from := 0; ; {
		offset := strings.Index(haystack[from:], needle)
		if offset < 0 {
			break
		}
		start := from + offset
		from = start + len(home)
		if start > 0 && (strings.IndexByte("_.-/~$}", text[start-1]) >= 0 || asciiAlphanumeric(text[start-1])) {
			continue
		}
		out.WriteString(text[last:start])
		out.WriteByte('~')
		last = from
	}
	out.WriteString(text[last:])
	return out.String()
}

func asciiAlphanumeric(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9'
}
