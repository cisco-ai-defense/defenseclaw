// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The secret shapes of a process's argument vector:
//
//   - cmdlineSecretArg is an argument that names a secret and carries it
//     (--token=..., api_key=...), and cmdlineSecretFlag a flag whose next
//     argument is one (--password value);
//   - cmdlineLongToken is a bare argument shaped like a key: 32 or more
//     letters, digits and key punctuation with both letters and digits;
//   - cmdlineUserFlag is a flag whose next argument may be user:password
//     (curl -u, --user, --proxy-user, -U), and cmdlineUserArg one with it
//     attached;
//   - cmdlineURLPassword is the password of a URL's userinfo
//     (scheme://user:password@host).
var (
	cmdlineSecretArg   = regexp.MustCompile(`(?i)^(-{0,2}[a-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth|credential|private[_-]?key)[a-z0-9_.-]*[=:])(.+)$`)
	cmdlineSecretFlag  = regexp.MustCompile(`(?i)^-{1,2}[a-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth|credential|private[_-]?key)[a-z0-9_.-]*$`)
	cmdlineLongToken   = regexp.MustCompile(`^[A-Za-z0-9_\-+/=.]{32,}$`)
	cmdlineUserFlag    = regexp.MustCompile(`^(?:-u|-U|--user|--proxy-user)$`)
	cmdlineUserArg     = regexp.MustCompile(`^(-u|-U|--user=|--proxy-user=)([^:]*:)(.+)$`)
	cmdlineURLPassword = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^/@:\s]*:)([^/@\s]+)@`)
)

// CommandLine is a process's argument vector as DefenseClaw keeps and shows
// it: joined with spaces, with the values of arguments that name secrets,
// key-shaped arguments, URL passwords, the password of a user:password
// argument (curl -u) and a MySQL client's attached -pPASSWORD replaced by
// redaction placeholders, cut to at most max bytes without splitting a UTF-8
// sequence (max <= 0 means no bound).
//
// It is the one implementation shared by the sandbox process tree and the
// Linux sensor helper, which runs it on every kernel-sourced command line
// before the line leaves the helper. Telemetry destinations redact the result
// again by their own profile: it is content.
func CommandLine(args []string, max int) string {
	return truncateUTF8(strings.Join(CommandArgs(args), " "), max)
}

// CommandArgs is CommandLine's pass without the join: one output word per
// argument, with the same rules. A caller that needs the words (the hook
// join's command hash) uses it; a placeholder can contain spaces, so a joined
// line cannot be split back into words.
//
// The quotes a word starts or ends with are set aside while the word is
// checked and put back after. A command line split on white space keeps the
// quoting of its arguments (Tetragon wraps an argument with a space in double
// quotes, a tool shell runs `-c "... eval '...'"`, /proc keeps a shell's
// literal quotes), and the rules are anchored at the start of a word, so
// without this `"--token=..."` would pass unredacted.
func CommandArgs(args []string) []string {
	out := make([]string, 0, len(args))
	mysql := len(args) > 0 && mysqlClient(args[0])
	hideNext, userNext := false, false
	for _, word := range args {
		opening, a, closing := splitEdgeQuotes(word)
		user := userNext
		userNext = false
		switch {
		case hideNext:
			a, hideNext = ForSinkEntity(a), false
		case user && !strings.HasPrefix(a, "-") && strings.Contains(a, ":"):
			name, password, _ := strings.Cut(a, ":")
			a = name + ":" + ForSinkEntity(password)
		case cmdlineSecretArg.MatchString(a):
			m := cmdlineSecretArg.FindStringSubmatch(a)
			a = m[1] + ForSinkEntity(m[2])
		case cmdlineSecretFlag.MatchString(a):
			hideNext = true
		case cmdlineUserFlag.MatchString(a):
			userNext = true
		case cmdlineUserArg.MatchString(a):
			m := cmdlineUserArg.FindStringSubmatch(a)
			a = m[1] + m[2] + ForSinkEntity(m[3])
		case mysql && len(a) > 2 && strings.HasPrefix(a, "-p"):
			a = "-p" + ForSinkEntity(a[2:])
		case cmdlineLongToken.MatchString(a) && strings.ContainsAny(a, "0123456789") && strings.IndexFunc(a, isASCIILetter) >= 0 && !strings.Contains(a, "/"):
			a = ForSinkEntity(a)
		}
		a = cmdlineURLPassword.ReplaceAllStringFunc(a, func(m string) string {
			sub := cmdlineURLPassword.FindStringSubmatch(m)
			return sub[1] + ForSinkEntity(sub[2]) + "@"
		})
		out = append(out, opening+a+closing)
	}
	return out
}

// splitEdgeQuotes splits the quote characters a word starts and ends with
// off its core.
func splitEdgeQuotes(word string) (opening, core, closing string) {
	core = strings.TrimLeft(word, `"'`)
	opening = word[:len(word)-len(core)]
	trimmed := strings.TrimRight(core, `"'`)
	return opening, trimmed, core[len(trimmed):]
}

// TruncateUTF8 cuts s to at most n bytes without splitting a UTF-8
// sequence; n <= 0 leaves s whole.
func TruncateUTF8(s string, n int) string { return truncateUTF8(s, n) }

// mysqlClient reports a MySQL or MariaDB client, which takes its password
// attached to -p.
func mysqlClient(argv0 string) bool {
	name := path.Base(argv0)
	return strings.HasPrefix(name, "mysql") || strings.HasPrefix(name, "mariadb")
}

func isASCIILetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

// truncateUTF8 cuts s to at most n bytes without splitting a UTF-8 sequence;
// n <= 0 leaves s whole.
func truncateUTF8(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	for i := n; i > 0 && i > n-utf8.UTFMax; i-- {
		if utf8.RuneStart(s[i]) {
			return s[:i]
		}
	}
	return s[:n]
}
