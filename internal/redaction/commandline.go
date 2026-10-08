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
//     (scheme://user:password@host); a redaction placeholder in the user or
//     the password counts as one character, so its spaces do not hide the
//     password next to it;
//   - cmdlineSecretKey is a word that names a secret and ends where its
//     value, the next word, starts (a header: "Authorization: Bearer ...",
//     "X-Api-Key: ..."), and cmdlineAuthScheme the scheme word an
//     Authorization value starts with.
//
// cmdlineSecretArg and cmdlineSecretKey also take the name after a flag or
// key that carries it (--header=X-Api-Key: ..., header=Authorization: ...).
var (
	cmdlineSecretArg   = regexp.MustCompile(`(?i)^((?:-{0,2}[a-z0-9_.-]+=)?-{0,2}[a-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth|credential|private[_-]?key)[a-z0-9_.-]*[=:])(.+)$`)
	cmdlineSecretFlag  = regexp.MustCompile(`(?i)^-{1,2}[a-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth|credential|private[_-]?key)[a-z0-9_.-]*$`)
	cmdlineLongToken   = regexp.MustCompile(`^[A-Za-z0-9_\-+/=.]{32,}$`)
	cmdlineUserFlag    = regexp.MustCompile(`^(?:-u|-U|--user|--proxy-user)$`)
	cmdlineUserArg     = regexp.MustCompile(`^(-u|-U|--user=|--proxy-user=)([^:]*:)(.+)$`)
	cmdlineURLPassword = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://(?:<redacted[^<>]{0,90}>|[^/@:\s])*:)((?:<redacted[^<>]{0,90}>|[^/@\s])+)@`)
	cmdlineSecretKey   = regexp.MustCompile(`(?i)^(?:-{0,2}[a-z0-9_.-]+=)?[a-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth|credential|private[_-]?key)[a-z0-9_.-]*[=:]$`)
	cmdlineAuthScheme  = regexp.MustCompile(`(?i)^(?:bearer|basic|token|digest|negotiate)$`)
)

// WithheldArgv replaces the arguments of a Codex notify program, which
// receives the agent turn's JSON (the user's prompt and the agent's reply) as
// its last argument (GAP-0045).
const WithheldArgv = "[argv withheld: agent turn payload]"

// CommandLine is a process's argument vector (argv[0] first) as DefenseClaw
// keeps and shows it: joined with spaces, with the values of arguments that
// name secrets, key-shaped arguments, URL passwords, the password of a
// user:password argument (curl -u) and a MySQL client's attached -pPASSWORD
// replaced by redaction placeholders, cut to at most max bytes without
// splitting a UTF-8 sequence (max <= 0 means no bound). A Codex notify
// program keeps only the words up to the program and then WithheldArgv.
//
// It is the one implementation shared by the sandbox process tree and the
// Linux sensor helper, which runs it on every kernel-sourced command line
// (Tetragon's and the cn_proc fallback's) before the line leaves the helper.
// Telemetry destinations redact the result again by their own profile: it is
// content.
func CommandLine(args []string, max int) string {
	if prefix, ok := notifyPrefix(args); ok {
		return truncateUTF8(strings.Join(CommandArgs(prefix), " ")+" "+WithheldArgv, max)
	}
	return truncateUTF8(strings.Join(CommandArgs(args), " "), max)
}

// notifyPrefix recognizes a Codex notify program in an argument vector: the
// bridge script, run directly or by an interpreter within the first three
// arguments, and `defenseclaw-hook notify` (also the sandbox's bridge). It
// returns the words kept before the marker.
func notifyPrefix(args []string) ([]string, bool) {
	if len(args) > 1 && path.Base(strings.Trim(args[0], `"'`)) == "defenseclaw-hook" && args[1] == "notify" {
		return args[:2], true
	}
	for i, word := range args {
		if i > 3 {
			break
		}
		if path.Base(strings.Trim(word, `"'`)) == "notify-bridge.sh" {
			return args[:i+1], true
		}
	}
	return nil, false
}

// CommandArgs is CommandLine's pass without the join: one output word per
// argument (the words of a placeholder cut apart are one), with the same
// rules. A caller that needs the words (the hook
// join's command hash) uses it; a placeholder can contain spaces, so a joined
// line cannot be split back into words.
//
// The quotes, backslash escapes and brackets a word starts or ends with are
// set aside while the word is checked and put back after. A command line
// split on white space keeps the quoting of its arguments (Tetragon wraps an
// argument with a space in double quotes, a tool shell runs
// `-c "... eval '...'"`, Claude Code's wrapper nests a script in another with
// escaped quotes, /proc keeps a shell's literal quotes), and the rules are
// anchored at the start of a word, so without this `"--token=..."` would pass
// unredacted. An argument of several words (the script of sh -c '...' or
// eval '...', a header value) has its words redacted the same way.
//
// It is idempotent: the words of a redaction placeholder a split on white
// space cut apart ("<redacted", "len=9", "sha=...>") are one word again, the
// quotes inside one (prefix="d") never open or close a quoted value, and a
// value that is only a placeholder stays as it is (ForSinkEntity keeps its
// own placeholder). The sandbox feed redacts a command line and the gateway
// runs the rules again; without this the second pass took a placeholder's
// first word for the secret and multiplied the rest (GAP-0052). Text next to
// a placeholder in the same word goes through the rules like any other, so
// placeholder-shaped text cannot carry a secret past them (GAP-0062).
func CommandArgs(args []string) []string {
	return commandArgs(mergePlaceholders(args))
}

// commandArgs is CommandArgs on words whose placeholders are whole. It
// returns exactly one word per word it is given.
func commandArgs(args []string) []string {
	out := make([]string, 0, len(args))
	mysql := len(args) > 0 && mysqlClient(strings.Trim(args[0], `'"`))
	// afterKey: the hidden value follows a key word (a header name), so an
	// Authorization scheme before it stays.
	hideNext, userNext, afterKey := false, false, false
	// keyQuote is the quote the word that named the hidden value left open
	// ("Authorization: Bearer ..." split on spaces), hideQuote the quote a
	// hidden value is still inside.
	var keyQuote, hideQuote byte
	for _, word := range args {
		opening, a, closing := splitEdgeQuotes(word)
		// A placeholder's own quotes (prefix="d") are not the command
		// line's, and its spaces do not make a script of the word.
		bare := withoutPlaceholders(a)
		word = opening + bare + closing
		if hideQuote != 0 {
			// A text source split one quoted secret value on spaces.
			out = append(out, opening+ForSinkEntity(a)+closing)
			if quoteCloses(word, hideQuote) {
				hideQuote = 0
			}
			continue
		}
		user := userNext
		userNext = false
		sensitive := false
		switch {
		case hideNext && afterKey && cmdlineAuthScheme.MatchString(a):
			// The scheme of "Authorization: Bearer ..." stays; its value goes.
			if keyQuote != 0 && quoteCloses(word, keyQuote) {
				keyQuote = 0
			}
		case hideNext:
			a, hideNext, afterKey = ForSinkEntity(a), false, false
			sensitive = true
		case strings.ContainsAny(bare, " \t\r\n"):
			a = redactWords(a)
		case cmdlineSecretKey.MatchString(a):
			hideNext, afterKey, keyQuote = true, true, unclosedQuote(word)
		case user && !strings.HasPrefix(a, "-") && strings.Contains(a, ":"):
			name, password, _ := strings.Cut(a, ":")
			a = name + ":" + ForSinkEntity(password)
			sensitive = true
		case cmdlineSecretArg.MatchString(a):
			m := cmdlineSecretArg.FindStringSubmatch(a)
			a = m[1] + ForSinkEntity(m[2])
			sensitive = true
		case cmdlineSecretFlag.MatchString(a):
			hideNext, keyQuote = true, unclosedQuote(word)
		case cmdlineUserFlag.MatchString(a):
			userNext = true
		case cmdlineUserArg.MatchString(a):
			m := cmdlineUserArg.FindStringSubmatch(a)
			a = m[1] + m[2] + ForSinkEntity(m[3])
			sensitive = true
		case mysql && len(a) > 2 && strings.HasPrefix(a, "-p"):
			a = "-p" + ForSinkEntity(a[2:])
			sensitive = true
		case cmdlineLongToken.MatchString(bare) && strings.ContainsAny(bare, "0123456789") && strings.IndexFunc(bare, isASCIILetter) >= 0 && !strings.Contains(bare, "/"):
			// The shape is checked without the placeholders in the word,
			// whose spaces and brackets are not the token's.
			a = ForSinkEntity(a)
		}
		if sensitive {
			switch {
			case keyQuote == 0:
				hideQuote = unclosedQuote(word)
			case !quoteCloses(word, keyQuote):
				// The value is inside the quote its key opened, and it goes on.
				hideQuote = keyQuote
			}
			keyQuote = 0
		}
		a = cmdlineURLPassword.ReplaceAllStringFunc(a, func(m string) string {
			sub := cmdlineURLPassword.FindStringSubmatch(m)
			return sub[1] + ForSinkEntity(sub[2]) + "@"
		})
		out = append(out, opening+a+closing)
	}
	return out
}

// maxPlaceholderWords bounds how many words one placeholder spans
// ("<redacted len=23 prefix="d" sha=5f84a2a8>" is four).
const maxPlaceholderWords = 6

// placeholderStart opens every redaction placeholder.
const placeholderStart = "<redacted"

// placeholderEnd is the end of the redaction placeholder that starts at
// s[i], or -1 when none does.
func placeholderEnd(s string, i int) int {
	for k := i; k < len(s) && k-i < 96; k++ {
		if s[k] == '>' && isPlaceholder(s[i:k+1]) {
			return k + 1
		}
	}
	return -1
}

// openPlaceholder is where a placeholder starts in word that does not end in
// it, or -1.
func openPlaceholder(word string) int {
	for from := 0; ; {
		i := strings.Index(word[from:], placeholderStart)
		if i < 0 {
			return -1
		}
		i += from
		end := placeholderEnd(word, i)
		if end < 0 {
			return i
		}
		from = end
	}
}

// withoutPlaceholders is s with every redaction placeholder taken out.
func withoutPlaceholders(s string) string {
	if !strings.Contains(s, placeholderStart) {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, placeholderStart)
		if i < 0 {
			break
		}
		end := placeholderEnd(s, i)
		if end < 0 {
			b.WriteString(s[:i+len(placeholderStart)])
			s = s[i+len(placeholderStart):]
			continue
		}
		b.WriteString(s[:i])
		s = s[end:]
	}
	b.WriteString(s)
	return b.String()
}

// mergePlaceholders joins the words of each redaction placeholder that a
// split on white space cut apart back into one word, with what the word it
// starts in holds before it ("--password=<redacted", "len=9", "sha=...>").
func mergePlaceholders(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		at := openPlaceholder(args[i])
		if at < 0 {
			out = append(out, args[i])
			continue
		}
		merged := false
		for j := i + 1; j < len(args) && j < i+maxPlaceholderWords; j++ {
			group := strings.Join(args[i:j+1], " ")
			if placeholderEnd(group, at) > 0 {
				out = append(out, group)
				i, merged = j, true
				break
			}
		}
		if !merged {
			out = append(out, args[i])
		}
	}
	return out
}

// unclosedQuote finds a quote opened in a word from a text command line.
// A real argv element can contain spaces; balanced quotes need no continuation.
func unclosedQuote(word string) byte {
	var quote byte
	escaped := false
	for i := 0; i < len(word); i++ {
		switch {
		case escaped:
			escaped = false
		case word[i] == '\\' && quote != '\'':
			escaped = true
		case quote == 0 && (word[i] == '\'' || word[i] == '"'):
			quote = word[i]
		case word[i] == quote:
			quote = 0
		}
	}
	return quote
}

func quoteCloses(word string, quote byte) bool {
	escaped := false
	for i := 0; i < len(word); i++ {
		switch {
		case escaped:
			escaped = false
		case word[i] == '\\' && quote != '\'':
			escaped = true
		case word[i] == quote:
			return true
		}
	}
	return false
}

// redactWords redacts the words of an argument that holds several, keeping
// the white space between them. A placeholder is part of the word it is in,
// so each word comes back as one (GAP-0064: split on every space, the words
// of a placeholder were merged again and fewer came back than went in).
func redactWords(s string) string {
	at := wordSpans(s)
	words := make([]string, len(at))
	for i, r := range at {
		words[i] = s[r[0]:r[1]]
	}
	red := commandArgs(words)
	var b strings.Builder
	last := 0
	for i, r := range at {
		b.WriteString(s[last:r[0]])
		b.WriteString(red[i])
		last = r[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// wordSpans are the start and end of each word of s: a run of characters
// other than white space, in which a redaction placeholder, spaces and all,
// counts as one character.
func wordSpans(s string) [][2]int {
	var spans [][2]int
	start := -1
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], placeholderStart) {
			if end := placeholderEnd(s, i); end > 0 {
				if start < 0 {
					start = i
				}
				i = end
				continue
			}
		}
		switch s[i] {
		case ' ', '\t', '\n', '\f', '\r':
			if start >= 0 {
				spans = append(spans, [2]int{start, i})
				start = -1
			}
		default:
			if start < 0 {
				start = i
			}
		}
		i++
	}
	if start >= 0 {
		spans = append(spans, [2]int{start, len(s)})
	}
	return spans
}

// splitEdgeQuotes splits the shell quotes, their backslash escapes (a script
// nested in another) and the brackets a word starts and ends with off its
// core.
func splitEdgeQuotes(word string) (opening, core, closing string) {
	core = strings.TrimLeft(word, `\'"($`+"`")
	opening = word[:len(word)-len(core)]
	trimmed := strings.TrimRight(core, `\'");`+"`")
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
