// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// A failed docker build is reported with the end of what docker printed:
// the builder's log may be a file, the terminal or nothing at all (the
// daemon's), and none of those is where the person who asked for the
// image reads the error.
const (
	buildTailLines = 40
	buildTailBytes = 8 << 10
	// buildLineRunes is the most of one line the tail shows. Docker's
	// last line repeats the whole failing RUN command (ERROR: failed to
	// build: failed to solve: process "/bin/sh -c …"), 6.9 KB for Hermes'
	// base64 shims, which would leave no room for the lines that say why
	// the command failed.
	buildLineRunes = 300
	// buildLineBytes is the most of one line the tail keeps as docker
	// wrote it: room for buildLineRunes once escapes are removed.
	buildLineBytes = 4 << 10
	// buildTailKeep is how many lines the tail keeps as written; the
	// blank ones are left out when it is shown.
	buildTailKeep = 4 * buildTailLines
)

// BuildError is a docker build that failed.
type BuildError struct {
	// Err is docker's failure (a *CommandError when it exited non-zero).
	Err error
	// Output is the last lines docker printed (at most 40 lines and 8
	// KiB, each shortened to 300 characters), without control characters
	// and with anything shaped like a credential redacted. The build has
	// no secrets; the redaction is a guard all the same.
	Output string
}

func (e *BuildError) Error() string {
	if e.Output == "" {
		return e.Err.Error()
	}
	return e.Err.Error() + "; the last lines docker printed:\n    " + strings.ReplaceAll(e.Output, "\n", "\n    ")
}

func (e *BuildError) Unwrap() error { return e.Err }

// tailLine is one line written to an outputTail, without its newline:
// its first buildLineBytes, and whether more were dropped.
type tailLine struct {
	text []byte
	cut  bool
}

// outputTail keeps the last buildTailKeep lines written to it, each cut to
// buildLineBytes, so one long line never pushes out the lines before it.
// It is safe for concurrent writes (docker's stdout and stderr).
type outputTail struct {
	mu    sync.Mutex
	lines []tailLine
	// cur is the line being written.
	cur tailLine
}

func (t *outputTail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		chunk := p
		if i >= 0 {
			chunk = p[:i]
		}
		if room := buildLineBytes - len(t.cur.text); len(chunk) > room {
			chunk, t.cur.cut = chunk[:max(room, 0)], true
		}
		t.cur.text = append(t.cur.text, chunk...)
		if i < 0 {
			break
		}
		t.lines = append(t.lines, t.cur)
		t.cur = tailLine{}
		if len(t.lines) > 2*buildTailKeep {
			t.lines = append(t.lines[:0], t.lines[len(t.lines)-buildTailKeep:]...)
		}
		p = p[i+1:]
	}
	return n, nil
}

// String is the safe tail (BuildError.Output).
func (t *outputTail) String() string {
	t.mu.Lock()
	lines := slices.Clone(t.lines)
	if len(t.cur.text) > 0 {
		lines = append(lines, t.cur)
	}
	t.mu.Unlock()
	var out []string
	for _, l := range lines {
		out = append(out, safeLines(string(l.text), l.cut)...)
	}
	return tailOf(out, buildTailLines)
}

// safeOutput is the last maxLines non-blank lines of s, at most
// buildTailBytes in all, each without terminal escape sequences, control
// or bidirectional-override characters, with credential-shaped strings
// redacted, and shortened to buildLineRunes.
func safeOutput(s string, maxLines int) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		out = append(out, safeLines(line, false)...)
	}
	return tailOf(out, maxLines)
}

// safeLines are the non-blank lines of one line docker wrote (a carriage
// return starts another), made safe to show as safeOutput says. cut says
// docker's line went on past raw: its last line ends in "…" without its
// last word, which may be part of one the redaction would have recognized.
func safeLines(raw string, cut bool) []string {
	raw = strings.ToValidUTF8(raw, "?")
	raw = ansiEscapeRE.ReplaceAllString(raw, "")
	parts := strings.Split(strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(raw), "\n")
	var out []string
	for i, line := range parts {
		line = strings.TrimRightFunc(strings.Map(displayRune, line), unicode.IsSpace)
		if strings.TrimSpace(line) == "" {
			continue
		}
		line = redactCredentials(line)
		switch {
		case utf8.RuneCountInString(line) > buildLineRunes:
			line = string([]rune(line)[:buildLineRunes]) + "…"
		case cut && i == len(parts)-1:
			if j := strings.LastIndexFunc(line, unicode.IsSpace); j >= 0 {
				line = strings.TrimRightFunc(line[:j], unicode.IsSpace) + " …"
			} else {
				line = "…"
			}
		}
		out = append(out, line)
	}
	return out
}

// tailOf joins the last maxLines of lines, as many as fit
// buildTailBytes.
func tailOf(lines []string, maxLines int) string {
	first, size := len(lines), 0
	for first > 0 && len(lines)-first < maxLines && size+len(lines[first-1]) <= buildTailBytes {
		first--
		size += len(lines[first]) + 1
	}
	return strings.Join(lines[first:], "\n")
}

// ansiEscapeRE matches CSI and OSC sequences and the other two-byte ESC
// sequences.
var ansiEscapeRE = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b\n]*(?:\x07|\x1b\\)?|[@-Z\\-_])`)

func displayRune(r rune) rune {
	switch {
	case r == '\t':
		return ' '
	case unicode.IsControl(r), r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f:
		return -1
	}
	return r
}

// Credential shapes redactCredentials replaces.
var (
	// Known token formats: OpenAI and Anthropic keys, GitHub, GitLab,
	// Slack, AWS access key IDs, Google API keys, Hugging Face and npm
	// tokens, and JWTs.
	knownTokenRE = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,}|` +
		`xox[abprs]-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{36}|` +
		`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)
	// The password of a URL's user information.
	urlPasswordRE = regexp.MustCompile(`(://[^\s:/@]+:)[^\s/@]+@`)
	// Bearer and Basic credentials, as in an Authorization header.
	authSchemeRE = regexp.MustCompile(`(?i)(\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/-]{8,}=*`)
	// NAME=value where NAME names a secret (NPM_TOKEN=…, ?password=…).
	secretAssignRE = regexp.MustCompile(`(?i)(\b[A-Za-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)["']?=["']?)[^\s"'&;,]{4,}`)
	// NAME: value with a token-shaped value: 16 or more characters with a
	// digit, so prose such as "oauth token: unexpected status" stays.
	secretFieldRE = regexp.MustCompile(`(?i)(\b[A-Za-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)["']?:\s*["']?)([A-Za-z0-9_./+=-]{16,})`)
)

const redacted = "[redacted]"

// redactCredentials replaces what looks like a credential in line.
func redactCredentials(line string) string {
	line = knownTokenRE.ReplaceAllString(line, redacted)
	line = urlPasswordRE.ReplaceAllString(line, "${1}"+redacted+"@")
	line = authSchemeRE.ReplaceAllString(line, "${1}"+redacted)
	line = secretAssignRE.ReplaceAllString(line, "${1}"+redacted)
	return secretFieldRE.ReplaceAllStringFunc(line, func(m string) string {
		sub := secretFieldRE.FindStringSubmatch(m)
		if !strings.ContainsAny(sub[2], "0123456789") {
			return m
		}
		return sub[1] + redacted
	})
}
