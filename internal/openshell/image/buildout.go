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
	"regexp"
	"strings"
	"sync"
	"unicode"
)

// A failed docker build is reported with the end of what docker printed:
// the builder's log may be a file, the terminal or nothing at all (the
// daemon's), and none of those is where the person who asked for the
// image reads the error.
const (
	buildTailLines = 40
	buildTailBytes = 8 << 10
)

// BuildError is a docker build that failed.
type BuildError struct {
	// Err is docker's failure (a *CommandError when it exited non-zero).
	Err error
	// Output is the last lines docker printed (at most 40 lines and 8
	// KiB), without control characters and with anything shaped like a
	// credential redacted. The build has no secrets; the redaction is a
	// guard all the same.
	Output string
}

func (e *BuildError) Error() string {
	if e.Output == "" {
		return e.Err.Error()
	}
	return e.Err.Error() + "; the last lines docker printed:\n    " + strings.ReplaceAll(e.Output, "\n", "\n    ")
}

func (e *BuildError) Unwrap() error { return e.Err }

// outputTail keeps the last buildTailBytes written to it. It is safe for
// concurrent writes (docker's stdout and stderr).
type outputTail struct {
	mu  sync.Mutex
	buf []byte
	// cut is set once earlier bytes were dropped.
	cut bool
}

func (t *outputTail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(p)
	if len(p) > buildTailBytes {
		p, t.buf, t.cut = p[len(p)-buildTailBytes:], t.buf[:0], true
	}
	t.buf = append(t.buf, p...)
	if len(t.buf) > 2*buildTailBytes {
		t.buf, t.cut = append(t.buf[:0], t.buf[len(t.buf)-buildTailBytes:]...), true
	}
	return n, nil
}

// String is the safe tail (BuildError.Output).
func (t *outputTail) String() string {
	t.mu.Lock()
	raw, cut := t.buf, t.cut
	if len(raw) > buildTailBytes {
		raw, cut = raw[len(raw)-buildTailBytes:], true
	}
	s := string(raw)
	t.mu.Unlock()
	if cut {
		// The first line is a fragment (maybe of a UTF-8 sequence).
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
	}
	return safeOutput(s, buildTailLines)
}

// safeOutput is the last maxLines non-blank lines of s, each without
// terminal escape sequences, control or bidirectional-override
// characters, and with credential-shaped strings redacted.
func safeOutput(s string, maxLines int) string {
	s = strings.ToValidUTF8(s, "?")
	s = ansiEscapeRE.ReplaceAllString(s, "")
	s = strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(s)
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRightFunc(strings.Map(displayRune, line), unicode.IsSpace)
		if strings.TrimSpace(line) != "" {
			lines = append(lines, redactCredentials(line))
		}
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n")
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
