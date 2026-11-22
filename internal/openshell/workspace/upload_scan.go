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

package workspace

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// Upload scan defaults for copies (StageOptions.ScanMaxFileBytes,
// ScanTimeBudget). A live mount keeps its own budget
// (defaultMaxContentScanFiles, maxContentScanBytes).
const (
	DefaultScanMaxFileBytes = 8 << 20
	DefaultScanTimeBudget   = 120 * time.Second
)

// Placeholder forms for StageOptions.RewriteSecrets.
const (
	// PlaceholderToken writes DC_SECRET_<n> where the value was, inside
	// the existing quotes, which keeps every language's syntax.
	PlaceholderToken = "token"
	// PlaceholderEnv writes ${DC_SECRET_<n>} (shell, compose and dotenv
	// interpolation).
	PlaceholderEnv = "env"
)

// SpanDetector is a SecretDetector that can also say where each value
// sits, which a copy needs to replace the values instead of holding the
// file back. DefaultSecretDetector implements it.
type SpanDetector interface {
	SecretSpans(rel string, content []byte) []scanner.SecretSpan
}

func (d clawShieldDetector) SecretSpans(_ string, content []byte) []scanner.SecretSpan {
	return d.s.ScanContentSpans(content)
}

// SecretLine is one credential a copy replaced with a placeholder in the
// file it uploaded. It lives in the local copy record only, never in the
// sandbox: where the value sits in the person's file and a digest of the
// lines that hold it, never the value. Pull uses it to bring the local
// lines back around the agent's edits.
type SecretLine struct {
	Rel  string `json:"rel"`
	Rule string `json:"rule"`
	// Line is the 1-based first line of the value in the local file and
	// Lines the number of lines it spans (a private key block spans many).
	Line  int `json:"line"`
	Lines int `json:"lines"`
	// Column and Length locate the value in the text of those lines.
	Column int `json:"column"`
	Length int `json:"length"`
	// Placeholder is what the uploaded file holds in its place.
	Placeholder string `json:"placeholder"`
	// LinesSHA256 is the digest of the local lines Line..Line+Lines-1.
	LinesSHA256 string `json:"lines_sha256"`
	// Signing marks key material a header swap cannot stand in for (an
	// AWS secret key, a private key).
	Signing bool `json:"signing,omitempty"`
}

// copyScan is what the upload scan of a copy decided.
type copyScan struct {
	held []string
	// rewritten are the uploaded bytes of the files whose credentials
	// were replaced; lines says where each value was.
	rewritten map[string][]byte
	lines     []SecretLine
	// tooBig, late, binary and unread were not content-scanned: over the
	// per-file limit, past the time budget, binary (a NUL byte that is not
	// UTF-16 text) or not readable (GAP-0756).
	tooBig, late, binary, unread []string
}

// notScanned lists every file the content scan did not read.
func (s *copyScan) notScanned() []string {
	return slices.Concat(s.tooBig, s.late, s.binary, s.unread)
}

// found reports whether the scan held back or rewrote any file.
func (s *copyScan) found() bool { return len(s.held) > 0 || len(s.rewritten) > 0 }

// detectSecretsIn applies the mask rules to a fixed list of files (copy
// mode ships exactly git's view of the working tree, not a directory walk).
// Every regular file up to the per-file limit is content-scanned until the
// time budget runs out; what is not scanned is reported, never skipped in
// silence. With rewrite set, a file whose credentials all have a span is
// uploaded with each value replaced instead of being held back.
func detectSecretsIn(root string, rels []string, opts secretScanOptions) (*copyScan, error) {
	res := &copyScan{}
	maxFile := opts.maxFileBytes
	if maxFile <= 0 {
		maxFile = DefaultScanMaxFileBytes
	}
	budget := opts.timeBudget
	if budget <= 0 {
		budget = DefaultScanTimeBudget
	}
	clock := opts.clock
	if clock == nil {
		clock = time.Now
	}
	deadline := clock().Add(budget)
	spanner, _ := opts.detector.(SpanDetector)
	num := newNumbering(opts.prior)
	for _, rel := range rels {
		if opts.isUnmasked(rel) {
			continue
		}
		if secretByName(opts.patterns, rel) {
			res.held = append(res.held, rel)
			continue
		}
		if !opts.contentScan || opts.detector == nil {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			continue
		}
		if info.Size() > maxFile {
			res.tooBig = append(res.tooBig, rel)
			continue
		}
		if !clock().Before(deadline) {
			res.late = append(res.late, rel)
			continue
		}
		content, err := readSmallRegular(p, maxFile)
		if err != nil {
			res.unread = append(res.unread, rel)
			continue
		}
		// UTF-16 text (a .ps1 or .reg saved by Windows tools) is scanned
		// as its UTF-8 form and held back when it holds a credential: its
		// spans are not the file's bytes.
		text, wide := decodeUTF16(content)
		// Decoded text with a NUL is not UTF-16 text: a UTF-32 file (its
		// byte order mark starts like UTF-16 LE) decodes to characters
		// split by NULs, in which no credential is found (RV6-5).
		if (!wide && looksBinary(content)) || (wide && bytes.IndexByte(text, 0) >= 0) {
			res.binary = append(res.binary, rel)
			continue
		}
		if _, ok := opts.detector.DetectSecret(rel, text); !ok {
			continue
		}
		if opts.rewrite == "" || spanner == nil || wide {
			res.held = append(res.held, rel)
			continue
		}
		out, lines, ok := replaceSpans(rel, content, spanner.SecretSpans(rel, content), opts.rewrite, num)
		if !ok {
			res.held = append(res.held, rel)
			continue
		}
		if res.rewritten == nil {
			res.rewritten = map[string][]byte{}
		}
		res.rewritten[rel] = out
		res.lines = append(res.lines, lines...)
	}
	return res, nil
}

// decodeUTF16 returns b as UTF-8 when it is UTF-16 text with a byte
// order mark (wide true), else b itself.
func decodeUTF16(b []byte) ([]byte, bool) {
	var order binary.ByteOrder
	switch {
	case len(b) < 2 || len(b)%2 != 0:
		return b, false
	case b[0] == 0xff && b[1] == 0xfe:
		order = binary.LittleEndian
	case b[0] == 0xfe && b[1] == 0xff:
		order = binary.BigEndian
	default:
		return b, false
	}
	u := make([]uint16, 0, len(b)/2-1)
	for i := 2; i < len(b); i += 2 {
		u = append(u, order.Uint16(b[i:]))
	}
	return []byte(string(utf16.Decode(u))), true
}

// numbering hands out placeholders. A credential the copy already
// replaced keeps its placeholder: the same file, rule, line text (its
// digest) and place in the line, each prior entry used once. A new one gets
// the next number after the highest the copy holds. A push numbered from 1
// again: a new credential took a number the sandbox already had, and one
// in a file that sorts first renumbered the others (RV6-1).
type numbering struct {
	next  int
	prior []SecretLine
	used  []bool
}

func newNumbering(prior []SecretLine) *numbering {
	n := &numbering{prior: prior, used: make([]bool, len(prior))}
	for _, l := range prior {
		if m := placeholderRE.FindString(l.Placeholder); m != "" {
			if v, err := strconv.Atoi(strings.TrimPrefix(m, "DC_SECRET_")); err == nil && v > n.next {
				n.next = v
			}
		}
	}
	return n
}

// take returns the placeholder for l (its Placeholder not yet set).
func (n *numbering) take(l SecretLine, form string) string {
	for i, p := range n.prior {
		if !n.used[i] && p.Rel == l.Rel && p.Rule == l.Rule && p.LinesSHA256 == l.LinesSHA256 &&
			p.Column == l.Column && p.Length == l.Length && p.Placeholder != "" {
			n.used[i] = true
			return p.Placeholder
		}
	}
	n.next++
	return placeholder(form, n.next)
}

// replaceSpans writes content with each span replaced by its placeholder
// (numbering.take). It refuses (ok false) when there is no span or a span
// is the whole file, so the caller holds the file back.
func replaceSpans(rel string, content []byte, spans []scanner.SecretSpan, form string, num *numbering) ([]byte, []SecretLine, bool) {
	if len(spans) == 0 {
		return nil, nil, false
	}
	for _, sp := range spans {
		if sp.Whole || sp.Start < 0 || sp.End > len(content) || sp.Start >= sp.End {
			return nil, nil, false
		}
	}
	var out bytes.Buffer
	out.Grow(len(content))
	var lines []SecretLine
	at := 0
	for _, sp := range spans {
		lineStart := bytes.LastIndexByte(content[:sp.Start], '\n') + 1
		lineEnd := len(content)
		if i := bytes.IndexByte(content[sp.End:], '\n'); i >= 0 {
			lineEnd = sp.End + i
		}
		sum := sha256.Sum256(content[lineStart:lineEnd])
		l := SecretLine{
			Rel: rel, Rule: sp.RuleID,
			Line:   bytes.Count(content[:lineStart], []byte{'\n'}) + 1,
			Lines:  bytes.Count(content[lineStart:lineEnd], []byte{'\n'}) + 1,
			Column: sp.Start - lineStart, Length: sp.End - sp.Start,
			LinesSHA256: hex.EncodeToString(sum[:]),
			Signing:     scanner.SigningKeyRule(sp.RuleID),
		}
		l.Placeholder = num.take(l, form)
		ph := l.Placeholder
		lines = append(lines, l)
		out.Write(content[at:sp.Start])
		out.WriteString(ph)
		at = sp.End
	}
	out.Write(content[at:])
	return out.Bytes(), lines, true
}

func placeholder(form string, n int) string {
	if form == PlaceholderEnv {
		return fmt.Sprintf("${DC_SECRET_%d}", n)
	}
	return fmt.Sprintf("DC_SECRET_%d", n)
}

// notScannedWarnings names the files the upload scan did not read.
func notScannedWarnings(s *copyScan, maxFile int64, budget time.Duration) []string {
	if maxFile <= 0 {
		maxFile = DefaultScanMaxFileBytes
	}
	if budget <= 0 {
		budget = DefaultScanTimeBudget
	}
	limit := fmt.Sprintf("%d MiB", maxFile>>20)
	if maxFile%(1<<20) != 0 {
		limit = fmt.Sprintf("%d bytes", maxFile)
	}
	var w []string
	if n := len(s.tooBig); n > 0 {
		w = append(w, fmt.Sprintf("%d file(s) not scanned for secrets because they are over %s (upload_scan.max_file_bytes): %s",
			n, limit, strings.Join(firstN(s.tooBig, 5), ", ")))
	}
	if n := len(s.late); n > 0 {
		w = append(w, fmt.Sprintf("%d file(s) not scanned for secrets because the scan used its %s (upload_scan.time_budget): %s",
			n, budget, strings.Join(firstN(s.late, 5), ", ")))
	}
	if n := len(s.binary); n > 0 {
		w = append(w, fmt.Sprintf("%d file(s) not scanned for secrets because they look binary: %s", n, strings.Join(firstN(s.binary, 5), ", ")))
	}
	if n := len(s.unread); n > 0 {
		w = append(w, fmt.Sprintf("%d file(s) not scanned for secrets because they could not be read: %s", n, strings.Join(firstN(s.unread, 5), ", ")))
	}
	return w
}

// writeReplaced writes a copied file's replaced bytes with the source's
// mode and modification time.
func writeReplaced(to string, content []byte, mode os.FileMode, mtime time.Time) error {
	if err := os.WriteFile(to, content, mode.Perm()); err != nil {
		return err
	}
	return os.Chtimes(to, mtime, mtime)
}
