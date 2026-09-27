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
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// SecretDetector decides whether file content is credential material worth
// hiding from the agent. It returns a short rule identifier on a match.
type SecretDetector interface {
	DetectSecret(rel string, content []byte) (rule string, ok bool)
}

// DefaultSecretDetector masks files in which DefenseClaw's ClawShield
// secret rules find a critical-severity credential (private keys, cloud
// keys, provider tokens). Lower-severity heuristics (passwords in config,
// JWTs) stay visible: masking hides the whole file and must not trip on
// ordinary source.
func DefaultSecretDetector() SecretDetector {
	return clawShieldDetector{s: scanner.NewClawShieldSecretsScanner()}
}

type clawShieldDetector struct {
	s *scanner.ClawShieldSecretsScanner
}

func (d clawShieldDetector) DetectSecret(rel string, content []byte) (string, bool) {
	for _, f := range d.s.ScanContent(rel, content) {
		if f.Severity == scanner.SeverityCritical {
			return f.RuleID, true
		}
	}
	return "", false
}

// MaskedPath is a secret file or directory hidden from the sandbox.
type MaskedPath struct {
	// Rel is slash-separated and relative to the mounted folder.
	Rel string `json:"rel"`
	Dir bool   `json:"dir,omitempty"`
	// Reason is "name", "pattern:<glob>" or "content:<rule>".
	Reason string `json:"reason"`
	// Hardlinked is set when the file has other hard links, which may
	// expose the same bytes under a name that is not masked.
	Hardlinked bool `json:"hardlinked,omitempty"`
}

const (
	defaultMaxWalkEntries      = 250_000
	defaultMaxContentScanFiles = 2_000
	// defaultMaxTrackedCompares bounds how many tracked files a scan reads
	// to learn whether they still hold their committed bytes.
	defaultMaxTrackedCompares = 20_000
	maxContentScanBytes       = 256 << 10
	// maxCompareBytes bounds the read of a tracked secret-named file; a
	// larger one is treated as differing from its committed copy.
	maxCompareBytes = 8 << 20
	maxMasks        = 256
)

type secretScanOptions struct {
	patterns    []string // operator mask globs; apply to tracked files too
	unmask      []string // operator exceptions (paths or globs)
	maskTracked bool     // mask tracked secret names even when unchanged
	// tracked is the project's index (live mounts of a git project).
	tracked         map[string]trackedEntry
	detector        SecretDetector
	contentScan     bool
	maxEntries      int
	maxScanFiles    int
	maxTrackedReads int
}

// trackedEntry is a path in the project's index.
type trackedEntry struct {
	mode, oid string
	// watched: stage 0 and neither skip-worktree nor assume-unchanged, so
	// git itself compares the working copy with the entry.
	watched bool
}

type secretScan struct {
	masks          []MaskedPath
	unmasked       []string
	trackedSecrets []string
	warnings       []string
}

// walkFunc receives every entry below the root. rel is slash-separated.
// .git directories and heavy package caches are reported but never
// descended into, whatever the callback returns.
type walkFunc func(rel string, d fs.DirEntry) error

// walkLimit is the entry limit a walk uses for the configured value n.
func walkLimit(n int) int {
	if n <= 0 {
		return defaultMaxWalkEntries
	}
	return n
}

// walkProject walks root without following symlinks. It returns true when
// the entry limit (walkLimit) stopped the walk early; callers that need
// the whole folder must refuse a truncated walk.
func walkProject(root string, limit int, fn walkFunc) (bool, error) {
	limit = walkLimit(limit)
	count := 0
	truncated := false
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if p == root {
				return walkErr
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if p == root {
			return nil
		}
		count++
		if count > limit {
			truncated = true
			return fs.SkipAll
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		err = fn(filepath.ToSlash(rel), d)
		if d.IsDir() && (d.Name() == ".git" || isHeavyDir(d.Name())) && err == nil {
			return fs.SkipDir
		}
		return err
	})
	return truncated, err
}

func isOpaqueDir(d fs.DirEntry) bool {
	return d.IsDir() && (d.Name() == ".git" || isHeavyDir(d.Name()))
}

// detectSecrets walks root and returns the files and directories to mask.
//
// A tracked file is exempt only while its working copy holds exactly the
// bytes of its index entry: the sandbox can read those from the mounted
// .git anyway. A working copy of its own (different bytes, or an entry
// marked skip-worktree or assume-unchanged, the usual way to keep local
// credentials in a committed config file) is treated like an untracked
// file: masked by name and scanned for content.
func detectSecrets(root string, opts secretScanOptions) (*secretScan, error) {
	res := &secretScan{}
	scanBudget := opts.maxScanFiles
	if scanBudget <= 0 {
		scanBudget = defaultMaxContentScanFiles
	}
	trackedLimit := opts.maxTrackedReads
	if trackedLimit <= 0 {
		trackedLimit = defaultMaxTrackedCompares
	}
	trackedReads, uncompared := trackedLimit, 0
	unmasked := func(rel string) bool { return unmaskedBy(opts.unmask, rel) }
	add := func(m MaskedPath) {
		if unmasked(m.Rel) {
			res.unmasked = append(res.unmasked, m.Rel)
			return
		}
		res.masks = append(res.masks, m)
	}
	truncated, err := walkProject(root, opts.maxEntries, func(rel string, d fs.DirEntry) error {
		entry, isTracked := opts.tracked[rel]
		if isOpaqueDir(d) || d.Name() == ".git" {
			return nil
		}
		if d.IsDir() {
			if isSecretDirName(d.Name()) && !dirHasTracked(opts.tracked, rel) {
				add(MaskedPath{Rel: rel, Dir: true, Reason: "name"})
				return fs.SkipDir
			}
			if p, ok := matchAny(opts.patterns, rel); ok {
				add(MaskedPath{Rel: rel, Dir: true, Reason: "pattern:" + p})
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		hardlinked := linkCount(info) > 1
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if p, ok := matchAny(opts.patterns, rel); ok {
			add(MaskedPath{Rel: rel, Reason: "pattern:" + p, Hardlinked: hardlinked})
			return nil
		}
		if secretByName(nil, rel) {
			if isTracked && !opts.maskTracked && entry.watched && info.Size() <= maxCompareBytes {
				if content, err := readSmallRegular(abs, maxCompareBytes+1); err == nil && entry.holds(content) {
					res.trackedSecrets = append(res.trackedSecrets, rel)
					return nil
				}
			}
			add(MaskedPath{Rel: rel, Reason: "name", Hardlinked: hardlinked})
			return nil
		}
		if !opts.contentScan || opts.detector == nil || info.Size() == 0 || info.Size() > maxContentScanBytes {
			return nil
		}
		var content []byte
		if isTracked && entry.watched {
			if trackedReads <= 0 {
				uncompared++
				return nil
			}
			trackedReads--
			if content, err = readSmallRegular(abs, maxContentScanBytes); err != nil || entry.holds(content) {
				return nil
			}
		}
		if scanBudget <= 0 {
			return nil
		}
		scanBudget--
		if content == nil {
			if content, err = readSmallRegular(abs, maxContentScanBytes); err != nil {
				return nil
			}
		}
		if looksBinary(content) {
			return nil
		}
		if rule, ok := opts.detector.DetectSecret(rel, content); ok {
			add(MaskedPath{Rel: rel, Reason: "content:" + rule, Hardlinked: hardlinked})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("workspace: scan %s for secrets: %w", root, err)
	}
	if truncated {
		res.warnings = append(res.warnings, fmt.Sprintf("secret scan of %s stopped after %d entries; files beyond that are not masked", root, opts.maxEntries))
	}
	if opts.contentScan && scanBudget <= 0 {
		res.warnings = append(res.warnings, "secret content scan reached its file budget; remaining files were checked by name only")
	}
	if uncompared > 0 {
		res.warnings = append(res.warnings, fmt.Sprintf("%d tracked file(s) past the first %d were not compared with their committed copy and were checked by name only", uncompared, trackedLimit))
	}
	for _, m := range res.masks {
		if m.Hardlinked {
			res.warnings = append(res.warnings, m.Rel+" has other hard links; its contents may still be readable under another name")
		}
	}
	if len(res.trackedSecrets) > 0 {
		res.warnings = append(res.warnings, fmt.Sprintf(
			"%d secret-like file(s) stay visible because they hold exactly their committed contents, which the sandbox can read from the repository anyway: %s",
			len(res.trackedSecrets), strings.Join(firstN(res.trackedSecrets, 5), ", ")))
	}
	if pathExists(filepath.Join(root, "node_modules", ".pnpm")) {
		res.warnings = append(res.warnings, "node_modules is linked from the pnpm store; installs inside the sandbox can modify packages shared with other projects")
	}
	if len(res.masks) > maxMasks {
		return nil, &NeedsCopyError{Path: root, Reason: fmt.Sprintf("it has %d secret files to hide (at most %d can be masked in a live mount)", len(res.masks), maxMasks)}
	}
	sort.Slice(res.masks, func(i, j int) bool { return res.masks[i].Rel < res.masks[j].Rel })
	sort.Strings(res.unmasked)
	return res, nil
}

func dirHasTracked(tracked map[string]trackedEntry, dir string) bool {
	if len(tracked) == 0 {
		return false
	}
	prefix := dir + "/"
	for p := range tracked {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func readSmallRegular(p string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

func looksBinary(b []byte) bool {
	if len(b) > 8192 {
		b = b[:8192]
	}
	return bytes.IndexByte(b, 0) >= 0
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	out := append([]string(nil), s[:n]...)
	return append(out, fmt.Sprintf("+%d more", len(s)-n))
}

// trackedFiles reads the project's index (pre-session): each path's mode,
// object name, and whether git watches its working copy. `ls-files -v`
// tags skip-worktree entries "S" and assume-unchanged ones in lower case.
func trackedFiles(ctx context.Context, project, gitDir string) (map[string]trackedEntry, error) {
	out, err := gitCmd{dir: project, gitDir: gitDir, workTree: project}.output(ctx, "ls-files", "-z", "-v", "--stage")
	if err != nil {
		return nil, err
	}
	set := map[string]trackedEntry{}
	for _, rec := range splitNUL(out) {
		meta, p, ok := strings.Cut(rec, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 4 {
			continue
		}
		e := trackedEntry{mode: f[1], oid: f[2], watched: f[0] == "H" && f[3] == "0"}
		if prev, seen := set[p]; seen {
			// An unmerged path has several stages; none is its content.
			prev.watched = false
			e = prev
		}
		set[p] = e
	}
	return set, nil
}

// holds reports whether content is exactly the blob of a regular-file
// entry: its git object name (SHA-1 or SHA-256, by length) matches.
func (e trackedEntry) holds(content []byte) bool {
	if e.mode != "100644" && e.mode != "100755" {
		return false
	}
	header := "blob " + strconv.Itoa(len(content)) + "\x00"
	var sum []byte
	switch len(e.oid) {
	case 40:
		h := sha1.New()
		h.Write([]byte(header))
		h.Write(content)
		sum = h.Sum(nil)
	case 64:
		h := sha256.New()
		h.Write([]byte(header))
		h.Write(content)
		sum = h.Sum(nil)
	default:
		return false
	}
	return hex.EncodeToString(sum) == strings.ToLower(e.oid)
}
