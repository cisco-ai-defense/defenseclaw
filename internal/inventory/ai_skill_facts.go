// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Skill content status values (defenseclaw.inventory.skill.content_status).
const (
	SkillContentOK         = "ok"
	SkillContentSymlink    = "symlink"
	SkillContentTooLarge   = "too_large"
	SkillContentUnreadable = "unreadable"
)

const (
	maxSkillEntries        = 1000 // included files and folders
	maxSkillVisitedEntries = 2 * maxSkillEntries
	maxSkillBytes          = 32 << 20
	maxSkillScanBytes      = 256 << 20
	maxSkillDepth          = 12
	skillReadDirBatch      = 64
)

var errSkillTooLarge = errors.New("skill folder exceeds the hash limits")

// AISkillFacts describes one skill folder. The hash covers every file, so
// a changed script or binary changes it; it is the same on every device.
type AISkillFacts struct {
	ContentHash   string `json:"content_hash,omitempty"`
	ContentStatus string `json:"content_status"`
}

func (s *ContinuousDiscoveryService) resetSkillFacts() {
	s.skillFactsMu.Lock()
	s.skillFactsSeen, s.skillBytesRead = nil, 0
	s.skillFactsMu.Unlock()
}

// skillFacts returns the facts of the skill folder at path, computed once
// per skill scan. One scan reads at most maxSkillScanBytes across all users.
func (s *ContinuousDiscoveryService) skillFacts(path string) *AISkillFacts {
	if s.opts.DisableSkillContentHashes {
		return nil
	}
	s.skillFactsMu.Lock()
	defer s.skillFactsMu.Unlock()
	if facts, seen := s.skillFactsSeen[path]; seen {
		return &facts
	}
	limit := min(maxSkillBytes, maxSkillScanBytes-s.skillBytesRead)
	hash, status, read := hashSkillFolder(path, limit)
	facts := AISkillFacts{ContentHash: hash, ContentStatus: status}
	s.skillBytesRead += read
	if s.skillFactsSeen == nil {
		s.skillFactsSeen = map[string]AISkillFacts{}
	}
	s.skillFactsSeen[path] = facts
	return &facts
}

// hashSkillFolder hashes the sorted "rel NUL kind NUL sha256(payload) LF"
// lines of every entry below root (see defenseclaw.inventory.skill.content_hash).
// Child directories and files are opened relative to held parent handles.
// Links contribute their stored targets without opening those targets.
func hashSkillFolder(root string, limit int64) (hash, status string, consumed int64) {
	dir, err := safefile.OpenDirectoryNoFollow(root)
	if errors.Is(err, safefile.ErrSymlinkRefused) {
		return "", SkillContentSymlink, 0
	}
	if err != nil {
		return "", SkillContentUnreadable, 0
	}
	defer dir.Close()
	if limit <= 0 {
		return "", SkillContentTooLarge, 0
	}
	walk := skillHashWalk{limit: limit}
	err = walk.readDir(dir, "", 0)
	switch {
	case errors.Is(err, errSkillTooLarge), errors.Is(err, safefile.ErrReadLimit):
		return "", SkillContentTooLarge, walk.consumed
	case err != nil:
		return "", SkillContentUnreadable, walk.consumed
	}
	sort.Strings(walk.lines)
	digest := sha256.New()
	for _, line := range walk.lines {
		_, _ = io.WriteString(digest, line)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), SkillContentOK, walk.consumed
}

type skillHashWalk struct {
	limit    int64
	consumed int64
	visited  int
	included int
	lines    []string
}

func (walk *skillHashWalk) readDir(dir *os.File, prefix string, depth int) error {
	for {
		batch := min(skillReadDirBatch, maxSkillVisitedEntries-walk.visited+1)
		entries, err := dir.ReadDir(batch)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		for _, entry := range entries {
			walk.visited++
			if walk.visited > maxSkillVisitedEntries {
				return errSkillTooLarge
			}
			if excludedSkillEntry(entry) {
				continue
			}
			walk.included++
			if walk.included > maxSkillEntries {
				return errSkillTooLarge
			}
			if err := walk.readEntry(dir, entry, prefix+entry.Name(), depth); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func excludedSkillEntry(entry fs.DirEntry) bool {
	if entry.IsDir() {
		return entry.Name() == ".git"
	}
	switch entry.Name() {
	case ".DS_Store", "Thumbs.db", "desktop.ini":
		return true
	default:
		return false
	}
}

func (walk *skillHashWalk) readEntry(parent *os.File, entry fs.DirEntry, rel string, depth int) error {
	name := entry.Name()
	if entry.IsDir() {
		if depth >= maxSkillDepth {
			return errSkillTooLarge
		}
		dir, err := safefile.OpenDirectoryChildNoFollow(parent, name)
		if err != nil {
			return err
		}
		defer dir.Close()
		return walk.readDir(dir, rel+"/", depth+1)
	}

	kind := "other"
	var sum [sha256.Size]byte
	switch {
	case entry.Type()&fs.ModeSymlink != 0:
		target, err := safefile.ReadChildLink(parent, name)
		if err != nil {
			return err
		}
		kind, sum = "link", sha256.Sum256([]byte(filepath.ToSlash(target)))
	case entry.Type().IsRegular():
		file, err := safefile.OpenRegularChildNoFollow(parent, name)
		if err != nil {
			return err
		}
		defer file.Close()
		digest, consumed, err := safefile.HashOpenedRegularFileBounded(file, walk.limit-walk.consumed)
		walk.consumed += consumed
		if err != nil {
			return err
		}
		current, err := safefile.OpenRegularChildNoFollow(parent, name)
		if err != nil {
			return err
		}
		defer current.Close()
		if !sameOpenedSkillFile(file, current) {
			return errors.New("skill file was replaced while reading")
		}
		kind, sum = "file", digest
	default:
		sum = sha256.Sum256(nil)
	}
	walk.lines = append(walk.lines, rel+"\x00"+kind+"\x00"+hex.EncodeToString(sum[:])+"\n")
	return nil
}

func sameOpenedSkillFile(first, second *os.File) bool {
	before, err := first.Stat()
	if err != nil {
		return false
	}
	after, err := second.Stat()
	return err == nil && os.SameFile(before, after)
}

// validateSkillFacts bounds the facts a per-user scan reports.
func validateSkillFacts(facts AISkillFacts) error {
	switch facts.ContentStatus {
	case SkillContentOK:
		if !strings.HasPrefix(facts.ContentHash, "sha256:") || !isSHA256Hash(facts.ContentHash) {
			return errors.New("skill content hash must be a sha256 digest")
		}
	case SkillContentSymlink, SkillContentTooLarge, SkillContentUnreadable:
		if facts.ContentHash != "" {
			return errors.New("skill content hash without an ok status")
		}
	default:
		return fmt.Errorf("unknown skill content status %q", facts.ContentStatus)
	}
	return nil
}
