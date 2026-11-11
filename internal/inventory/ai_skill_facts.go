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
	maxSkillEntries   = 1000 // files and folders
	maxSkillBytes     = 32 << 20
	maxSkillScanBytes = 256 << 20
	maxSkillDepth     = 12
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
	s.skillFactsMu.Lock()
	facts, seen := s.skillFactsSeen[path]
	limit := min64(maxSkillBytes, maxSkillScanBytes-s.skillBytesRead)
	s.skillFactsMu.Unlock()
	if seen {
		return &facts
	}
	hash, status, read := hashSkillFolder(path, limit)
	facts = AISkillFacts{ContentHash: hash, ContentStatus: status}
	s.skillFactsMu.Lock()
	s.skillBytesRead += read
	if s.skillFactsSeen == nil {
		s.skillFactsSeen = map[string]AISkillFacts{}
	}
	s.skillFactsSeen[path] = facts
	s.skillFactsMu.Unlock()
	return &facts
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// hashSkillFolder hashes the sorted "rel NUL kind NUL sha256(payload) LF"
// lines of every entry below root (see defenseclaw.inventory.skill.content_hash).
// Links are recorded by target and never followed, and each file is read
// through safefile, so a scan running as root or SYSTEM reads only what is
// inside the folder.
func hashSkillFolder(root string, limit int64) (hash, status string, total int64) {
	info, err := os.Lstat(root)
	if err != nil {
		return "", SkillContentUnreadable, 0
	}
	if info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return "", SkillContentSymlink, 0
	}
	var lines []string
	entries := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		// Every entry counts, so empty folders cannot stretch the walk.
		if entries++; entries > maxSkillEntries {
			return errSkillTooLarge
		}
		if entry.IsDir() {
			switch {
			case entry.Name() == ".git":
				return fs.SkipDir
			case strings.Count(rel, "/") >= maxSkillDepth:
				return errSkillTooLarge
			}
			return nil
		}
		switch entry.Name() {
		case ".DS_Store", "Thumbs.db", "desktop.ini":
			return nil
		}
		kind, payload := "other", []byte(nil)
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			kind, payload = "link", []byte(filepath.ToSlash(target))
		case entry.Type().IsRegular():
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Size() > limit-total {
				return errSkillTooLarge
			}
			data, err := safefile.ReadRegularFileBounded(path, max(limit-total, 1))
			if err != nil {
				return err
			}
			total += int64(len(data))
			kind, payload = "file", data
		}
		sum := sha256.Sum256(payload)
		lines = append(lines, rel+"\x00"+kind+"\x00"+hex.EncodeToString(sum[:])+"\n")
		return nil
	})
	switch {
	case errors.Is(err, errSkillTooLarge):
		return "", SkillContentTooLarge, total
	case err != nil:
		return "", SkillContentUnreadable, total
	}
	sort.Strings(lines)
	digest := sha256.New()
	for _, line := range lines {
		_, _ = io.WriteString(digest, line)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), SkillContentOK, total
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
