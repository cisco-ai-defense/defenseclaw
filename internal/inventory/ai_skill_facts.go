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
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Skill scope values (defenseclaw.inventory.skill.scope).
const (
	SkillScopeUser    = "user"
	SkillScopeProject = "project"
	SkillScopeBundled = "bundled"
	SkillScopeManaged = "managed"
	SkillScopePlugin  = "plugin"
)

// Skill content status values (defenseclaw.inventory.skill.content_status).
const (
	SkillContentOK         = "ok"
	SkillContentSymlink    = "symlink"
	SkillContentTooLarge   = "too_large"
	SkillContentUnreadable = "unreadable"
)

const (
	maxSkillEntries     = 1000 // files and folders
	maxSkillBytes       = 32 << 20
	maxSkillScanBytes   = 256 << 20
	maxSkillDepth       = 12
	maxSkillLocation    = 512
	maxSkillManifest    = 64 << 10
	maxSkillAuthorBytes = 128
)

var errSkillTooLarge = errors.New("skill folder exceeds the hash limits")

// AISkillFacts describes one skill folder. The hash covers every file, so
// a changed script or binary changes it; it is the same on every device.
type AISkillFacts struct {
	ContentHash   string `json:"content_hash,omitempty"`
	ContentStatus string `json:"content_status"`
	Scope         string `json:"scope"`
	// Location is the folder below the user's home ("~/..."); the absolute
	// path never leaves the endpoint.
	Location string `json:"location,omitempty"`
	// Author is the skill's own unverified SKILL.md claim.
	Author string         `json:"author,omitempty"`
	Plugin *AISkillPlugin `json:"plugin,omitempty"`
}

func (s *ContinuousDiscoveryService) resetSkillFacts() {
	s.skillFactsMu.Lock()
	s.skillFactsSeen, s.skillBytesRead = nil, 0
	s.skillFactsMu.Unlock()
}

// skillFacts returns the facts of the skill folder at path, computed once
// per skill scan. One scan reads at most maxSkillScanBytes across all users.
func (s *ContinuousDiscoveryService) skillFacts(path string, bundled bool) *AISkillFacts {
	s.skillFactsMu.Lock()
	facts, seen := s.skillFactsSeen[path]
	limit := min64(maxSkillBytes, maxSkillScanBytes-s.skillBytesRead)
	s.skillFactsMu.Unlock()
	if seen {
		return &facts
	}
	hash, status, manifest, read := hashSkillFolder(path, limit)
	location, inHome := s.skillLocation(path)
	facts = AISkillFacts{
		ContentHash: hash, ContentStatus: status, Scope: SkillScopeUser,
		Location: location, Author: skillAuthor(manifest),
	}
	switch {
	case bundled:
		facts.Scope = SkillScopeBundled
	case !inHome:
		facts.Scope = SkillScopeManaged // an admin folder such as /etc/codex/skills
	}
	s.skillFactsMu.Lock()
	s.skillBytesRead += read
	if s.skillFactsSeen == nil {
		s.skillFactsSeen = map[string]AISkillFacts{}
	}
	s.skillFactsSeen[path] = facts
	s.skillFactsMu.Unlock()
	return &facts
}

// realChildDirs lists the folders in dir, never a link to one.
func realChildDirs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			out = append(out, entry.Name())
		}
	}
	sort.Strings(out)
	return out
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
func hashSkillFolder(root string, limit int64) (hash, status string, manifest []byte, total int64) {
	info, err := os.Lstat(root)
	if err != nil {
		return "", SkillContentUnreadable, nil, 0
	}
	if info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return "", SkillContentSymlink, nil, 0
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
			if strings.EqualFold(rel, "SKILL.md") {
				manifest = data[:min(len(data), maxSkillManifest)]
			}
		}
		sum := sha256.Sum256(payload)
		lines = append(lines, rel+"\x00"+kind+"\x00"+hex.EncodeToString(sum[:])+"\n")
		return nil
	})
	switch {
	case errors.Is(err, errSkillTooLarge):
		return "", SkillContentTooLarge, manifest, total
	case err != nil:
		return "", SkillContentUnreadable, manifest, total
	}
	sort.Strings(lines)
	digest := sha256.New()
	for _, line := range lines {
		_, _ = io.WriteString(digest, line)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), SkillContentOK, manifest, total
}

// skillAuthor returns the author a SKILL.md frontmatter declares at the top
// level or under metadata.
func skillAuthor(manifest []byte) string {
	lines := strings.Split(strings.TrimPrefix(string(manifest), "\ufeff"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return ""
	}
	inMetadata := false
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" || trimmed == "..." {
			break
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		indented := line[0] == ' ' || line[0] == '\t'
		if !indented {
			inMetadata = key == "metadata" && value == ""
		}
		if key != "author" || (indented && !inMetadata) {
			continue
		}
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		} else if comment := strings.Index(value, " #"); comment >= 0 {
			value = strings.TrimSpace(value[:comment])
		}
		if !utf8.ValidString(value) || containsUnicodeControl(value) {
			return ""
		}
		for len(value) > maxSkillAuthorBytes {
			_, size := utf8.DecodeLastRuneInString(value)
			value = value[:len(value)-size]
		}
		return value
	}
	return ""
}

// skillLocation is path below the scanned home that holds it, as "~/rel"
// with forward slashes ("" when it cannot be sent), and whether path is in
// a scanned home at all.
func (s *ContinuousDiscoveryService) skillLocation(path string) (string, bool) {
	for _, home := range s.homesToScan() {
		rel, err := filepath.Rel(home, path)
		if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) ||
			strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if location := "~/" + filepath.ToSlash(rel); len(location) <= maxSkillLocation && !containsUnicodeControl(location) {
			return location, true
		}
		return "", true
	}
	return "", false
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
	switch facts.Scope {
	case SkillScopeUser, SkillScopeProject, SkillScopeBundled, SkillScopeManaged, SkillScopePlugin:
	default:
		return fmt.Errorf("unknown skill scope %q", facts.Scope)
	}
	if facts.Location != "" && (!strings.HasPrefix(facts.Location, "~/") || !userScanText(facts.Location, maxSkillLocation)) {
		return errors.New("skill location must be a printable home-relative path")
	}
	if !userScanText(facts.Author, maxSkillAuthorBytes) {
		return errors.New("skill author must be short printable text")
	}
	if plugin := facts.Plugin; plugin != nil && (!validPluginID(plugin.ID) ||
		!userScanText(plugin.Version, 64) || !userScanText(plugin.Author, maxSkillAuthorBytes)) {
		return errors.New("skill plugin fields must be short printable text")
	}
	return nil
}
