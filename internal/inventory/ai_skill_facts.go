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
	maxSkillEntries        = 1000 // included files and folders
	maxSkillVisitedEntries = 2 * maxSkillEntries
	maxSkillBytes          = 32 << 20
	maxSkillScanBytes      = 256 << 20
	maxSkillDepth          = 12
	skillReadDirBatch      = 64
	maxSkillLocation       = 512
	maxSkillManifest       = 64 << 10 // the part parseSkillFrontMatter reads
	maxSkillAuthorBytes    = 128
	// maxSkillDescriptionBytes matches defenseclaw.inventory.item.description.
	maxSkillDescriptionBytes = 512
	maxSkillVersionBytes     = 64
)

// maxSkillManifestFolders bounds the hash-to-folder index SkillManifest
// reads from.
const maxSkillManifestFolders = 4096

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
	// Author, Description and Version are the skill's own unverified
	// SKILL.md claims, one bounded line each.
	Author      string         `json:"author,omitempty"`
	Description string         `json:"description,omitempty"`
	Version     string         `json:"version,omitempty"`
	Plugin      *AISkillPlugin `json:"plugin,omitempty"`

	// ManifestHash is the SHA-256 of the folder's SKILL.md; SkillManifest
	// reads that file again for a managed publish. ManifestSize is its size
	// in bytes.
	ManifestHash string `json:"manifest_hash,omitempty"`
	ManifestSize int64  `json:"manifest_size,omitempty"`
}

func (s *ContinuousDiscoveryService) resetSkillFacts() {
	s.skillFactsMu.Lock()
	s.skillFactsSeen, s.skillBytesRead = nil, 0
	s.skillFactsMu.Unlock()
}

func (s *ContinuousDiscoveryService) beginSkillFactsScan() {
	s.skillFactsMu.Lock()
	s.skillFactsSeen, s.skillBytesRead = nil, 0
	s.skillManifests = nil
	s.skillFactsMu.Unlock()
}

// skillFacts returns the facts of the skill folder at path, computed once
// per skill scan. One scan reads at most maxSkillScanBytes across all users.
func (s *ContinuousDiscoveryService) skillFacts(path string, bundled bool) *AISkillFacts {
	if s.opts.DisableSkillContentHashes {
		return nil
	}
	s.skillFactsMu.Lock()
	defer s.skillFactsMu.Unlock()
	if facts, seen := s.skillFactsSeen[path]; seen {
		return &facts
	}
	limit := min(maxSkillBytes, maxSkillScanBytes-s.skillBytesRead)
	hash, status, manifest, manifestName, read := hashSkillFolderCaptureNamed(path, limit, maxSkillBytes)
	location, inHome := s.skillLocation(path)
	front := parseSkillFrontMatter(manifest)
	facts := AISkillFacts{
		ContentHash: hash, ContentStatus: status, Scope: SkillScopeUser, Location: location,
		Author: front.author, Description: front.description, Version: front.version,
	}
	if status == SkillContentOK && manifest != nil {
		facts.ManifestHash = skillManifestHash(manifest)
		facts.ManifestSize = int64(len(manifest))
	}
	switch {
	case bundled:
		facts.Scope = SkillScopeBundled
	case !inHome:
		facts.Scope = SkillScopeManaged // an admin folder such as /etc/codex/skills
	}
	s.skillBytesRead += read
	if s.skillFactsSeen == nil {
		s.skillFactsSeen = map[string]AISkillFacts{}
	}
	s.skillFactsSeen[path] = facts
	if facts.ManifestHash != "" {
		if s.skillManifests == nil {
			s.skillManifests = map[string]string{}
		}
		if _, known := s.skillManifests[facts.ManifestHash]; known || len(s.skillManifests) < maxSkillManifestFolders {
			s.skillManifests[facts.ManifestHash] = filepath.Join(path, manifestName)
		}
	}
	return &facts
}

// SkillManifest returns the SKILL.md a skill scan hashed to hash, read again
// from its recorded root leaf, or false when it is gone or changed since.
func (s *ContinuousDiscoveryService) SkillManifest(hash string) ([]byte, bool) {
	if s.opts.DisableSkillContentHashes {
		return nil, false
	}
	s.skillFactsMu.Lock()
	path := s.skillManifests[hash]
	s.skillFactsMu.Unlock()
	if path == "" {
		return nil, false
	}
	dir, err := safefile.OpenDirectoryNoFollow(filepath.Dir(path))
	if err != nil {
		return nil, false
	}
	defer dir.Close()
	name := filepath.Base(path)
	file, err := safefile.OpenRegularChildNoFollow(dir, name)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	digest, data, _, err := safefile.HashOpenedRegularFileBoundedCapture(file, maxSkillBytes, maxSkillBytes)
	if err != nil || "sha256:"+hex.EncodeToString(digest[:]) != hash {
		return nil, false
	}
	current, err := safefile.OpenRegularChildNoFollow(dir, name)
	if err != nil {
		return nil, false
	}
	defer current.Close()
	if !sameOpenedSkillFile(file, current) {
		return nil, false
	}
	return data, true
}

func skillManifestHash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
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

// hashSkillFolder hashes the sorted "rel NUL kind NUL sha256(payload) LF"
// lines of every entry below root (see defenseclaw.inventory.skill.content_hash).
// Child directories and files are opened relative to held parent handles.
// Links contribute their stored targets without opening those targets.
func hashSkillFolder(root string, limit int64) (hash, status string, consumed int64) {
	hash, status, _, consumed = hashSkillFolderCapture(root, limit, 0)
	return hash, status, consumed
}

// hashSkillFolderCapture retains only a root SKILL.md prefix from the same
// bounded, stable read that supplies that file's complete digest.
func hashSkillFolderCapture(root string, limit int64, captureLimit int) (hash, status string, manifest []byte, consumed int64) {
	hash, status, manifest, _, consumed = hashSkillFolderCaptureNamed(root, limit, captureLimit)
	return hash, status, manifest, consumed
}

// hashSkillFolderCaptureNamed also returns the exact root manifest leaf observed
// by the pinned walk, so a later explicit readback never needs to list again.
func hashSkillFolderCaptureNamed(root string, limit int64, captureLimit int) (hash, status string, manifest []byte, manifestName string, consumed int64) {
	dir, err := safefile.OpenDirectoryNoFollow(root)
	if errors.Is(err, safefile.ErrSymlinkRefused) {
		return "", SkillContentSymlink, nil, "", 0
	}
	if err != nil {
		return "", SkillContentUnreadable, nil, "", 0
	}
	defer dir.Close()
	if limit <= 0 {
		return "", SkillContentTooLarge, nil, "", 0
	}
	walk := skillHashWalk{limit: limit, captureLimit: captureLimit}
	err = walk.readDir(dir, "", 0)
	switch {
	case errors.Is(err, errSkillTooLarge), errors.Is(err, safefile.ErrReadLimit):
		return "", SkillContentTooLarge, walk.manifest, walk.manifestName, walk.consumed
	case err != nil:
		return "", SkillContentUnreadable, walk.manifest, walk.manifestName, walk.consumed
	}
	sort.Strings(walk.lines)
	digest := sha256.New()
	for _, line := range walk.lines {
		_, _ = io.WriteString(digest, line)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), SkillContentOK, walk.manifest, walk.manifestName, walk.consumed
}

type skillHashWalk struct {
	captureLimit int
	manifest     []byte
	manifestName string
	limit        int64
	consumed     int64
	visited      int
	included     int
	lines        []string
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
		captureLimit := 0
		// Match only a root manifest, never one in a nested skill or scripts folder.
		// Retain the lexically last case alias, like the original sorted walk.
		if walk.captureLimit > 0 && strings.EqualFold(rel, "SKILL.md") &&
			(walk.manifestName == "" || rel > walk.manifestName) {
			captureLimit = walk.captureLimit
		}
		digest, retained, consumed, err := safefile.HashOpenedRegularFileBoundedCapture(file, walk.limit-walk.consumed, captureLimit)
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
		if captureLimit > 0 {
			walk.manifest, walk.manifestName = retained, rel
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

// skillFrontMatter is what a SKILL.md frontmatter declares about its skill.
type skillFrontMatter struct{ author, description, version string }

// parseSkillFrontMatter reads the author and version a SKILL.md frontmatter
// declares at the top level or under metadata, and its top-level
// description. A block (| or >) or wrapped value is folded into one line;
// the first declaration of a key wins, and a value that is not printable
// text is left out.
func parseSkillFrontMatter(manifest []byte) skillFrontMatter {
	var out skillFrontMatter
	manifest = manifest[:min(len(manifest), maxSkillManifest)]
	lines := strings.Split(strings.TrimPrefix(string(manifest), "\ufeff"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return out
	}
	seen := map[string]bool{}
	inMetadata, metadataIndent := false, 0
	for i := 1; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent == 0 && (trimmed == "---" || trimmed == "...") {
			break
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if indent == 0 {
			inMetadata = key == "metadata" && value == ""
			metadataIndent = 0
		} else if inMetadata && metadataIndent == 0 {
			metadataIndent = indent
		}
		var field *string
		limit := 0
		switch {
		case key == "author" && (indent == 0 || inMetadata && indent == metadataIndent):
			field, limit = &out.author, maxSkillAuthorBytes
		case key == "version" && (indent == 0 || inMetadata && indent == metadataIndent):
			field, limit = &out.version, maxSkillVersionBytes
		case key == "description" && indent == 0:
			field, limit = &out.description, maxSkillDescriptionBytes
		default:
			continue
		}
		block := isYAMLBlockIndicator(value)
		inner, quoted := closedQuotedValue(value)
		plain := !block && (value == "" || value[0] != '"' && value[0] != '\'')
		switch {
		case quoted:
			value = inner
		case block:
			value = ""
		case value == "" || (value[0] != '"' && value[0] != '\''):
			if comment := strings.Index(value, " #"); comment >= 0 {
				value = strings.TrimSpace(value[:comment])
			}
		}
		// A block scalar, or a plain one wrapped onto more-indented lines,
		// continues until a line indented no deeper than its key.
		if block || (!quoted && value != "") {
			var folded strings.Builder
			for i+1 < len(lines) {
				next := strings.TrimRight(lines[i+1], "\r")
				nextTrimmed := strings.TrimSpace(next)
				if nextTrimmed == "" {
					if !block {
						break
					}
					i++
					continue
				}
				if len(next)-len(strings.TrimLeft(next, " \t")) <= indent {
					break
				}
				if plain {
					if strings.HasPrefix(nextTrimmed, "#") {
						i++
						continue
					}
					if comment := strings.Index(nextTrimmed, " #"); comment >= 0 {
						nextTrimmed = strings.TrimSpace(nextTrimmed[:comment])
					}
				}
				if folded.Len() == 0 {
					folded.WriteString(value)
				}
				folded.WriteByte(' ')
				folded.WriteString(nextTrimmed)
				i++
			}
			if folded.Len() > 0 {
				value = folded.String()
			}
			// A quoted value may wrap too.
			if !block && len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
				value = value[1 : len(value)-1]
			}
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		*field = skillFrontMatterText(value, limit)
	}
	return out
}

// closedQuotedValue is the text of a value quoted and closed on its own line,
// before any trailing comment.
func closedQuotedValue(value string) (string, bool) {
	if len(value) < 2 || (value[0] != '"' && value[0] != '\'') {
		return "", false
	}
	end := strings.IndexByte(value[1:], value[0])
	if end < 0 {
		return "", false
	}
	if rest := strings.TrimSpace(value[end+2:]); rest != "" && !strings.HasPrefix(rest, "#") {
		return "", false
	}
	return value[1 : end+1], true
}

// isYAMLBlockIndicator reports a literal or folded block scalar header such
// as |, >-, |+ or >2.
func isYAMLBlockIndicator(value string) bool {
	if comment := strings.Index(value, " #"); comment >= 0 {
		value = strings.TrimSpace(value[:comment])
	}
	if value == "" || (value[0] != '|' && value[0] != '>') || len(value) > 3 {
		return false
	}
	for _, r := range value[1:] {
		if r != '-' && r != '+' && (r < '1' || r > '9') {
			return false
		}
	}
	return true
}

// skillFrontMatterText is value as one line of at most limit bytes, or ""
// when it holds anything but printable text.
func skillFrontMatterText(value string, limit int) string {
	if !utf8.ValidString(value) {
		return ""
	}
	value = strings.Join(strings.Fields(value), " ")
	if containsUnicodeControl(value) {
		return ""
	}
	for len(value) > limit {
		_, size := utf8.DecodeLastRuneInString(value)
		value = value[:len(value)-size]
	}
	return strings.TrimSpace(value)
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
	if !userScanText(facts.Author, maxSkillAuthorBytes) || !userScanText(facts.Description, maxSkillDescriptionBytes) ||
		!userScanText(facts.Version, maxSkillVersionBytes) {
		return errors.New("skill author, description and version must be short printable text")
	}
	if facts.ManifestSize < 0 || facts.ManifestSize > maxSkillBytes || (facts.ManifestSize > 0 && facts.ManifestHash == "") {
		return errors.New("skill manifest size must come with its manifest hash")
	}
	if facts.ManifestHash != "" && (facts.ContentStatus != SkillContentOK || !strings.HasPrefix(facts.ManifestHash, "sha256:") || !isSHA256Hash(facts.ManifestHash)) {
		return errors.New("skill manifest hash must be a sha256 digest of an ok folder")
	}
	if plugin := facts.Plugin; plugin != nil && (!validPluginID(plugin.ID) ||
		!userScanText(plugin.Version, 64) || !userScanText(plugin.Author, maxSkillAuthorBytes)) {
		return errors.New("skill plugin fields must be short printable text")
	}
	return nil
}
