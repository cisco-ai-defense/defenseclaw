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
	"time"
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
	cached, inCache := s.skillHashCache[path]
	// An unchanged folder keeps its last hash without being read again
	// (ai_skill_hash_cache.go), and costs nothing from the scan budget.
	now := s.skillNow()
	signature, newest, signed := skillFolderSignature(path)
	// A managed Windows scan reads every folder each time: the metadata a
	// user can write back by hand there is all the cache could check.
	signed = signed && (skillChangeStampTamperEvident || !s.opts.ManagedEnterprise)
	location, inHome := s.skillLocation(path)
	// Only a folder outside every home is ever reported as managed.
	var managedProbe func(*os.File, string) bool
	if !bundled && !inHome {
		managedProbe = skillFolderManaged
	}
	hashed, read, keep := cached, int64(0), false
	managed := false
	if !inCache || !signed || !cached.fresh(signature, now) {
		var manifest []byte
		hashed = skillHashCacheEntry{signature: signature, hashedAt: now}
		hashed.hash, hashed.status, manifest, hashed.manifestPath, read, hashed.managed = hashSkillFolderCaptureNamed(
			path, limit, maxSkillBytes, s.skillFolderTrust(path), managedProbe)
		managed = hashed.managed
		hashed.front = parseSkillFrontMatter(manifest)
		if hashed.status == SkillContentOK && manifest != nil {
			hashed.manifestHash = skillManifestHash(manifest)
			hashed.manifestSize = int64(len(manifest))
		}
		// A folder cut short by the scan budget, not by its own size, is
		// read again next scan.
		keep = signed && (hashed.status == SkillContentOK ||
			hashed.status == SkillContentTooLarge && limit >= maxSkillBytes)
		// A folder with an entry stamped within one timestamp tick of the read
		// is not kept: a later same-size write could carry the same stamp and
		// leave the signature as it was (skillHashCacheRacyWindow).
		keep = keep && !skillSignatureRacy(newest, now)
	} else if managedProbe != nil {
		// Nothing was read this scan: the label is the hashed result's, and
		// the folder must still be one only administrators can change.
		managed = hashed.managed && skillFolderManagedNow(path)
	}
	facts := AISkillFacts{
		ContentHash: hashed.hash, ContentStatus: hashed.status, Scope: SkillScopeUser, Location: location,
		Author: hashed.front.author, Description: hashed.front.description, Version: hashed.front.version,
		ManifestHash: hashed.manifestHash, ManifestSize: hashed.manifestSize,
	}
	switch {
	case bundled:
		facts.Scope = SkillScopeBundled
	case managed:
		facts.Scope = SkillScopeManaged // an admin folder such as /etc/codex/skills
	}
	s.skillBytesRead += read
	if s.skillFactsSeen == nil {
		s.skillFactsSeen = map[string]AISkillFacts{}
	}
	s.skillFactsSeen[path] = facts
	if keep {
		if s.skillHashCache == nil || len(s.skillHashCache) >= maxSkillHashCacheFolders {
			s.skillHashCache = map[string]skillHashCacheEntry{}
		}
		s.skillHashCache[path] = hashed
	}
	if facts.ManifestHash != "" {
		if s.skillManifests == nil {
			s.skillManifests = map[string]string{}
		}
		if _, known := s.skillManifests[facts.ManifestHash]; known || len(s.skillManifests) < maxSkillManifestFolders {
			s.skillManifests[facts.ManifestHash] = hashed.manifestPath
		}
	}
	return &facts
}

// skillFolderManagedNow decides skillFolderManaged for the folder at path
// from a fresh open, when the scan did not read the folder.
func skillFolderManagedNow(path string) bool {
	dir, err := safefile.OpenDirectoryNoFollow(path)
	if err != nil {
		return false
	}
	defer dir.Close()
	return skillFolderManaged(dir, path)
}

// skillNow is the time a skill folder's hash is read at, for the racy-entry
// check and the cache age; a test sets skillClock.
func (s *ContinuousDiscoveryService) skillNow() time.Time {
	if s.skillClock != nil {
		return s.skillClock()
	}
	return time.Now()
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

// skillReadDir is how the hash walk lists a folder; a test replaces it to
// give the walk the listing a file system can give (a stale size).
var skillReadDir = (*os.File).ReadDir

// hashSkillFolderCaptureNamed hashes the sorted "rel NUL kind NUL
// sha256(payload) LF" lines of every entry below root (see
// defenseclaw.inventory.skill.content_hash). Child directories and files are
// opened relative to held parent handles; links contribute their stored
// targets without opening those targets. It retains a root SKILL.md prefix
// from the same bounded, stable read that supplies that file's digest, and
// returns that manifest's exact path, so a later readback never lists again.
// When managed is set it decides, from the handle of the folder it hashes
// (and root, the path it was asked for) and of every folder and file it
// opens, whether only administrators can change what was hashed (GAP-2147).
func hashSkillFolderCaptureNamed(root string, limit int64, captureLimit int, trusted, managed func(*os.File, string) bool) (hash, status string, manifest []byte, manifestPath string, consumed int64, adminOnly bool) {
	dir, opened, linked, err := openSkillFolder(root, trusted)
	if errors.Is(err, safefile.ErrSymlinkRefused) {
		return "", SkillContentSymlink, nil, "", 0, false
	}
	if err != nil {
		return "", SkillContentUnreadable, nil, "", 0, false
	}
	defer dir.Close()
	folderManaged := managed != nil && managed(dir, root)
	if limit <= 0 {
		return "", SkillContentTooLarge, nil, "", 0, folderManaged
	}
	walk := skillHashWalk{limit: limit, captureLimit: captureLimit, root: opened, hardLinkTrust: trusted, managed: folderManaged}
	if linked {
		walk.trusted = trusted
	}
	if folderManaged {
		walk.entryManaged = skillEntryManaged
	}
	walk.rootInfo, _ = dir.Stat()
	err = walk.readDir(dir, "", 0)
	if walk.manifestName != "" {
		manifestPath = filepath.Join(opened, walk.manifestName)
	}
	switch {
	case errors.Is(err, errSkillUntrusted):
		return "", SkillContentSymlink, nil, "", walk.consumed, false
	case errors.Is(err, errSkillTooLarge), errors.Is(err, safefile.ErrReadLimit):
		return "", SkillContentTooLarge, walk.manifest, manifestPath, walk.consumed, walk.managed
	case err != nil:
		return "", SkillContentUnreadable, walk.manifest, manifestPath, walk.consumed, walk.managed
	}
	sort.Strings(walk.lines)
	digest := sha256.New()
	for _, line := range walk.lines {
		_, _ = io.WriteString(digest, line)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), SkillContentOK, walk.manifest, manifestPath, walk.consumed, walk.managed
}

// openSkillFolder opens the skill folder at root. A skill folder that is a
// link stays refused (ErrSymlinkRefused), as does every link below it. A link
// above it, such as ~/.claude linked into a dotfiles repo or /home linked to
// /var/home, is resolved once, and the resolved folders, the skill folder
// included, are accepted only when trusted approves each (GAP-2001). It
// returns the spelling it opened root by, and linked when that spelling is
// the resolved one: the walk below then asks trusted for every folder and
// file too (GAP-2008).
func openSkillFolder(root string, trusted func(*os.File, string) bool) (*os.File, string, bool, error) {
	lexical := filepath.Dir(root)
	parent, resolved, err := safefile.OpenDirectoryResolved(lexical, trusted)
	if err != nil {
		return nil, "", false, err
	}
	defer parent.Close()
	name := filepath.Base(root)
	dir, err := safefile.OpenDirectoryChildNoFollow(parent, name)
	if err != nil {
		if _, linkErr := safefile.ReadChildLink(parent, name); linkErr == nil {
			return nil, "", false, fmt.Errorf("%w: %w", safefile.ErrSymlinkRefused, err)
		}
		return nil, "", false, err
	}
	opened, linked := filepath.Join(resolved, name), resolved != lexical
	if linked && !trusted(dir, opened) {
		_ = dir.Close()
		return nil, "", false, fmt.Errorf("%w: %s has an untrusted owner", safefile.ErrSymlinkRefused, opened)
	}
	return dir, opened, linked, nil
}

// skillFolderTrust approves the folders a skill folder at path is reached
// through when a link above it is resolved, and what the walk opens below it:
// those of the scanned home that holds path, or of the scanning account
// outside every home.
func (s *ContinuousDiscoveryService) skillFolderTrust(path string) func(*os.File, string) bool {
	home, _ := s.skillHome(path)
	return s.skillHomeTrust(home)
}

// errSkillUntrusted is a folder or file below a linked skill folder that the
// trust does not approve; the folder reads as a refused link (GAP-2008).
var errSkillUntrusted = errors.New("skill folder entry has an untrusted owner")

type skillHashWalk struct {
	// trusted, when set (a skill folder reached through a resolved link),
	// approves every folder and file the walk opens below root, the opened
	// spelling of the skill folder, so a link in a home cannot lead a root
	// or SYSTEM scan into what the home owner may not list or read.
	trusted func(*os.File, string) bool
	// hardLinkTrust approves a file with more than one name in a walk with
	// no trust of its own, where the other name may be one only a root scan
	// can read (GAP-2146).
	hardLinkTrust func(*os.File, string) bool
	// managed is whether only administrators can change the folder and
	// everything opened so far; entryManaged, when set, is asked of each
	// folder and file the walk opens while it holds (GAP-2147).
	managed      bool
	entryManaged func(*os.File, string) bool
	root         string
	captureLimit int
	rootInfo     fs.FileInfo // the opened skill folder, for skillManifestOwned
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
		entries, err := skillReadDir(dir, batch)
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
		if err := walk.approve(dir, rel); err != nil {
			return err
		}
		walk.checkManaged(dir, rel)
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
			return walk.openRefused(parent, name, err)
		}
		defer file.Close()
		if err := walk.approve(file, rel); err != nil {
			return err
		}
		if walk.trusted == nil && skillHardLinked(file) && !walk.hardLinkTrust(file, filepath.Join(walk.root, filepath.FromSlash(rel))) {
			return fmt.Errorf("%w: %s", errSkillUntrusted, rel)
		}
		walk.checkManaged(file, rel)
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
		// The SKILL.md text is kept only when the owner of the skill folder owns
		// it as a single-link regular file (GAP-1811), checked on this handle.
		if captureLimit > 0 && skillManifestOwned(file, walk.rootInfo) {
			walk.manifest, walk.manifestName = retained, rel
		}
		kind, sum = "file", digest
	default:
		sum = sha256.Sum256(nil)
	}
	walk.lines = append(walk.lines, rel+"\x00"+kind+"\x00"+hex.EncodeToString(sum[:])+"\n")
	return nil
}

// openRefused is the error for a regular file the walk could not open. A file
// too large for the budget by its own record (never the listing, GAP-1901) is
// too large, as on rel, even when it cannot be opened: on Windows while a
// writer holds it open, or one the scan may not read (GAP-2006). Only its
// size is looked at, never its bytes, and it is read relative to the held
// parent, never by a path that could be resolved again (GAP-2009).
func (walk *skillHashWalk) openRefused(parent *os.File, name string, err error) error {
	if size, regular, statErr := safefile.RegularChildSize(parent, name); statErr == nil && regular && size > walk.limit-walk.consumed {
		return errSkillTooLarge
	}
	return err
}

// approve asks the trust about an opened folder or file at rel below a linked
// skill folder; below an unlinked one everything is the folder's own.
func (walk *skillHashWalk) approve(opened *os.File, rel string) error {
	if walk.trusted == nil || walk.trusted(opened, filepath.Join(walk.root, filepath.FromSlash(rel))) {
		return nil
	}
	return fmt.Errorf("%w: %s", errSkillUntrusted, rel)
}

// checkManaged keeps the folder managed only while the opened folder or file
// at rel is one only administrators can change: an administrator copy that
// kept a user's access entry on a subfolder or file is not (GAP-2147).
func (walk *skillHashWalk) checkManaged(opened *os.File, rel string) {
	if walk.managed && walk.entryManaged != nil && !walk.entryManaged(opened, filepath.Join(walk.root, filepath.FromSlash(rel))) {
		walk.managed = false
	}
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
	home, rel := s.skillHome(path)
	if home == "" {
		return "", false
	}
	if location := "~/" + filepath.ToSlash(rel); len(location) <= maxSkillLocation && !containsUnicodeControl(location) {
		return location, true
	}
	return "", true
}

// skillHome is the first scanned home that holds path and path below it, or
// "" when no scanned home does.
func (s *ContinuousDiscoveryService) skillHome(path string) (home, rel string) {
	for _, home := range s.homesToScan() {
		rel, err := filepath.Rel(home, path)
		if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) ||
			strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return home, rel
	}
	return "", ""
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
