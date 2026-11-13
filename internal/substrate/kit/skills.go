// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Skills that arrive mid-session (substrate-1 GAP-0039). Claude Code loads
// every skill's name and description into the model context as soon as it
// sees the folder, with no tool call, so a skill that arrives by cp, git
// clone or an installer would reach the model before any hook saw it. On
// UserPromptSubmit, PostToolUse, SessionStart and Stop the kit fingerprints
// the skill roots (lstat only), and attaches each new or changed folder's
// files with role skill_file; the gateway scans them (attest.RuntimeScanner)
// and names a folder it blocks in its answer, which the kit then moves out
// of the skill root (quarantine).
//
// Every such call also lists the fingerprint of every folder (facts.skills).
// For a folder that passed, the gateway answers a scan receipt (an HMAC
// every gateway replica can check); the kit keeps it with the fingerprint
// and sends it back instead of the files while the folder is unchanged. The
// cache is the agent's to edit, so it proves nothing: a folder that is
// neither attached nor carries a valid receipt is named unscanned (the kit
// attaches it next time), and when the kit had room to attach it, it is
// refused in managed installs and the strict tier (quarantined) and alerted
// on in the OSS default tiers (GAP-0039, gateway substrate_skills.go).
//
// Gateway answer fields: "substrate_quarantine": [{"path", "reason"}],
// "substrate_scanned": [{"path", "fp", "receipt"}], "substrate_unscanned":
// [{"path", "fp"}]. The kit acts only on folders it listed in that call.

const (
	// SkillQuarantineField is the answer field naming blocked folders.
	SkillQuarantineField = "substrate_quarantine"
	// RoleSkillFile is the attached-file role of a skill folder's file.
	RoleSkillFile = "skill_file"

	maxSkillFoldersPerCall = 4
	maxSkillFilesPerFolder = 64
	maxSkillFoldersPerRoot = 64
	maxSkillDepth          = 3
	quarantineDirName      = ".defenseclaw-quarantine"
	skillCacheName         = "skill-receipts.json"
	maxSkillCacheEntries   = 512
)

// skillScanEvents are the events on which the kit looks at the roots:
// UserPromptSubmit runs before the model reads the prompt, so a folder
// copied in between turns (outside any tool call) is scanned before the
// next turn.
var skillScanEvents = map[string]bool{
	"UserPromptSubmit": true, "userPromptSubmit": true,
	"PostToolUse": true, "postToolUse": true, "SessionStart": true, "sessionStart": true, "Stop": true, "stop": true,
}

// skillRoots are the directories whose subfolders an agent loads as skills,
// in the home and the project.
func skillRoots(home, cwd string) []string {
	var roots []string
	seen := map[string]bool{}
	for _, base := range []string{home, cwd} {
		if base == "" || !filepath.IsAbs(base) {
			continue
		}
		for _, rel := range []string{".claude/skills", ".codex/skills", ".agents/skills"} {
			r := filepath.Join(base, rel)
			if !seen[r] {
				seen[r] = true
				roots = append(roots, r)
			}
		}
	}
	return roots
}

// skillFolder is one folder under a skill root.
type skillFolder struct {
	Path  string
	FP    string
	Files []string
	// Over is set when the folder has more files than the kit attaches.
	Over bool
}

// scanSkillFolders fingerprints every folder under roots from lstat data.
func scanSkillFolders(roots []string) []skillFolder {
	var out []skillFolder
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		n := 0
		for _, e := range entries {
			if n >= maxSkillFoldersPerRoot {
				break
			}
			p := filepath.Join(root, e.Name())
			info, err := os.Lstat(p)
			if err != nil || !info.IsDir() {
				// A symlinked skill folder is followed by the agent; the
				// kit attaches what it points at.
				if err == nil && info.Mode()&os.ModeSymlink != 0 {
					if t, err := os.Stat(p); err == nil && t.IsDir() {
						info = t
					} else {
						continue
					}
				} else {
					continue
				}
			}
			n++
			out = append(out, fingerprintFolder(p))
		}
	}
	return out
}

func fingerprintFolder(dir string) skillFolder {
	f := skillFolder{Path: dir}
	h := sha256.New()
	var walk func(d string, depth int)
	walk = func(d string, depth int) {
		entries, err := os.ReadDir(d)
		if err != nil {
			fmt.Fprintf(h, "E %s\n", d)
			return
		}
		for _, e := range entries {
			p := filepath.Join(d, e.Name())
			info, err := os.Stat(p)
			if err != nil {
				continue
			}
			fmt.Fprintf(h, "%s %o %d %d\n", strings.TrimPrefix(p, dir), uint32(info.Mode()), info.Size(), info.ModTime().UnixNano())
			switch {
			case info.IsDir() && depth < maxSkillDepth:
				walk(p, depth+1)
			case info.Mode().IsRegular():
				if len(f.Files) < maxSkillFilesPerFolder {
					f.Files = append(f.Files, p)
				} else {
					f.Over = true
				}
			}
		}
	}
	walk(dir, 0)
	sort.Strings(f.Files)
	f.FP = hex.EncodeToString(h.Sum(nil))[:32]
	return f
}

// collectSkills lists every folder's fingerprint in f and attaches the files
// of the folders the cache has no receipt for (new, changed, or never
// scanned) within budget, at most maxSkillFoldersPerCall. A folder with a
// receipt for its current fingerprint is listed with the receipt instead of
// its files. It returns every listed folder and its fingerprint.
func collectSkills(f *Facts, roots []string, known map[string]skillCacheEntry, budget int64) (map[string]string, int64) {
	listed := map[string]string{}
	attachedFolders := 0
	for _, folder := range scanSkillFolders(roots) {
		fp := SkillFingerprint{Path: folder.Path, FP: folder.FP}
		listed[folder.Path] = folder.FP
		if k, ok := known[folder.Path]; ok && k.FP == folder.FP && k.Receipt != "" {
			fp.Receipt = k.Receipt
		} else if attachedFolders >= maxSkillFoldersPerCall || budget <= 0 {
			f.Truncated = true
		} else {
			for _, file := range folder.Files {
				budget = attach(f, RoleSkillFile, file, "", budget)
			}
			if folder.Over {
				f.Truncated = true
			}
			fp.Attached = true
			attachedFolders++
		}
		f.Skills = append(f.Skills, fp)
	}
	return listed, budget
}

// skillCacheEntry is a folder fingerprint and the gateway's scan receipt.
type skillCacheEntry struct {
	FP      string `json:"fp"`
	Receipt string `json:"receipt"`
}

// The receipt cache, ~/.defenseclaw/skill-receipts.json, only saves bytes
// (see above); unreadable means empty.
func skillCachePath(home string) string { return filepath.Join(home, ".defenseclaw", skillCacheName) }

func loadSkillCache(home string) map[string]skillCacheEntry {
	m := map[string]skillCacheEntry{}
	if home == "" {
		return m
	}
	b, err := os.ReadFile(skillCachePath(home))
	if err == nil && len(b) < 1<<20 {
		if json.Unmarshal(b, &m) != nil {
			m = map[string]skillCacheEntry{}
		}
	}
	return m
}

func saveSkillCache(home string, m map[string]skillCacheEntry) {
	if home == "" {
		return
	}
	if len(m) > maxSkillCacheEntries {
		// Keep the bound: drop entries in path order (a dropped folder is
		// only attached once more).
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[maxSkillCacheEntries:] {
			delete(m, k)
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	p := skillCachePath(home)
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, p)
	}
}

// skillAnswer is the skill part of a gateway hook answer.
type skillAnswer struct {
	Quarantine []struct {
		Path   string `json:"path"`
		Reason string `json:"reason"`
	} `json:"substrate_quarantine"`
	Scanned []struct {
		Path    string `json:"path"`
		FP      string `json:"fp"`
		Receipt string `json:"receipt"`
	} `json:"substrate_scanned"`
	Unscanned []struct {
		Path string `json:"path"`
	} `json:"substrate_unscanned"`
}

// applySkillAnswer acts on a 2xx answer to a post that listed the folders in
// listed: receipts are kept for the fingerprint the kit listed, a folder the
// gateway names unscanned loses its cache entry (so its files go with the
// next post), and a quarantined folder is moved out of its skill root. It
// returns what it moved.
func applySkillAnswer(home string, answer []byte, listed map[string]string, now time.Time) []string {
	if len(listed) == 0 {
		return nil
	}
	var a skillAnswer
	if json.Unmarshal(answer, &a) != nil {
		return nil
	}
	cache := loadSkillCache(home)
	changed := false
	for _, s := range a.Scanned {
		dir := filepath.Clean(s.Path)
		if fp, ok := listed[dir]; ok && fp == s.FP && s.Receipt != "" {
			cache[dir] = skillCacheEntry{FP: s.FP, Receipt: s.Receipt}
			changed = true
		}
	}
	for _, u := range a.Unscanned {
		dir := filepath.Clean(u.Path)
		if _, ok := cache[dir]; ok {
			delete(cache, dir)
			changed = true
		}
	}
	var moved []string
	for _, q := range a.Quarantine {
		dir := filepath.Clean(q.Path)
		if _, ok := listed[dir]; !ok {
			continue // the kit moves only folders it listed in this call
		}
		if quarantineSkillFolder(dir, now) {
			moved = append(moved, dir)
			delete(cache, dir)
			changed = true
		}
	}
	if changed {
		saveSkillCache(home, cache)
	}
	return moved
}

// quarantineSkillFolder moves one folder out of its skill root, into
// <root>/../.defenseclaw-quarantine/ (the same file system, so a rename).
func quarantineSkillFolder(dir string, now time.Time) bool {
	root := filepath.Dir(dir)
	if filepath.Base(root) != "skills" {
		return false
	}
	qdir := filepath.Join(filepath.Dir(root), quarantineDirName)
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		return false
	}
	dst := filepath.Join(qdir, fmt.Sprintf("%s-%d", filepath.Base(dir), now.UnixNano()))
	return os.Rename(dir, dst) == nil
}
