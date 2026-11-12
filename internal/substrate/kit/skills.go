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
// clone or an installer would reach the model before any hook saw it. After
// PostToolUse, SessionStart and Stop the kit fingerprints the skill roots
// (lstat only), and attaches each new or changed folder's files with role
// skill_file; the gateway scans them (attest.RuntimeScanner) and names a
// folder it blocks in its answer, which the kit then moves out of the skill
// root (quarantine).
//
// Every such call also lists the fingerprint of every folder (facts.skills).
// The kit keeps the fingerprints the gateway has answered for in a cache to
// skip re-sending files; the cache is the agent's to edit, so the gateway
// must not trust it: a folder whose fingerprint the gateway has not scanned
// and whose files are not attached counts as not scanned (A2: quarantine it,
// and deny the skill at its next use).
//
// Gateway answer field (A2): "substrate_quarantine": [{"path": "<the
// folder>", "reason": "..."}]. The kit moves only folders it listed in that
// call.

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
	skillCacheName         = "skills-seen.json"
	maxSkillCacheEntries   = 512
)

// skillScanEvents are the events after which the kit looks at the roots.
var skillScanEvents = map[string]bool{
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
// of the folders not in known (the cache) within budget, at most
// maxSkillFoldersPerCall. It returns every listed fingerprint.
func collectSkills(f *Facts, roots []string, known map[string]string, budget int64) (map[string]string, int64) {
	listed := map[string]string{}
	attachedFolders := 0
	for _, folder := range scanSkillFolders(roots) {
		fp := SkillFingerprint{Path: folder.Path, FP: folder.FP}
		listed[folder.Path] = folder.FP
		if known[folder.Path] != folder.FP {
			if attachedFolders >= maxSkillFoldersPerCall || budget <= 0 {
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
		}
		f.Skills = append(f.Skills, fp)
	}
	return listed, budget
}

// The seen-cache, ~/.defenseclaw/skills-seen.json, is only an optimization
// (see above); unreadable means empty.
func skillCachePath(home string) string { return filepath.Join(home, ".defenseclaw", skillCacheName) }

func loadSkillCache(home string) map[string]string {
	m := map[string]string{}
	if home == "" {
		return m
	}
	b, err := os.ReadFile(skillCachePath(home))
	if err == nil && len(b) < 1<<20 {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func saveSkillCache(home string, sent map[string]string) {
	if home == "" || len(sent) == 0 {
		return
	}
	m := loadSkillCache(home)
	for k, v := range sent {
		m[k] = v
	}
	if len(m) > maxSkillCacheEntries {
		m = sent
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

// quarantineSkills moves the folders the gateway blocked out of their skill
// root, into <root>/../.defenseclaw-quarantine/ (the same file system, so a
// rename). Only folders the kit attached in this call are moved. It returns
// what it moved.
func quarantineSkills(answer []byte, attached map[string]string, now time.Time) []string {
	if len(attached) == 0 {
		return nil
	}
	var a struct {
		Q []struct {
			Path   string `json:"path"`
			Reason string `json:"reason"`
		} `json:"substrate_quarantine"`
	}
	if json.Unmarshal(answer, &a) != nil {
		return nil
	}
	var moved []string
	for _, q := range a.Q {
		dir := filepath.Clean(q.Path)
		if _, ok := attached[dir]; !ok {
			continue
		}
		root := filepath.Dir(dir)
		if filepath.Base(root) != "skills" {
			continue
		}
		qdir := filepath.Join(filepath.Dir(root), quarantineDirName)
		if err := os.MkdirAll(qdir, 0o700); err != nil {
			continue
		}
		dst := filepath.Join(qdir, fmt.Sprintf("%s-%d", filepath.Base(dir), now.UnixNano()))
		if os.Rename(dir, dst) == nil {
			moved = append(moved, dir)
		}
	}
	return moved
}
