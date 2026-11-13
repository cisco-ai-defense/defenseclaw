// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/skilldigest"
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

	// maxSkillFoldersPerCall matches the folders the gateway scans per post.
	maxSkillFoldersPerCall = 8
	// maxSkillFoldersListed bounds the folders one post lists (envelope
	// size); past it a root is one Over entry.
	maxSkillFoldersListed = 512
	// maxSkillReadBytes bounds what one pass reads to digest folders.
	maxSkillReadBytes = 32 << 20
	// Plugin skill roots: how deep below ~/.claude/plugins, and how many
	// folders the search visits; past that the plugins folder itself is
	// one Over entry (fail closed).
	maxPluginDepth       = 6
	maxPluginVisits      = 20000
	quarantineDirName    = ".defenseclaw-quarantine"
	skillCacheName       = "skill-receipts.json"
	maxSkillCacheEntries = 1024
)

// skillScanEvents are the events on which the kit looks at the roots:
// UserPromptSubmit runs before the model reads the prompt, so a folder
// copied in between turns (outside any tool call) is scanned before the
// next turn.
var skillScanEvents = map[string]bool{
	"UserPromptSubmit": true, "userPromptSubmit": true,
	"PostToolUse": true, "postToolUse": true, "SessionStart": true, "sessionStart": true, "Stop": true, "stop": true,
}

// skillRoots are the directories whose subfolders an agent loads as skills:
// in the home and the project, and every skills folder of an installed
// Claude Code plugin (~/.claude/plugins/.../skills, also the project's).
func skillRoots(home, cwd string) []string {
	var roots []string
	seen := map[string]bool{}
	add := func(r string) {
		if !seen[r] {
			seen[r] = true
			roots = append(roots, r)
		}
	}
	for _, base := range []string{home, cwd} {
		if base == "" || !filepath.IsAbs(base) {
			continue
		}
		for _, rel := range []string{".claude/skills", ".codex/skills", ".agents/skills"} {
			add(filepath.Join(base, rel))
		}
		plugins := filepath.Join(base, ".claude", "plugins")
		found, complete := pluginSkillRoots(plugins)
		for _, r := range found {
			add(r)
		}
		if !complete {
			add(plugins) // stands in for the plugin skill roots not found
		}
	}
	return roots
}

// pluginSkillRoots finds the folders named skills below a plugins folder
// (cache/<marketplace>/<plugin>/<version>/skills and the like), at most
// maxPluginDepth deep, not inside node_modules or hidden folders (no plugin
// is installed there). Every one found is a root: the folder listing cap,
// with its stand-ins, bounds what is listed (GAP-0039). complete is false
// when the search visited maxPluginVisits folders and stopped. Links are
// not followed while searching (a link loop must not hang the hook).
func pluginSkillRoots(plugins string) (roots []string, complete bool) {
	visits := 0
	complete = true
	var walk func(d string, depth int)
	walk = func(d string, depth int) {
		if depth > maxPluginDepth || !complete {
			return
		}
		if visits++; visits > maxPluginVisits {
			complete = false
			return
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() || e.Name() == "node_modules" || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			p := filepath.Join(d, e.Name())
			if e.Name() == "skills" {
				roots = append(roots, p)
				continue
			}
			walk(p, depth+1)
		}
	}
	walk(plugins, 0)
	return roots, complete
}

// skillFolder is one folder under a skill root.
type skillFolder struct {
	Path string
	// FP is the content digest (skilldigest.Digest) of the files the kit
	// attaches; "" when the folder is over a cap (Over).
	FP    string
	Files []string
	// Over is set when the folder has no digest: more files, deeper files or
	// bigger files than the kit attaches, a file it cannot read, or the pass's
	// read budget ran out. The gateway's fail mode decides for such a folder:
	// managed and strict refuse it, OSS default tiers alert.
	Over bool
	// Root marks the entry that stands for the folders of a root past
	// maxSkillFoldersListed (Path is the root).
	Root bool
	// Sums are the files' digests (relative name -> skilldigest.Sum) and
	// Size their total bytes.
	Sums map[string]string
	Size int64
}

// skillRootStandIn is the listed fingerprint of a root's stand-in entry:
// a quarantine of it moves the root's folders the kit did not list.
const skillRootStandIn = "root"

// scanSkillFolders lists every folder under roots (a symlinked folder is
// followed, as the agent follows it) and digests its content. Past
// maxSkillFoldersListed folders the rest of each root is one Over entry for
// the root, so a folder is never left out silently.
func scanSkillFolders(roots []string) []skillFolder {
	var out []skillFolder
	budget := int64(maxSkillReadBytes)
	listed := 0
	for _, root := range roots {
		if filepath.Base(root) == "plugins" {
			// pluginSkillRoots stopped before it found every plugin's
			// skills: the plugins folder stands in for them.
			if _, err := os.Stat(root); err == nil {
				out = append(out, skillFolder{Path: root, Over: true, Root: true})
			}
			continue
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			p := filepath.Join(root, e.Name())
			info, err := os.Stat(p)
			if err != nil || !info.IsDir() {
				continue
			}
			if listed >= maxSkillFoldersListed {
				out = append(out, skillFolder{Path: root, Over: true, Root: true})
				break
			}
			listed++
			var f skillFolder
			f, budget = digestFolder(p, budget)
			out = append(out, f)
		}
	}
	return out
}

// digestFolder reads the folder's regular files (as the agent reads them:
// links followed) at most skilldigest.MaxDepth folders deep and digests their
// content. budget bounds the bytes one pass reads.
func digestFolder(dir string, budget int64) (skillFolder, int64) {
	f := skillFolder{Path: dir, Sums: map[string]string{}}
	files := map[string][]byte{}
	over := false
	var walk func(d string, depth int)
	walk = func(d string, depth int) {
		if over {
			return
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			over = true
			return
		}
		for _, e := range entries {
			if over {
				return
			}
			p := filepath.Join(d, e.Name())
			info, err := os.Stat(p)
			switch {
			case err != nil:
				continue // a dangling link has no content for the agent either
			case info.IsDir():
				if depth >= skilldigest.MaxDepth {
					over = true // deeper than the kit attaches
					return
				}
				walk(p, depth+1)
			case info.Mode().IsRegular():
				if len(files) >= skilldigest.MaxFiles || info.Size() > skilldigest.MaxFileBytes || info.Size() > budget {
					over = true
					return
				}
				b, err := os.ReadFile(p)
				if err != nil || int64(len(b)) > skilldigest.MaxFileBytes {
					over = true
					return
				}
				budget -= int64(len(b))
				rel, _ := filepath.Rel(dir, p)
				files[filepath.ToSlash(rel)] = b
				f.Sums[filepath.ToSlash(rel)] = skilldigest.Sum(b)
				f.Size += int64(len(b))
				f.Files = append(f.Files, p)
			}
		}
	}
	walk(dir, 0)
	sort.Strings(f.Files)
	if !over {
		f.FP = skilldigest.Digest(files)
	}
	if f.FP == "" {
		f.Over, f.Files, f.Sums, f.Size = true, nil, nil, 0
	}
	return f, budget
}

// collectSkills lists every folder in f: with its receipt when the cache has
// one for its current content, else attached when it fits, else pending
// (f.Truncated). Pending folders are attached least recently attached first,
// so folders that change on every call cannot keep another one pending
// forever. A pending folder that did not fit carries its file digests
// (Sums, at most maxSkillFoldersPerCall per post), so the gateway can match
// it to the attested template build without the files, and one bigger than
// a post (Big: over postCap, the kit's whole attach cap) is never left
// waiting for room it cannot get (GAP-0164). It
// returns every listed folder and its fingerprint (skillRootStandIn for a
// root's stand-in), and the folders it attached.
func collectSkills(f *Facts, roots []string, known map[string]skillCacheEntry, budget, postCap int64) (map[string]string, []string) {
	listed := map[string]string{}
	var pending []skillFolder
	for _, folder := range scanSkillFolders(roots) {
		fp := SkillFingerprint{Path: folder.Path, FP: folder.FP, Over: folder.Over}
		listed[folder.Path] = folder.FP
		if folder.Root {
			listed[folder.Path] = skillRootStandIn
		}
		if !folder.Over {
			if k, ok := known[folder.Path]; ok && k.FP == folder.FP && k.Receipt != "" {
				fp.Receipt = k.Receipt
			} else {
				pending = append(pending, folder)
			}
		}
		f.Skills = append(f.Skills, fp)
	}
	sort.SliceStable(pending, func(i, j int) bool {
		a, b := known[pending[i].Path].LastAttached, known[pending[j].Path].LastAttached
		if a != b {
			return a < b
		}
		return pending[i].Path < pending[j].Path
	})
	var attached []string
	manifests := 0
	for _, folder := range pending {
		if len(attached) >= maxSkillFoldersPerCall || folder.Size > budget {
			f.Truncated = true
			if folder.Size > budget && manifests < maxSkillFoldersPerCall {
				manifests++
				for i := range f.Skills {
					if f.Skills[i].Path == folder.Path {
						f.Skills[i].Sums, f.Skills[i].Big = folder.Sums, folder.Size > postCap
					}
				}
			}
			continue
		}
		for _, file := range folder.Files {
			budget = attach(f, RoleSkillFile, file, "", budget)
		}
		for i := range f.Skills {
			if f.Skills[i].Path == folder.Path {
				f.Skills[i].Attached = true
			}
		}
		attached = append(attached, folder.Path)
	}
	return listed, attached
}

// skillCacheEntry is a folder fingerprint, the gateway's scan receipt and
// when the kit last attached the folder (rotation order).
type skillCacheEntry struct {
	FP           string `json:"fp"`
	Receipt      string `json:"receipt"`
	LastAttached int64  `json:"last_attached,omitempty"`
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
		// only attached once more, first in the rotation).
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
// listed and attached those in attached: their attach time is kept (rotation
// order), receipts are kept for the fingerprint the kit listed, a folder the
// gateway names unscanned loses its receipt (so its files go with a later
// post), and a quarantined folder is moved out of its skill root. It returns
// what it moved.
func applySkillAnswer(home string, answer []byte, listed map[string]string, attached []string, now time.Time) []string {
	if len(listed) == 0 {
		return nil
	}
	var a skillAnswer
	if json.Unmarshal(answer, &a) != nil {
		return nil
	}
	cache := loadSkillCache(home)
	changed := false
	for _, dir := range attached {
		e := cache[dir]
		e.FP, e.Receipt, e.LastAttached = listed[dir], "", now.UnixNano()
		cache[dir] = e
		changed = true
	}
	for _, s := range a.Scanned {
		dir := filepath.Clean(s.Path)
		if fp, ok := listed[dir]; ok && fp == s.FP && s.Receipt != "" {
			e := cache[dir]
			e.FP, e.Receipt = s.FP, s.Receipt
			cache[dir] = e
			changed = true
		}
	}
	for _, u := range a.Unscanned {
		dir := filepath.Clean(u.Path)
		if e, ok := cache[dir]; ok && e.Receipt != "" {
			e.Receipt = ""
			cache[dir] = e
			changed = true
		}
	}
	var moved []string
	for _, q := range a.Quarantine {
		dir := filepath.Clean(q.Path)
		fp, ok := listed[dir]
		if !ok {
			continue // the kit moves only folders it listed in this call
		}
		dirs := []string{dir}
		switch {
		case fp == skillRootStandIn && filepath.Base(dir) == "plugins":
			// The plugins folder stood in for plugin skills the kit could
			// not find: the plugins are put out of the agent's reach.
			if quarantinePlugins(dir, now) {
				moved = append(moved, dir)
				changed = true
			}
			continue
		case fp == skillRootStandIn:
			// The root stood in for its folders past the listing cap: those
			// are the ones refused, never the root itself (GAP-0039).
			dirs = unlistedSkillFolders(dir, listed)
		}
		for _, d := range dirs {
			if quarantineSkillFolder(d, now) {
				moved = append(moved, d)
				delete(cache, d)
				changed = true
			}
		}
	}
	if changed {
		saveSkillCache(home, cache)
	}
	return moved
}

// unlistedSkillFolders are the folders of root that are not in listed: the
// ones past maxSkillFoldersListed (and any that arrived since the listing,
// which no scan has seen either).
func unlistedSkillFolders(root string, listed map[string]string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		p := filepath.Join(root, e.Name())
		if _, ok := listed[p]; ok {
			continue
		}
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// quarantinePlugins moves a plugins folder the kit could not search whole
// into <parent>/.defenseclaw-quarantine/ (managed and strict refuse what
// they cannot scan).
func quarantinePlugins(dir string, now time.Time) bool {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	qdir := filepath.Join(filepath.Dir(dir), quarantineDirName)
	if os.MkdirAll(qdir, 0o700) != nil {
		return false
	}
	return os.Rename(dir, filepath.Join(qdir, fmt.Sprintf("plugins-%d", now.UnixNano()))) == nil
}

// quarantineSkillFolder moves one folder out of its skill root, into
// <root>/../.defenseclaw-quarantine/ (the same file system, so a rename).
// When the move fails (a read-only root), a real folder's permissions are
// removed instead, so the agent cannot read it either (never through a
// link: that would change what it points to). It reports whether it took
// the folder out of the agent's reach in this call; a folder it already
// locked is not reported again.
func quarantineSkillFolder(dir string, now time.Time) bool {
	root := filepath.Dir(dir)
	if filepath.Base(root) != "skills" {
		return false
	}
	qdir := filepath.Join(filepath.Dir(root), quarantineDirName)
	if os.MkdirAll(qdir, 0o700) == nil {
		dst := filepath.Join(qdir, fmt.Sprintf("%s-%d", filepath.Base(dir), now.UnixNano()))
		if os.Rename(dir, dst) == nil {
			return true
		}
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() == 0 {
		return false
	}
	return os.Chmod(dir, 0) == nil
}
