// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentpaths"
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
// [{"path", "fp"}], "substrate_pending": [{"path", "fp"}] (managed and
// strict: still being scanned, every tool call is refused until it has a
// verdict). The kit acts only on folders it listed in that call.

const (
	// SkillQuarantineField is the answer field naming blocked folders.
	SkillQuarantineField = "substrate_quarantine"
	// SkillPendingField is the answer field naming held folders (GAP-0980).
	SkillPendingField = "substrate_pending"
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

// skillRoots are the directories whose subfolders an agent loads as skills,
// read from the one connector table (agentpaths, GAP-0788; it replaced the
// kit's own list of .claude, .codex and .agents, which missed the Cursor,
// Copilot, Devin, Amp, Antigravity, OpenCode and Hermes folders): the home,
// config and absolute roots first, then the project's, each followed by the
// skills folders found inside that side's plugin folders. Command folders
// hold single files, not skill folders, and are left out.
func skillRoots(home, cwd string) []string {
	var roots []string
	seen := map[string]bool{}
	add := func(r string) {
		if !seen[r] {
			seen[r] = true
			roots = append(roots, r)
		}
	}
	entries := agentpaths.ActorEntries()
	for _, project := range []bool{false, true} {
		var plugins []string
		for _, e := range entries {
			if (e.Base == agentpaths.Project) != project || e.Kind == agentpaths.Commands {
				continue
			}
			for _, dir := range actorDirs(e, home, cwd) {
				if e.Kind == agentpaths.Plugins {
					plugins = append(plugins, dir)
				} else {
					add(dir)
				}
			}
		}
		searched := map[string]bool{}
		for _, dir := range plugins {
			if searched[dir] {
				continue
			}
			searched[dir] = true
			found, complete := pluginSkillRoots(dir)
			for _, r := range found {
				add(r)
			}
			if !complete {
				add(dir) // stands in for the plugin skill roots not found
			}
		}
	}
	return roots
}

// pluginSkillsDir is the name of the skills folder inside a plugin.
const pluginSkillsDir = "skills"

// isSkillRoot reports whether root is a skill root by name: the last element
// of a Skills entry of the connector table (skills, and the singular skill of
// the OpenCode roots), or a plugin's skills folder. quarantineSkillFolder
// asks it, so the roots the scan lists (skillRoots, from the same table) and
// the roots a refused folder can be moved out of cannot differ (GAP-1074:
// the quarantine knew only "skills" and left a refused folder in
// .opencode/skill, ~/.config/opencode/skill and Config/skill in reach).
func isSkillRoot(root string) bool {
	name := filepath.Base(root)
	if name == pluginSkillsDir {
		return true
	}
	for _, e := range agentpaths.ActorEntries() {
		if e.Kind == agentpaths.Skills && path.Base(e.Rel) == name {
			return true
		}
	}
	return false
}

// actorDirs resolves one table entry in the actor. A Config entry is looked
// at both under the default config home and under the vendor variable's
// folder (CLAUDE_CONFIG_DIR, CODEX_HOME, HERMES_HOME, OPENCODE_CONFIG_DIR)
// when one is set: the agent may have been started with either.
func actorDirs(e agentpaths.ActorEntry, home, cwd string) []string {
	rel := filepath.FromSlash(e.Rel)
	switch e.Base {
	case agentpaths.Home:
		if filepath.IsAbs(home) {
			return []string{filepath.Join(home, rel)}
		}
	case agentpaths.Project:
		if filepath.IsAbs(cwd) {
			return []string{filepath.Join(cwd, rel)}
		}
	case agentpaths.Abs:
		return []string{rel}
	case agentpaths.Config:
		var out []string
		if filepath.IsAbs(home) {
			out = append(out, filepath.Join(home, filepath.FromSlash(e.ConfigRel), rel))
		}
		if e.ConfigEnv != "" {
			if v := strings.TrimSpace(os.Getenv(e.ConfigEnv)); filepath.IsAbs(v) {
				out = append(out, filepath.Join(filepath.Clean(v), rel))
			}
		}
		return out
	}
	return nil
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
			if e.Name() == pluginSkillsDir {
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
	Pending []struct {
		Path string `json:"path"`
		FP   string `json:"fp"`
	} `json:"substrate_pending"`
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

// renameFolder and lockFolder are how a refused folder is taken out of the
// agent's reach: a rename into the quarantine folder, else removing its
// permissions. Variables for tests, which make both fail.
var (
	renameFolder = os.Rename
	lockFolder   = os.Chmod
)

// skillsStillInReach is the folders a 2xx answer refused (substrate_quarantine)
// that the agent can still reach after applySkillAnswer: named in the answer,
// listed by this call, and neither moved out of the root, nor locked (no
// permissions), nor gone. A quarantine that failed this way (a failed rename
// and a failed lock) was silent, and nothing else denied the folder: the hook
// refuses the call instead (GAP-0039).
func skillsStillInReach(answer []byte, listed map[string]string) []string {
	var a skillAnswer
	if len(listed) == 0 || json.Unmarshal(answer, &a) != nil {
		return nil
	}
	var stuck []string
	seen := map[string]bool{}
	for _, q := range a.Quarantine {
		dir := filepath.Clean(q.Path)
		fp, ok := listed[dir]
		if !ok {
			continue
		}
		dirs := []string{dir}
		if fp == skillRootStandIn && filepath.Base(dir) != "plugins" {
			dirs = unlistedSkillFolders(dir, listed)
		}
		for _, d := range dirs {
			if !seen[d] && folderInReach(d) {
				seen[d] = true
				stuck = append(stuck, d)
			}
		}
	}
	sort.Strings(stuck)
	return stuck
}

// skillStuckName is the kit's record of refused folders it could not take out
// of reach, beside the receipt cache. A later PreToolUse call reads it
// (stuckSkillsInReach) and is refused while any is still in reach, so the
// refusal of the post that found the folder holds for the calls after it. The
// agent can delete the record, but the next skill pass lists the folder
// again and the gateway refuses it again.
const skillStuckName = "skill-stuck.json"

// maxStuckSkills bounds the record.
const maxStuckSkills = 64

// preToolEvents are the events that can deny a tool call before it runs.
var preToolEvents = map[string]bool{
	"PreToolUse": true, "preToolUse": true, "beforeShellExecution": true, "beforeMCPExecution": true,
}

func skillStuckPath(home string) string { return filepath.Join(home, ".defenseclaw", skillStuckName) }

// recordStuckSkills adds dirs to the record.
func recordStuckSkills(home string, dirs []string) {
	if home == "" || len(dirs) == 0 {
		return
	}
	all := append(readStuckSkills(home), dirs...)
	sort.Strings(all)
	all = slices.Compact(all)
	if len(all) > maxStuckSkills {
		all = all[:maxStuckSkills]
	}
	writeStuckSkills(home, all)
}

func readStuckSkills(home string) []string {
	var dirs []string
	if b, err := os.ReadFile(skillStuckPath(home)); err == nil && len(b) < 1<<20 {
		_ = json.Unmarshal(b, &dirs)
	}
	return dirs
}

func writeStuckSkills(home string, dirs []string) {
	p := skillStuckPath(home)
	if len(dirs) == 0 {
		_ = os.Remove(p)
		return
	}
	b, err := json.Marshal(dirs)
	if err != nil || os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, p)
	}
}

// stuckSkillsInReach is the recorded folders the agent can still reach; the
// record keeps only those.
func stuckSkillsInReach(home string) []string {
	if home == "" {
		return nil
	}
	recorded := readStuckSkills(home)
	var left []string
	for _, d := range recorded {
		if folderInReach(d) {
			left = append(left, d)
		}
	}
	if len(left) != len(recorded) {
		writeStuckSkills(home, left)
	}
	return left
}

// skillPendingName is the kit's record of folders a pass left with no
// verdict (GAP-0980): a managed post that was never answered (its attached
// folders), or folders the gateway named substrate_pending (managed and
// strict hold them while the scan runs). While one is in reach every
// PreToolUse call runs the skill pass, whatever the tool or connector, so
// the gateway sees the folder and refuses the call while it is held; a call
// whose pass goes unanswered too is refused (skillPendingRefusal). No record
// (the usual case) adds no work beyond one missing-file read.
const skillPendingName = "skill-pending.json"

func skillPendingPath(home string) string {
	return filepath.Join(home, ".defenseclaw", skillPendingName)
}

func readSkillPending(home string) map[string]string {
	m := map[string]string{}
	if home == "" {
		return m
	}
	if b, err := os.ReadFile(skillPendingPath(home)); err == nil && len(b) < 1<<20 {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func writeSkillPending(home string, m map[string]string) {
	p := skillPendingPath(home)
	if len(m) == 0 {
		_ = os.Remove(p)
		return
	}
	b, err := json.Marshal(m)
	if err != nil || os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, p)
	}
}

// skillsPendingInReach is the recorded folders the agent can still reach;
// the record keeps only those.
func skillsPendingInReach(home string) []string {
	if home == "" {
		return nil
	}
	if _, err := os.Lstat(skillPendingPath(home)); err != nil {
		return nil
	}
	m := readSkillPending(home)
	var left []string
	for d := range m {
		if folderInReach(d) {
			left = append(left, d)
		} else {
			delete(m, d)
		}
	}
	if len(left) == 0 {
		writeSkillPending(home, nil)
	}
	sort.Strings(left)
	return left
}

// updateSkillPending updates the record after a pass post that listed the
// folders in listed and attached those in attached. answered: the gateway
// answered the call (2xx, or 403 refused): a listed folder is recorded when
// the answer names it pending and dropped otherwise (scanned, refused and
// moved, or no hold). Not answered (no answer inside the kit's budget):
// managed records the folders it attached, which have no verdict. It returns
// the recorded folders still in reach.
func updateSkillPending(home string, answer []byte, answered bool, listed map[string]string, attached []string, managed bool) []string {
	if home == "" || listed == nil {
		return nil
	}
	m := readSkillPending(home)
	n := len(m)
	if answered {
		var a skillAnswer
		_ = json.Unmarshal(answer, &a)
		held := map[string]string{}
		for _, p := range a.Pending {
			if _, ok := listed[p.Path]; ok {
				held[p.Path] = p.FP
			}
		}
		for d := range listed {
			if fp, ok := held[d]; ok {
				m[d] = fp
			} else {
				delete(m, d)
			}
		}
	} else if managed {
		for _, d := range attached {
			m[d] = listed[d]
		}
	}
	if len(m) == 0 && n == 0 {
		return nil
	}
	var left []string
	for d := range m {
		if folderInReach(d) {
			left = append(left, d)
		} else {
			delete(m, d)
		}
	}
	sort.Strings(left)
	if len(left) > maxStuckSkills {
		for _, d := range left[maxStuckSkills:] {
			delete(m, d)
		}
		left = left[:maxStuckSkills]
	}
	writeSkillPending(home, m)
	return left
}

// skillPendingRefusal is the reason a PreToolUse call is refused when its
// pass for held folders went unanswered (GAP-0980).
func skillPendingRefusal(dirs []string) string {
	names := make([]string, 0, len(dirs))
	for _, d := range dirs {
		names = append(names, strconv.Quote(filepath.Base(d)))
	}
	return strings.Join(names, ", ") + " is still being scanned; DefenseClaw refuses tool calls until the scan finishes. Try again in a few seconds."
}

// folderInReach reports whether the agent can still use dir: it exists and is
// not a folder with its permissions removed. A link counts as in reach.
func folderInReach(dir string) bool {
	info, err := os.Lstat(dir)
	if err != nil {
		return false
	}
	return !info.IsDir() || info.Mode().Perm() != 0
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
	return renameFolder(dir, filepath.Join(qdir, fmt.Sprintf("plugins-%d", quarantineStamp(now)))) == nil
}

var lastQuarantineStamp atomic.Int64

// quarantineStamp is now in nanoseconds, made strictly increasing: one answer
// quarantines several folders with one now, and two roots that share a parent
// (.opencode/skill and .opencode/skills, which the table lists side by side)
// share one quarantine folder, so two refused folders of the same name got the
// same destination and the second move failed (GAP-1074).
func quarantineStamp(now time.Time) int64 {
	for {
		last := lastQuarantineStamp.Load()
		n := now.UnixNano()
		if n <= last {
			n = last + 1
		}
		if lastQuarantineStamp.CompareAndSwap(last, n) {
			return n
		}
	}
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
	if !isSkillRoot(root) {
		return false
	}
	qdir := filepath.Join(filepath.Dir(root), quarantineDirName)
	if os.MkdirAll(qdir, 0o700) == nil {
		dst := filepath.Join(qdir, fmt.Sprintf("%s-%d", filepath.Base(dir), quarantineStamp(now)))
		if renameFolder(dir, dst) == nil {
			return true
		}
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() == 0 {
		return false
	}
	return lockFolder(dir, 0) == nil
}
