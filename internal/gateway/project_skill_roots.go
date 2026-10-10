// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
)

// projectSkillRootsSettle is how long the watcher waits after a new project
// folder before it restarts, so a burst of them restarts it once.
const projectSkillRootsSettle = 2 * time.Second

// projectSkillRoots are the skill folders of the projects the agents run in
// (<project>/.claude/skills, <project>/.agents/skills, <project>/.codex/skills).
// Install admission used to watch only the connectors' user folders, so a
// CRITICAL skill in a project folder was never scanned and the Skill tool
// loaded it (GAP-1063). A hook from a project registers that project's
// existing skill folders; the watcher restarts with them and admits what
// they hold at its start, and the hooks refuse a project skill whose first
// scan has not finished. The zero value is ready to use.
type projectSkillRoots struct {
	mu      sync.Mutex
	roots   []projectSkillRoot
	started map[string]bool
	active  bool
	changed chan struct{}
	// unverified holds, by root key, the project skill folders a managed
	// Windows gateway could not verify (GAP-1356): they are not watched,
	// their skills are refused, and the watcher health names them.
	unverified map[string]projectSkillRootRefusal
	// grant asks the hook guardian to let the gateway read a project skill
	// folder; nil where no guardian grants reads.
	grant func(targetType, path string) error
	// verifying serialises the guardian round trips, so concurrent hooks
	// from one project ask once.
	verifying sync.Mutex
}

type projectSkillRootRefusal struct {
	path, reason string
	at           time.Time
}

// projectSkillRootRetry is how long a project skill folder that could not
// be verified stays refused before a hook may ask the guardian again.
const projectSkillRootRetry = 2 * time.Minute

// projectSkillRootGrantTimeout bounds the hooks wait for the guardians
// read grant on a new project skill folder.
const projectSkillRootGrantTimeout = 5 * time.Second

type projectSkillRoot struct {
	Path      string
	Connector string
}

func projectRootKey(path string) string {
	key := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	return key
}

func (p *projectSkillRoots) changes() chan struct{} {
	if p.changed == nil {
		p.changed = make(chan struct{}, 1)
	}
	return p.changed
}

// add registers root for connector and tells the watcher; false when root
// is already registered or the watcher does not use project folders.
// Every registered root must remain visible to the pending-admission check;
// a registration cap would let later project skills run without admission.
func (p *projectSkillRoots) add(connector, root string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active {
		return false
	}
	key := projectRootKey(root)
	for _, r := range p.roots {
		if projectRootKey(r.Path) == key {
			return false
		}
	}
	p.roots = append(p.roots, projectSkillRoot{Path: filepath.Clean(root), Connector: connector})
	delete(p.unverified, key)
	select {
	case p.changes() <- struct{}{}:
	default:
	}
	return true
}

// changeSignal is the channel add signals on.
func (p *projectSkillRoots) changeSignal() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.changes()
}

// registered reports whether root is a registered project skill folder.
func (p *projectSkillRoots) registered(root string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := projectRootKey(root)
	for _, r := range p.roots {
		if projectRootKey(r.Path) == key {
			return true
		}
	}
	return false
}

// registeredPath returns the registered folder that names root, as it was
// registered; the watcher records its skills under that spelling.
func (p *projectSkillRoots) registeredPath(root string) (string, bool) {
	if p == nil {
		return "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := projectRootKey(root)
	for _, r := range p.roots {
		if projectRootKey(r.Path) == key {
			return r.Path, true
		}
	}
	return "", false
}

// setReadGranter installs what asks the hook guardian for read access to a
// project skill folder; nil removes it.
func (p *projectSkillRoots) setReadGranter(grant func(targetType, path string) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.grant = grant
}

func (p *projectSkillRoots) readGranter() func(targetType, path string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.grant
}

// refuse records root as a project skill folder that could not be verified.
func (p *projectSkillRoots) refuse(root, reason string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unverified == nil {
		p.unverified = map[string]projectSkillRootRefusal{}
	}
	p.unverified[projectRootKey(root)] = projectSkillRootRefusal{path: filepath.Clean(root), reason: reason, at: now}
}

// refusal returns why root could not be verified, and whether that was less
// than projectSkillRootRetry before now.
func (p *projectSkillRoots) refusal(root string, now time.Time) (reason string, recent bool) {
	if p == nil {
		return "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	refusal, ok := p.unverified[projectRootKey(root)]
	if !ok {
		return "", false
	}
	return refusal.reason, now.Sub(refusal.at) < projectSkillRootRetry
}

// unverifiedFolders lists, sorted, the project skill folders that could
// not be verified, each with its reason.
func (p *projectSkillRoots) unverifiedFolders() []string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.unverified))
	for _, refusal := range p.unverified {
		out = append(out, refusal.path+": "+refusal.reason)
	}
	sort.Strings(out)
	return out
}

func (p *projectSkillRoots) isActive() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active
}

// start is called by each watcher start: active says whether it watches
// project folders. It returns the folders to watch and those no earlier
// watcher watched, which it admits at its start.
func (p *projectSkillRoots) start(active bool) (roots []projectSkillRoot, fresh []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = active
	select {
	case <-p.changes():
	default:
	}
	if !active {
		return nil, nil
	}
	if p.started == nil {
		p.started = map[string]bool{}
	}
	for _, r := range p.roots {
		roots = append(roots, r)
		if key := projectRootKey(r.Path); !p.started[key] {
			p.started[key] = true
			fresh = append(fresh, r.Path)
		}
	}
	return roots, fresh
}

// projectSkillFolders lists the existing project skill folders a connector
// loads for a session in cwd: its skill roots for cwd that are not the
// user's own. A link is not followed.
func projectSkillFolders(connector, home, cwd string) []string {
	user := map[string]bool{}
	for _, root := range assetfacts.SkillRoots(connector, home, "") {
		user[projectRootKey(root)] = true
	}
	var folders []string
	for _, root := range assetfacts.SkillRoots(connector, home, cwd) {
		if user[projectRootKey(root)] {
			continue
		}
		if info, err := os.Lstat(root); err == nil && info.IsDir() {
			folders = append(folders, root)
		}
	}
	return folders
}

// insideHome reports whether path lies strictly inside home, compared
// lexically and, on Windows, case-insensitively. A path with a ".."
// element, or on Windows a stream or device form, is not inside any home.
// A managed Windows gateway compares this way because its service account
// may not stat the profile, so neither path resolves (GAP-1356).
func insideHome(home, path string) bool {
	home, path = strings.TrimSpace(home), strings.TrimSpace(path)
	if !filepath.IsAbs(home) || !filepath.IsAbs(path) || hasParentElement(path) {
		return false
	}
	if runtime.GOOS == "windows" {
		if strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) ||
			strings.Contains(path[len(filepath.VolumeName(path)):], ":") {
			return false
		}
		home, path = strings.ToLower(home), strings.ToLower(path)
	}
	rel, err := filepath.Rel(filepath.Clean(home), filepath.Clean(path))
	return err == nil && rel != "." && rel != ".." && !filepath.IsAbs(rel) &&
		!strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func hasParentElement(path string) bool {
	for _, element := range strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || (runtime.GOOS == "windows" && r == '\\')
	}) {
		if element == ".." {
			return true
		}
	}
	return false
}

// enrolledProjectSkillCandidates lists the project skill folders a
// connector loads for a session in cwd that lie inside home, found
// lexically; whether each exists is left to the caller.
func enrolledProjectSkillCandidates(connector, home, cwd string) []string {
	if !insideHome(home, cwd) {
		return nil
	}
	user := map[string]bool{}
	for _, root := range assetfacts.SkillRoots(connector, home, "") {
		user[projectRootKey(root)] = true
	}
	var folders []string
	for _, root := range assetfacts.SkillRoots(connector, home, cwd) {
		if !user[projectRootKey(root)] && insideHome(home, root) {
			folders = append(folders, root)
		}
	}
	return folders
}
