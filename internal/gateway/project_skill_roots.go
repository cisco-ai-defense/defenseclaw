// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
)

// maxProjectSkillRoots bounds the project skill folders the install watcher
// watches next to the connectors' own folders.
const maxProjectSkillRoots = 32

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
}

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
// is already registered, the watcher does not use project folders, or the
// bound is reached.
func (p *projectSkillRoots) add(connector, root string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active || len(p.roots) >= maxProjectSkillRoots {
		return false
	}
	key := projectRootKey(root)
	for _, r := range p.roots {
		if projectRootKey(r.Path) == key {
			return false
		}
	}
	p.roots = append(p.roots, projectSkillRoot{Path: filepath.Clean(root), Connector: connector})
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
