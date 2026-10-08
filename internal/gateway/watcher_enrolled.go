// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// enrolledWatchPollInterval is how often a managed gateway re-reads the
// enrolled users and their connector folders.
var enrolledWatchPollInterval = 30 * time.Second

// watcherUsesEnrolledUserDirs reports a standalone managed Windows gateway.
// Its own home is the service profile, which holds no skill or plugin, so
// its install watcher watches every enrolled user's connector folders, the
// set a per-user gateway watches for its user (GAP-0132). The enumerator
// grants the gateway service read access to those folders; on Linux and
// macOS the service account has no such access, and the Secure Client
// profile is never standalone.
func watcherUsesEnrolledUserDirs(cfg *config.Config) bool {
	return runtime.GOOS == "windows" && cfg != nil && cfg.StandaloneEnterprise() && !cfg.SecureClientIntegration()
}

// serviceHomeDir is the gateway account's own profile.
func serviceHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// enrolledWatchSet is what a managed gateway watches for its enrolled users.
type enrolledWatchSet struct {
	skillDirs  []string
	pluginDirs []string
	// roots maps each watched folder to the connector that owns it.
	roots map[string]string
	// mcp is every enrolled user's MCP servers, tagged with the connector
	// and the user home.
	mcp []config.MCPServerEntry
	// live is what the running watcher reads; the poller refreshes it.
	live *enrolledMCPServers
	// owners names the account of each enrolled home (GAP-0575).
	owners []watcher.AssetOwner
}

// enrolledMCPServers is the MCP server list a running watcher reads.
type enrolledMCPServers struct {
	mu      sync.RWMutex
	entries []config.MCPServerEntry
}

func (m *enrolledMCPServers) list() ([]config.MCPServerEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]config.MCPServerEntry(nil), m.entries...), nil
}

func (m *enrolledMCPServers) set(entries []config.MCPServerEntry) {
	m.mu.Lock()
	m.entries = append([]config.MCPServerEntry(nil), entries...)
	m.mu.Unlock()
}

func (e enrolledWatchSet) dirsKey() string {
	parts := make([]string, 0, len(e.roots)+len(e.skillDirs)+len(e.pluginDirs))
	for root, name := range e.roots {
		parts = append(parts, strings.ToLower(root)+"="+name)
	}
	for _, dir := range e.skillDirs {
		parts = append(parts, "s:"+strings.ToLower(dir))
	}
	for _, dir := range e.pluginDirs {
		parts = append(parts, "p:"+strings.ToLower(dir))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// mcpKey changes only when a server changes: the entries are sorted, as
// the Codex reader lists them in map order, which asked for a rescan on
// almost every poll.
func (e enrolledWatchSet) mcpKey() string {
	entries := append([]config.MCPServerEntry(nil), e.mcp...)
	sort.SliceStable(entries, func(i, j int) bool {
		return watcher.MCPEventPath(entries[i]) < watcher.MCPEventPath(entries[j])
	})
	raw, _ := json.Marshal(entries)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// newEnrolledWatchRoots returns the folders in dirs that the previous
// watcher of this process did not watch, and remembers dirs for the next.
// The first watcher of a process gets none: at gateway start the root
// markers decide what the startup rescan admits.
func (s *Sidecar) newEnrolledWatchRoots(dirs []string) []string {
	var added []string
	next := make(map[string]struct{}, len(dirs))
	for _, dir := range dirs {
		key := strings.ToLower(filepath.Clean(dir))
		next[key] = struct{}{}
		if _, seen := s.enrolledWatchRoots[key]; !seen && s.enrolledWatchRoots != nil {
			added = append(added, dir)
		}
	}
	s.enrolledWatchRoots = next
	return added
}

// resolveEnrolledWatchSet lists, for every user the hook guardian protects,
// the existing skill and plugin folders of that user's connector and the
// user's MCP servers. The folders are the connector's ComponentTargets for
// the gateway's own home, moved under the user's home; folders outside a
// home and folders that do not exist yet are left out (the watcher never
// creates folders in a user's profile; the next poll picks up new ones).
func resolveEnrolledWatchSet(cfg *config.Config, reg *connector.Registry, wcfg config.GatewayWatcherConfig, serviceHome string) enrolledWatchSet {
	return resolveEnrolledWatchSetWithStat(cfg, reg, wcfg, serviceHome, os.Stat)
}

func resolveEnrolledWatchSetWithStat(cfg *config.Config, reg *connector.Registry, wcfg config.GatewayWatcherConfig, serviceHome string, stat func(string) (os.FileInfo, error)) enrolledWatchSet {
	set := enrolledWatchSet{roots: map[string]string{}, live: &enrolledMCPServers{}}
	defer func() { set.live.set(set.mcp) }()
	if cfg == nil || reg == nil || strings.TrimSpace(serviceHome) == "" {
		return set
	}
	authorization, _ := readManagedGuardianAuthorization(cfg.DataDir)
	if authorization == nil {
		return set
	}
	seenSkill := map[string]bool{}
	seenPlugin := map[string]bool{}
	seenMCP := map[string]bool{}
	type userConnector struct{ home, connector, sid string }
	var targets []userConnector
	ownedHomes := map[string]bool{}
	for _, target := range authorization.ProtectedTargets {
		home := strings.TrimSpace(target.UserHome)
		if home == "" && target.Result != nil {
			home = strings.TrimSpace(target.Result.UserHome)
		}
		name := managedGuardianTargetConnector(target)
		if !target.OK || home == "" || name == "" || !filepath.IsAbs(home) {
			continue
		}
		targets = append(targets, userConnector{filepath.Clean(home), name, strings.TrimSpace(target.SID)})
		if key := strings.ToLower(filepath.Clean(home)); !ownedHomes[key] {
			ownedHomes[key] = true
			owner := watcher.AssetOwner{Home: filepath.Clean(home), Name: strings.TrimSpace(target.User)}
			if sid := strings.TrimSpace(target.SID); sid != "" {
				owner.ID, owner.IDKind = sid, useridentity.KindWindowsSID
			}
			set.owners = append(set.owners, owner)
		}
	}
	// A folder several connectors list (Amp and OpenCode also read Claude
	// Code's ~/.claude/skills) belongs to the connector that owns its layout,
	// so the watcher applies that connector's rules (Claude Code's skills
	// and plugin cache, Hermes categories): owners claim first.
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].home != targets[j].home {
			return targets[i].home < targets[j].home
		}
		if pi, pj := enrolledRootPrecedence(targets[i].connector), enrolledRootPrecedence(targets[j].connector); pi != pj {
			return pi < pj
		}
		return targets[i].connector < targets[j].connector
	})
	for _, target := range targets {
		conn, ok := reg.Get(target.connector)
		if !ok {
			continue
		}
		componentScanner, ok := conn.(connector.ComponentScanner)
		if !ok || !componentScanner.SupportsComponentScanning() {
			continue
		}
		components := componentScanner.ComponentTargets("")
		add := func(dirs []string, seen map[string]bool, out *[]string) {
			for _, dir := range dirs {
				userDir, ok := rebaseUnderHome(dir, serviceHome, target.home)
				if !ok {
					continue
				}
				key := strings.ToLower(userDir)
				if seen[key] {
					continue
				}
				info, err := stat(userDir)
				if errors.Is(err, os.ErrNotExist) || (err == nil && !info.IsDir()) {
					continue
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "[watcher] cannot stat enrolled directory %s: %v\n", userDir, err)
				}
				seen[key] = true
				*out = append(*out, userDir)
				if _, owned := set.roots[userDir]; !owned {
					set.roots[userDir] = target.connector
				}
			}
		}
		if wcfg.Skill.Enabled {
			add(components["skill"], seenSkill, &set.skillDirs)
		}
		if wcfg.Plugin.Enabled {
			add(components["plugin"], seenPlugin, &set.pluginDirs)
		}
		// A server is the user's and the connector's: another user's (or
		// connector's) server with the same name is admitted on its own.
		entries := config.ReadUserMCPServersForHome(target.connector, target.home)
		if target.connector == "claudecode" {
			entries = append(entries, enrolledClaudeMCPServers(cfg, target.sid)...)
		}
		for _, entry := range entries {
			entry.Home = target.home
			key := watcher.MCPEventPath(entry)
			if entry.Name == "" || entry.Bundled || seenMCP[key] {
				continue
			}
			seenMCP[key] = true
			set.mcp = append(set.mcp, entry)
		}
	}
	return set
}

// enrolledClaudeMCPServers are the Claude Code MCP servers the enumerator
// published for the account sid: the gateway service account cannot read
// ~/.claude.json in the profile root, which holds the user-scope and
// local-scope servers (GAP-0424).
func enrolledClaudeMCPServers(cfg *config.Config, sid string) []config.MCPServerEntry {
	dir := enterprisehooks.ClaudeMCPSpoolDir(managed.HookGuardianAuthorizationDir(cfg.DataDir))
	servers, err := enterprisehooks.ReadClaudeMCPSpool(dir, sid, validateManagedGuardianAuthorization)
	if err != nil {
		return nil
	}
	return servers
}

// EnrolledWatchRoot is a skill or plugin folder a managed Windows gateway
// watches for an enrolled user, with that user's profile and SID.
type EnrolledWatchRoot struct {
	Dir, Home, SID string
}

// EnrolledWatchRoots lists the folders a managed Windows gateway watches for
// its enrolled users, as its watcher resolves them. The hook guardian removes
// a quarantined source only inside one of them (GAP-0202).
func EnrolledWatchRoots(cfg *config.Config) []EnrolledWatchRoot {
	if !watcherUsesEnrolledUserDirs(cfg) {
		return nil
	}
	set := resolveEnrolledWatchSet(cfg, connector.NewDefaultRegistry(), cfg.Gateway.Watcher, serviceHomeDir())
	authorization, _ := readManagedGuardianAuthorization(cfg.DataDir)
	if authorization == nil {
		return nil
	}
	var roots []EnrolledWatchRoot
	for dir := range set.roots {
		for _, target := range authorization.ProtectedTargets {
			home := strings.TrimSpace(target.UserHome)
			if home == "" && target.Result != nil {
				home = strings.TrimSpace(target.Result.UserHome)
			}
			if target.OK && strings.TrimSpace(target.SID) != "" && filepath.IsAbs(home) {
				if _, ok := rebaseUnderHome(dir, home, home); ok {
					roots = append(roots, EnrolledWatchRoot{Dir: dir, Home: filepath.Clean(home), SID: strings.TrimSpace(target.SID)})
					break
				}
			}
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].Dir < roots[j].Dir })
	return roots
}

// enrolledRootPrecedence orders the connectors whose folder layout the
// watcher interprets itself ahead of the ones that only share a folder.
func enrolledRootPrecedence(connectorName string) int {
	switch connectorName {
	case "claudecode":
		return 0
	case "codex":
		return 1
	case "hermes":
		return 2
	default:
		return 3
	}
}

// rebaseUnderHome moves path from below fromHome to the same place below
// toHome. Paths outside fromHome are not a user's and are refused.
func rebaseUnderHome(path, fromHome, toHome string) (string, bool) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(fromHome) {
		return "", false
	}
	rel, err := filepath.Rel(filepath.Clean(fromHome), filepath.Clean(path))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return filepath.Join(toHome, rel), true
}

// pollEnrolledWatchSet re-reads the enrolled watch set until ctx ends. A
// changed folder set closes changed (the watcher restarts on it); a changed
// MCP server list asks the running watcher for a rescan.
func (s *Sidecar) pollEnrolledWatchSet(ctx context.Context, reg *connector.Registry, wcfg config.GatewayWatcherConfig, current enrolledWatchSet, w *watcher.InstallWatcher, changed chan struct{}) {
	ticker := time.NewTicker(enrolledWatchPollInterval)
	defer ticker.Stop()
	dirs, mcp := current.dirsKey(), current.mcpKey()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			next := resolveEnrolledWatchSet(s.currentConfig(), reg, wcfg, serviceHomeDir())
			if next.dirsKey() != dirs {
				close(changed)
				return
			}
			if key := next.mcpKey(); key != mcp {
				mcp = key
				current.live.set(next.mcp)
				if w != nil {
					// Admit a server the user added within this poll, not
					// after the running rescan cycle: every server without a
					// baseline, so a second user adding a server named like
					// another user is admitted too (GAP-0254).
					w.DiscoverAddedMCPServers()
					w.RequestRescan()
				}
			}
		}
	}
}
