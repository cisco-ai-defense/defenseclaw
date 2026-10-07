// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
	// mcp is every enrolled user's MCP servers, tagged with the connector.
	mcp []config.MCPServerEntry
	// live is what the running watcher reads; the poller refreshes it.
	live *enrolledMCPServers
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

func (e enrolledWatchSet) mcpKey() string {
	raw, _ := json.Marshal(e.mcp)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// resolveEnrolledWatchSet lists, for every user the hook guardian protects,
// the existing skill and plugin folders of that user's connector and the
// user's MCP servers. The folders are the connector's ComponentTargets for
// the gateway's own home, moved under the user's home; folders outside a
// home and folders that do not exist yet are left out (the watcher never
// creates folders in a user's profile; the next poll picks up new ones).
func resolveEnrolledWatchSet(cfg *config.Config, reg *connector.Registry, wcfg config.GatewayWatcherConfig, serviceHome string) enrolledWatchSet {
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
	type userConnector struct{ home, connector string }
	var targets []userConnector
	for _, target := range authorization.ProtectedTargets {
		home := strings.TrimSpace(target.UserHome)
		if home == "" && target.Result != nil {
			home = strings.TrimSpace(target.Result.UserHome)
		}
		name := managedGuardianTargetConnector(target)
		if !target.OK || home == "" || name == "" || !filepath.IsAbs(home) {
			continue
		}
		targets = append(targets, userConnector{filepath.Clean(home), name})
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].home != targets[j].home {
			return targets[i].home < targets[j].home
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
				if info, err := os.Stat(userDir); err != nil || !info.IsDir() {
					continue
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
		for _, entry := range config.ReadUserMCPServersForHome(target.connector, target.home) {
			if entry.Name == "" || entry.Bundled || seenMCP[entry.Name] {
				continue
			}
			seenMCP[entry.Name] = true
			set.mcp = append(set.mcp, entry)
		}
	}
	return set
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
					w.RequestRescan()
				}
			}
		}
	}
}
