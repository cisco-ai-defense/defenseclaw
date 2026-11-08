// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// mcpResolvedTTL is how long a resolved MCP server definition is kept after
// the last call that used it. An agent keeps its connection to a server for
// as long as its process lives, whatever its config file says later, so the
// memory has to outlast an edit of that file; a day is longer than an
// ordinary session and short enough that a server the user really dropped
// stops being judged on its old definition.
const mcpResolvedTTL = 24 * time.Hour

// mcpResolvedLimit bounds the definitions kept in all, and mcpResolvedPerHome
// the share of one account: the names come from tool calls, so one user
// making many up must not push the definitions of the others out.
const (
	mcpResolvedLimit   = 2048
	mcpResolvedPerHome = 256
)

// mcpResolvedDefinitions remembers, per connector, account home, working
// directory and server name, the definition a hook last resolved for an MCP
// server, so a tool call of a server whose entry has since left the config of
// its agent (claude mcp remove while the session runs) is still judged on
// where that server points. Without it the call carried only a name, a deny
// pinned to a URL or command never matched, and the live connection kept
// working (GAP-0861). The zero value is ready to use.
type mcpResolvedDefinitions struct {
	mu      sync.Mutex
	entries map[string]mcpResolvedDefinition
	perHome map[string]int
}

type mcpResolvedDefinition struct {
	entry config.MCPServerEntry
	home  string
	seen  time.Time
}

func mcpResolvedKey(connector, home, cwd, name string) string {
	return strings.ToLower(connector) + "\x00" + home + "\x00" + cwd + "\x00" + strings.ToLower(name)
}

// remember records entry, the definition just resolved for name.
func (m *mcpResolvedDefinitions) remember(connector, home, cwd, name string, entry config.MCPServerEntry, now time.Time) {
	if strings.TrimSpace(name) == "" {
		return
	}
	key := mcpResolvedKey(connector, home, cwd, name)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = map[string]mcpResolvedDefinition{}
		m.perHome = map[string]int{}
	}
	if _, known := m.entries[key]; !known {
		m.expireLocked(now)
		if len(m.entries) >= mcpResolvedLimit || m.perHome[home] >= mcpResolvedPerHome {
			return
		}
		m.perHome[home]++
	}
	m.entries[key] = mcpResolvedDefinition{entry: entry, home: home, seen: now}
}

// recall returns the definition last resolved for name, when one was within
// the TTL, and renews it.
func (m *mcpResolvedDefinitions) recall(connector, home, cwd, name string, now time.Time) (config.MCPServerEntry, bool) {
	key := mcpResolvedKey(connector, home, cwd, name)
	m.mu.Lock()
	defer m.mu.Unlock()
	kept, ok := m.entries[key]
	if !ok {
		return config.MCPServerEntry{}, false
	}
	if now.Sub(kept.seen) > mcpResolvedTTL {
		m.dropLocked(key, kept)
		return config.MCPServerEntry{}, false
	}
	kept.seen = now
	m.entries[key] = kept
	return kept.entry, true
}

func (m *mcpResolvedDefinitions) expireLocked(now time.Time) {
	for key, kept := range m.entries {
		if now.Sub(kept.seen) > mcpResolvedTTL {
			m.dropLocked(key, kept)
		}
	}
}

func (m *mcpResolvedDefinitions) dropLocked(key string, kept mcpResolvedDefinition) {
	delete(m.entries, key)
	if m.perHome[kept.home]--; m.perHome[kept.home] <= 0 {
		delete(m.perHome, kept.home)
	}
}
