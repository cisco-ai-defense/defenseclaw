// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
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
// the share of one account. A definition that a denied rule matched is kept
// apart (mcpResolvedDeniedLimit, mcpResolvedDeniedPerHome) and is never
// pushed out by the others: losing it is what let a denied server run once
// its entry was gone. Only a definition read from an agent config is
// remembered, so the bounds follow the size of the configs, not the number of
// names a tool call can make up. A denied definition that still does not fit
// goes into the lost set of its session (mcpLostSet), whole, so it is judged
// on the policy in force like any remembered one. The lost definitions are
// bounded by mcpResolvedLostLimit in all; a session that cannot hold one more
// is marked instead and refuses what a denied rule covers by name.
const (
	mcpResolvedLimit         = 2048
	mcpResolvedPerHome       = 256
	mcpResolvedDeniedLimit   = 4096
	mcpResolvedDeniedPerHome = 1024
	mcpResolvedLostLimit     = 65536
)

// mcpLostSet holds the denied definitions of one session that did not fit in
// the memory, by the key they were resolved under, with the time of its last
// use. The definition is kept whole, not a digest of the rule that matched
// it: the live connection is judged on the policy in force now (a replaced
// rule, an equivalent spelling of it, a second rule, a scoped allow), exactly
// as a remembered definition is.
type mcpLostSet struct {
	defs map[string]config.MCPServerEntry
	// overflow is set when a definition could not be kept, because the lost
	// definitions were full.
	overflow bool
	at       time.Time
}

// mcpResolvedDefinitions remembers, per connector, account home, agent
// session, working directory and server name, the definition a hook resolved
// for an MCP server, so a tool call of a server whose entry has since left the
// config of its agent (claude mcp remove while the session runs), or whose
// entry was edited, is still judged on where the live connection points.
// Without it the call carried only a name, a deny pinned to a URL or command
// never matched, and the connection kept working (GAP-0861). The session is
// part of the key because a new agent process connects to whatever its config
// lists then; forgetSession drops a session when it starts again. The zero
// value is ready to use.
type mcpResolvedDefinitions struct {
	mu      sync.Mutex
	entries map[string]mcpResolvedDefinition
	// lost holds, per session (connector, account and session id), the
	// denied definitions of that session that did not fit. A session that
	// starts again drops its set.
	lost map[string]*mcpLostSet
}

type mcpResolvedDefinition struct {
	entry config.MCPServerEntry
	// denied is set once a rule of asset_policy.mcp.denied matched this
	// definition. It is kept, and a later definition read for the same name
	// does not replace it: the live connection is the one it was judged on.
	denied                   bool
	connector, home, session string
	seen                     time.Time
}

func mcpResolvedKey(connector, home, session, cwd, name string) string {
	// The name is the form the tool call spells (config.MCPToolServerName):
	// a Codex tool name loses punctuation of the configured name, which is
	// what the call still carries once the entry is gone, while names that
	// differ in case or punctuation Claude keeps stay distinct.
	return strings.ToLower(connector) + "\x00" + home + "\x00" + session + "\x00" + cwd + "\x00" +
		config.MCPToolServerName(connector, strings.TrimSpace(name))
}

// remember records entry, the definition just read for name, and whether a
// denied rule matched it. It reports whether the definition is kept in the
// memory; a denied one that does not fit is held in the lost set of its
// session.
func (m *mcpResolvedDefinitions) remember(connector, home, session, cwd, name string, entry config.MCPServerEntry, denied bool, now time.Time) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	key := mcpResolvedKey(connector, home, session, cwd, name)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = map[string]mcpResolvedDefinition{}
	}
	kept, known := m.entries[key]
	if known && kept.denied && !denied {
		// The live connection is the denied one; the config now says
		// something else.
		kept.seen = now
		m.entries[key] = kept
		return true
	}
	if !known {
		m.expireLocked(now)
	}
	if (!known || denied && !kept.denied) && !m.hasRoomLocked(home, denied, key) {
		if denied {
			m.markLostLocked(connector, home, session, key, entry, now)
		}
		return false
	}
	m.entries[key] = mcpResolvedDefinition{
		entry: entry, denied: denied, connector: strings.ToLower(connector), home: home, session: session, seen: now,
	}
	return true
}

func mcpLostKey(connector, home, session string) string {
	return strings.ToLower(connector) + "\x00" + home + "\x00" + session
}

// markLostLocked holds the denied definition entry, resolved under key, that
// could not be kept. The first one held for a key stays, as a denied
// remembered definition does. No room for another one marks the session.
func (m *mcpResolvedDefinitions) markLostLocked(connector, home, session, key string, entry config.MCPServerEntry, now time.Time) {
	if m.lost == nil {
		m.lost = map[string]*mcpLostSet{}
	}
	lostKey := mcpLostKey(connector, home, session)
	set, ok := m.lost[lostKey]
	if !ok || now.Sub(set.at) > mcpResolvedTTL {
		set = &mcpLostSet{}
		m.lost[lostKey] = set
	}
	set.at = now
	if _, held := set.defs[key]; held {
		return
	}
	if m.lostCountLocked() >= mcpResolvedLostLimit {
		set.overflow = true
		return
	}
	if set.defs == nil {
		set.defs = map[string]config.MCPServerEntry{}
	}
	set.defs[key] = entry
}

func (m *mcpResolvedDefinitions) lostCountLocked() int {
	var n int
	for _, set := range m.lost {
		n += len(set.defs)
	}
	return n
}

// lostDenied returns, within the TTL, the denied definition held for the name
// of the call because it did not fit in the memory, and whether the session
// could not hold every denied definition (overflow). A set that answers
// renews itself.
func (m *mcpResolvedDefinitions) lostDenied(connector, home, session, cwd, name string, now time.Time) (entry config.MCPServerEntry, held, overflow bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.lost[mcpLostKey(connector, home, session)]
	if set == nil || now.Sub(set.at) > mcpResolvedTTL {
		return config.MCPServerEntry{}, false, false
	}
	entry, held = set.defs[mcpResolvedKey(connector, home, session, cwd, name)]
	if held || set.overflow {
		set.at = now
	}
	return entry, held, set.overflow
}

// hasRoomLocked reports whether the definition under key, of the kind denied
// says, fits for home, not counting the one already kept under key.
func (m *mcpResolvedDefinitions) hasRoomLocked(home string, denied bool, key string) bool {
	var all, mine int
	for other, kept := range m.entries {
		if other == key || kept.denied != denied {
			continue
		}
		all++
		if kept.home == home {
			mine++
		}
	}
	if denied {
		return all < mcpResolvedDeniedLimit && mine < mcpResolvedDeniedPerHome
	}
	return all < mcpResolvedLimit && mine < mcpResolvedPerHome
}

// recall returns the definition remembered for name, when one was within the
// TTL, and renews it.
func (m *mcpResolvedDefinitions) recall(connector, home, session, cwd, name string, now time.Time) (config.MCPServerEntry, bool) {
	key := mcpResolvedKey(connector, home, session, cwd, name)
	m.mu.Lock()
	defer m.mu.Unlock()
	kept, ok := m.entries[key]
	if !ok {
		return config.MCPServerEntry{}, false
	}
	if now.Sub(kept.seen) > mcpResolvedTTL {
		delete(m.entries, key)
		return config.MCPServerEntry{}, false
	}
	kept.seen = now
	m.entries[key] = kept
	return kept.entry, true
}

// forgetSession drops what was remembered for one session of an account: its
// agent started again, so it connects to the servers its config lists now.
func (m *mcpResolvedDefinitions) forgetSession(connector, home, session string) {
	connector = strings.ToLower(connector)
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, kept := range m.entries {
		if kept.connector == connector && kept.home == home && kept.session == session {
			delete(m.entries, key)
		}
	}
	delete(m.lost, mcpLostKey(connector, home, session))
}

func (m *mcpResolvedDefinitions) expireLocked(now time.Time) {
	for key, kept := range m.entries {
		if now.Sub(kept.seen) > mcpResolvedTTL {
			delete(m.entries, key)
		}
	}
	for key, set := range m.lost {
		if now.Sub(set.at) > mcpResolvedTTL {
			delete(m.lost, key)
		}
	}
}

// sameMCPDefinition reports whether two entries are the same server under the
// same configured name: where it points or how it starts, and the name the
// lists and the registry know it by. An edit that only renames the entry is a
// change too, because a rule can deny the old name.
func sameMCPDefinition(a, b config.MCPServerEntry) bool {
	return strings.TrimSpace(a.Name) == strings.TrimSpace(b.Name) &&
		strings.TrimSpace(a.URL) == strings.TrimSpace(b.URL) &&
		strings.TrimSpace(a.Command) == strings.TrimSpace(b.Command) &&
		strings.TrimSpace(a.Transport) == strings.TrimSpace(b.Transport) &&
		slices.Equal(a.Args, b.Args)
}
