// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/binary"
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
// is not forgotten: the name it was kept under goes into a fixed-size filter
// of its session (mcpLostSet), which answers yes for every name added and may
// answer yes for others, so a bound can only make the memory refuse more.
// mcpResolvedLostLimit sessions have a filter of their own; the sessions past
// that share one.
const (
	mcpResolvedLimit         = 2048
	mcpResolvedPerHome       = 256
	mcpResolvedDeniedLimit   = 4096
	mcpResolvedDeniedPerHome = 1024
	mcpResolvedLostLimit     = 1024
)

// mcpLostBloomWords sizes the filter of lost names: 16384 bits, three probes
// per name, so a few thousand lost names keep false answers to a few percent
// and a flood of them saturates toward refusing, never toward allowing.
const (
	mcpLostBloomWords  = 256
	mcpLostBloomProbes = 3
)

// mcpLostSet is a Bloom filter of the keys (mcpResolvedKey) of denied
// definitions that did not fit in the memory, with the time of its last use.
type mcpLostSet struct {
	bits [mcpLostBloomWords]uint64
	at   time.Time
}

func (s *mcpLostSet) probes(key string) [mcpLostBloomProbes]uint32 {
	sum := sha256.Sum256([]byte(key))
	var at [mcpLostBloomProbes]uint32
	for i := range at {
		at[i] = binary.BigEndian.Uint32(sum[i*4:]) % (mcpLostBloomWords * 64)
	}
	return at
}

func (s *mcpLostSet) add(key string) {
	for _, bit := range s.probes(key) {
		s.bits[bit/64] |= 1 << (bit % 64)
	}
}

func (s *mcpLostSet) has(key string) bool {
	for _, bit := range s.probes(key) {
		if s.bits[bit/64]&(1<<(bit%64)) == 0 {
			return false
		}
	}
	return true
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
	// names of the denied definitions of that session that did not fit.
	lost map[string]*mcpLostSet
	// spill takes them for the sessions past mcpResolvedLostLimit. It is not
	// cleared when one of those sessions starts again; it expires with the TTL.
	spill *mcpLostSet
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
// denied rule matched it. It reports whether the definition is kept.
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
			m.markLostLocked(connector, home, session, key, now)
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

// markLostLocked records that the denied definition kept under key could not
// be kept. When the session has no filter and the filters are all in use, the
// shared one takes the name.
func (m *mcpResolvedDefinitions) markLostLocked(connector, home, session, key string, now time.Time) {
	if m.lost == nil {
		m.lost = map[string]*mcpLostSet{}
	}
	lostKey := mcpLostKey(connector, home, session)
	set, ok := m.lost[lostKey]
	switch {
	case ok && now.Sub(set.at) > mcpResolvedTTL, !ok && len(m.lost) < mcpResolvedLostLimit:
		set = &mcpLostSet{}
		m.lost[lostKey] = set
	case !ok:
		if m.spill == nil || now.Sub(m.spill.at) > mcpResolvedTTL {
			m.spill = &mcpLostSet{}
		}
		set = m.spill
	}
	set.add(key)
	set.at = now
}

// lostDenied reports whether the denied definition kept under the name of the
// call did not fit in the memory within the TTL, and renews the filter that
// holds it.
func (m *mcpResolvedDefinitions) lostDenied(connector, home, session, cwd, name string, now time.Time) bool {
	key := mcpResolvedKey(connector, home, session, cwd, name)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, set := range []*mcpLostSet{m.lost[mcpLostKey(connector, home, session)], m.spill} {
		if set != nil && now.Sub(set.at) <= mcpResolvedTTL && set.has(key) {
			set.at = now
			return true
		}
	}
	return false
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
