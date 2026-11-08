// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
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
// is not forgotten: a short record of its name and of the denied rule that
// matched it goes into the lost set of its session (mcpLostSet). The records
// are exact and bounded by mcpResolvedLostLimit in all; a session that cannot
// record one more is marked instead and refuses what a denied rule covers by
// name.
const (
	mcpResolvedLimit         = 2048
	mcpResolvedPerHome       = 256
	mcpResolvedDeniedLimit   = 4096
	mcpResolvedDeniedPerHome = 1024
	mcpResolvedLostLimit     = 65536
)

// mcpLostID identifies a lost denied definition: the key it was kept under
// (connector, account, session, directory, name) and the denied rule that
// matched it, as a truncated digest, so two records are equal only when both
// are.
type mcpLostID [16]byte

func newMCPLostID(key, rule string) mcpLostID {
	sum := sha256.Sum256([]byte(key + "\x00" + rule))
	return mcpLostID(sum[:16])
}

// mcpRuleID is the identity of a rule of asset_policy.mcp.denied: what it
// matches on. The reason does not take part, so rewording a rule does not
// release the connections it denied.
func mcpRuleID(rule config.AssetPolicyRule) string {
	return strings.Join([]string{
		rule.Name, rule.Connector, rule.URL, rule.Command, rule.Transport,
		strings.Join(rule.ArgsPrefix, "\x01"), strings.Join(rule.SourcePathContains, "\x01"),
	}, "\x00")
}

// mcpLostSet holds the denied definitions of one session that did not fit in
// the memory, with the time of its last use. A record counts only while the
// rule that matched the definition is still in the denied list: the live
// connection is judged on the policy in force now, as a remembered definition
// is.
type mcpLostSet struct {
	ids map[mcpLostID]struct{}
	// overflow is set when a record could not be made, because the lost
	// records were full or the rule that matched is not known.
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
// denied rule matched it. It reports whether the definition is kept. When a
// denied definition does not fit, deniedBy names the rule that matched it
// (mcpRuleID), for the record of the session.
func (m *mcpResolvedDefinitions) remember(connector, home, session, cwd, name string, entry config.MCPServerEntry, denied bool, deniedBy func() string, now time.Time) bool {
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
			m.markLostLocked(connector, home, session, key, deniedBy(), now)
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

// markLostLocked records that the denied definition kept under key, matched
// by the denied rule rule, could not be kept. A rule that is not known, or no
// room for another record, marks the session.
func (m *mcpResolvedDefinitions) markLostLocked(connector, home, session, key, rule string, now time.Time) {
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
	id := newMCPLostID(key, rule)
	if _, held := set.ids[id]; held {
		return
	}
	if rule == "" || m.lostCountLocked() >= mcpResolvedLostLimit {
		set.overflow = true
		return
	}
	if set.ids == nil {
		set.ids = map[mcpLostID]struct{}{}
	}
	set.ids[id] = struct{}{}
}

func (m *mcpResolvedDefinitions) lostCountLocked() int {
	var n int
	for _, set := range m.lost {
		n += len(set.ids)
	}
	return n
}

// lostDenied reports, within the TTL, whether the denied definition kept under
// the name of the call did not fit in the memory and a rule of denied that
// matched it is still in force (held), and whether the session could not
// record every denied definition (overflow). A set that answers renews itself.
func (m *mcpResolvedDefinitions) lostDenied(connector, home, session, cwd, name string, denied []config.AssetPolicyRule, now time.Time) (held, overflow bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.lost[mcpLostKey(connector, home, session)]
	if set == nil || now.Sub(set.at) > mcpResolvedTTL {
		return false, false
	}
	key := mcpResolvedKey(connector, home, session, cwd, name)
	for _, rule := range denied {
		if _, ok := set.ids[newMCPLostID(key, mcpRuleID(rule))]; ok {
			held = true
			break
		}
	}
	if held || set.overflow {
		set.at = now
	}
	return held, set.overflow
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
