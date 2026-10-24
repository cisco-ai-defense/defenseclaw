// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// profileAgentBridge decides, for the agents entries an assignment wrote for
// a legacy identity (1.0.0 to 1.0.3: keyed without the account's domain and
// without an account incarnation, agentidentity.LegacyAgentID), whether an
// entry is the request agent's own. 1.0.3 gave one legacy identity to every
// domain's namesake of a uid and to every account that took the uid over,
// so the derivation alone proves nothing. The upgrade's migration map does:
// the root guardian records, once, at its first pass after the upgrade,
// which account incarnation held each enrolled uid (its name, and its SID or
// the identity of its home directory; enterprisehooks.LegacyAgentOwnersFile).
// An entry the request derives as its 1.0.3 identity is the agent's own when
// the account that holds the uid now is that incarnation under that name
// (legacyAgentOwnerBound), or is a per-user gateway's own account; it then
// matches as the agent's current identity does, with no rebind.
//
// Any other entry the request derives (no map entry, another holder,
// another domain's namesake) is a candidate, not a match: the request is
// refused until the entry's owner is proven (selectProfile). Windows
// identities are SIDs, which 1.0.3 keyed the same way, so
// their entries match as they did. Remove with agentidentity.LegacyAgentID.
type profileAgentBridge struct {
	once sync.Once
	// entries are the assignments' agents entries, lower-cased.
	entries map[string]bool
	mu      sync.Mutex
	// derived maps every identity the agent ledger's records derive to its
	// 1.0.3 claim, at the ledger's last read: explain names an agent by its
	// identity only. read is false until the ledger answered once.
	derived map[string]profileAgentClaim
	read    bool
	// readAt is when the ledger is read again.
	readAt time.Time
	// noted holds the entries already logged; "" the unreadable ledger.
	noted map[string]bool
}

// profileAgentBridgeRetry is how long a ledger that could not be read is
// left alone; profileAgentBridgeRefresh is how long an answer is kept.
const (
	profileAgentBridgeRetry   = 30 * time.Second
	profileAgentBridgeRefresh = 5 * time.Minute
)

// profileAgentLedger returns the agent ledger's records that filter
// selects, and false when the ledger cannot be read now.
var profileAgentLedger = func(filter inventory.AgentIdentityFilter) ([]inventory.AgentIdentityRecord, bool) {
	store := sharedAgentIdentities.store()
	if store == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	records, _, err := store.ListAgentIdentities(ctx, filter)
	return records, err == nil
}

// profileAgentClaim is the 1.0.3 identity of an agent and whether the
// upgrade binds it to the account that holds the uid now.
type profileAgentClaim struct {
	// ID is the 1.0.3 identity (agentidentity.LegacyAgentID), lower-cased;
	// "" when the agent's identity did not change (a SID).
	ID string
	// UserID, MachineHash and Account are the facts ID was derived from:
	// Account is the account as the host names it now.
	UserID, MachineHash, Account string
	// Bound reports that ID is the agent's own: the migration map records
	// the account that holds UserID now as the one that held it at the
	// upgrade, or UserID is a per-user gateway's own account.
	Bound bool
}

// legacyAgentClaim is the claim of the 1.0.3 identity legacy derived for the
// account account that holds userID on machine. self marks a per-user
// gateway's own account.
func legacyAgentClaim(legacy, userID, machine, account string, self bool) profileAgentClaim {
	claim := profileAgentClaim{
		ID:     strings.ToLower(strings.TrimSpace(legacy)),
		UserID: agentidentity.NormalizeUserID(userID), MachineHash: machine, Account: account,
	}
	if claim.ID == "" {
		return claim
	}
	claim.Bound = self || legacyAgentOwnerBound(claim.UserID, account)
	return claim
}

// profileAgentSelf reports whether userID is a per-user gateway's own
// account, which only it can be the verified user of.
func profileAgentSelf(userID string) bool {
	if gatewayRunsAsServiceAccount() {
		return false
	}
	self := agentidentity.NormalizeUserID(gatewaySelfUser().ID)
	return self != "" && self == agentidentity.NormalizeUserID(userID)
}

// profileAgentLegacy returns the 1.0.3 identity of a request's agent with
// its binding (profileAgentClaim) and true, or false when it is not known.
type profileAgentLegacy func() (claim profileAgentClaim, known bool)

// matchAgent is set.match for a request of the agent identity agent;
// legacy, when not nil, derives agent's 1.0.3 identity. An agents entry that
// may be that identity, which the upgrade did not bind, leaves the agent
// fact unproven (resolveIdentity): its assignment is a candidate and the
// request is refused. An entry the upgrade bound
// matches as agent does.
func (set *guardrailProfileSet) matchAgent(subject *profileSubject, source, connectorName string, scans []string, agent string, legacy profileAgentLegacy) profileDecision {
	matched, unresolved, owned := set.profileAgent(agent, legacy)
	if subject == nil || source == "" {
		unresolved, owned = nil, nil
	}
	res := resolveIdentity(subject, unresolved)
	if owned != nil {
		// The binding depends on the account holding the uid now, which
		// the memo key does not carry: not memoised.
		res.agentOwned = owned
		return set.selectProfile(subject, res, source, connectorName, scans, matched)
	}
	return set.matchResolved(subject, res, source, connectorName, scans, matched)
}

// profileAgent is what the request's agent identity agent is matched as
// (match's agent argument): agent itself. unresolved, when not nil, reports
// the entries that may be agent's 1.0.3 identity, which the upgrade did not
// bind; owned, when not nil, the entry it bound: it matches as agent does.
func (set *guardrailProfileSet) profileAgent(agent string, legacy profileAgentLegacy) (matched string, unresolved, owned func(entry string) bool) {
	agent = strings.TrimSpace(agent)
	if set == nil || agent == "" {
		return agent, nil, nil
	}
	bridge := &set.agentBridge
	bridge.once.Do(func() {
		bridge.entries = map[string]bool{}
		for _, assignment := range set.assignments {
			for _, entry := range assignment.Match.Agents {
				if entry = strings.ToLower(strings.TrimSpace(entry)); entry != "" {
					bridge.entries[entry] = true
				}
			}
		}
	})
	if len(bridge.entries) == 0 {
		return agent, nil, nil
	}
	var claim profileAgentClaim
	known := false
	if legacy != nil {
		claim, known = legacy()
		claim.ID = strings.ToLower(strings.TrimSpace(claim.ID))
	}
	if known && (claim.ID == "" || !bridge.entries[claim.ID]) {
		// No entry is agent's 1.0.3 identity.
		return agent, nil, nil
	}
	unresolved, owned = bridge.resolve(strings.ToLower(agent), claim, known)
	return agent, unresolved, owned
}

// resolve is profileAgent's binding side. claim is agent's when known; else
// (explain names an agent by its identity only) the ledger's records of
// agent say what its 1.0.3 identity is.
func (b *profileAgentBridge) resolve(agent string, claim profileAgentClaim, known bool) (unresolved, owned func(string) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !known {
		wasRead := b.read
		b.refreshLocked(false)
		recorded, ok := b.derived[agent]
		if wasRead && b.read && !ok {
			// A hook may have enrolled this agent after explain last read
			// the ledger. An absent entry must be checked at the current
			// ledger head before explain calls it unconfirmed.
			b.refreshLocked(true)
			recorded, ok = b.derived[agent]
		}
		if !b.read || !ok {
			// Neither the request nor the ledger says what agent's 1.0.3
			// identity is: any entry may be it.
			return func(entry string) bool { return entry != agent }, nil
		}
		if recorded.ID == "" || !b.entries[recorded.ID] {
			return nil, nil
		}
		claim = legacyAgentClaim(recorded.ID, recorded.UserID, recorded.MachineHash, recorded.Account, profileAgentSelf(recorded.UserID))
	}
	legacy := claim.ID
	if claim.Bound {
		if !b.noted["="+legacy] {
			b.note("=" + legacy)
			fmt.Fprintf(os.Stderr, "[guardrail] profile assignment agent %s: the 1.0.3 identity of %s's agent %s, which the upgrade "+
				"bound to this account; it keeps applying\n", legacy, claim.Account, agent)
		}
		return nil, func(entry string) bool { return entry == legacy }
	}
	if !b.noted["?"+legacy] {
		b.note("?" + legacy)
		fmt.Fprintf(os.Stderr, "[guardrail] profile assignment agent %s: the upgrade did not record the account holding uid %s now as the "+
			"one 1.0.3 derived it for; agent %s is refused until ownership is proven (default_lookup_failed)\n",
			legacy, claim.UserID, agent)
	}
	return func(entry string) bool { return entry == legacy }, nil
}

// refreshLocked reads the ledger again once its answer is due. b.mu is held.
func (b *profileAgentBridge) refreshLocked(force bool) {
	now := time.Now()
	if !force && now.Before(b.readAt) {
		return
	}
	if derived, ok := readProfileAgentLedger(); ok {
		b.derived, b.read, b.readAt = derived, true, now.Add(profileAgentBridgeRefresh)
		return
	}
	b.readAt = now.Add(profileAgentBridgeRetry)
	if !b.read && !b.noted[""] {
		b.note("")
		fmt.Fprintf(os.Stderr, "[guardrail] the agent ledger cannot be read: explain cannot tell which 1.0.3 agents entry an agent "+
			"identity derives until it answers\n")
	}
}

func (b *profileAgentBridge) note(key string) {
	if b.noted == nil {
		b.noted = map[string]bool{}
	}
	b.noted[key] = true
}

// readProfileAgentLedger maps every identity the ledger's records derive to
// its 1.0.3 claim, unbound (legacyAgentClaim binds it), reading the records
// a prune kept aside too (inventory.retireLegacyAgentIdentities); false
// when the ledger cannot be read.
func readProfileAgentLedger() (map[string]profileAgentClaim, bool) {
	records, ok := profileAgentLedger(inventory.AgentIdentityFilter{Retired: true})
	if !ok {
		return nil, false
	}
	derived := map[string]profileAgentClaim{}
	for _, rec := range records {
		if agentidentity.IsSID(agentidentity.NormalizeUserID(rec.UserID)) || agentidentity.AccountKey(rec.UserName) == "" {
			continue
		}
		in := agentidentity.Inputs{
			MachineHash: rec.MachineHash, UserID: rec.UserID, Account: rec.UserName,
			Connector: rec.Connector, InstallFP: rec.InstallFP,
		}
		legacy := strings.ToLower(agentidentity.LegacyAgentID(in))
		if legacy == "" {
			continue
		}
		id, current := strings.ToLower(rec.AgentID), strings.ToLower(agentidentity.AgentID(in))
		claim := profileAgentClaim{ID: legacy, UserID: agentidentity.NormalizeUserID(rec.UserID), MachineHash: rec.MachineHash, Account: rec.UserName}
		switch {
		case id == legacy:
			// A 1.0.3 record derives its account's current identity.
			if _, seen := derived[current]; !seen {
				derived[current] = claim
			}
		case id == current:
			derived[id] = claim
		case strings.TrimSpace(rec.UserIncarnation) != "":
			in.Incarnation = rec.UserIncarnation
			if id == strings.ToLower(agentidentity.AgentID(in)) {
				derived[id] = claim
			}
		}
	}
	return derived, true
}
