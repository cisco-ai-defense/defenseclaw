// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// agentIdentityFlushInterval is how often observed agent identities are
// written to inventory.db. The hook path only updates memory.
const agentIdentityFlushInterval = 30 * time.Second

// agentIdentityRecorderMaxPending bounds the identities buffered between
// flushes. One identity is one install of one connector for one user, so a
// busy host stays far below it; past it new identities wait for the next
// window.
const agentIdentityRecorderMaxPending = 4096

// agentIdentityRecorder buffers agent identities seen on the hook path and
// upserts them in one batch per flush.
type agentIdentityRecorder struct {
	flushMu sync.Mutex // serialize API, ticker and final writes
	mu      sync.Mutex
	pending map[string]*inventory.AgentIdentityRecord
	// hints keeps the latest claimed install hint per identity. Hints are not
	// stored in inventory.db; the API reports the ones this process saw.
	hints map[string]string
	// subSessions are the sessions known to be a sub-agent's, per agent
	// identity: a Codex 0.160 thread a spawn call started, or any session that
	// names a parent session. They are not chats of the agent, so they are
	// neither counted nor its last session. Past the bound the oldest are
	// dropped, and one of them that hooks again counts as a session.
	subSessions     map[string]struct{}
	subSessionOrder []string
	// exclusions are late child links awaiting the next inventory write.
	// They must survive a failed write and are removed only after commit.
	// Each one is a sub-session still in subSessions: one dropped past that
	// bound loses its exclusion too, so a write that keeps failing cannot
	// grow them past agentIdentityRecorderMaxPending (GAP-1128).
	exclusions map[string]inventory.AgentIdentitySession
	// subagents are the sub-agent instances (ais-) seen since the last
	// write, per agent identity and instance: a sub-agent that shares its
	// parent's session, or one in a child session. Past
	// agentIdentityRecorderMaxPending new ones wait for the next window.
	subagents map[string]inventory.AgentIdentitySubagent
	// upns is the newest UPN sighting applied per agent identity, by its
	// read number (agentIdentityFacts.UPNRead). It outlives flushes, so a
	// hook that read the UPN before another never writes its older UPN,
	// before or after the newer one is written. Past
	// agentIdentityRecorderMaxPending identities new ones are not tracked
	// (none is evicted) and take their sightings as they arrive.
	upns map[string]agentIdentityUPN

	// persistErr is why the last write to inventory.db failed, "" after
	// one succeeded: the ledger then runs from memory, and its counts and
	// first-seen times reset at the next restart (GAP-0393).
	persistMu    sync.Mutex
	persistErr   string
	persistSince time.Time

	storeMu         sync.Mutex
	storeGeneration uint64
	storeSource     func() *inventory.InventoryStore
	dataDir         func() string
	retentionDays   func() int
	ownStore        *inventory.InventoryStore
	// ownSweep prunes the ledger in the store the recorder opened itself;
	// discovery's own sweep prunes the store discovery opened.
	ownSweep inventory.AgentLedgerSweeper
}

var sharedAgentIdentities = &agentIdentityRecorder{
	pending: make(map[string]*inventory.AgentIdentityRecord),
	hints:   make(map[string]string),
}

// observe records one hook of an agent identity. newSession is true when the
// hook started a session the registry had not seen. The registry is in
// memory, so a session resumed after a restart is new to it again; the batch
// names the sessions it counted and the store counts each id once.
func (r *agentIdentityRecorder) observe(facts agentIdentityFacts, sessionID string, newSession bool) {
	if r == nil || facts.ID == "" {
		return
	}
	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.pending[facts.ID]
	if !ok {
		if len(r.pending) >= agentIdentityRecorderMaxPending {
			return
		}
		rec = &inventory.AgentIdentityRecord{
			AgentID: facts.ID, UserID: facts.UserID, Connector: facts.Connector,
			InstallFP: facts.InstallFP, MachineHash: facts.MachineHash, FirstSeen: now,
		}
		r.pending[facts.ID] = rec
	}
	rec.LastSeen = now
	if facts.UserName != "" {
		rec.UserName = facts.UserName
	}
	if facts.UserDomain != "" {
		rec.UserDomain = facts.UserDomain
	}
	if facts.UserIncarnation != "" {
		rec.UserIncarnation = facts.UserIncarnation
	}
	r.applyUPNLocked(rec, facts)
	sessionID = strings.TrimSpace(sessionID)
	if _, sub := r.subSessions[subSessionKey(facts.ID, sessionID)]; sub {
		sessionID = ""
	}
	if newSession && sessionID != "" {
		// The last session is the newest one counted, not the one that
		// hooked last: the previous chat can hook once more after a new one
		// started, as Codex's does after /new (GAP-0395).
		rec.NoteSession(sessionID)
		rec.LastSessionID = sessionID
	}
	if facts.InstallHint != "" && (len(r.hints) < agentIdentityRecorderMaxPending || r.hints[facts.ID] != "") {
		r.hints[facts.ID] = facts.InstallHint
	}
}

// agentIdentityUPN is one UPN sighting of an agent identity.
type agentIdentityUPN struct {
	read        uint64
	upn         string
	unavailable bool
}

// applyUPNLocked sets rec's UPN to the newest sighting: facts's, unless a
// hook that read the UPN later was applied first.
func (r *agentIdentityRecorder) applyUPNLocked(rec *inventory.AgentIdentityRecord, facts agentIdentityFacts) {
	sighting := agentIdentityUPN{read: facts.UPNRead, upn: facts.UserUPN, unavailable: facts.UPNUnavailable}
	if newest, tracked := r.upns[facts.ID]; tracked && newest.read > sighting.read {
		sighting = newest
	} else if tracked || len(r.upns) < agentIdentityRecorderMaxPending {
		if r.upns == nil {
			r.upns = make(map[string]agentIdentityUPN)
		}
		r.upns[facts.ID] = sighting
	}
	rec.UPN, rec.UPNUnavailable = sighting.upn, sighting.unavailable
}

func subSessionKey(agentID, sessionID string) string { return agentID + "\x00" + sessionID }

// observeSubagent records the sub-agent instance (ais-) a hook of agentID
// in sessionID ran as, the one its records carry: subagentInstance for a
// sub-agent that shares its parent's session, else sessionInstance when
// sessionID is a child session (markSubagentSession). A hook of the main
// agent records none.
func (r *agentIdentityRecorder) observeSubagent(agentID, sessionID, subagentInstance, sessionInstance string) {
	if r == nil || agentID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	instance := subagentInstance
	if _, child := r.subSessions[subSessionKey(agentID, strings.TrimSpace(sessionID))]; instance == "" && child {
		instance = sessionInstance
	}
	if instance == "" {
		return
	}
	seen := time.Now().UTC()
	r.noteSubagentLocked(inventory.AgentIdentitySubagent{AgentID: agentID, InstanceID: instance, FirstSeen: seen, LastSeen: seen})
}

func (r *agentIdentityRecorder) noteSubagentLocked(sub inventory.AgentIdentitySubagent) {
	key := subSessionKey(sub.AgentID, sub.InstanceID)
	if known, ok := r.subagents[key]; ok {
		if sub.FirstSeen.Before(known.FirstSeen) {
			known.FirstSeen = sub.FirstSeen
		}
		if sub.LastSeen.After(known.LastSeen) {
			known.LastSeen = sub.LastSeen
		}
		r.subagents[key] = known
		return
	}
	if len(r.subagents) >= agentIdentityRecorderMaxPending {
		return
	}
	if r.subagents == nil {
		r.subagents = make(map[string]inventory.AgentIdentitySubagent)
	}
	r.subagents[key] = sub
}

// markSubagentSession records that sessionID belongs to a sub-agent of
// agentID, which may have counted it already: the link to the parent can be
// learned after the session's first hook (GAP-0226).
func (r *agentIdentityRecorder) markSubagentSession(agentID, sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if r == nil || agentID == "" || sessionID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := subSessionKey(agentID, sessionID)
	if _, known := r.subSessions[key]; !known {
		if r.subSessions == nil {
			r.subSessions = make(map[string]struct{})
		}
		for len(r.subSessionOrder) >= agentIdentityRecorderMaxPending {
			delete(r.subSessions, r.subSessionOrder[0])
			delete(r.exclusions, r.subSessionOrder[0])
			r.subSessionOrder = r.subSessionOrder[1:]
		}
		r.subSessions[key] = struct{}{}
		r.subSessionOrder = append(r.subSessionOrder, key)
		if r.exclusions == nil {
			r.exclusions = make(map[string]inventory.AgentIdentitySession)
		}
		r.exclusions[key] = inventory.AgentIdentitySession{AgentID: agentID, SessionID: sessionID}
	}
	if rec, ok := r.pending[agentID]; ok {
		rec.ForgetSession(sessionID)
	}
}

// take removes and returns the buffered sightings, child exclusions and
// sub-agent sightings.
func (r *agentIdentityRecorder) take() ([]inventory.AgentIdentityRecord, []inventory.AgentIdentitySession, []inventory.AgentIdentitySubagent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	batch := make([]inventory.AgentIdentityRecord, 0, len(r.pending))
	for _, rec := range r.pending {
		batch = append(batch, *rec)
	}
	excluded := make([]inventory.AgentIdentitySession, 0, len(r.exclusions))
	for _, child := range r.exclusions {
		excluded = append(excluded, child)
	}
	subagents := make([]inventory.AgentIdentitySubagent, 0, len(r.subagents))
	for _, sub := range r.subagents {
		subagents = append(subagents, sub)
	}
	r.pending = make(map[string]*inventory.AgentIdentityRecord)
	r.exclusions = nil
	r.subagents = nil
	return batch, excluded, subagents
}

// restore puts back a failed write, merging it with hooks and child links
// buffered while the write was in flight.
func (r *agentIdentityRecorder) restore(
	batch []inventory.AgentIdentityRecord, excluded []inventory.AgentIdentitySession, subagents []inventory.AgentIdentitySubagent,
) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sub := range subagents {
		r.noteSubagentLocked(sub)
	}
	if r.exclusions == nil {
		r.exclusions = make(map[string]inventory.AgentIdentitySession)
	}
	for _, child := range excluded {
		// A child dropped from subSessions while the write was in flight
		// counts as a session again, as one past the bound does.
		key := subSessionKey(child.AgentID, child.SessionID)
		if _, sub := r.subSessions[key]; sub {
			r.exclusions[key] = child
		}
	}
	for i := range batch {
		old := batch[i]
		for _, sessionID := range append([]string(nil), old.SessionIDs...) {
			if _, child := r.subSessions[subSessionKey(old.AgentID, sessionID)]; child {
				old.ForgetSession(sessionID)
			}
		}
		cur, ok := r.pending[old.AgentID]
		if !ok {
			if len(r.pending) >= agentIdentityRecorderMaxPending {
				continue
			}
			r.pending[old.AgentID] = &old
			continue
		}
		if old.FirstSeen.Before(cur.FirstSeen) {
			cur.FirstSeen = old.FirstSeen
		}
		for _, sessionID := range old.SessionIDs {
			cur.NoteSession(sessionID)
		}
		cur.SessionsSeen += max(old.SessionsSeen-int64(len(old.SessionIDs)), 0)
		if cur.UserName == "" {
			cur.UserName = old.UserName
		}
		if cur.LastSessionID == "" {
			cur.LastSessionID = old.LastSessionID
		}
	}
}

// snapshot copies buffered rows, hints and distinct sub-agent sightings for
// the API. A buffered row counts its sub-agents until the store reconciles
// those sightings with instances already persisted there.
func (r *agentIdentityRecorder) snapshot() (map[string]inventory.AgentIdentityRecord, map[string]string, []inventory.AgentIdentitySubagent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pending := make(map[string]inventory.AgentIdentityRecord, len(r.pending))
	for id, rec := range r.pending {
		pending[id] = *rec
	}
	newest := map[string]time.Time{}
	subagents := make([]inventory.AgentIdentitySubagent, 0, len(r.subagents))
	for _, sub := range r.subagents {
		subagents = append(subagents, sub)
		rec, ok := pending[sub.AgentID]
		if !ok {
			continue
		}
		rec.SubagentsSeen++
		if sub.FirstSeen.After(newest[sub.AgentID]) {
			newest[sub.AgentID] = sub.FirstSeen
			rec.LastSubagentID = sub.InstanceID
		}
		pending[sub.AgentID] = rec
	}
	hints := make(map[string]string, len(r.hints))
	for id, hint := range r.hints {
		hints[id] = hint
	}
	return pending, hints, subagents
}

// flush writes the buffered batch to store.
func (r *agentIdentityRecorder) flush(ctx context.Context, store *inventory.InventoryStore) error {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	if store == nil {
		return nil
	}
	batch, excluded, subagents := r.take()
	if len(batch) == 0 && len(excluded) == 0 && len(subagents) == 0 {
		return nil
	}
	if err := store.UpsertAgentIdentityBatch(ctx, batch, excluded, subagents); err != nil {
		r.restore(batch, excluded, subagents)
		r.notePersist(err)
		return err
	}
	r.notePersist(nil)
	return nil
}

// flushFinal opens its own handle so AI Discovery may close its inventory
// store first during shutdown without losing the recorder's last batch.
func (r *agentIdentityRecorder) flushFinal(ctx context.Context) error {
	if r.pendingCount() == 0 {
		return nil
	}
	r.storeMu.Lock()
	dataDir := r.dataDir
	r.storeMu.Unlock()
	if dataDir != nil {
		if dir := strings.TrimSpace(dataDir()); dir != "" {
			store, err := inventory.NewInventoryStoreForProfile(filepath.Join(dir, "inventory.db"), ManagedEnterpriseActive())
			if err != nil {
				r.notePersist(err)
				return err
			}
			defer store.Close()
			return r.flush(ctx, store)
		}
	}
	return r.flush(ctx, r.store())
}

// notePersist records whether the last write of the ledger succeeded.
func (r *agentIdentityRecorder) notePersist(err error) {
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	switch {
	case err == nil:
		r.persistErr, r.persistSince = "", time.Time{}
	case r.persistErr == "":
		r.persistErr, r.persistSince = err.Error(), time.Now().UTC()
	default:
		r.persistErr = err.Error()
	}
}

// persistFailure is why agent identities are not being saved, and since
// when, or "" while they are.
func (r *agentIdentityRecorder) persistFailure() (string, time.Time) {
	if r == nil {
		return "", time.Time{}
	}
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	return r.persistErr, r.persistSince
}

// agentIdentityLedgerHealth is the /health entry of a ledger that is not
// being saved, or nil while it is. Secure Client records no identities.
func agentIdentityLedgerHealth() map[string]any {
	reason, since := sharedAgentIdentities.persistFailure()
	if reason == "" || ManagedEnterpriseActive() {
		return nil
	}
	return map[string]any{"persisted": false, "error": reason, "since": since.Format(time.RFC3339)}
}

// setStoreSource wires where flushes go: source returns AI discovery's
// inventory store when it runs, and dataDir locates inventory.db for the
// store the recorder opens itself when discovery is off. retentionDays is
// the window that store's ledger keeps. The returned token unwires it again.
func (r *agentIdentityRecorder) setStoreSource(source func() *inventory.InventoryStore, dataDir func() string,
	retentionDays func() int) uint64 {
	r.storeMu.Lock()
	defer r.storeMu.Unlock()
	r.storeGeneration++
	r.storeSource, r.dataDir, r.retentionDays = source, dataDir, retentionDays
	return r.storeGeneration
}

// clearStoreSource unwires the source set under token, unless a newer one
// replaced it, and closes the store the recorder opened itself.
func (r *agentIdentityRecorder) clearStoreSource(token uint64) {
	r.storeMu.Lock()
	defer r.storeMu.Unlock()
	if r.storeGeneration != token {
		return
	}
	r.storeSource, r.dataDir, r.retentionDays = nil, nil, nil
	if r.ownStore != nil {
		_ = r.ownStore.Close()
		r.ownStore = nil
	}
}

// store returns the inventory store agent identities are written to and
// read from, or nil when none can be opened.
func (r *agentIdentityRecorder) store() *inventory.InventoryStore {
	r.storeMu.Lock()
	defer r.storeMu.Unlock()
	if r.storeSource != nil {
		if store := r.storeSource(); store != nil {
			return store
		}
	}
	if r.ownStore != nil {
		return r.ownStore
	}
	dir := ""
	if r.dataDir != nil {
		dir = strings.TrimSpace(r.dataDir())
	}
	if dir == "" {
		return nil
	}
	store, err := inventory.NewInventoryStoreForProfile(filepath.Join(dir, "inventory.db"), ManagedEnterpriseActive())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] agent identities not persisted: %v\n", err)
		if r.pendingCount() > 0 {
			r.notePersist(err)
		}
		return nil
	}
	r.ownStore = store
	return store
}

// runFlusher upserts buffered agent identities every interval
// and once more on shutdown. Under the Secure Client integration nothing is
// buffered, so it never writes.
func (r *agentIdentityRecorder) runFlusher(ctx context.Context, interval time.Duration, token uint64) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer r.clearStoreSource(token)
	flush := func(ctx context.Context) {
		if ManagedEnterpriseActive() || r.pendingCount() == 0 {
			return
		}
		if err := r.flush(ctx, r.store()); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] agent identity flush failed: %v\n", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if !ManagedEnterpriseActive() {
				if err := r.flushFinal(final); err != nil {
					fmt.Fprintf(os.Stderr, "[sidecar] agent identity final flush failed: %v\n", err)
				}
			}
			cancel()
			return
		case <-ticker.C:
			flush(ctx)
			if !ManagedEnterpriseActive() {
				r.sweepOwnStore(ctx)
			}
		}
	}
}

// sweepOwnStore prunes agent identities and sessions past the retention
// window from the inventory.db the recorder opens while AI discovery is
// off, which no discovery sweep reaches (GAP-0289). A store discovery owns
// is left to discovery's sweep, and an inventory.db that does not exist is
// not created for it.
func (r *agentIdentityRecorder) sweepOwnStore(ctx context.Context) {
	r.storeMu.Lock()
	source, dataDir, days, own := r.storeSource, r.dataDir, r.retentionDays, r.ownStore
	r.storeMu.Unlock()
	if days == nil || (source != nil && source() != nil) {
		return
	}
	if own == nil {
		dir := ""
		if dataDir != nil {
			dir = strings.TrimSpace(dataDir())
		}
		if dir == "" {
			return
		}
		if _, err := os.Stat(filepath.Join(dir, "inventory.db")); err != nil {
			return
		}
		if own = r.store(); own == nil {
			return
		}
	}
	r.ownSweep.SweepIfDue(ctx, own, days())
}

func (r *agentIdentityRecorder) pendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending) + len(r.exclusions) + len(r.subagents)
}

// agentIdentityRow is one row of GET /api/v1/agents/identities.
type agentIdentityRow struct {
	inventory.AgentIdentityRecord
	InstallHint string `json:"install_hint,omitempty"`
	// Retired marks the identity of an account that no longer holds its
	// uid or SID: the account was renamed, or removed and the uid handed to
	// another account, which has agent identities of its own (GAP-0947),
	// or removed and its uid or SID left to no account on a managed host
	// (GAP-1222). The row keeps the name it was recorded with.
	Retired bool `json:"retired,omitempty"`
}

// agentIdentitiesPageLimit is the default and largest page of GET
// /api/v1/agents/identities.
const agentIdentitiesPageLimit = 1000

// handleAgentIdentities serves GET
// /api/v1/agents/identities?user=&connector=&limit=&cursor=: the stored agent
// identities, most recently seen first, a page at a time. It writes the ones
// buffered since the last flush first, so a new agent shows at once and the
// store, which knows which sessions it has counted, counts each once; rows
// that could not be written are merged in. total counts every matching row;
// next_cursor is the cursor of the next page, empty on the last one.
func (a *APIServer) handleAgentIdentities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ManagedEnterpriseActive() {
		a.writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "identities": []agentIdentityRow{}})
		return
	}
	q := r.URL.Query()
	limit := agentIdentitiesPageLimit
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = min(n, agentIdentitiesPageLimit)
	}
	offset := 0
	if raw := strings.TrimSpace(q.Get("cursor")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cursor"})
			return
		}
		// Past every row anyway; the bound keeps offset+limit from overflowing.
		offset = min(n, 1<<30)
	}
	user := strings.TrimSpace(q.Get("user"))
	ids := adminViewAccountIDs(user)
	incarnation, holderChanged := adminViewAccountProvenance(ids)
	filter := inventory.AgentIdentityFilter{
		User:            user,
		UserIDs:         ids,
		UserDomains:     adminViewAccountDomains(ids),
		UserIncarnation: incarnation,
		HolderChanged:   holderChanged,
		RemovedAccount:  adminViewRemovedAccount(user),
		Connector:       strings.ToLower(strings.TrimSpace(q.Get("connector"))),
	}
	// Write the buffered rows first, so one count of sessions serves the
	// listing. A failed write leaves them buffered and merged below.
	if store := sharedAgentIdentities.store(); store != nil {
		if err := sharedAgentIdentities.flush(r.Context(), store); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] agent identity flush failed: %v\n", err)
		}
	}
	// Keep a successful ticker flush from moving the buffered sightings into
	// the store between this snapshot and the reconciliation below.
	sharedAgentIdentities.flushMu.Lock()
	pending, hints, bufferedSubagents := sharedAgentIdentities.snapshot()
	var stored []inventory.AgentIdentityRecord
	start, total, persisted := 0, 0, false
	if store := sharedAgentIdentities.store(); store != nil {
		var err error
		var overlays map[string]inventory.AgentIdentitySubagentOverlay
		if overlays, err = store.ReconcileAgentIdentitySubagents(r.Context(), bufferedSubagents); err != nil {
			sharedAgentIdentities.flushMu.Unlock()
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "agent identities unavailable"})
			return
		}
		for id, overlay := range overlays {
			if rec, ok := pending[id]; ok {
				rec.SubagentsSeen = overlay.NewCount
				rec.LastSubagentID = overlay.LastSubagentID
				pending[id] = rec
			}
		}
		if stored, start, total, err = storedAgentIdentityWindow(r.Context(), store, filter, offset, limit, pending); err != nil {
			sharedAgentIdentities.flushMu.Unlock()
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "agent identities unavailable"})
			return
		}
		persisted = true
	} else {
		for _, rec := range pending {
			if agentIdentityMatches(rec, filter) {
				total++
			}
		}
	}
	// rows begins at merged row start.
	rows := mergeAgentIdentityRows(stored, pending, hints, filter)
	sharedAgentIdentities.flushMu.Unlock()
	from := offset - start
	page := rows[min(from, len(rows)):min(from+limit, len(rows))]
	next := ""
	if offset+limit < total {
		next = strconv.Itoa(offset + limit)
	}
	nameAgentIdentityRows(page)
	body := map[string]any{
		"enabled": true, "persisted": persisted, "identities": page, "total": total, "next_cursor": next,
	}
	if reason, _ := sharedAgentIdentities.persistFailure(); reason != "" {
		body["persisted"], body["persist_error"] = false, reason
	}
	a.writeJSON(w, http.StatusOK, body)
}

// storedAgentIdentityWindow reads the stored rows that merged rows offset
// to offset+limit come from, the merged row the first of them is, and how
// many rows match after the merge. With nothing buffered the store pages.
// A buffered sighting only moves an identity up, so otherwise those are the
// first offset+limit stored rows plus the stored rows of the buffered
// identities further down.
func storedAgentIdentityWindow(
	ctx context.Context,
	store *inventory.InventoryStore,
	filter inventory.AgentIdentityFilter,
	offset, limit int,
	pending map[string]inventory.AgentIdentityRecord,
) ([]inventory.AgentIdentityRecord, int, int, error) {
	buffered := false
	for _, rec := range pending {
		buffered = buffered || agentIdentityMatches(rec, filter)
	}
	window := filter
	if !buffered {
		window.Offset, window.Limit = offset, limit
		stored, total, err := store.ListAgentIdentities(ctx, window)
		return stored, offset, total, err
	}
	window.Limit = offset + limit
	stored, total, err := store.ListAgentIdentities(ctx, window)
	if err != nil {
		return nil, 0, 0, err
	}
	inWindow := make(map[string]bool, len(stored))
	for _, rec := range stored {
		inWindow[rec.AgentID] = true
	}
	var below []string
	for id, rec := range pending {
		if !inWindow[id] && agentIdentityMatches(rec, filter) {
			below = append(below, id)
		}
	}
	if len(below) == 0 {
		return stored, 0, total, nil
	}
	further, _, err := store.ListAgentIdentities(ctx, inventory.AgentIdentityFilter{AgentIDs: below})
	if err != nil {
		return nil, 0, 0, err
	}
	// A buffered identity adds to the total unless its stored row already
	// matched.
	total += len(below)
	for _, rec := range further {
		if agentIdentityMatches(rec, filter) {
			total--
		}
	}
	return append(stored, further...), 0, total, nil
}

// mergeAgentIdentityRows overlays the rows still buffered on the stored ones
// (all of them when there is no store, the unwritten ones after a failed
// flush), most recently seen first.
func mergeAgentIdentityRows(
	stored []inventory.AgentIdentityRecord,
	pending map[string]inventory.AgentIdentityRecord,
	hints map[string]string,
	filter inventory.AgentIdentityFilter,
) []agentIdentityRow {
	byID := make(map[string]*inventory.AgentIdentityRecord, len(stored)+len(pending))
	order := make([]string, 0, len(stored)+len(pending))
	for i := range stored {
		rec := stored[i]
		byID[rec.AgentID] = &rec
		order = append(order, rec.AgentID)
	}
	for id, buffered := range pending {
		if !agentIdentityMatches(buffered, filter) {
			continue
		}
		rec, ok := byID[id]
		if !ok {
			copied := buffered
			byID[id] = &copied
			order = append(order, id)
			continue
		}
		rec.SessionsSeen += buffered.SessionsSeen
		if buffered.LastSeen.After(rec.LastSeen) {
			rec.LastSeen = buffered.LastSeen
			if buffered.LastSessionID != "" {
				rec.LastSessionID = buffered.LastSessionID
			}
		}
		if buffered.FirstSeen.Before(rec.FirstSeen) {
			rec.FirstSeen = buffered.FirstSeen
		}
		if buffered.UserName != "" {
			rec.UserName = buffered.UserName
		}
		if buffered.UserDomain != "" {
			rec.UserDomain = buffered.UserDomain
		}
		if buffered.UserIncarnation != "" {
			rec.UserIncarnation = buffered.UserIncarnation
		}
		rec.UPN = buffered.UPN
		rec.UPNUnavailable = buffered.UPNUnavailable
		// With a store, buffered.SubagentsSeen contains only instance IDs
		// absent from it and LastSubagentID was ordered against its keys.
		rec.SubagentsSeen += buffered.SubagentsSeen
		if buffered.LastSubagentID != "" {
			rec.LastSubagentID = buffered.LastSubagentID
		}
	}
	rows := make([]agentIdentityRow, 0, len(order))
	for _, id := range order {
		rows = append(rows, agentIdentityRow{AgentIdentityRecord: *byID[id], InstallHint: hints[id]})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if !rows[i].LastSeen.Equal(rows[j].LastSeen) {
			return rows[i].LastSeen.After(rows[j].LastSeen)
		}
		return rows[i].AgentID < rows[j].AgentID
	})
	return rows
}

// nameAgentIdentityRows names each row's account as the host names its uid
// or SID now, the way a new hook call would record it, so a row an older
// build stored with another spelling (a bare SSSD name, DOMAIN\user) reads
// like the rest (GAP-0103). A row whose account no longer resolves keeps its
// name, and is retired when the account was removed (GAP-1222); so does a row
// of an account whose uid another account holds now, which is retired instead
// of being listed under that account (GAP-0947), also when that account has
// the same bare name in another domain (agentIdentityRecordedInAnotherDomain).
func nameAgentIdentityRows(rows []agentIdentityRow) {
	name := hostAccountNamer()
	for i := range rows {
		holder := name(rows[i].UserID)
		switch {
		case holder == "":
			rows[i].Retired = agentIdentityAccountRemoved(rows[i].UserID)
		case agentIdentityHeldByAnother(rows[i].AgentIdentityRecord, holder),
			agentIdentityRecordedInAnotherDomain(rows[i].AgentIdentityRecord):
			rows[i].Retired = true
		default:
			rows[i].UserName = holder
		}
	}
}

// agentIdentityAccountRemoved reports whether the account of id, a uid or
// SID no account holds now, was removed: the guardian of the managed host
// keeps no identity record for it. The guardian drops an account's record
// once the account has left the enrollment, a directory account's only after
// a pass in which the directory answered (GAP-1113, GAP-1103), and keeps the
// records of enrolled accounts while the directory is away, so an outage
// retires no one. A gateway without a guardian retires none: a per-user
// gateway lists its own account.
func agentIdentityAccountRemoved(id string) bool {
	dir := currentIdentitySpoolDir()
	if dir == "" || useridentity.KindForID(id) == "" {
		return false
	}
	_, err := enterprisehooks.ReadIdentitySpoolRecord(dir, id, validateManagedGuardianAuthorization)
	return errors.Is(err, os.ErrNotExist)
}

// agentIdentityHeldByAnother reports whether rec was derived for another
// account than holder, the account that holds its uid now: holder's account
// (its name and incarnation) does not derive its ID, and the name it was
// recorded with is another account's or missing, or the ID is the one the
// first account the gateway saw hold the uid derived, while another account
// of the same name holds it now. A SID is never handed on.
func agentIdentityHeldByAnother(rec inventory.AgentIdentityRecord, holder string) bool {
	if agentidentity.IsSID(agentidentity.NormalizeUserID(rec.UserID)) {
		return false
	}
	inputs := agentidentity.Inputs{MachineHash: rec.MachineHash, UserID: rec.UserID, Account: holder, Connector: rec.Connector,
		InstallFP: rec.InstallFP, Incarnation: agentIdentityIncarnation(rec.UserID)}
	if agentidentity.AgentID(inputs) == rec.AgentID {
		return false
	}
	if inputs.Incarnation != "" {
		inputs.Incarnation = ""
		if agentidentity.AgentID(inputs) == rec.AgentID {
			return true
		}
	}
	return rec.UserName == "" || agentidentity.UIDReassigned(rec.UserID, rec.UserName, holder)
}

// agentIdentityRecordedInAnotherDomain reports whether rec was recorded for
// another account than the one that holds its uid now: one of another
// account token, or, where a side names none, of other domains than the
// account whose facts the gateway holds for the uid. One bare name in two
// domains derives one agent ID, so the row CORP\alice's agent left read as
// OTHER\alice's once OTHER\alice held the uid (review of GAP-1263). Domains
// alone may overlap (UPNs under one suffix), so the token decides where both
// sides name one. A side that names neither proves nothing.
func agentIdentityRecordedInAnotherDomain(rec inventory.AgentIdentityRecord) bool {
	if recorded := strings.TrimSpace(rec.UserIncarnation); recorded != "" {
		if current := agentIdentityAccountToken(rec.UserID); current != "" {
			return current != recorded
		}
	}
	recorded := strings.Fields(rec.UserDomain)
	current := strings.Fields(agentIdentityAccountDomains(rec.UserID))
	if len(recorded) == 0 || len(current) == 0 {
		return false
	}
	return !slices.ContainsFunc(recorded, func(domain string) bool { return slices.Contains(current, domain) })
}

// hostAccountNamer names accounts by uid or SID as the host's account
// database does (an SSSD account keeps its qualified name), looking each id
// up once. The admin views that list accounts (agent identities, IDE
// plugins) name a user the same way (GAP-0278).
func hostAccountNamer() func(id string) string {
	names := map[string]string{}
	return func(id string) string {
		if id == "" {
			return ""
		}
		name, ok := names[id]
		if !ok {
			name = sanitizeLLMEventUser(userScopedIdentityName(id))
			names[id] = name
		}
		return name
	}
}

// adminViewAccountIDs resolves the --user filter of the agent identity and
// IDE plugin views. A qualified name (DOMAIN\name, .\name, user@domain)
// names the account the OS resolves it to, as profile-explain resolves it,
// so the views select that account by its uid or SID, not every account that
// shares its bare name: the domain and the local twin of one name, or the
// SSSD account whose rows carry the bare name (GAP-0366, GAP-1080). A bare
// name, an id, or a name that resolves to no account gives none.
var adminViewAccountIDs = func(user string) []string {
	if !useridentity.QualifiedAccountName(user) {
		return nil
	}
	id, _, err := profileExplainAccount(strings.TrimSpace(user))
	if err != nil || id == "" {
		return nil
	}
	return []string{id}
}

// adminViewAccountProvenance is the account token of the account ids name
// (the uid a qualified filter resolves to) and whether another account is
// known to have held that uid (agentIdentityHolderHistory), for
// AgentIdentityFilter.UserIncarnation and HolderChanged.
func adminViewAccountProvenance(ids []string) (string, bool) {
	if len(ids) != 1 {
		return "", false
	}
	// The first inventory request after a uid handoff may precede any new
	// agent hook. Refresh the holder before reading its history; rowToken
	// alone resolves the new token without recording the handoff.
	_ = agentIdentityIncarnation(ids[0])
	current := agentIdentityVerifiedAccountToken(ids[0])
	last, changed := agentIdentityHolderHistory(ids[0])
	if useridentity.KindForID(ids[0]) == useridentity.KindPOSIXUID && (current == "" || last != current) {
		// A qualified filter cannot prove ownership of any row of an
		// unresolved uid, or of a holder change that did not persist in
		// history (for example, when its bounded cache is full).
		return "", true
	}
	return current, changed
}

// adminViewAccountDomains is the useridentity.AccountDomains of the
// accounts ids name (adminViewAccountIDs), from the facts the gateway
// cached for them.
func adminViewAccountDomains(ids []string) string {
	var domains []string
	for _, id := range ids {
		if own := agentIdentityAccountDomains(id); own != "" {
			domains = append(domains, own)
		}
	}
	return strings.Join(domains, " ")
}

// adminViewRemovedAccount is the RemovedAccount of an agent identity
// listing for user: a deleted account's rows keep its last name and its uid
// or SID, so its qualified name still lists the ones recorded with the bare
// name (GAP-1221). An id is a removed account's when no account holds it now
// and the domain user names could have held it (adminViewDomainCouldHold).
// A bare name or an id needs none.
func adminViewRemovedAccount(user string) func(id string) bool {
	if !useridentity.QualifiedAccountName(user) {
		return nil
	}
	name := hostAccountNamer()
	return func(id string) bool {
		return useridentity.KindForID(id) != "" && name(id) == "" && adminViewDomainCouldHold(user, id)
	}
}

// adminViewKnownDomain reports whether the gateway knows id, an account no
// account holds now, as an account of domain, the domain of a qualified
// --user filter: the facts its hooks cached for it name that domain (its
// DNS domain, NetBIOS domain, realm, or the suffix of its UPN or principal),
// or a domain it was otherwise seen in does (extra: the domain of the name a
// uid last resolved to, the domain the LSA names for a SID). Two deleted accounts of one bare name
// in two domains are then told apart by their own domain; one the gateway
// knows no domain for is not listed by a qualified name, only by its bare
// name or its id (GAP-1183, GAP-1263).
func adminViewKnownDomain(domain, id string, extra ...string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}
	matches := func(candidate string) bool {
		candidate = strings.TrimSpace(candidate)
		return candidate != "" && useridentity.EqualFold(candidate, domain)
	}
	for _, candidate := range extra {
		if matches(candidate) {
			return true
		}
	}
	key := strings.TrimSpace(id)
	if useridentity.KindForID(key) == useridentity.KindWindowsSID {
		key = strings.ToUpper(key)
	}
	facts, _, ok := peerDirectoryCache().peek(key)
	if !ok {
		return false
	}
	_, upnDomain := useridentity.SplitQualifiedName(facts.UPN)
	_, principalDomain := useridentity.SplitQualifiedName(facts.Principal)
	for _, candidate := range []string{facts.Domain, facts.AccountDomain, facts.Realm, upnDomain, principalDomain} {
		if matches(candidate) {
			return true
		}
	}
	return false
}

func agentIdentityMatches(rec inventory.AgentIdentityRecord, filter inventory.AgentIdentityFilter) bool {
	if filter.User != "" && !filter.Account().MatchesIn(rec.UserID, rec.UserName, rec.UserDomain, rec.UserIncarnation) {
		return false
	}
	return filter.Connector == "" || rec.Connector == filter.Connector
}
