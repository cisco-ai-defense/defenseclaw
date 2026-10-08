// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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

func subSessionKey(agentID, sessionID string) string { return agentID + "\x00" + sessionID }

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
			r.subSessionOrder = r.subSessionOrder[1:]
		}
		r.subSessions[key] = struct{}{}
		r.subSessionOrder = append(r.subSessionOrder, key)
	}
	if rec, ok := r.pending[agentID]; ok {
		rec.ForgetSession(sessionID)
	}
}

// take removes and returns the buffered batch.
func (r *agentIdentityRecorder) take() []inventory.AgentIdentityRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) == 0 {
		return nil
	}
	batch := make([]inventory.AgentIdentityRecord, 0, len(r.pending))
	for _, rec := range r.pending {
		batch = append(batch, *rec)
	}
	r.pending = make(map[string]*inventory.AgentIdentityRecord)
	return batch
}

// restore puts back a batch whose write failed, merging it with whatever the
// hook path buffered since.
func (r *agentIdentityRecorder) restore(batch []inventory.AgentIdentityRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range batch {
		old := batch[i]
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

// snapshot copies the buffered rows and hints for the API.
func (r *agentIdentityRecorder) snapshot() (map[string]inventory.AgentIdentityRecord, map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pending := make(map[string]inventory.AgentIdentityRecord, len(r.pending))
	for id, rec := range r.pending {
		pending[id] = *rec
	}
	hints := make(map[string]string, len(r.hints))
	for id, hint := range r.hints {
		hints[id] = hint
	}
	return pending, hints
}

// flush writes the buffered batch to store.
func (r *agentIdentityRecorder) flush(ctx context.Context, store *inventory.InventoryStore) error {
	if store == nil {
		return nil
	}
	batch := r.take()
	if len(batch) == 0 {
		return nil
	}
	if err := store.UpsertAgentIdentities(ctx, batch); err != nil {
		r.restore(batch)
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
	return len(r.pending)
}

// agentIdentityRow is one row of GET /api/v1/agents/identities.
type agentIdentityRow struct {
	inventory.AgentIdentityRecord
	InstallHint string `json:"install_hint,omitempty"`
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
	filter := inventory.AgentIdentityFilter{
		User:      strings.TrimSpace(q.Get("user")),
		Connector: strings.ToLower(strings.TrimSpace(q.Get("connector"))),
	}
	// Write the buffered rows first, so one count of sessions serves the
	// listing. A failed write leaves them buffered and merged below.
	if store := sharedAgentIdentities.store(); store != nil {
		if err := sharedAgentIdentities.flush(r.Context(), store); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] agent identity flush failed: %v\n", err)
		}
	}
	pending, hints := sharedAgentIdentities.snapshot()
	var stored []inventory.AgentIdentityRecord
	start, total, persisted := 0, 0, false
	if store := sharedAgentIdentities.store(); store != nil {
		var err error
		if stored, start, total, err = storedAgentIdentityWindow(r.Context(), store, filter, offset, limit, pending); err != nil {
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
// name.
func nameAgentIdentityRows(rows []agentIdentityRow) {
	name := hostAccountNamer()
	for i := range rows {
		if n := name(rows[i].UserID); n != "" {
			rows[i].UserName = n
		}
	}
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

func agentIdentityMatches(rec inventory.AgentIdentityRecord, filter inventory.AgentIdentityFilter) bool {
	if user := filter.User; user != "" && !useridentity.AccountFilterMatches(user, rec.UserID, rec.UserName) {
		return false
	}
	return filter.Connector == "" || rec.Connector == filter.Connector
}
