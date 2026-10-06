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

	storeMu         sync.Mutex
	storeGeneration uint64
	storeSource     func() *inventory.InventoryStore
	dataDir         func() string
	ownStore        *inventory.InventoryStore
}

var sharedAgentIdentities = &agentIdentityRecorder{
	pending: make(map[string]*inventory.AgentIdentityRecord),
	hints:   make(map[string]string),
}

// observe records one hook of an agent identity. newSession is true when the
// hook started a session the registry had not seen; the registry is in
// memory, so the batch keeps the first session it counted for the upsert to
// recognize a session resumed after a restart.
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
	if newSession && sessionID != "" && sessionID != rec.LastSessionID {
		if rec.SessionsSeen == 0 {
			rec.FirstSessionID = sessionID
		}
		rec.SessionsSeen++
	}
	if sessionID != "" {
		rec.LastSessionID = sessionID
	}
	if facts.InstallHint != "" && (len(r.hints) < agentIdentityRecorderMaxPending || r.hints[facts.ID] != "") {
		r.hints[facts.ID] = facts.InstallHint
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
		if old.SessionsSeen > 0 {
			cur.FirstSessionID = old.FirstSessionID
		}
		cur.SessionsSeen += old.SessionsSeen
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
		return err
	}
	return nil
}

// setStoreSource wires where flushes go: source returns AI discovery's
// inventory store when it runs, and dataDir locates inventory.db for the
// store the recorder opens itself when discovery is off. The returned token
// unwires it again.
func (r *agentIdentityRecorder) setStoreSource(source func() *inventory.InventoryStore, dataDir func() string) uint64 {
	r.storeMu.Lock()
	defer r.storeMu.Unlock()
	r.storeGeneration++
	r.storeSource, r.dataDir = source, dataDir
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
	r.storeSource, r.dataDir = nil, nil
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
	store, err := inventory.NewInventoryStore(filepath.Join(dir, "inventory.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] agent identities not persisted: %v\n", err)
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
			flush(final)
			cancel()
			return
		case <-ticker.C:
			flush(ctx)
		}
	}
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

// handleAgentIdentities serves GET /api/v1/agents/identities?user=&connector=:
// the stored agent identities plus the ones buffered since the last flush,
// most recently seen first.
func (a *APIServer) handleAgentIdentities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ManagedEnterpriseActive() {
		a.writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "identities": []agentIdentityRow{}})
		return
	}
	filter := inventory.AgentIdentityFilter{
		User:      strings.TrimSpace(r.URL.Query().Get("user")),
		Connector: strings.ToLower(strings.TrimSpace(r.URL.Query().Get("connector"))),
	}
	var stored []inventory.AgentIdentityRecord
	persisted := false
	if store := sharedAgentIdentities.store(); store != nil {
		rows, err := store.ListAgentIdentities(r.Context(), filter)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "agent identities unavailable"})
			return
		}
		stored, persisted = rows, true
	}
	pending, hints := sharedAgentIdentities.snapshot()
	rows := mergeAgentIdentityRows(stored, pending, hints, filter)
	a.writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "persisted": persisted, "identities": rows})
}

// mergeAgentIdentityRows overlays the buffered rows on the stored ones, the
// way the next flush will write them.
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
		// The way the upsert counts: a buffered session that resumes the
		// stored last session is not a new one.
		rec.SessionsSeen += buffered.SessionsSeen
		if buffered.SessionsSeen > 0 && buffered.FirstSessionID != "" && buffered.FirstSessionID == rec.LastSessionID {
			rec.SessionsSeen--
		}
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

func agentIdentityMatches(rec inventory.AgentIdentityRecord, filter inventory.AgentIdentityFilter) bool {
	if user := filter.User; user != "" && !useridentity.AccountFilterMatches(user, rec.UserID, rec.UserName) {
		return false
	}
	return filter.Connector == "" || rec.Connector == filter.Connector
}
