// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// lockedPeerResolver is a fakePeerHomeResolver a test changes while
// requests run.
type lockedPeerResolver struct {
	unixidentity.Resolver
	mu       sync.Mutex
	accounts map[int]unixidentity.Account
}

func (r *lockedPeerResolver) LookupUID(uid int) (unixidentity.Account, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	account, ok := r.accounts[uid]
	if !ok {
		return unixidentity.Account{}, unixidentity.ErrNotFound
	}
	return account, nil
}

func (r *lockedPeerResolver) set(uid int, account unixidentity.Account) {
	r.mu.Lock()
	r.accounts[uid] = account
	r.mu.Unlock()
}

// Review of GAP-0551 (loop 3): a directory hands a uid from CORP's alice to
// OTHER's alice (same name and home) or to another account without changing
// /etc/passwd. The account cache served the former account and its
// incarnation for the whole 5 minute TTL, so CORP's cached groups and
// profile went to OTHER. The account is rechecked once a second is past;
// the facts of the former account are dropped before they are served. A
// directory that cannot answer the recheck keeps the cached facts (outage),
// and is asked again only after the retry interval; concurrent requests
// share one recheck.
func TestManagedHookPeerDirectoryFollowsAHandoffInsideTheAccountTTL(t *testing.T) {
	const uid = 41301
	const corp, other = "sid:S-1-5-21-1-1-1-1301", "sid:S-1-5-21-2-2-2-1301"
	previousFacts, previousIncarnation := identityFactsEnabled.Load(), managedHookPeerAccountIncarnation
	setIdentityFactsEnabled(true)
	t.Cleanup(func() {
		setIdentityFactsEnabled(previousFacts)
		managedHookPeerAccountIncarnation = previousIncarnation
	})
	var mu sync.Mutex
	incarnation, known := corp, true
	var incarnationCalls atomic.Int32
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) {
		incarnationCalls.Add(1)
		mu.Lock()
		defer mu.Unlock()
		return incarnation, known
	}
	holds := func(token string, ok bool) {
		mu.Lock()
		incarnation, known = token, ok
		mu.Unlock()
	}
	resolver := &lockedPeerResolver{accounts: map[int]unixidentity.Account{uid: {Name: "alice", UID: uid, Home: "/home/alice"}}}
	var clock sync.Mutex
	now := time.Unix(4_000_000, 0)
	advance := func(d time.Duration) {
		clock.Lock()
		now = now.Add(d)
		clock.Unlock()
	}
	cache := &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver { return resolver },
		now: func() time.Time {
			clock.Lock()
			defer clock.Unlock()
			return now
		},
	}
	var lookups atomic.Int32
	var group atomic.Value
	group.Store("corp-strict")
	cache.directoriesOnce.Do(func() {
		cache.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
			lookups.Add(1)
			return useridentity.DirectoryFacts{Groups: []string{group.Load().(string)}, ResolvedAt: time.Now()}, nil
		})
	})
	groups := func() []string {
		t.Helper()
		facts, ok := cache.directory(uid, true)
		if !ok {
			t.Fatal("no hook facts")
		}
		return facts.Groups
	}
	if got := groups(); !slices.Equal(got, []string{"corp-strict"}) {
		t.Fatalf("first facts = %v", got)
	}

	// OTHER's alice takes the uid over 2 seconds later, well inside the TTL.
	group.Store("other-open")
	holds(other, true)
	advance(2 * time.Second)
	if got := groups(); !slices.Equal(got, []string{"other-open"}) || lookups.Load() != 2 {
		t.Fatalf("OTHER's alice inside the account TTL got %v after %d lookups; want its own facts", got, lookups.Load())
	}

	// Another account name for the uid inside the TTL.
	group.Store("bob-open")
	resolver.set(uid, unixidentity.Account{Name: "bob", UID: uid, Home: "/home/alice"})
	advance(2 * time.Second)
	if got := groups(); !slices.Equal(got, []string{"bob-open"}) || lookups.Load() != 3 {
		t.Fatalf("bob inside the account TTL got %v after %d lookups; want his own facts", got, lookups.Load())
	}

	// A directory that does not answer the recheck keeps the facts, and is
	// not asked again before the retry interval.
	holds("", false)
	advance(2 * time.Second)
	calls := incarnationCalls.Load()
	if got := groups(); !slices.Equal(got, []string{"bob-open"}) || lookups.Load() != 3 {
		t.Fatalf("during an outage the facts were %v after %d lookups; want the cached ones", got, lookups.Load())
	}
	if incarnationCalls.Load() != calls+1 {
		t.Fatalf("the recheck asked the directory %d times; want once", incarnationCalls.Load()-calls)
	}
	advance(2 * time.Second)
	groups()
	if incarnationCalls.Load() != calls+1 {
		t.Fatal("the directory that did not answer was asked again before the retry interval")
	}

	// Concurrent requests share one recheck.
	holds(other, true)
	advance(managedHookPeerLookupRetry)
	calls = incarnationCalls.Load()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache.directory(uid, true)
		}()
	}
	wg.Wait()
	if got := incarnationCalls.Load() - calls; got != 1 {
		t.Fatalf("8 concurrent requests made %d rechecks; want 1", got)
	}

	// Inside the second, the answer is served as it is.
	calls = incarnationCalls.Load()
	groups()
	if incarnationCalls.Load() != calls {
		t.Fatal("a request inside the recheck interval asked the directory")
	}
}

// Review of GAP-0947 (loop 3): after an upgrade from a build that kept no
// account token, the account holding a uid when 1.0.4 first sees it may not
// be the account the older build saw: OTHER's alice took CORP's uid, name
// and home in between, became the first incarnation, and got CORP's agent
// ID, its match.agents profile and its ledger row. It now keeps the IDs of
// before only when its token shows continuity: a token this build cannot
// tell accounts apart by either (files), or a SID SSSD's default id mapping
// derives the uid from. Otherwise it derives its own ID, the old rows are
// retired, a qualified filter does not list them, and the ledger keeps them
// apart. The state survives a restart.
func TestAgentIdentityAfterAnUpgradeNeedsContinuityForTheIDsOfBefore(t *testing.T) {
	agentIdentityTestSetup(t)
	previousHomes, previousFacts := managedHookPeerHomes, identityFactsEnabled.Load()
	previousIncarnation, previousName := managedHookPeerAccountIncarnation, userScopedIdentityName
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookPeerAccountIncarnation, userScopedIdentityName = previousHomes, previousIncarnation, previousName
		setIdentityFactsEnabled(previousFacts)
	})
	setIdentityFactsEnabled(true)
	userScopedIdentityName = func(string) string { return "alice" }
	var mu sync.Mutex
	tokens := map[int]string{}
	managedHookPeerAccountIncarnation = func(account unixidentity.Account) (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		token, ok := tokens[account.UID]
		return token, ok
	}
	home := t.TempDir()
	store := filepath.Join(t.TempDir(), "peer-homes.json")
	start := func(uids ...int) {
		accounts := map[int]unixidentity.Account{}
		for _, uid := range uids {
			accounts[uid] = unixidentity.Account{Name: "alice", UID: uid, Home: home}
		}
		managedHookPeerHomes = &managedHookPeerHomeCache{
			newResolver: func() unixidentity.Resolver { return &fakePeerHomeResolver{accounts: accounts} },
			now:         time.Now,
		}
		managedHookPeerHomes.setStore(store)
	}
	hook := func(uid int) agentIdentityFacts {
		t.Helper()
		peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: uid, Name: "alice", Home: home})
		facts := resolveHookAgentIdentity(peer, agentHookRequest{ConnectorName: "codex"})
		if facts.ID == "" {
			t.Fatal("no agent identity")
		}
		return facts
	}
	before := func(facts agentIdentityFacts, uid int) string {
		return agentidentity.AgentID(agentidentity.Inputs{MachineHash: facts.MachineHash, UserID: strconv.Itoa(uid), Account: "alice",
			Connector: "codex", InstallFP: facts.InstallFP})
	}
	const (
		rfc2307UID = 41501     // an RFC 2307 uidNumber: no SID maps to it
		mappedUID  = 297801105 // SSSD's default id mapping of RID 1105 (slice 1488 of S-1-5-21-7-7-7)
		moduloUID  = 201105    // an RFC 2307 uid that matches RID 1105 modulo the range size only
		localUID   = 41502
		laterUID   = 41503
	)
	const other = "sid:S-1-5-21-2-2-2-3301"
	// The homes file a 1.0.3 gateway wrote: no format entry, no tokens.
	legacy := map[string]map[string]string{}
	for _, uid := range []int{rfc2307UID, mappedUID, moduloUID, localUID, laterUID} {
		legacy[strconv.Itoa(uid)] = map[string]string{"home": home, "name": "alice"}
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store, data, 0o600); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	tokens[rfc2307UID], tokens[mappedUID], tokens[localUID] = other, "sid:S-1-5-21-7-7-7-1105", "files"
	tokens[moduloUID] = "sid:S-1-5-21-2-2-2-1105"
	mu.Unlock()
	start(rfc2307UID, mappedUID, moduloUID, localUID, laterUID)

	otherAgent := hook(rfc2307UID)
	legacyID := before(otherAgent, rfc2307UID)
	if otherAgent.ID == legacyID {
		t.Fatalf("OTHER's alice, first seen after the upgrade, derived the agent ID of before %s", legacyID)
	}
	if got := hook(mappedUID); got.ID != before(got, mappedUID) {
		t.Fatalf("an id-mapped SSSD account derived %s; want the ID it had before", got.ID)
	}
	// Review of GAP-0947 (loop 4): 201105 - 200000 is RID 1105, but the
	// uid is not that of its domain's slice: ldap_id_mapping is off.
	if got := hook(moduloUID); got.ID == before(got, moduloUID) {
		t.Fatal("an RFC 2307 uid that matches its RID modulo the range size kept the agent ID of before")
	}
	if got := hook(localUID); got.ID != before(got, localUID) {
		t.Fatalf("a local account derived %s; want the ID it had before", got.ID)
	}
	if otherAgent.UserIncarnation != other {
		t.Fatalf("the sighting records token %q; want %q", otherAgent.UserIncarnation, other)
	}

	// A restart keeps the distinct ID and the legacy mark of a uid no token
	// was adopted for yet.
	start(rfc2307UID, mappedUID, moduloUID, localUID, laterUID)
	if got := hook(rfc2307UID).ID; got != otherAgent.ID {
		t.Fatalf("after a restart OTHER's alice derived %s, want %s", got, otherAgent.ID)
	}
	mu.Lock()
	tokens[laterUID] = "sid:S-1-5-21-3-3-3-3302"
	mu.Unlock()
	if got := hook(laterUID); got.ID == before(got, laterUID) {
		t.Fatal("a legacy uid first seen after a restart derived the agent ID of before")
	}

	// The ledger: the row of before keeps its own history, OTHER's starts
	// with its own sighting.
	st, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	id := strconv.Itoa(rfc2307UID)
	ctx := context.Background()
	corpRow := inventory.AgentIdentityRecord{AgentID: legacyID, UserID: id, UserName: "alice", Connector: "codex",
		InstallFP: otherAgent.InstallFP, MachineHash: otherAgent.MachineHash, FirstSeen: t0, LastSeen: t0, SessionsSeen: 3}
	otherRow := inventory.AgentIdentityRecord{AgentID: otherAgent.ID, UserID: id, UserName: "alice", UserIncarnation: other,
		Connector: "codex", InstallFP: otherAgent.InstallFP, MachineHash: otherAgent.MachineHash,
		FirstSeen: t0.Add(48 * time.Hour), LastSeen: t0.Add(48 * time.Hour), SessionsSeen: 1}
	if err := st.UpsertAgentIdentities(ctx, []inventory.AgentIdentityRecord{corpRow}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAgentIdentities(ctx, []inventory.AgentIdentityRecord{otherRow}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.ListAgentIdentities(ctx, inventory.AgentIdentityFilter{})
	if err != nil || len(rows) != 2 {
		t.Fatalf("ledger rows = %+v, %v; want the row of before and OTHER's", rows, err)
	}
	listed := make([]agentIdentityRow, 0, len(rows))
	for _, row := range rows {
		want := map[string]time.Time{legacyID: t0, otherAgent.ID: t0.Add(48 * time.Hour)}[row.AgentID]
		if !row.FirstSeen.Equal(want) {
			t.Fatalf("row %s first seen %s; want %s", row.AgentID, row.FirstSeen, want)
		}
		listed = append(listed, agentIdentityRow{AgentIdentityRecord: row})
	}
	nameAgentIdentityRows(listed)
	for _, row := range listed {
		if row.Retired != (row.AgentID == legacyID) {
			t.Fatalf("row %s retired %v; want only the row of before retired", row.AgentID, row.Retired)
		}
	}
	incarnation, changed := adminViewAccountProvenance([]string{id}, "")
	filter := inventory.AgentIdentityFilter{User: `OTHER\alice`, UserIDs: []string{id}, UserIncarnation: incarnation, HolderChanged: changed}
	var selected []string
	for _, row := range rows {
		if agentIdentityMatches(row, filter) {
			selected = append(selected, row.AgentID)
		}
	}
	if !slices.Equal(selected, []string{otherAgent.ID}) {
		t.Fatalf(`OTHER\alice selects %v; want only OTHER's row, not the row of before`, selected)
	}
	written, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]managedHookPeerLast
	if err := json.Unmarshal(written, &persisted); err != nil || persisted[managedHookPeerHomesFormatKey].Format != 1 ||
		persisted[id].BaseIncarnation != agentIncarnationUnproven {
		t.Fatalf("persisted homes = %s, %v; want the format entry and the unproven base", written, err)
	}
}

// Review of GAP-1263 (loop 3): the recorded rows carry the account token,
// and a token that differs retires a row whose domains overlap the holder's
// (two accounts with UPNs under one suffix).
func TestAgentIdentityRowsOfAnotherTokenAreRetiredDespiteSharedDomains(t *testing.T) {
	const id = "41601"
	previousToken, previousName := agentIdentityAccountToken, userScopedIdentityName
	t.Cleanup(func() { agentIdentityAccountToken, userScopedIdentityName = previousToken, previousName })
	agentIdentityAccountToken = func(string) string { return "sid:S-1-5-21-2-2-2-1601" }
	userScopedIdentityName = func(string) string { return "alice" }
	row := func(agent, domains, token string) agentIdentityRow {
		return agentIdentityRow{AgentIdentityRecord: inventory.AgentIdentityRecord{AgentID: agent, UserID: id, UserName: "alice",
			UserDomain: domains, UserIncarnation: token, Connector: "codex", LastSeen: time.Now()}}
	}
	rows := []agentIdentityRow{
		row("agt-corp", "login.example other.example", "sid:S-1-5-21-1-1-1-1601"),
		row("agt-other", "login.example other.example", "sid:S-1-5-21-2-2-2-1601"),
	}
	previousIncarnation := agentIdentityIncarnation
	t.Cleanup(func() { agentIdentityIncarnation = previousIncarnation })
	agentIdentityIncarnation = func(string) string { return "" }
	nameAgentIdentityRows(rows)
	if !rows[0].Retired || rows[1].Retired {
		t.Fatalf("retired = %v %v; want CORP's row retired by its token", rows[0].Retired, rows[1].Retired)
	}
}
