// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// recreatedAccountFixture is a managed Linux gateway whose local account
// alice ("files", the incarnation every account of one name, uid and home
// shares) is deleted and created again under the same name, uid and home
// path with a new home directory (userdel -r; useradd -u), as T8r did on
// dc-fc-r103-rhel (TST-17151, GAP-0422). recordProof is the home proof of
// the guardian's current identity record of the uid.
type recreatedAccountFixture struct {
	t     *testing.T
	uid   int
	id    string
	home  string
	store string
	inv   *inventory.InventoryStore

	mu          sync.Mutex
	recordProof string
	now         time.Time
}

func newRecreatedAccountFixture(t *testing.T) *recreatedAccountFixture {
	t.Helper()
	agentIdentityTestSetup(t)
	f := &recreatedAccountFixture{t: t, uid: 41450, id: "41450", home: t.TempDir(),
		store: filepath.Join(t.TempDir(), "peer-homes.json"), now: time.Unix(3_100_000, 0)}
	previousHomes, previousFacts := managedHookPeerHomes, identityFactsEnabled.Load()
	previousIncarnation, previousName, previousProof := managedHookPeerAccountIncarnation, userScopedIdentityName, managedHookPeerHomeProof
	previousExplain, previousRecorder := profileExplainAccount, sharedAgentIdentities
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookPeerAccountIncarnation, userScopedIdentityName = previousHomes, previousIncarnation, previousName
		managedHookPeerHomeProof, profileExplainAccount, sharedAgentIdentities = previousProof, previousExplain, previousRecorder
		setIdentityFactsEnabled(previousFacts)
	})
	setIdentityFactsEnabled(true)
	userScopedIdentityName = func(got string) string {
		if got == f.id {
			return "alice"
		}
		return ""
	}
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "files", true }
	managedHookPeerHomeProof = func(uid int, name, incarnation string) string {
		f.mu.Lock()
		defer f.mu.Unlock()
		if uid != f.uid || name != "alice" || incarnation != "files" {
			return ""
		}
		return normalizeHomeProof(f.recordProof)
	}
	profileExplainAccount = func(name string) (string, string, error) {
		if name == "alice" || name == `.\alice` {
			return f.id, "alice", nil
		}
		return "", "", unixidentity.ErrNotFound
	}
	inv, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	f.inv = inv
	sharedAgentIdentities = &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	sharedAgentIdentities.setStoreSource(func() *inventory.InventoryStore { return inv }, nil, nil)
	f.start()
	return f
}

// start starts the gateway (again): its peer cache reads the persisted homes.
func (f *recreatedAccountFixture) start() {
	managedHookPeerHomes = &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver {
			return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{f.uid: {Name: "alice", UID: f.uid, Home: f.home}}}
		},
		now: func() time.Time {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.now
		},
	}
	managedHookPeerHomes.setStore(f.store)
}

// guardian sets the home proof of the guardian's record and lets the cached
// account and proof reads expire.
func (f *recreatedAccountFixture) guardian(proof string) {
	f.mu.Lock()
	f.recordProof = proof
	f.now = f.now.Add(managedHookPeerHomeTTL + time.Second)
	f.mu.Unlock()
}

func (f *recreatedAccountFixture) hook(session string) agentIdentityFacts {
	f.t.Helper()
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: f.uid, Name: "alice", Home: f.home})
	facts := resolveHookAgentIdentity(peer, agentHookRequest{ConnectorName: "codex"})
	if facts.ID == "" {
		f.t.Fatal("no agent identity")
	}
	sharedAgentIdentities.observe(facts, session, true)
	return facts
}

// view lists the agent identities as the administrator's view asks for
// them, by agent id.
func (f *recreatedAccountFixture) view(query url.Values) map[string]agentIdentityRow {
	f.t.Helper()
	rec := httptest.NewRecorder()
	(&APIServer{}).handleAgentIdentities(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agents/identities?"+query.Encode(), nil))
	var body struct {
		Identities []agentIdentityRow `json:"identities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
		f.t.Fatalf("identities response %d %s", rec.Code, rec.Body.String())
	}
	rows := map[string]agentIdentityRow{}
	for _, row := range body.Identities {
		rows[row.AgentID] = row
	}
	return rows
}

func viewOf(user, proof string) url.Values {
	query := url.Values{"user": {user}, "connector": {"codex"}}
	if proof != "" {
		query.Set("holder_proof", proof)
	}
	return query
}

func listedIDs(rows map[string]agentIdentityRow) []string {
	ids := make([]string, 0, len(rows))
	for id := range rows {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// GAP-0422, reopened by T8r (TST-17151): a local account is deleted and
// created again under the same name, uid and home path. The administrator's
// first inventory view of it, before any hook of the new account and before
// the guardian's next pass, lists none of the account before it's rows, by
// its bare or its qualified name; a deleted namesake's row of another uid
// stays listed by the bare name. Once the guardian's record proves the new
// home, the new account's hooks derive agent identities of their own, which
// survive a restart and an outage of the record; the old rows are retired.
func TestRecreatedLocalAccountDoesNotListThePreviousHoldersRows(t *testing.T) {
	f := newRecreatedAccountFixture(t)
	const oldHome, newHome = "home:2049:1000:111", "home:2049:2000:222"
	f.guardian(oldHome)
	oldAgent := f.hook("s-old-1")
	// A row written before 1.0.4 names no token; a deleted namesake of
	// another uid left one too.
	if err := f.inv.UpsertAgentIdentities(context.Background(), []inventory.AgentIdentityRecord{
		{AgentID: "agt-00000000000a0001", UserID: f.id, UserName: "alice", Connector: "codex", MachineHash: oldAgent.MachineHash,
			FirstSeen: f.now.Add(-time.Hour), LastSeen: f.now.Add(-time.Hour)},
		{AgentID: "agt-00000000000a0002", UserID: "41499", UserName: "alice", Connector: "codex", MachineHash: oldAgent.MachineHash,
			FirstSeen: f.now.Add(-2 * time.Hour), LastSeen: f.now.Add(-2 * time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	oldRows := []string{oldAgent.ID, "agt-00000000000a0001"}
	namesake := "agt-00000000000a0002"
	sameAccount := strconv.Itoa(f.uid) + ":" + oldHome
	remounted := strconv.Itoa(f.uid) + ":home:77:1000:111"
	for _, proof := range []string{"", sameAccount, remounted, "41451:" + newHome} {
		if rows := f.view(viewOf("alice", proof)); len(rows) != 3 {
			t.Fatalf("alice's own view (holder_proof %q) lists %v; want her two rows and the namesake's", proof, listedIDs(rows))
		}
	}

	// userdel -r alice; useradd -u 41450 alice: the same name, uid and home
	// path, another home directory. The guardian's record still names the
	// home before.
	f.guardian(oldHome)
	recreated := strconv.Itoa(f.uid) + ":" + newHome
	for _, user := range []string{"alice", `.\alice`} {
		rows := f.view(viewOf(user, recreated))
		for _, id := range oldRows {
			if _, listed := rows[id]; listed {
				t.Fatalf("first view of the new account %q lists the previous holder's row %s (%v)", user, id, listedIDs(rows))
			}
		}
		if _, listed := rows[namesake]; listed != (user == "alice") {
			t.Fatalf("first view %q: the deleted namesake's row of another uid listed=%v; want it only under the bare name", user, listed)
		}
	}

	// The guardian's next pass proves the new home.
	f.guardian(newHome)
	newAgent := f.hook("s-new-1")
	if newAgent.ID == oldAgent.ID {
		t.Fatalf("the new account derived the previous holder's agent identity %s", oldAgent.ID)
	}
	for _, user := range []string{"alice", `.\alice`} {
		rows := f.view(viewOf(user, ""))
		if _, listed := rows[newAgent.ID]; !listed {
			t.Fatalf("view %q does not list the new account's agent %s (%v)", user, newAgent.ID, listedIDs(rows))
		}
		for _, id := range oldRows {
			if _, listed := rows[id]; listed {
				t.Fatalf("view %q lists the previous holder's row %s (%v)", user, id, listedIDs(rows))
			}
		}
	}
	all := f.view(url.Values{})
	if !all[oldAgent.ID].Retired {
		t.Fatalf("unfiltered view: previous holder's agent %s not retired (%+v)", oldAgent.ID, all[oldAgent.ID])
	}
	if all[newAgent.ID].Retired {
		t.Fatalf("unfiltered view retired the new account's agent %s", newAgent.ID)
	}

	// A restart, then a pass that cannot read the record: the new account
	// keeps its own agent identity.
	f.start()
	if got := f.hook("s-new-2").ID; got != newAgent.ID {
		t.Fatalf("after a restart the new account's agent identity is %s, want %s", got, newAgent.ID)
	}
	f.guardian("")
	if got := f.hook("s-new-3").ID; got != newAgent.ID {
		t.Fatalf("without a readable record the new account's agent identity is %s, want %s", got, newAgent.ID)
	}
	f.guardian(newHome)
	if got := f.hook("s-new-4").ID; got != newAgent.ID {
		t.Fatalf("with the record back the new account's agent identity is %s, want %s", got, newAgent.ID)
	}
}

// The first proof a gateway reads for a uid keeps the agent identities of
// before: an upgraded gateway, whose account had none recorded, keeps its
// IDs when the guardian's record first gives a proof, and so does a home
// remounted under another device number.
func TestFirstHomeProofKeepsTheAgentIdentityOfBefore(t *testing.T) {
	f := newRecreatedAccountFixture(t)
	f.guardian("")
	before := f.hook("s-1")
	for _, proof := range []string{"home:2049:1000:111", "home:77:1000:111", "home:77:1000"} {
		f.guardian(proof)
		if got := f.hook("s-" + proof).ID; got != before.ID {
			t.Fatalf("home proof %q moved the agent identity to %s, want %s", proof, got, before.ID)
		}
	}
	if _, changed := agentIdentityHolderHistory(f.id); changed {
		t.Fatal("the first proof recorded a holder change")
	}
}

// GAP-0422 (T8r): once the guardian's record proves the recreated
// account's new home, its first hook derives an agent identity of its own
// instead of updating the previous holder's row (which T8r saw at
// sessions_seen 2 after the new account's refused turn).
func TestRecreatedLocalAccountDerivesItsOwnAgentIdentity(t *testing.T) {
	f := newRecreatedAccountFixture(t)
	f.guardian("home:2049:1000:111")
	before := f.hook("s-old")
	f.guardian("home:2049:2000:222")
	after := f.hook("s-new")
	if after.ID == before.ID {
		t.Fatalf("the recreated account derived the previous holder's agent identity %s", before.ID)
	}
	if last, changed := agentIdentityHolderHistory(f.id); !changed || last == "files" {
		t.Fatalf("holder history = %q, changed %v; want the new account's token recorded as a change", last, changed)
	}
}
