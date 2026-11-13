// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/accountjoin"
	"github.com/defenseclaw/defenseclaw/internal/budgetstore"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// routingAdminFleet is the device side of the opt-in fleet budget store
// (routing.admin.budget_store): the HTTPS client and the key mapping that
// keeps names on the device. A user is named in the fleet by a keyed hash of
// the account join canonical identity (the verified domain SID, else the
// verified UPN) with the store's tenant secret; group and named-user budget
// subjects by a keyed hash of the configured entry. Nil while the store is
// not configured: budgets then count on this device only.
var routingAdminFleet = &fleetState{}

type fleetState struct {
	mu      sync.Mutex
	url     string // the configured store, to rebuild only on change
	client  *budgetstore.Client
	keys    *budgetstore.Keys
	budgets []config.RoutingBudget
	// allowed are the shared-form keys the current keys produce (named
	// users, groups, named connectors) and connectorAll the budget ids of *
	// connector budgets: anything else is never sent (an unkeyed hash from
	// before the store was on, a hash under an old secret).
	allowed      map[string]bool
	connectorAll map[string]bool
	users        map[string]string // local caller key -> fleet user id
	byFleet      map[string]string // fleet user id -> local caller key
	err          string
}

const fleetUsersMax = 4096

// apply builds (or drops) the client for cfg. A store that cannot be set up
// (no secret, bad CA file) leaves budgets counting on this device and is
// reported by SeedState and doctor.
func (f *fleetState) apply(cfg *config.Config) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var store *config.RoutingBudgetStoreConfig
	if cfg != nil && cfg.Routing.Admin != nil && cfg.StandaloneEnterprise() {
		store = cfg.Routing.Admin.BudgetStore
	}
	if store == nil || strings.TrimSpace(store.URL) == "" {
		f.url, f.client, f.keys, f.budgets, f.err = "", nil, nil, nil, ""
		return
	}
	f.budgets = append([]config.RoutingBudget(nil), cfg.Routing.Admin.Budgets...)
	value := cfg.RoutingCredential(store.EffectiveCredential())
	var ca []byte
	if store.CAFile != "" {
		var err error
		if ca, err = os.ReadFile(store.CAFile); err != nil {
			f.url, f.client, f.keys, f.err = "", nil, nil, "budget store ca_file cannot be read"
			return
		}
	}
	// A changed secret or CA (rotation) rebuilds the client and forgets the
	// fleet ids hashed with the old secret.
	secretSum, caSum := sha256.Sum256([]byte(value)), sha256.Sum256(ca)
	sig := fmt.Sprintf("%s|%x|%x|%d", store.URL, secretSum, caSum, store.TimeoutMs)
	if sig == f.url && f.client != nil {
		f.allowKeysLocked()
		return
	}
	f.url, f.client, f.keys, f.err = sig, nil, nil, ""
	f.users, f.byFleet = map[string]string{}, map[string]string{}
	secret, err := decodeStoreSecret(value)
	if err != nil {
		f.err = err.Error()
		return
	}
	keys, err := budgetstore.DeriveKeys(secret)
	clear(secret)
	if err != nil {
		f.err = err.Error()
		return
	}
	client, err := budgetstore.NewClient(store.URL, keys, ca, store.EffectiveTimeout())
	if err != nil {
		f.err = err.Error()
		return
	}
	f.client, f.keys = client, &keys
	f.allowKeysLocked()
}

// allowKeysLocked lists the shared-form keys of the configured budgets.
func (f *fleetState) allowKeysLocked() {
	f.allowed, f.connectorAll = map[string]bool{}, map[string]bool{}
	if f.keys == nil {
		return
	}
	for _, b := range f.budgets {
		switch {
		case b.Scope == config.RoutingBudgetScopeUser && b.Subject != config.RoutingBudgetSubjectAll:
			f.allowed["user:"+b.ID+":="+f.keys.SubjectHash(b.Subject)] = true
		case b.Scope == config.RoutingBudgetScopeGroup:
			f.allowed["group:"+b.ID+":"+f.keys.SubjectHash(b.Subject)] = true
		case b.Scope == config.RoutingBudgetScopeConnector && b.Subject == config.RoutingBudgetSubjectAll:
			f.connectorAll[b.ID] = true
		case b.Scope == config.RoutingBudgetScopeConnector:
			f.allowed["connector:"+b.ID+":"+config.NormalizeConnectorName(b.Subject)] = true
		}
	}
}

// sharedKeyLocked reports whether a key that is not a * user key may be sent.
func (f *fleetState) sharedKeyLocked(key string) bool {
	if f.allowed[key] {
		return true
	}
	if rest, ok := strings.CutPrefix(key, "connector:"); ok {
		id, connector, _ := strings.Cut(rest, ":")
		return f.connectorAll[id] && connector != "" && config.NormalizeConnectorName(connector) == connector
	}
	return false
}

func decodeStoreSecret(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("budget store secret is not stored (protected credential)")
	}
	secret, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(secret) != budgetstore.SecretBytes {
		return nil, fmt.Errorf("budget store secret must be 32 bytes, base64")
	}
	return secret, nil
}

// counter returns the fleet counter, nil when none is configured.
func (f *fleetState) counter() routingadmin.SpendCounter {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.client == nil {
		return nil
	}
	return f.client
}

// mapper returns the key mapping, nil when no store is configured.
func (f *fleetState) mapper() routingadmin.FleetKeys {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.client == nil {
		return nil
	}
	return f
}

// hasher returns the keyed subject hash, nil when no store is configured.
func (f *fleetState) hasher() func(string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keys == nil {
		return nil
	}
	keys := *f.keys
	return keys.SubjectHash
}

// noteUser records the fleet id of a verified caller (its canonical domain
// SID or UPN, keyed); a caller with neither stays on this device only.
func (f *fleetState) noteUser(callerKey, sid, upn string) {
	if f == nil || callerKey == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keys == nil || f.users == nil {
		return
	}
	if _, ok := f.users[callerKey]; ok {
		return
	}
	canonical, err := accountjoin.Canonical(accountjoin.Account{SID: sid, UPN: upn})
	if err != nil {
		return
	}
	id := "u" + f.keys.SubjectHash("account:"+canonical)
	if len(f.users) >= fleetUsersMax {
		f.users, f.byFleet = map[string]string{}, map[string]string{}
	}
	f.users[callerKey], f.byFleet[id] = id, callerKey
	// Read this user's fleet spend now rather than at the next interval.
	routingAdminRuntime.Kick()
}

// ToFleet maps a local charge key: a * user budget names the caller by its
// fleet id; other keys are already in the shared form.
func (f *fleetState) ToFleet(local string) (string, bool) {
	prefix, caller, ok := splitUserStarKey(local)
	f.mu.Lock()
	defer f.mu.Unlock()
	if !ok {
		return local, f.sharedKeyLocked(local)
	}
	id, known := f.users[caller]
	if !known {
		return "", false
	}
	return prefix + id, true
}

// FromFleet maps a fleet key back; another device's user has no local form.
func (f *fleetState) FromFleet(fleet string) (string, bool) {
	prefix, id, ok := splitUserStarKey(fleet)
	f.mu.Lock()
	defer f.mu.Unlock()
	if !ok {
		return fleet, f.sharedKeyLocked(fleet)
	}
	caller, known := f.byFleet[id]
	if !known {
		return "", false
	}
	return prefix + caller, true
}

// Wanted lists the fleet keys of every budget this device can name: named
// user and group subjects, named connectors, and each user seen here for *
// user budgets.
func (f *fleetState) Wanted() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keys == nil {
		return nil
	}
	var out []string
	for _, b := range f.budgets {
		switch {
		case b.Scope == config.RoutingBudgetScopeUser && b.Subject == config.RoutingBudgetSubjectAll:
			for _, id := range f.users {
				out = append(out, "user:"+b.ID+":*:"+id)
			}
		case b.Scope == config.RoutingBudgetScopeUser:
			out = append(out, "user:"+b.ID+":="+f.keys.SubjectHash(b.Subject))
		case b.Scope == config.RoutingBudgetScopeGroup:
			out = append(out, "group:"+b.ID+":"+f.keys.SubjectHash(b.Subject))
		case b.Scope == config.RoutingBudgetScopeConnector && b.Subject != config.RoutingBudgetSubjectAll:
			out = append(out, "connector:"+b.ID+":"+config.NormalizeConnectorName(b.Subject))
		}
	}
	return out
}

// splitUserStarKey splits user:<id>:*:<subject> into its prefix and subject.
func splitUserStarKey(key string) (prefix, subject string, ok bool) {
	if !strings.HasPrefix(key, "user:") {
		return "", "", false
	}
	i := strings.Index(key, ":*:")
	if i < 0 {
		return "", "", false
	}
	return key[:i+3], key[i+3:], true
}

// routingNoteFleetUser records the caller's fleet id when a fleet store is
// configured (called with the verified subject on each routed call).
func routingNoteFleetUser(s VerifiedSubject) {
	sid := s.Directory.AccountSID // the SID SSSD holds for a Linux domain account
	if s.IDKind == useridentity.KindWindowsSID {
		sid = s.UserID
	}
	routingAdminFleet.noteUser(s.UserID, sid, s.Directory.UPN)
}
