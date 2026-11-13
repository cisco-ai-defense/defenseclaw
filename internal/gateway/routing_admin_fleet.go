// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
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
// (routing.admin.budget_store): the HTTPS client with this device's own
// credential, and the key mapping the credential gives. The credential
// names only this device's users (their SID or UPN and fleet id) and the
// fleet keys of the budgets they are in; the device holds no tenant-wide
// secret and can neither name nor read another device's users. Nil while
// the store is not configured: budgets then count on this device only.
var routingAdminFleet = &fleetState{}

type fleetState struct {
	mu        sync.Mutex
	sig       string // the configured store and credential digest, to rebuild only on change
	client    *budgetstore.Client
	cred      *budgetstore.Credential
	toFleet   map[string]string // local key -> fleet key (credential keys)
	fromFleet map[string]string
	userAll   map[string]bool   // budget ids of * user budgets in the credential
	connAll   map[string]bool   // budget ids of * connector budgets in the credential
	bundle    map[string]bool   // budget ids in the current bundle (a retired budget is never sent or asked)
	users     map[string]string // local caller key -> fleet user id
	byFleet   map[string]string // fleet user id -> local caller key
	err       string
}

const fleetUsersMax = 4096

// apply builds (or drops) the client for cfg. A store that cannot be set up
// (no credential, bad CA file) leaves budgets counting on this device.
func (f *fleetState) apply(cfg *config.Config) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var store *config.RoutingBudgetStoreConfig
	if cfg != nil && cfg.Routing.Admin != nil && cfg.StandaloneEnterprise() {
		store = cfg.Routing.Admin.BudgetStore
	}
	if store == nil || strings.TrimSpace(store.URL) == "" {
		*f = fleetState{}
		return
	}
	f.bundle = map[string]bool{}
	for _, b := range cfg.Routing.Admin.Budgets {
		f.bundle[b.ID] = true
	}
	value := cfg.RoutingCredential(store.EffectiveCredential())
	var ca []byte
	if store.CAFile != "" {
		var err error
		if ca, err = os.ReadFile(store.CAFile); err != nil {
			f.sig, f.client, f.cred, f.err = "", nil, nil, "budget store ca_file cannot be read"
			return
		}
	}
	credSum, caSum := sha256.Sum256([]byte(value)), sha256.Sum256(ca)
	sig := fmt.Sprintf("%s|%x|%x|%d", store.URL, credSum, caSum, store.TimeoutMs)
	if sig == f.sig && f.client != nil {
		return
	}
	f.sig, f.client, f.cred, f.err = sig, nil, nil, ""
	f.users, f.byFleet = map[string]string{}, map[string]string{}
	cred, err := budgetstore.DecodeCredential(value)
	if err != nil {
		f.err = "budget store device credential: " + err.Error()
		return
	}
	key, err := cred.Key()
	if err != nil {
		f.err = err.Error()
		return
	}
	client, err := budgetstore.NewClient(store.URL, key, ca, store.EffectiveTimeout())
	if err != nil {
		f.err = err.Error()
		return
	}
	f.installLocked(cred, client)
}

// installLocked takes the decoded credential and its client.
func (f *fleetState) installLocked(cred budgetstore.Credential, client *budgetstore.Client) {
	f.client, f.cred = client, &cred
	f.users, f.byFleet = map[string]string{}, map[string]string{}
	f.toFleet, f.fromFleet, f.connAll, f.userAll = map[string]string{}, map[string]string{}, map[string]bool{}, map[string]bool{}
	for _, id := range cred.UserBudgets {
		f.userAll[id] = true
	}
	for local, fleet := range cred.Keys {
		f.toFleet[local], f.fromFleet[fleet] = fleet, local
	}
	for _, id := range cred.ConnectorBudgets {
		f.connAll[id] = true
	}
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

// status is the setup error of the configured store ("" when fine or off).
func (f *fleetState) status() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

// noteUser records the fleet id of a verified caller when the credential
// names it (its domain SID or UPN); any other caller stays on this device.
func (f *fleetState) noteUser(callerKey, sid, upn string) {
	if f == nil || callerKey == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cred == nil {
		return
	}
	if _, ok := f.users[callerKey]; ok {
		return
	}
	id := ""
	for _, u := range f.cred.Users {
		if (sid != "" && u.SID != "" && sameCanonical(accountjoin.Account{SID: sid}, accountjoin.Account{SID: u.SID})) ||
			(upn != "" && u.UPN != "" && sameCanonical(accountjoin.Account{UPN: upn}, accountjoin.Account{UPN: u.UPN})) {
			id = u.ID
			break
		}
	}
	if id == "" {
		return
	}
	if len(f.users) >= fleetUsersMax {
		f.users, f.byFleet = map[string]string{}, map[string]string{}
	}
	f.users[callerKey], f.byFleet[id] = id, callerKey
	// Read this user's fleet spend now rather than at the next interval.
	routingAdminRuntime.Kick()
}

func sameCanonical(a, b accountjoin.Account) bool {
	ca, errA := accountjoin.Canonical(a)
	cb, errB := accountjoin.Canonical(b)
	return errA == nil && errB == nil && ca == cb
}

// ToFleet maps a local charge key to the fleet key the credential allows.
func (f *fleetState) ToFleet(local string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.inBundleLocked(local) {
		return "", false
	}
	if prefix, caller, ok := splitUserStarKey(local); ok {
		if !f.userAll[strings.TrimSuffix(strings.TrimPrefix(prefix, "user:"), ":*:")] {
			return "", false
		}
		id, known := f.users[caller]
		return prefix + id, known
	}
	if fleet, ok := f.toFleet[local]; ok {
		return fleet, true
	}
	if f.connectorAllLocked(local) {
		return local, true
	}
	return "", false
}

// FromFleet maps a fleet key back to the local key.
func (f *fleetState) FromFleet(fleet string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if prefix, id, ok := splitUserStarKey(fleet); ok {
		caller, known := f.byFleet[id]
		return prefix + caller, known
	}
	if local, ok := f.fromFleet[fleet]; ok {
		return local, true
	}
	if f.connectorAllLocked(fleet) {
		return fleet, true
	}
	return "", false
}

func (f *fleetState) connectorAllLocked(key string) bool {
	rest, ok := strings.CutPrefix(key, "connector:")
	if !ok {
		return false
	}
	id, name, _ := strings.Cut(rest, ":")
	return f.connAll[id] && name != "" && config.NormalizeConnectorName(name) == name
}

// Wanted lists the fleet keys this device may ask about: its credential's
// keys and each of its users seen here for * user budgets.
func (f *fleetState) Wanted() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cred == nil {
		return nil
	}
	var out []string
	for _, fleet := range f.toFleet {
		if !f.inBundleLocked(fleet) {
			continue
		}
		out = append(out, fleet)
	}
	for id := range f.userAll {
		if f.bundle != nil && !f.bundle[id] {
			continue
		}
		for _, uid := range f.users {
			out = append(out, "user:"+id+":*:"+uid)
		}
	}
	return out
}

// inBundleLocked reports whether the budget of a charge key is in the
// current bundle (true while no bundle is known, as in tests).
func (f *fleetState) inBundleLocked(key string) bool {
	if f.bundle == nil {
		return true
	}
	_, rest, _ := strings.Cut(key, ":")
	id, _, _ := strings.Cut(rest, ":")
	return f.bundle[id]
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
