// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Trusted connectors (issue #1392).
//
// A gateway that runs agents for many people calls the managed hook socket
// as its own service account. When enterprise.identity.trusted_connectors
// lists that account, and only on the agent-gateway route, the call may
// name the person it acts for (acting_for). The gateway then resolves that
// person's directory facts itself and selects the person's guardrail
// profile; audit names the person and the connector, and the person gets
// their own agt- and ais- ids. The trust root is the kernel-verified caller
// plus the signed admin entry: the request alone never raises assurance.
//
// Rules, from the design review:
//   - acting_for is honoured only for a caller the hook socket verified by
//     its peer credentials. Never for a per-user credential (the Windows TCP
//     route), a process owner, a TCP token call, a sandbox or relayed call.
//   - The list is honoured only when trust anchors are installed and the
//     live configuration was activated as a signed bundle; on a CONFIG=
//     install it is ignored with a status warning.
//   - Accounts, users and groups resolve to uids and gids at start and on
//     every refresh, and match by id. Ambiguous names, names from a domain
//     that is not joined or trusted, root, admin accounts and members of
//     admin groups, the service account itself and other connectors'
//     accounts are refused.
//   - A listed account that sends no acting_for on its route is refused
//     (acting_for_required): it can never fall back to its own profile.
//   - A lookup that times out or answers in part refuses the call and is not
//     cached; the person's own local calls use their own cache.
//   - Path rules and ~ resolve against the account that runs the tools (the
//     service account), never the person's home.
//   - Chain partitions are per (connector account, person): two people
//     behind one connector never share a session's chain state.

// Refusal codes the agent-gateway route answers with (HTTP 403, a deny).
const (
	actingForRefusedRequired          = "acting_for_required"
	actingForRefusedNotAllowed        = "acting_for_not_allowed"
	actingForRefusedLookupUnavailable = "acting_for_lookup_unavailable"
	actingForRefusedSessionMismatch   = "acting_for_session_mismatch"
	actingForRefusedConnectorDisabled = "acting_for_connector_disabled"
	actingForRefusedUnsupported       = "acting_for_unsupported_platform"
)

// Local-audit causes behind acting_for_not_allowed. The caller gets one code
// for an unknown person, a person outside may_act_for and an administrator,
// so the route is no directory oracle; the local audit keeps the cause.
const (
	actingForCauseUnknownUser    = "unknown_user"
	actingForCauseAmbiguousUser  = "ambiguous_user"
	actingForCauseOutOfSet       = "out_of_set"
	actingForCauseAdminTarget    = "admin_target"
	actingForCauseConnectorSelf  = "connector_account"
	actingForCauseUntrustedRealm = "untrusted_domain"
)

// Reasons trusted_connectors is configured but not honoured (status).
const (
	trustedConnectorsNotManaged      = "not_managed_standalone"
	trustedConnectorsNoAnchors       = "no_trust_anchors"
	trustedConnectorsNotSigned       = "not_signed_bundle_activation"
	trustedConnectorsUnsupportedOS   = "platform_unsupported"
	trustedConnectorsActivationError = "activation_unreadable"
)

// trustedConnectorEntry is one resolved enterprise.identity.trusted_connectors
// entry. Disabled is "" when the entry may be used.
type trustedConnectorEntry struct {
	Name        string
	AccountSpec string
	// AccountID is the service account's uid (or SID) resolved at the last
	// refresh; AccountName its name as the account database gives it.
	AccountID, AccountName string
	Disabled               string
	// Users and Groups are the canonical ids of may_act_for.
	Users  map[string]bool
	Groups map[string]bool
	// Warnings name the may_act_for entries that did not resolve.
	Warnings []string
}

// trustedConnectorState is the set the hook socket consults.
type trustedConnectorState struct {
	configured bool
	honoured   bool
	reason     string
	entries    []trustedConnectorEntry
	byAccount  map[string]int
	refreshed  time.Time
	cfg        []config.TrustedConnectorConfig
	// unresolved is set while an honoured entry's account never resolved:
	// any acting_for is then refused, since the caller may be that account.
	unresolved bool
}

var trustedConnectorsState atomic.Pointer[trustedConnectorState]

// trustedConnectorStateNow returns the current set (never nil).
func trustedConnectorStateNow() *trustedConnectorState {
	if s := trustedConnectorsState.Load(); s != nil {
		return s
	}
	return &trustedConnectorState{}
}

// trustedConnectorForAccount returns the usable entry whose service account
// is id, when the list is honoured.
func trustedConnectorForAccount(id string) (trustedConnectorEntry, bool) {
	s := trustedConnectorStateNow()
	if !s.honoured || id == "" {
		return trustedConnectorEntry{}, false
	}
	i, ok := s.byAccount[id]
	if !ok {
		return trustedConnectorEntry{}, false
	}
	entry := s.entries[i]
	return entry, true
}

// trustedConnectorAccountListed reports whether id is the service account of
// any configured entry, honoured or not, usable or not. The hook socket
// lets such an account reach the agent-gateway route, where its calls are
// refused when the entry cannot be used, rather than served under the
// account's own profile.
func trustedConnectorAccountListed(id string) bool {
	s := trustedConnectorStateNow()
	_, ok := s.byAccount[id]
	return ok && s.honoured
}

// trustedConnectorActivation decides whether a managed gateway honours the
// list: trust anchors are installed and config.yaml is exactly what a signed
// bundle in the store renders for the bundle its generation record names
// (enterprisebundle.CheckSignedActivation, the activation gate the config
// manager applies to every reload). The record only names the candidate; the
// signature and the re-render decide. A CONFIG= install (no anchors), or a
// record that names no bundle, is not honoured.
var trustedConnectorActivation = signedBundleActivation

// trustedConnectorSignatures caches manifest signature checks in memory.
var trustedConnectorSignatures enterprisebundle.SignatureCache

func signedBundleActivation(cfg *config.Config) (bool, string) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return false, trustedConnectorsNotManaged
	}
	path := strings.TrimSpace(cfg.ConfigFilePath)
	if path == "" {
		return false, trustedConnectorsActivationError
	}
	dir := filepath.Dir(path)
	anchors, anchorsRaw, err := enterprisebundle.ReadAnchorsFile(filepath.Join(dir, "trust", enterprisebundle.AnchorsName), nil)
	if err != nil {
		if enterprisebundle.CodeOf(err) == enterprisebundle.CodeAnchorMissing || errors.Is(err, fs.ErrNotExist) {
			return false, trustedConnectorsNoAnchors
		}
		return false, trustedConnectorsActivationError
	}
	installed, err := os.ReadFile(path)
	if err != nil {
		return false, trustedConnectorsActivationError
	}
	state, err := configwrite.ReadGenerationState(path)
	if err != nil || strings.TrimSpace(state.BundleID) == "" {
		return false, trustedConnectorsNotSigned
	}
	in := enterprisebundle.ActivationInput{
		BundlesDir: filepath.Join(dir, enterprisebundle.BundlesDirName),
		Anchors:    anchors, AnchorsRaw: anchorsRaw, Platform: runtime.GOOS, Cache: &trustedConnectorSignatures,
	}
	if _, refusal := enterprisebundle.CheckSignedActivation(in, state.BundleID, state.BundleVersion, state.SignerKeyID, installed); refusal != nil {
		return false, trustedConnectorsNotSigned
	}
	return true, ""
}

// trustedConnectorRefreshInterval is how often the entries resolve again, so
// an account that becomes an administrator, or a group that changes, is seen.
const trustedConnectorRefreshInterval = 5 * time.Minute

var trustedConnectorRefresh struct {
	sync.Mutex
	stop chan struct{}
}

// configureTrustedConnectors builds the set from cfg and starts its refresh.
// The list is lifecycle (restart-required): it is read at start.
func configureTrustedConnectors(cfg *config.Config) {
	state := buildTrustedConnectorState(cfg)
	trustedConnectorsState.Store(state)
	logTrustedConnectorState(state)
	trustedConnectorRefresh.Lock()
	defer trustedConnectorRefresh.Unlock()
	if trustedConnectorRefresh.stop != nil {
		close(trustedConnectorRefresh.stop)
		trustedConnectorRefresh.stop = nil
	}
	if !state.configured {
		return
	}
	stop := make(chan struct{})
	trustedConnectorRefresh.stop = stop
	go func() {
		ticker := time.NewTicker(trustedConnectorRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				next := buildTrustedConnectorState(cfg)
				trustedConnectorsState.Store(next)
				logTrustedConnectorState(next)
			}
		}
	}()
}

func buildTrustedConnectorState(cfg *config.Config) *trustedConnectorState {
	return buildTrustedConnectorStateFrom(cfg, trustedConnectorsState.Load())
}

// buildTrustedConnectorStateFrom resolves cfg's entries. An entry whose
// lookup fails keeps the account id the previous state resolved, disabled
// (lookup_failed): its calls are refused rather than served under the
// account's own profile.
func buildTrustedConnectorStateFrom(cfg *config.Config, previous *trustedConnectorState) *trustedConnectorState {
	state := &trustedConnectorState{byAccount: map[string]int{}, refreshed: time.Now().UTC()}
	if cfg == nil || cfg.SecureClientIntegration() || len(cfg.Enterprise.Identity.TrustedConnectors) == 0 {
		return state
	}
	state.configured = true
	state.cfg = append([]config.TrustedConnectorConfig(nil), cfg.Enterprise.Identity.TrustedConnectors...)
	honoured, reason := trustedConnectorActivation(cfg)
	if honoured && !trustedConnectorPlatformSupported() {
		honoured, reason = false, trustedConnectorsUnsupportedOS
	}
	state.honoured, state.reason = honoured, reason
	if !honoured {
		return state
	}
	accounts := map[string]bool{}
	for _, entry := range state.cfg {
		resolved := resolveTrustedConnectorEntry(entry)
		if resolved.AccountID == "" && previous != nil {
			for _, old := range previous.entries {
				if old.Name == resolved.Name && old.AccountSpec == resolved.AccountSpec && old.AccountID != "" {
					resolved.AccountID, resolved.AccountName = old.AccountID, old.AccountName
					if resolved.Disabled == "" {
						resolved.Disabled = "lookup_failed"
					}
				}
			}
		}
		if resolved.AccountID == "" {
			state.unresolved = true
		}
		state.entries = append(state.entries, resolved)
		if resolved.AccountID != "" {
			if accounts[resolved.AccountID] {
				// Two entries name one account: neither may be used.
				for i := range state.entries {
					if state.entries[i].AccountID == resolved.AccountID {
						state.entries[i].Disabled = "account_listed_twice"
					}
				}
			}
			accounts[resolved.AccountID] = true
		}
	}
	for i := range state.entries {
		entry := &state.entries[i]
		if entry.AccountID == "" {
			continue
		}
		state.byAccount[entry.AccountID] = i
		// No entry may act for any connector's account.
		for id := range entry.Users {
			if accounts[id] {
				delete(entry.Users, id)
				entry.Warnings = append(entry.Warnings, "may_act_for.users names a trusted connector account; dropped")
			}
		}
		if len(entry.Users) == 0 && len(entry.Groups) == 0 && entry.Disabled == "" {
			entry.Disabled = "may_act_for_unresolved"
		}
	}
	return state
}

func logTrustedConnectorState(state *trustedConnectorState) {
	if state == nil || !state.configured {
		return
	}
	if !state.honoured {
		fmt.Fprintf(os.Stderr, "[identity] enterprise.identity.trusted_connectors is set but ignored (%s): "+
			"trusted connectors are honoured only from a signed bundle on a managed device\n", state.reason)
		return
	}
	for _, entry := range state.entries {
		if entry.Disabled != "" {
			fmt.Fprintf(os.Stderr, "[identity] trusted connector %q is disabled: %s\n", entry.Name, entry.Disabled)
		}
		for _, warning := range entry.Warnings {
			fmt.Fprintf(os.Stderr, "[identity] trusted connector %q: %s\n", entry.Name, warning)
		}
	}
}

// actingFor is a request's honoured acting_for.
type actingFor struct {
	Connector          string
	ConnectorAccountID string
	ConnectorAccount   string
	// Person is the person the connector acts for, with directory facts the
	// gateway resolved (Assurance verified_by_connector).
	Person VerifiedSubject
}

type actingForContextKey struct{}

func withActingFor(ctx context.Context, af actingFor) context.Context {
	af.Person.Directory.Assurance = useridentity.AssuranceVerifiedByConnector
	return context.WithValue(ctx, actingForContextKey{}, af)
}

// actingForFromContext returns the request's honoured acting_for.
func actingForFromContext(ctx context.Context) (actingFor, bool) {
	if ctx == nil {
		return actingFor{}, false
	}
	af, ok := ctx.Value(actingForContextKey{}).(actingFor)
	return af, ok && af.Person.UserID != ""
}

// actingForProfileSubject is the profile matcher's view of the person.
func actingForProfileSubject(ctx context.Context) (profileSubject, bool) {
	af, ok := actingForFromContext(ctx)
	if !ok {
		return profileSubject{}, false
	}
	person := af.Person
	person.Directory.Assurance = useridentity.AssuranceVerified
	return profileSubjectFromVerified(person, true), true
}

// actingForRequestIdentity is the directory identity records of the person
// carry: the facts the gateway resolved, at verified_by_connector.
func actingForRequestIdentity(ctx context.Context, userID string) (*llmEventIdentity, bool) {
	af, ok := actingForFromContext(ctx)
	if !ok || af.Person.UserID != userID {
		return nil, false
	}
	if af.Person.Directory.Empty() {
		return nil, true
	}
	facts := af.Person.Directory
	facts.Assurance = useridentity.AssuranceVerifiedByConnector
	return &llmEventIdentity{Directory: facts}, true
}

// actingForAuditExtra are the local audit fields of a call made for a
// person: the connector, its account and the assurance.
func actingForAuditExtra(ctx context.Context) map[string]string {
	af, ok := actingForFromContext(ctx)
	if !ok {
		return nil
	}
	return map[string]string{
		"trusted_connector":            af.Connector,
		"trusted_connector_account_id": af.ConnectorAccountID,
		"acting_for_user_id":           af.Person.UserID,
		"acting_for_user_name":         af.Person.UserName,
		"principal_assurance":          string(useridentity.AssuranceVerifiedByConnector),
	}
}

// actingForSessionCaller scopes per-session state (the session-start gate)
// to the person as well as the service account.
func actingForSessionCaller(ctx context.Context) string {
	if af, ok := actingForFromContext(ctx); ok {
		return "/for:" + af.Person.UserID
	}
	return ""
}

// trustedConnectorInstanceNamespace keys the correlation connector instance
// of a (trusted connector account, person) pair.
const trustedConnectorInstanceNamespace = "defenseclaw.connector.trusted.v1"

// trustedConnectorInstanceID is the correlation connector instance of a call
// made for a person: one per (connector account, person), so cursors,
// pending operations and tool-chain partitions of two people behind one
// connector never mix, also when they send the same session id. Each input
// is length-prefixed.
func trustedConnectorInstanceID(af actingFor) audit.ConnectorInstanceID {
	digest := sha256.New()
	for _, part := range []string{trustedConnectorInstanceNamespace, af.ConnectorAccountID, af.Person.UserID} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		digest.Write(size[:])
		digest.Write([]byte(part))
	}
	sum := digest.Sum(nil)
	var id uuid.UUID
	copy(id[:], sum[:16])
	id[6] = 0x70 | id[6]&0x0f // version 7
	id[8] = 0x80 | id[8]&0x3f // RFC 9562 variant
	return audit.ConnectorInstanceID(id.String())
}

// actingForSessionPins remembers the first person each (connector account,
// session id) was used for, so a session that switches person is refused
// (acting_for_session_mismatch). Partitions are per person already; the
// pin keeps one session from being attributed to two people.
var actingForSessionPins = struct {
	sync.Mutex
	pins  map[string]actingForPin
	order []string
}{pins: map[string]actingForPin{}}

type actingForPin struct {
	person string
	at     time.Time
}

const (
	actingForSessionPinsMax = 16384
	actingForSessionPinTTL  = 24 * time.Hour
)

// pinActingForSession reports whether sessionID may be used for person.
func pinActingForSession(connectorAccount, sessionID, person string, now time.Time) bool {
	if sessionID == "" {
		return true
	}
	key := connectorAccount + "\x00" + sessionID
	actingForSessionPins.Lock()
	defer actingForSessionPins.Unlock()
	if pin, ok := actingForSessionPins.pins[key]; ok && now.Sub(pin.at) < actingForSessionPinTTL {
		if pin.person != person {
			return false
		}
		actingForSessionPins.pins[key] = actingForPin{person: person, at: now}
		return true
	}
	if len(actingForSessionPins.pins) >= actingForSessionPinsMax {
		// Drop the oldest half: a pin only refuses a person switch, so a
		// dropped pin never lets two people share a chain partition.
		sort.SliceStable(actingForSessionPins.order, func(i, j int) bool {
			return actingForSessionPins.pins[actingForSessionPins.order[i]].at.Before(actingForSessionPins.pins[actingForSessionPins.order[j]].at)
		})
		half := len(actingForSessionPins.order) / 2
		for _, old := range actingForSessionPins.order[:half] {
			delete(actingForSessionPins.pins, old)
		}
		actingForSessionPins.order = append([]string(nil), actingForSessionPins.order[half:]...)
	}
	if _, known := actingForSessionPins.pins[key]; !known {
		actingForSessionPins.order = append(actingForSessionPins.order, key)
	}
	actingForSessionPins.pins[key] = actingForPin{person: person, at: now}
	return true
}

// actingForCallerEligible reports whether ctx's caller is one acting_for may
// be honoured for: verified by the hook socket's peer credentials, not a
// sandbox or relayed call, and the request's subject is that peer.
func actingForCallerEligible(ctx context.Context) (managedHookPeer, bool) {
	if _, sandboxed := sandboxauth.FromContext(ctx); sandboxed {
		return managedHookPeer{}, false
	}
	peer, ok := managedHookPeerFromContext(ctx)
	if !ok {
		return managedHookPeer{}, false
	}
	subject, ok := verifiedSubjectFromContext(ctx)
	if !ok || subject.Source != subjectSourcePeerCredentials || subject.UserID != strconv.Itoa(peer.UID) {
		return managedHookPeer{}, false
	}
	if _, userScoped := ctx.Value(verifiedUserScopedIdentityContextKey{}).(string); userScoped {
		return managedHookPeer{}, false
	}
	return peer, true
}

// actingForRefusal is a refused acting_for: Code is the answer, Cause the
// local audit detail.
type actingForRefusal struct {
	Code, Cause string
}

func (r actingForRefusal) refused() bool { return r.Code != "" }

// trustedConnectorAdminGroupNames are the bare group names that make an
// account an administrator (compared without case, without a domain).
var trustedConnectorAdminGroupNames = map[string]bool{
	"root": true, "wheel": true, "sudo": true, "admin": true,
	"administrators": true, "domain admins": true, "enterprise admins": true, "schema admins": true,
}

func trustedConnectorAdminGroup(name string) bool {
	name = strings.TrimSpace(name)
	if strings.EqualFold(name, "S-1-5-32-544") {
		return true
	}
	bare, _ := useridentity.SplitQualifiedName(name)
	return trustedConnectorAdminGroupNames[strings.ToLower(bare)]
}

// trustedConnectorCallerIsAdmin is the per-call check of the service
// account itself, from the facts the hook socket verified: root's group or
// an admin group refuses the call even between two refreshes.
func trustedConnectorCallerIsAdmin(ctx context.Context, peer managedHookPeer) bool {
	if peer.UID == 0 || peer.GID == 0 {
		return true
	}
	subject, ok := verifiedSubjectFromContext(ctx)
	if !ok {
		return false
	}
	for _, group := range subject.Directory.Groups {
		if trustedConnectorAdminGroup(group) {
			return true
		}
	}
	return false
}

// actingForSessionStateScope qualifies in-memory per-session state (the
// tool judge's context, step indexes) with the connector account and the
// person, so people behind one or two connectors never share it.
func actingForSessionStateScope(ctx context.Context) string {
	af, ok := actingForFromContext(ctx)
	if !ok {
		return ""
	}
	return "trusted\x00" + af.ConnectorAccountID + "\x00" + af.Person.UserID + "\x00"
}
