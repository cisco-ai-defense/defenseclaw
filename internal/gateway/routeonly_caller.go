// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Verified callers of the route-only listener and, on managed hosts with
// routing on, of the guardrail proxy (S1 DESIGN 16.3, 17.2, 18.2, 19).
// "Verified" means: the kernel names the account on the client end of the
// loopback connection, and that account is one DefenseClaw protects for the
// connector. Only a verified caller gets a profile overlay and
// gateway-held credentials; on managed route-only an unverified caller is
// refused (401).

// subjectSourceKernelPeer marks a subject proved by the kernel connection
// table (loopback TCP peer uid or SID).
const subjectSourceKernelPeer = "kernel_peer"

// Why a route caller is not verified (logged and in the 401 text; never a
// secret).
const (
	routeCallerAuthorizerUnavailable = "authorizer_unavailable"
	routeCallerPeerUnverified        = "peer_unverified"
	routeCallerPeerMismatch          = "peer_mismatch"
	routeCallerRoot                  = "root"
	routeCallerServiceAccount        = "service_account"
	routeCallerTrustedConnector      = "trusted_connector_account"
	routeCallerExempt                = "exempt"
	routeCallerConnectorDisabled     = "connector_disabled"
	routeCallerNotEnrolled           = "not_enrolled"
	routeCallerLedgerUnavailable     = "ledger_unavailable"
	routeCallerCredentialInvalid     = "route_credential_invalid"
	routeCallerCredentialMismatch    = "route_credential_mismatch"
	routeCallerNotOwner              = "not_gateway_owner"
)

// routeCaller is the verified-caller answer.
type routeCaller struct {
	Verified bool
	// Subject is the canonical uid (Unix) or SID (Windows) of a verified
	// caller; the per-subject limiter and the engine key on it.
	Subject string
	Reason  string
}

// routeCallerInputs are the facts decideRouteCaller decides on.
type routeCallerInputs struct {
	Managed   bool
	Windows   bool
	Connector string
	// Disabled: guardrail.connectors.<name>.enabled is false.
	Disabled bool
	// RequireCredential: the route credential (X-DC-Route-Auth) must be
	// present and bound to the caller (route-only); the guardrail proxy
	// asks without it.
	RequireCredential bool
	// CredentialIdentity is the identity the presented route credential is
	// bound to ("" = absent or invalid). OSS: the gateway owner when the
	// route token compares equal.
	CredentialIdentity string

	// Unix (Linux, macOS).
	Authz      *managedHookAuthorizer
	PeerUID    int
	PeerUIDErr error
	Peer       func(uid int) managedHookPeer
	OwnerUID   int

	// Windows.
	PeerSID    string
	PeerSIDErr error
	// Enrolled reports a protected ledger target (identity, connector).
	Enrolled func(identity string) bool
	// Exempt reports whether enterprise.enrollment.exempt_users names the
	// account.
	Exempt func(identity string) bool
	// PersonAccount reports whether the SID names a person (not a computer,
	// gMSA or other service account); known false = the lookup gave nothing.
	PersonAccount func(sid string) (person, known bool)
}

func unverifiedRoute(reason string) routeCaller { return routeCaller{Reason: reason} }

// decideRouteCaller applies the verified-caller rules.
func decideRouteCaller(in routeCallerInputs) routeCaller {
	if !in.Managed {
		return decideOSSRouteCaller(in)
	}
	if in.Windows {
		return decideWindowsRouteCaller(in)
	}
	return decideUnixRouteCaller(in)
}

// OSS (DESIGN 18.2): a valid route credential is the gateway owner; on
// Linux and macOS the kernel peer must also be the gateway account.
func decideOSSRouteCaller(in routeCallerInputs) routeCaller {
	if in.CredentialIdentity == "" {
		return unverifiedRoute(routeCallerCredentialInvalid)
	}
	if in.Windows {
		return routeCaller{Verified: true, Subject: in.CredentialIdentity}
	}
	if in.PeerUIDErr != nil {
		return unverifiedRoute(routeCallerPeerUnverified)
	}
	if in.PeerUID != in.OwnerUID {
		return unverifiedRoute(routeCallerNotOwner)
	}
	return routeCaller{Verified: true, Subject: strconv.Itoa(in.PeerUID)}
}

// Managed Linux and macOS (DESIGN 16.3, 17.2): the hook socket authorizer
// decides on the kernel uid, then the ledger must enroll it for the
// connector, then the route credential (route-only) must be bound to it.
func decideUnixRouteCaller(in routeCallerInputs) routeCaller {
	if in.Authz == nil {
		return unverifiedRoute(routeCallerAuthorizerUnavailable)
	}
	if in.PeerUIDErr != nil || in.PeerUID < 0 {
		return unverifiedRoute(routeCallerPeerUnverified)
	}
	uid := in.PeerUID
	if uid == 0 {
		return unverifiedRoute(routeCallerRoot)
	}
	if trustedConnectorAccountListed(strconv.Itoa(uid)) {
		return unverifiedRoute(routeCallerTrustedConnector)
	}
	peer := managedHookPeer{UID: uid}
	if in.Peer != nil {
		peer = in.Peer(uid)
	}
	decision := in.Authz.decideFor(peer, in.Connector, "", in.Disabled)
	switch {
	case !decision.Allow:
		return unverifiedRoute(firstNonEmptyRouteReason(decision.Reason, routeCallerNotEnrolled))
	case decision.Exempt:
		return unverifiedRoute(routeCallerExempt)
	case decision.Disabled:
		return unverifiedRoute(routeCallerConnectorDisabled)
	}
	// decide admits machine-policy connectors without a ledger read; a
	// verified caller must be enrolled for this connector all the same.
	if in.Authz.loadLedger == nil {
		return unverifiedRoute(routeCallerLedgerUnavailable)
	}
	ledger, err := in.Authz.loadLedger()
	if err != nil {
		return unverifiedRoute(routeCallerLedgerUnavailable)
	}
	if !ledger.enrolled(peer, strings.ToLower(strings.TrimSpace(in.Connector))) {
		return unverifiedRoute(routeCallerNotEnrolled)
	}
	subject := strconv.Itoa(uid)
	if in.RequireCredential {
		if in.CredentialIdentity == "" {
			return unverifiedRoute(routeCallerCredentialInvalid)
		}
		if in.CredentialIdentity != subject {
			return unverifiedRoute(routeCallerCredentialMismatch)
		}
	}
	return routeCaller{Verified: true, Subject: subject}
}

// Managed Windows (DESIGN 19): the kernel peer SID of the connection must be
// the SID the route credential is bound to (the store derives route
// credentials only for protected ledger targets); without a credential
// (guardrail proxy) the SID must be enrolled for the connector.
func decideWindowsRouteCaller(in routeCallerInputs) routeCaller {
	if in.RequireCredential && in.CredentialIdentity == "" {
		return unverifiedRoute(routeCallerCredentialInvalid)
	}
	if in.PeerSIDErr != nil {
		return unverifiedRoute(routeCallerPeerUnverified)
	}
	sid, ok := connector.CanonicalUserScopedIdentity(in.PeerSID)
	if !ok || useridentity.KindForID(sid) != useridentity.KindWindowsSID {
		return unverifiedRoute(routeCallerPeerUnverified)
	}
	if windowsServiceSID(sid) {
		return unverifiedRoute(routeCallerServiceAccount)
	}
	// A S-1-5-21 SID can still be a gMSA, a managed service account or a
	// computer account; refused when the account lookup says so (P3-8).
	if in.PersonAccount != nil {
		if person, known := in.PersonAccount(sid); known && !person {
			return unverifiedRoute(routeCallerServiceAccount)
		}
	}
	if in.RequireCredential && in.CredentialIdentity != sid {
		return unverifiedRoute(routeCallerPeerMismatch)
	}
	if trustedConnectorAccountListed(sid) {
		return unverifiedRoute(routeCallerTrustedConnector)
	}
	if in.Exempt != nil && in.Exempt(sid) {
		return unverifiedRoute(routeCallerExempt)
	}
	if in.Disabled {
		return unverifiedRoute(routeCallerConnectorDisabled)
	}
	if !in.RequireCredential && (in.Enrolled == nil || !in.Enrolled(sid)) {
		return unverifiedRoute(routeCallerNotEnrolled)
	}
	return routeCaller{Verified: true, Subject: sid}
}

func firstNonEmptyRouteReason(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// windowsServiceSID reports SYSTEM, LocalService, NetworkService and the
// service, virtual machine, window manager, font driver and other
// NT AUTHORITY non-user SIDs: only S-1-5-21 domain or local accounts (and
// S-1-12-1 Entra accounts) are people. A S-1-5-21 SID may still be a gMSA
// or computer account: PersonAccount checks the account type.
func windowsServiceSID(sid string) bool {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	return !strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasPrefix(sid, "S-1-12-1-")
}

// acpLoopbackPeerSID names the user SID of the process on the client end of
// a loopback TCP request (Windows); replaceable in tests. A connection is
// looked up once.
var acpLoopbackPeerSID = func(r *http.Request) (string, error) {
	if peer, ok := r.Context().Value(acpConnPeerKey{}).(*acpConnPeer); ok {
		return peer.lookupSID()
	}
	local, _ := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	remote, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if local == nil || err != nil {
		return "", errors.New("the request carries no TCP addresses")
	}
	return peercred.LoopbackTCPPeerSID(local, remote)
}

// lookupSID reads the SID of the connection client once; a failed lookup
// is not kept, so the next request asks again.
func (p *acpConnPeer) lookupSID() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sid != "" {
		return p.sid, nil
	}
	sid, err := peercred.LoopbackTCPPeerSID(p.local, p.remote)
	if err != nil {
		return "", err
	}
	p.sid = sid
	return sid, nil
}

// verifiedRouteCaller answers for a request on a managed gateway: the
// route-only listener passes the presented route credential
// (requireCredential), the guardrail proxy does not.
func (a *APIServer) verifiedRouteCaller(r *http.Request, connectorName string, requireCredential bool, presented string) routeCaller {
	if a == nil || !a.userScopedCredentialsRequired() {
		return unverifiedRoute(routeCallerAuthorizerUnavailable)
	}
	name := strings.ToLower(strings.TrimSpace(connectorName))
	in := routeCallerInputs{
		Managed:           true,
		Windows:           routeCallerWindows,
		Connector:         name,
		Disabled:          a.scannerCfg.ConnectorDisabled(name),
		RequireCredential: requireCredential,
	}
	if requireCredential {
		if identity, ok := a.lookupUserScopedCredential(connector.UserScopedRouteCredential, name, presented); ok {
			in.CredentialIdentity = identity
		}
	}
	if in.Windows {
		in.PeerSID, in.PeerSIDErr = acpLoopbackPeerSID(r)
		store := a.userScopedCredentialStore()
		in.Enrolled = func(identity string) bool { return store.enrolledFor(identity, name) }
		exempt := a.scannerCfg.Enterprise.Enrollment.ExemptUsers
		in.Exempt = func(identity string) bool { return windowsExemptListed(exempt, identity) }
		in.PersonAccount = windowsSIDPersonAccount
	} else {
		in.Authz = a.managedHookAuthz.Load()
		in.PeerUID, in.PeerUIDErr = acpLoopbackPeerUID(r)
		in.Peer = routeCallerPeer
	}
	return decideRouteCaller(in)
}

// routeCallerWindows selects the Windows rules; replaceable in tests.
var routeCallerWindows = runtime.GOOS == "windows"

// windowsExemptListed reports exempt_users naming the SID or its account.
func windowsExemptListed(entries []string, sid string) bool {
	if len(entries) == 0 {
		return false
	}
	name := useridentity.BareAccountName(userScopedIdentityName(sid))
	return slices.ContainsFunc(entries, func(entry string) bool {
		entry = strings.TrimSpace(entry)
		return entry != "" && (strings.EqualFold(entry, sid) || (name != "" && strings.EqualFold(useridentity.BareAccountName(entry), name)))
	})
}

// caller is the verified-caller answer for a route-only request: OSS by the
// route token and the gateway account (DESIGN 18.2), managed by
// verifiedRouteCaller (16.3, 17.2, 19).
func (s *routeOnlyServer) caller(r *http.Request, cfg *config.Config, connectorName string) routeCaller {
	presented := r.Header.Get(routeTokenHeader)
	if cfg.StandaloneEnterprise() {
		if s.api == nil {
			return unverifiedRoute(routeCallerAuthorizerUnavailable)
		}
		return s.api.verifiedRouteCaller(r, connectorName, true, presented)
	}
	in := routeCallerInputs{Windows: s.goos == "windows", Connector: connectorName, OwnerUID: s.ownerUID}
	if s.tokens.Valid(connectorName, presented) {
		in.CredentialIdentity = s.tokens.owner
		if !in.Windows {
			in.CredentialIdentity = strconv.Itoa(s.ownerUID)
		}
	}
	if !in.Windows && in.CredentialIdentity != "" {
		in.PeerUID, in.PeerUIDErr = acpLoopbackPeerUID(r)
	}
	return decideRouteCaller(in)
}

// custody reports whether this host forwards no agent provider credential
// on route-only: managed Windows and managed macOS (DESIGN 16.2); managed
// Linux holds its port through socket activation, OSS forwards the user own
// key.
func (s *routeOnlyServer) custody(cfg *config.Config) bool {
	return cfg != nil && cfg.StandaloneEnterprise() && routeOnlyCustodyOS(s.goos)
}

// routeOnlyCustodyOS is the custody rule by OS for managed hosts: the API
// port has no socket activation on Windows and macOS.
func routeOnlyCustodyOS(goos string) bool {
	return goos == "windows" || goos == "darwin"
}

// managedRouteOnlyGOOS selects the custody render of
// ManagedRouteOnlySetup; replaceable in tests.
var managedRouteOnlyGOOS = runtime.GOOS

// holdCredential turns a pass-through attempt into one with the gateway
// credential of a routing.models entry for the same provider and origin
// (credential refs only on managed). false when there is none.
func (s *routeOnlyServer) holdCredential(cfg *config.Config, a *routeOnlyAttempt, provider string) bool {
	key := routeOnlyHeldCredential(cfg, a.base, provider)
	if key == "" {
		return false
	}
	a.keepInbound, a.auth, a.provider = false, key, provider
	return true
}

// routingCredentialValue reads a protected routing credential (managed
// hosts only); replaceable in tests.
var routingCredentialValue = func(cfg *config.Config, name string) string { return cfg.RoutingCredential(name) }

func routeOnlyHeldCredential(cfg *config.Config, base, provider string) string {
	if cfg == nil {
		return ""
	}
	origin := originOf(base)
	for _, m := range cfg.Routing.Models {
		if !strings.EqualFold(m.Provider, provider) || strings.TrimSpace(m.Credential) == "" {
			continue
		}
		mOrigin := originOf(m.BaseURL)
		if mOrigin == "" {
			mOrigin = providerDefaultOrigins[strings.ToLower(m.Provider)]
		}
		if !strings.EqualFold(mOrigin, origin) {
			continue
		}
		if key := routingCredentialValue(cfg, m.Credential); key != "" {
			return key
		}
	}
	return ""
}

// routeCallerRefusalText is the 401 message for an unverified caller.
func routeCallerRefusalText(reason string) string {
	switch reason {
	case routeCallerCredentialInvalid:
		return "missing or invalid route credential; run defenseclaw doctor"
	case routeCallerNotOwner:
		return "the caller is not the account this gateway runs as"
	case routeCallerCredentialMismatch, routeCallerPeerMismatch:
		return "the route credential belongs to another account"
	default:
		return "this account is not verified for routing through DefenseClaw (" + reason + "); run defenseclaw doctor"
	}
}

// proxyKernelPeer is the guardrail proxy verified caller (S1 DESIGN 15.2,
// Q3): only on a managed host with routing.enabled, by the same rules as
// route-only without a route credential; OSS and routing off keep the
// 1.0.9 token behaviour.
func (s *Sidecar) proxyKernelPeer(r *http.Request, connectorName string) (string, bool) {
	if !proxyKernelPeerAllowed(s.currentConfig(), connectorName, routeCallerWindows) {
		return "", false
	}
	caller := s.apiSnapshot().verifiedRouteCaller(r, connectorName, false, "")
	return caller.Subject, caller.Verified
}

// proxyKernelPeerAllowed reports whether the guardrail proxy asks for the
// kernel peer: managed + routing.enabled only, and not on Windows yet. The
// Windows peer SID carries the creation-time PID reuse check
// (peercred.ownerSIDLookup, REVIEW-code-slice4 P1-1), but the guardrail
// proxy has no second factor there, so it stays off until the live probe
// on the managed Windows host (CERT-110, S1 slice 4) confirms the lookup;
// the proxy keeps the 1.0.9 base-only answer meanwhile.
func proxyKernelPeerAllowed(cfg *config.Config, connectorName string, windows bool) bool {
	if windows {
		return false
	}
	return cfg != nil && cfg.StandaloneEnterprise() && cfg.Routing.Enabled && connectorName != ""
}
