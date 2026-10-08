// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Human identity: verified vs claimed.
//
// A request's end user is verified when the gateway proved who is calling:
// the kernel-verified peer on the hook socket (managedHookPeerAuth), the
// account a per-user credential is bound to (serveUserScoped), or, on a
// per-user gateway, the gateway's own process owner, since only that account
// can read its hook token. The gateway then resolves that account's
// directory facts itself (NSS, the guardian identity spool, the Windows
// identity store) and attaches them once, as a VerifiedSubject.
//
// Everything a hook reports is claimed: the X-DefenseClaw-Session-Facts
// header (Kerberos principal, SSH and logind session) and the hook payload.
// Claimed facts are attribution only. They never change a verified fact and
// never select a guardrail profile. The gateway upgrades a claimed session
// to verified only when it confirms the session belongs to the verified uid
// itself (logind or utmp on Linux).
//
// With the Secure Client integration none of this runs: the header is
// ignored and no new attribute is emitted, so records stay byte-identical.

// VerifiedSubject is the authenticated end user of one request. S3's
// guardrail profile selection reads it; it is set once, right after
// authentication, and never from anything the caller sent.
type VerifiedSubject struct {
	// UserID is the uid or SID the kernel or a per-user credential
	// verified; IDKind is its useridentity.Kind*.
	UserID, IDKind, UserName string
	// Directory are the account's verified directory facts. Groups hold
	// group names (Linux, macOS) or SIDs and DOMAIN\names (Windows).
	// Directory.ResolvedAt is zero when the lookup has not completed (it
	// failed, or ran over its budget); a profile selector must then treat
	// the subject's groups as unknown rather than empty.
	Directory useridentity.DirectoryFacts
	// Source names how UserID was verified: one of the subjectSource*
	// constants.
	Source string
}

// How a VerifiedSubject was authenticated.
const (
	subjectSourcePeerCredentials = "peer_credentials"
	subjectSourceUserCredential  = "user_scoped_credential"
	subjectSourceProcessOwner    = "process_owner"
)

type verifiedSubjectContextKey struct{}

// verifiedSubjectFromContext returns the request's verified subject. ok is
// true only for a verified identity.
func verifiedSubjectFromContext(ctx context.Context) (VerifiedSubject, bool) {
	if ctx == nil {
		return VerifiedSubject{}, false
	}
	subject, ok := ctx.Value(verifiedSubjectContextKey{}).(VerifiedSubject)
	if !ok || subject.UserID == "" {
		return VerifiedSubject{}, false
	}
	return subject, true
}

// withVerifiedSubject attaches s. Only the authentication paths call it.
func withVerifiedSubject(ctx context.Context, s VerifiedSubject) context.Context {
	if s.UserID == "" {
		return ctx
	}
	s.Directory.Assurance = useridentity.AssuranceVerified
	return context.WithValue(ctx, verifiedSubjectContextKey{}, s)
}

// identityFactsEnabled is false under the Secure Client integration, where
// nothing in this file may change behaviour. Wired with the other posture
// flags by NewSidecar and applyConfigReload.
var identityFactsEnabled atomic.Bool

func setIdentityFactsEnabled(v bool) {
	identityFactsEnabled.Store(v)
	observability.SetUnicodeUserNames(v)
}

// identityLookupBlocking makes every request for an account whose directory
// lookup has not resolved yet wait for it (up to its budget), not only the
// request that started it. It is on when a guardrail profile assignment
// selects by group or user, which needs the facts on every request.
var identityLookupBlocking atomic.Bool

func setIdentityLookupBlocking(v bool) { identityLookupBlocking.Store(v) }

// userPrincipalCollectionEnabled mirrors ai_discovery.include_user_principal:
// off means no record carries defenseclaw.user.principal or
// defenseclaw.session.kerberos_principal, which identify a person across
// systems, like include_user_email for the address.
var userPrincipalCollectionEnabled atomic.Bool

// SetUserPrincipalCollectionEnabled records ai_discovery.include_user_principal.
func SetUserPrincipalCollectionEnabled(v bool) { userPrincipalCollectionEnabled.Store(v) }

type claimedSessionContextKey struct{}
type verifiedSessionContextKey struct{}

// withClaimedSessionFacts parses the hook's session facts header. The
// correlation middleware calls it for loopback, non-sandbox traffic.
func withClaimedSessionFacts(ctx context.Context, h http.Header) context.Context {
	if !identityFactsEnabled.Load() {
		return ctx
	}
	claimed, ok := useridentity.ParseSessionFactsHeader(h.Get(useridentity.SessionFactsHeader))
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, claimedSessionContextKey{}, claimed)
}

func claimedSessionFromContext(ctx context.Context) (useridentity.ClaimedSessionHeader, bool) {
	if ctx == nil {
		return useridentity.ClaimedSessionHeader{}, false
	}
	claimed, ok := ctx.Value(claimedSessionContextKey{}).(useridentity.ClaimedSessionHeader)
	return claimed, ok
}

// withVerifiedSession attaches session facts the gateway confirmed itself.
func withVerifiedSession(ctx context.Context, session useridentity.SessionFacts) context.Context {
	if session.Empty() {
		return ctx
	}
	session.Assurance = useridentity.AssuranceVerified
	return context.WithValue(ctx, verifiedSessionContextKey{}, session)
}

// llmEventIdentity is the directory and session attribution of one record.
// Directory.Assurance says whether its facts are verified or claimed; the
// session kind and client address are reported only under the same
// assurance (the registry ties defenseclaw.session.kind to
// defenseclaw.user.principal.assurance). The Kerberos principal is always
// claimed.
type llmEventIdentity struct {
	Directory useridentity.DirectoryFacts
	Session   useridentity.SessionFacts
}

// processOwnerIdentity is the directory identity of the gateway's own
// account, for records that no request carries (the OpenClaw stream). The
// account is verified: a per-user gateway runs as it.
func processOwnerIdentity(userID string) *llmEventIdentity {
	if userID == "" || !identityFactsEnabled.Load() {
		return nil
	}
	facts, _ := verifiedIdentityDirectory(userID, false)
	if facts.Empty() {
		return nil
	}
	facts.Assurance = useridentity.AssuranceVerified
	return &llmEventIdentity{Directory: facts}
}

// requestIdentityFor merges the request's verified subject, verified session
// and claimed session facts for the record of userID. Verified facts always
// win: claimed facts fill only what nothing verified, and a claimed
// principal is used only when there are no verified directory facts at all.
// Verified facts are attached only when the record names the verified
// subject, so they can never be stamped onto another account's record.
func requestIdentityFor(ctx context.Context, userID string) *llmEventIdentity {
	if ctx == nil || !identityFactsEnabled.Load() {
		return nil
	}
	var out llmEventIdentity
	subject, verified := verifiedSubjectFromContext(ctx)
	verified = verified && subject.UserID == userID
	if verified && !subject.Directory.Empty() {
		out.Directory = subject.Directory
		out.Directory.Assurance = useridentity.AssuranceVerified
	}
	claimed, hasClaim := claimedSessionFromContext(ctx)
	if session, ok := ctx.Value(verifiedSessionContextKey{}).(useridentity.SessionFacts); ok && verified {
		out.Session = session
	} else if hasClaim {
		out.Session = claimed.Session
		out.Session.Assurance = useridentity.AssuranceClaimed
	}
	if hasClaim {
		// Always claimed, whatever verified the rest of the session.
		out.Session.KerberosPrincipal = claimed.Session.KerberosPrincipal
		out.Session.CCacheType = claimed.Session.CCacheType
	}
	if out.Directory.Empty() && hasClaim {
		principal := firstNonEmpty(claimed.UPN, claimed.Session.KerberosPrincipal)
		if principal != "" {
			out.Directory = useridentity.DirectoryFacts{
				Principal: principal,
				UPN:       claimed.UPN,
				Realm:     useridentity.RealmOf(principal),
				Source:    useridentity.SourceHookReported,
				Assurance: useridentity.AssuranceClaimed,
			}
			out.Directory.Domain = strings.ToLower(out.Directory.Realm)
		}
	}
	if out.Directory.Empty() && out.Session.Empty() {
		return nil
	}
	return &out
}

// v8IdentityAttrs are the correlation.identity user and session fields of
// one v8 record, validated against the registry so a bad value drops the
// field rather than the record.
type v8IdentityAttrs struct {
	Principal, Domain, Directory, TenantID, Source, Assurance observability.Optional[string]
	SessionKind, KerberosPrincipal, ClientAddress             observability.Optional[string]
}

func (id *llmEventIdentity) v8() v8IdentityAttrs {
	attrs := v8IdentityAttrs{
		Principal: observability.Absent[string](), Domain: observability.Absent[string](),
		Directory: observability.Absent[string](), TenantID: observability.Absent[string](),
		Source: observability.Absent[string](), Assurance: observability.Absent[string](),
		SessionKind: observability.Absent[string](), KerberosPrincipal: observability.Absent[string](),
		ClientAddress: observability.Absent[string](),
	}
	if id == nil || !identityFactsEnabled.Load() {
		return attrs
	}
	dir := id.Directory
	assurance := dir.Assurance
	if dir.Empty() {
		assurance = ""
	}
	if userPrincipalCollectionEnabled.Load() {
		attrs.Principal = v8IdentityText(dir.Principal, 512)
		attrs.KerberosPrincipal = v8IdentityText(id.Session.KerberosPrincipal, 512)
	}
	attrs.Domain = v8IdentityText(dir.Domain, 255)
	attrs.Directory = v8IdentityEnum(string(dir.Directory),
		useridentity.DirectoryLocal, useridentity.DirectoryLDAP, useridentity.DirectoryActiveDirectory,
		useridentity.DirectoryEntraID, useridentity.DirectoryOkta, useridentity.DirectoryOther)
	attrs.TenantID = v8IdentityToken(dir.TenantID, 128, false, false)
	attrs.Source = v8IdentityToken(dir.Source, 64, true, false)
	// Session kind and client address ride the record's assurance: report
	// them when they are as trustworthy as the directory facts, or when there
	// are no directory facts and the record is claimed as a whole.
	session := id.Session
	if assurance == "" && !session.Empty() && (session.Kind != "" || session.ClientAddr != "") {
		assurance = session.Assurance
	}
	if session.Assurance == assurance && assurance != "" {
		attrs.SessionKind = v8IdentityEnum(string(session.Kind),
			useridentity.SessionLocal, useridentity.SessionSSH, useridentity.SessionRDP, useridentity.SessionConsole)
		attrs.ClientAddress = v8IdentityToken(session.ClientAddr, 256, false, true)
	}
	if assurance == useridentity.AssuranceVerified || assurance == useridentity.AssuranceClaimed {
		if attrs.Principal.IsPresent() || attrs.Domain.IsPresent() || attrs.Directory.IsPresent() ||
			attrs.TenantID.IsPresent() || attrs.Source.IsPresent() || attrs.SessionKind.IsPresent() ||
			attrs.ClientAddress.IsPresent() {
			attrs.Assurance = observability.Present(string(assurance))
		}
	}
	return attrs
}

// v8IdentityText accepts the registry's "no spaces or controls" pattern.
func v8IdentityText(value string, limit int) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > limit {
		return observability.Absent[string]()
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f {
			return observability.Absent[string]()
		}
	}
	return observability.Present(value)
}

// v8IdentityToken accepts ^(::|[A-Za-z0-9])[A-Za-z0-9._:/-]*$ (client.address,
// when address is set: a compressed IPv6 address may start with "::", as
// the loopback ::1 and an IPv4-mapped ::ffff:a.b.c.d do) or
// ^[A-Za-z0-9][A-Za-z0-9._-]*$ (tenant), or the source token
// ^[a-z][a-z0-9_]{0,63}$ when lowerSource is set.
func v8IdentityToken(value string, limit int, lowerSource, address bool) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > limit {
		return observability.Absent[string]()
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		alnum := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		switch {
		case lowerSource:
			if !(c >= 'a' && c <= 'z' || i > 0 && (c >= '0' && c <= '9' || c == '_')) {
				return observability.Absent[string]()
			}
		case i == 0 && !alnum && !(address && strings.HasPrefix(value, "::")):
			return observability.Absent[string]()
		case !alnum && c != '.' && c != '_' && c != '-' && c != ':' && c != '/':
			return observability.Absent[string]()
		}
	}
	return observability.Present(value)
}

func v8IdentityEnum[T ~string](value string, allowed ...T) observability.Optional[string] {
	for _, candidate := range allowed {
		if value != "" && value == string(candidate) {
			return observability.Present(value)
		}
	}
	return observability.Absent[string]()
}

// v8IdentityFieldNames are the generated input fields correlation.identity
// adds to every identity-bearing family, in v8IdentityAttrs order.
var v8IdentityFieldNames = [...]string{
	"DefenseClawUserPrincipal", "DefenseClawUserDomain", "DefenseClawUserDirectory",
	"DefenseClawUserTenantID", "DefenseClawUserIdentitySource", "DefenseClawUserPrincipalAssurance",
	"DefenseClawSessionKind", "DefenseClawSessionKerberosPrincipal", "ClientAddress",
}

// v8IdentityFieldIndex caches, per generated input type, the index of each
// identity field (or -1 when the family does not carry it).
var v8IdentityFieldIndex sync.Map // reflect.Type -> [len(v8IdentityFieldNames)]int

// applyTo sets the identity fields of a generated builder input (a pointer
// to an observability.*Input struct). Every family that carries
// correlation.identity names the fields identically, so one helper serves
// them all; a field the family lacks is skipped.
func (id *llmEventIdentity) applyTo(input any) {
	if id == nil || !identityFactsEnabled.Load() {
		return
	}
	value := reflect.ValueOf(input)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return
	}
	target := value.Elem()
	indexes := v8IdentityIndexes(target.Type())
	attrs := id.v8()
	values := [...]observability.Optional[string]{
		attrs.Principal, attrs.Domain, attrs.Directory, attrs.TenantID, attrs.Source, attrs.Assurance,
		attrs.SessionKind, attrs.KerberosPrincipal, attrs.ClientAddress,
	}
	for i, index := range indexes {
		if index < 0 {
			continue
		}
		field := target.Field(index)
		if field.CanSet() && field.Type() == reflect.TypeOf(values[i]) {
			field.Set(reflect.ValueOf(values[i]))
		}
	}
}

func v8IdentityIndexes(t reflect.Type) [len(v8IdentityFieldNames)]int {
	if cached, ok := v8IdentityFieldIndex.Load(t); ok {
		return cached.([len(v8IdentityFieldNames)]int)
	}
	var indexes [len(v8IdentityFieldNames)]int
	for i, name := range v8IdentityFieldNames {
		indexes[i] = -1
		if field, ok := t.FieldByName(name); ok && len(field.Index) == 1 {
			indexes[i] = field.Index[0]
		}
	}
	v8IdentityFieldIndex.Store(t, indexes)
	return indexes
}

// applyIdentityPosture wires the identity flags from a committed config:
// off entirely under the Secure Client integration, the guardian spool only
// on the standalone profile, blocking lookups only when a profile
// assignment selects by group or user.
func applyIdentityPosture(cfg *config.Config) {
	if cfg == nil {
		return
	}
	enabled := !cfg.SecureClientIntegration()
	setIdentityFactsEnabled(enabled)
	SetUserPrincipalCollectionEnabled(enabled && cfg.AIDiscovery.IncludeUserPrincipal)
	spool := ""
	if enabled && cfg.StandaloneEnterprise() {
		spool = enterprisehooks.IdentitySpoolDir(managed.HookGuardianAuthorizationDir(cfg.DataDir))
	}
	setIdentitySpoolDir(spool)
	// A managed Windows scan takes each profile owner's Claude Code and
	// Codex address from the owner's identity record, which the SYSTEM
	// enumerator writes (GAP-1025).
	if spool != "" && runtime.GOOS == "windows" {
		inventory.SetOwnerEmailLookup(identitySpoolConnectorEmail)
	} else {
		inventory.SetOwnerEmailLookup(nil)
	}
	// A managed gateway keeps the last home of each uid across restarts, so
	// one that starts during a directory outage keeps the agent identities
	// (GAP-0314). Secure Client persists nothing new.
	homes := ""
	if enabled && managed.IsManagedEnterprise(cfg.DeploymentMode) && strings.TrimSpace(cfg.DataDir) != "" {
		homes = filepath.Join(cfg.DataDir, "managed_peer_homes.json")
	}
	setManagedHookPeerHomeStore(homes)
	blocking := false
	for _, assignment := range cfg.Guardrail.ProfileAssignments {
		if len(assignment.Match.Groups) > 0 || len(assignment.Match.Users) > 0 {
			blocking = true
			break
		}
	}
	setIdentityLookupBlocking(enabled && blocking)
}
