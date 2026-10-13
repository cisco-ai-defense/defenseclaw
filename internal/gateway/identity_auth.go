// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// attachVerifiedSubject records the authenticated end user of a request,
// with their directory facts from the in-memory cache, and confirms the
// hook's claimed login session for a POSIX uid. Callers are the
// authentication points; nothing a caller sent can reach it. emitter
// carries the identity.observed record and may be nil.
func attachVerifiedSubject(ctx context.Context, emitter sidecarRuntimeEmitter, userID, userName, source string) context.Context {
	if ctx == nil || userID == "" || !identityFactsEnabled.Load() {
		return ctx
	}
	facts, _ := verifiedIdentityDirectory(userID, identityLookupBlocking.Load())
	name := verifiedAccountName(userID, userName)
	if name == "" {
		name = spooledAccountName(userID)
	}
	subject := VerifiedSubject{
		UserID:    userID,
		IDKind:    useridentity.KindForID(userID),
		UserName:  name,
		Directory: facts,
		Source:    source,
	}
	ctx = withVerifiedSubject(ctx, subject)
	// The correlation middleware ran before authentication and took the
	// user from the loopback X-DefenseClaw-User-* headers, which any local
	// caller holding the token can set. The verified subject replaces that
	// claim, so audit and telemetry name the account that was proved.
	id := AgentIdentityFromContext(ctx)
	id.UserID, id.UserIDKind, id.UserName = subject.UserID, subject.IDKind, subject.UserName
	ctx = ContextWithAgentIdentity(ctx, id)
	var session useridentity.SessionFacts
	if subject.IDKind == useridentity.KindPOSIXUID {
		if claimed, ok := claimedSessionFromContext(ctx); ok {
			uid, _ := strconv.Atoi(userID)
			pid := 0
			if peer, ok := managedHookRequestPeer(ctx); ok && peer.UID == uid {
				pid = peer.PID
			}
			if verified, ok := verifyPeerSession(uid, pid, userName, claimed.Session); ok {
				session = verified
				ctx = withVerifiedSession(ctx, verified)
			}
		}
	}
	observeIdentity(ctx, emitter, subject, session)
	return ctx
}

// verifiedAccountName preserves a Windows SID's literal account spelling.
// LSA lookups return the domain separately; a guardian spool may prefix it
// with DOMAIN\. Neither form makes an @ in the account a UPN suffix.
func verifiedAccountName(id, name string) string {
	if useridentity.KindForID(id) == useridentity.KindWindowsSID {
		name = strings.TrimSpace(name)
		if at := strings.LastIndexByte(name, '\\'); at >= 0 {
			return name[at+1:]
		}
		return name
	}
	return useridentity.BareAccountName(name)
}

// spooledAccountName is the bare name the guardian recorded for the account
// id, for a request whose caller was proved by id but not named: a domain
// controller that is down and an SSSD with a cold cache answer "no such user"
// for a uid that exists, and the audit rows of the request then carried no
// name at all (GAP-0231). The guardian resolved the name as root while the
// directory answered, and the record is trusted for as long as its facts
// (identitySpoolMaxAge). The name only attributes the audit rows: it takes no
// part in authorization, which keeps matching the name the account database
// gave (managedHookPeer.Name).
func spooledAccountName(id string) string {
	record, ok := readIdentitySpoolFacts(id, time.Now())
	if !ok {
		return ""
	}
	return verifiedAccountName(id, sanitizeLLMEventUser(record.User))
}

// attachProcessOwnerSubject verifies the caller of a per-user gateway as the
// gateway's own account: the gateway runs as its user, and only that account
// can read the hook, ACP or gateway token the request presented. A
// service-account gateway (any managed install) and sandbox traffic never
// take this path.
func (a *APIServer) attachProcessOwnerSubject(ctx context.Context) context.Context {
	if a.userScopedCredentialsRequired() {
		return ctx
	}
	return attachProcessOwner(ctx, a.observabilityV8RuntimeEmitter())
}

// attachProcessOwner is attachProcessOwnerSubject for listeners that do not
// know the enterprise profile, such as the LLM proxy; a standalone gateway
// runs as a service account, which gatewayRunsAsServiceAccount covers.
func attachProcessOwner(ctx context.Context, emitter sidecarRuntimeEmitter) context.Context {
	if ctx == nil || !identityFactsEnabled.Load() || gatewayRunsAsServiceAccount() {
		return ctx
	}
	if _, sandboxed := sandboxauth.FromContext(ctx); sandboxed {
		return ctx
	}
	if _, ok := verifiedSubjectFromContext(ctx); ok {
		return ctx
	}
	id, name := localProcessUser()
	if id == "" {
		return ctx
	}
	return attachVerifiedSubject(ctx, emitter, id, name, subjectSourceProcessOwner)
}

// identityObservedState remembers when each user's identity.observed record
// was last emitted and for which facts, so the low-rate record goes out once
// per user per identity cache lifetime, and again as soon as a request
// carries changed facts (a group added or removed in the directory).
var identityObservedState = struct {
	sync.Mutex
	last    map[string]identityObservedMark
	pending map[string]bool
}{last: map[string]identityObservedMark{}, pending: map[string]bool{}}

type identityObservedMark struct {
	at          time.Time
	fingerprint string
}

const identityObservedMaxUsers = 4096

func identityObservedBegin(userID string, facts useridentity.DirectoryFacts, now time.Time) (func(bool), bool) {
	fingerprint := identityFactsFingerprint(facts)
	identityObservedState.Lock()
	defer identityObservedState.Unlock()
	if identityObservedState.pending == nil {
		identityObservedState.pending = map[string]bool{}
	}
	if identityObservedState.pending[userID] {
		return nil, false
	}
	if last, ok := identityObservedState.last[userID]; ok && last.fingerprint == fingerprint && now.Sub(last.at) < identityDirectoryTTL {
		return nil, false
	}
	identityObservedState.pending[userID] = true
	return func(success bool) {
		identityObservedState.Lock()
		defer identityObservedState.Unlock()
		delete(identityObservedState.pending, userID)
		if !success {
			return
		}
		if len(identityObservedState.last) >= identityObservedMaxUsers {
			identityObservedState.last = map[string]identityObservedMark{}
		}
		identityObservedState.last[userID] = identityObservedMark{at: now, fingerprint: fingerprint}
	}, true
}

// identityFactsFingerprint digests the directory facts an identity.observed
// record reports or derives from, groups in sorted order.
func identityFactsFingerprint(facts useridentity.DirectoryFacts) string {
	groups := append([]string(nil), facts.Groups...)
	sort.Strings(groups)
	digest := sha256.New()
	for _, part := range append([]string{facts.Principal, facts.UPN, facts.Domain, facts.Realm,
		string(facts.Directory), facts.TenantID, facts.Source}, groups...) {
		digest.Write([]byte(part))
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil)[:12])
}

// observeIdentity emits identity.observed for a verified subject whose
// directory facts resolved. It carries the group count, never the names.
func observeIdentity(ctx context.Context, emitter sidecarRuntimeEmitter, subject VerifiedSubject, session useridentity.SessionFacts) {
	if emitter == nil || subject.Directory.Empty() {
		return
	}
	// Facts older than the cache lifetime are the stale ones the cache serves
	// while one background lookup replaces them. Reporting them would put the
	// account's pre-change group count on a record that is not repeated for
	// another lifetime; the first request after the refresh reports the
	// current facts (GAP-0172).
	if resolved := subject.Directory.ResolvedAt; !resolved.IsZero() && time.Since(resolved) >= identityDirectoryTTL {
		return
	}
	finish, due := identityObservedBegin(subject.UserID, subject.Directory, time.Now())
	if !due {
		return
	}
	success := false
	defer func() { finish(success) }()
	// identity.observed belongs to the gateway activity producer's
	// compliance.activity set; no producer is registered under "identity",
	// so classifying under that key failed and nothing was ever emitted.
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey(gatewaylog.EventActivity),
		observability.ClassificationContext{
			Bucket:      observability.BucketComplianceActivity,
			EventName:   observability.EventName(observability.TelemetryEventIdentityObserved),
			RawSeverity: "INFO",
		},
		observability.SourceGateway,
		"",
		observability.ProducerKey("identity"),
	)
	if err != nil {
		return
	}
	identity := &llmEventIdentity{Directory: subject.Directory, Session: session}
	attrs := identity.v8()
	groups := identityGroupCount(subject.Directory.Groups)
	if groups > 65535 {
		groups = 65535
	}
	_, emitErr := emitter.Emit(ctx, metadata, func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		correlation := observability.Correlation{RunID: gatewaylog.ProcessRunID(), SidecarInstanceID: gatewaylog.SidecarInstanceID()}
		if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
			correlation.TraceID = spanContext.TraceID().String()
			correlation.SpanID = spanContext.SpanID().String()
		}
		return builder.BuildLogIdentityObserved(observability.LogIdentityObservedInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source: observability.SourceGateway, Action: "identity", Phase: "observe",
				Correlation: correlation,
				Provenance: observability.FamilyProvenanceInput{
					Producer: "defenseclaw", BinaryVersion: version.Current().BinaryVersion,
					ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
			},
			Severity:                          observability.Present(observability.SeverityInfo),
			LogLevel:                          observability.Present(observability.LogLevelInfo),
			UserID:                            subject.UserID,
			DefenseClawUserPrincipalAssurance: string(useridentity.AssuranceVerified),
			DefenseClawUserIDKind:             v8UserIDKind(subject.IDKind),
			DefenseClawUserName:               v8UserName(subject.UserName, hookV8OptionalIdentifier),
			DefenseClawUserPrincipal:          attrs.Principal,
			DefenseClawUserDomain:             attrs.Domain,
			DefenseClawUserDirectory:          attrs.Directory,
			DefenseClawUserTenantID:           attrs.TenantID,
			DefenseClawUserIdentitySource:     attrs.Source,
			DefenseClawUserGroupCount:         observability.Present(groups),
			DefenseClawSessionKind:            attrs.SessionKind,
		})
	})
	success = emitErr == nil
}

// identityGroupCount counts an account's groups. Windows facts list each
// group's SID followed by its name, so there the SIDs are counted.
func identityGroupCount(groups []string) int64 {
	sids := int64(0)
	for _, group := range groups {
		if strings.HasPrefix(strings.ToUpper(group), "S-1-") {
			sids++
		}
	}
	if sids > 0 {
		return sids
	}
	return int64(len(groups))
}
