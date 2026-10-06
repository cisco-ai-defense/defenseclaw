// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
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
// hook's claimed login session for a POSIX uid. Callers are the three
// authentication points; nothing a caller sent can reach it.
func (a *APIServer) attachVerifiedSubject(ctx context.Context, userID, userName, source string) context.Context {
	if ctx == nil || userID == "" || !identityFactsEnabled.Load() {
		return ctx
	}
	facts, _ := verifiedIdentityDirectory(userID, identityLookupBlocking.Load())
	subject := VerifiedSubject{
		UserID:    userID,
		IDKind:    useridentity.KindForID(userID),
		UserName:  useridentity.BareAccountName(userName),
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
			if verified, ok := verifyPeerSession(uid, userName, claimed.Session); ok {
				session = verified
				ctx = withVerifiedSession(ctx, verified)
			}
		}
	}
	a.observeIdentity(ctx, subject, session)
	return ctx
}

// attachProcessOwnerSubject verifies the caller of a per-user gateway as the
// gateway's own account: the gateway runs as its user, and only that account
// can read the hook token the request presented. A service-account gateway
// (any managed install) and sandbox traffic never take this path.
func (a *APIServer) attachProcessOwnerSubject(ctx context.Context) context.Context {
	if ctx == nil || !identityFactsEnabled.Load() || gatewayRunsAsServiceAccount() || a.userScopedCredentialsRequired() {
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
	return a.attachVerifiedSubject(ctx, id, name, subjectSourceProcessOwner)
}

// identityObservedState remembers when each user's identity.observed record
// was last emitted, so the low-rate record goes out once per user per
// identity cache lifetime.
var identityObservedState = struct {
	sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

const identityObservedMaxUsers = 4096

func identityObservedDue(userID string, now time.Time) bool {
	identityObservedState.Lock()
	defer identityObservedState.Unlock()
	if last, ok := identityObservedState.last[userID]; ok && now.Sub(last) < identityDirectoryTTL {
		return false
	}
	if len(identityObservedState.last) >= identityObservedMaxUsers {
		identityObservedState.last = map[string]time.Time{}
	}
	identityObservedState.last[userID] = now
	return true
}

// observeIdentity emits identity.observed for a verified subject whose
// directory facts resolved. It carries the group count, never the names.
func (a *APIServer) observeIdentity(ctx context.Context, subject VerifiedSubject, session useridentity.SessionFacts) {
	if subject.Directory.Empty() || !identityObservedDue(subject.UserID, time.Now()) {
		return
	}
	emitter := a.observabilityV8RuntimeEmitter()
	if emitter == nil {
		return
	}
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
	_, _ = emitter.Emit(ctx, metadata, func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
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
			DefenseClawUserName:               hookV8OptionalIdentifier(subject.UserName),
			DefenseClawUserPrincipal:          attrs.Principal,
			DefenseClawUserDomain:             attrs.Domain,
			DefenseClawUserDirectory:          attrs.Directory,
			DefenseClawUserTenantID:           attrs.TenantID,
			DefenseClawUserIdentitySource:     attrs.Source,
			DefenseClawUserGroupCount:         observability.Present(groups),
			DefenseClawSessionKind:            attrs.SessionKind,
		})
	})
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
