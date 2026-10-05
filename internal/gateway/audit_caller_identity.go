// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Audit attribution keys. They are the keys the hook_decision and
// tool.invocation rows already carry, so one filter on the audit export
// finds every row of a user's calls.
const (
	auditUserIDKey     = "user.id"
	auditUserIDKindKey = "defenseclaw.user.id_kind"
	auditUserNameKey   = "defenseclaw.user.name"
)

// auditCaller is the caller identity an audit row carries.
type auditCaller struct {
	ID     string
	IDKind string
	Name   string
	// Identity is the caller's directory and session attribution, verified
	// facts only for the verified caller (identity_subject.go). It is not
	// part of the audit row.
	Identity *llmEventIdentity
}

// verifiedAuditCaller is the caller a standalone gateway has proven: the
// kernel-verified hook-socket peer, or the account a per-user credential is
// bound to. ok is false when neither applies.
func verifiedAuditCaller(ctx context.Context) (auditCaller, bool) {
	if ctx == nil {
		return auditCaller{}, false
	}
	if peer, found := managedHookPeerFromContext(ctx); found {
		return auditCaller{ID: strconv.Itoa(peer.UID), IDKind: useridentity.KindPOSIXUID, Name: peer.Name}, true
	}
	if identity, _ := ctx.Value(verifiedUserScopedIdentityContextKey{}).(string); identity != "" {
		caller := auditCaller{ID: identity, IDKind: useridentity.KindForID(identity)}
		if agent := AgentIdentityFromContext(ctx); agent.UserID == identity {
			caller.Name = agent.UserName
		}
		return caller, true
	}
	return auditCaller{}, false
}

// auditCallerIdentity is the caller identity for an audit row of an
// accepted or rejected request: the verified caller on a standalone
// gateway (none for a request it could not attribute), and on a per-user
// gateway, which runs as its user, the correlation identity the
// hook_decision rows carry.
func auditCallerIdentity(ctx context.Context) auditCaller {
	if caller, ok := verifiedAuditCaller(ctx); ok {
		caller.Identity = requestIdentityFor(ctx, caller.ID)
		return caller
	}
	if ctx == nil || serviceAccountGatewayFromContext(ctx) {
		return auditCaller{}
	}
	agent := AgentIdentityFromContext(ctx)
	caller := auditCaller{ID: agent.UserID, IDKind: agent.UserIDKind, Name: agent.UserName}
	caller.Identity = requestIdentityFor(ctx, caller.ID)
	return caller
}

// addTo copies the non-empty identity fields into a structured audit
// payload.
func (c auditCaller) addTo(structured map[string]any) {
	for key, value := range map[string]string{
		auditUserIDKey: c.ID, auditUserIDKindKey: c.IDKind, auditUserNameKey: c.Name,
	} {
		if value = strings.TrimSpace(stripLogInjectionRunes(value)); value != "" {
			structured[key] = value
		}
	}
}

// principalRef names a verified caller in an authentication-failure row
// ("uid:1001", "sid:S-1-5-21-..."), or "".
func (c auditCaller) principalRef() string {
	switch {
	case c.ID == "":
		return ""
	case c.IDKind == useridentity.KindWindowsSID:
		return "sid:" + c.ID
	case c.IDKind == useridentity.KindPOSIXUID:
		return "uid:" + c.ID
	}
	return ""
}
