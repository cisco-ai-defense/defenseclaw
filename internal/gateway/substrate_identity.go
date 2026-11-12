// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The verified caller of an Agent Substrate actor's model call (PLAN D6,
// 1.0.10 stream 1 section 15.2): the person the launcher verified with
// OIDC and bound to the actor at create, or the CI workload that launched
// it. It is attached as the request's VerifiedSubject, the same way the
// host authentication points attach theirs, so stream 1 routing and its
// admin rules, stream 10 usage (CallFacts.Subject, SubjectKind, Groups)
// and guardrail profile selection all read one caller. An actor with no
// bound person (attributed, D3) gets no subject: it is unverified and
// only the floor policy applies. Nothing the request sends is read.
const (
	// subjectSourceSubstrateActor is a launcher-bound person (OIDC).
	subjectSourceSubstrateActor = "substrate_actor"
	// subjectSourceSubstrateWorkload is a CI workload identity (OIDC
	// workload token) that launched an unattended actor.
	subjectSourceSubstrateWorkload = "substrate_workload"

	// substrateSubjectIDKind is defenseclaw.user.id_kind of an OIDC
	// subject (telemetry registry version 4, PLAN section 11).
	substrateSubjectIDKind = "oidc_subject"

	// Identity sources (defenseclaw.user.identity.source) of the
	// directory facts: the groups come from the sign-in token.
	substrateIdentitySourceOIDC     = "oidc"
	substrateIdentitySourceWorkload = "workload_oidc"
)

// substrateVerifiedSubject is the VerifiedSubject of a registration's
// person; ok is false for an actor with no bound person.
func substrateVerifiedSubject(reg registry.Registration, at time.Time) (userID, userName, source string, facts useridentity.DirectoryFacts, ok bool) {
	p := reg.Person
	if reg.Attributed || p.Subject == "" {
		return "", "", "", useridentity.DirectoryFacts{}, false
	}
	source, factSource := subjectSourceSubstrateActor, substrateIdentitySourceOIDC
	if p.Kind == identity.PersonWorkload {
		source, factSource = subjectSourceSubstrateWorkload, substrateIdentitySourceWorkload
	}
	facts = useridentity.DirectoryFacts{
		Principal: p.Principal,
		UPN:       p.Principal,
		// Groups as the identity provider asserted them at sign-in: the
		// directory facts profile assignments match on.
		Groups: append([]string(nil), p.Groups...),
		Source: factSource,
		// The facts are complete as of the sign-in: a profile selector
		// must not treat them as an unfinished lookup.
		ResolvedAt: at,
	}
	return sanitizeLLMEventUser(p.Subject), sanitizeLLMEventUser(p.Principal), source, facts, true
}

// attachSubstrateSubject attaches the actor's verified person to ctx
// (no-op for an actor with no bound person).
func (a *APIServer) attachSubstrateSubject(ctx context.Context, reg registry.Registration) context.Context {
	userID, userName, source, facts, ok := substrateVerifiedSubject(reg, reg.CreatedAt)
	if !ok {
		return ctx
	}
	if facts.ResolvedAt.IsZero() {
		facts.ResolvedAt = time.Now()
	}
	return attachVerifiedSubjectFacts(ctx, a.observabilityV8RuntimeEmitter(), userID, substrateSubjectIDKind, userName, source, facts)
}

// isSubstrateSubjectSource reports a subject a Substrate actor's
// registration supplied.
func isSubstrateSubjectSource(source string) bool {
	return source == subjectSourceSubstrateActor || source == subjectSourceSubstrateWorkload
}
