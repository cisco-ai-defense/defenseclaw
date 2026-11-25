// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// A link created by one agent call may be used by a later call. This memo
// stores only proved credential members and placed aliases, never call text.
const (
	effectAliasSessionLimit    = 128
	effectAliasPerSessionLimit = 32
	effectAliasTTL             = 30 * time.Minute
	effectAliasMaxSessionBytes = 256
	effectAliasMaxPathBytes    = 4096
)

type effectAliasKey struct {
	connector, session, home string
}
type effectAliasEntry struct {
	proof decide.Proof
	at    time.Time
}
type effectAliasSession struct {
	aliases map[string]effectAliasEntry
	at      time.Time
}

// effectAliasUse is one Known read or write of the call through a remembered
// alias: the member's class proof and the index of the using effect, so the
// caller grades it as the plain spelling of the member (its own read flow,
// the class write cell).
type effectAliasUse struct {
	proof  decide.Proof
	effect int
}
type effectAliasMemo struct {
	mu       sync.Mutex
	sessions map[effectAliasKey]*effectAliasSession
}

var sessionEffectAliases effectAliasMemo

// effectAliasPending holds a call's memo change until the hook decides
// whether the tool will run. A blocked call must not create or erase aliases.
type effectAliasPending struct {
	request trustedActionRequest
	result  effects.Result
	facts   []*semanticpb.EffectFact
	flavor  effects.Flavor
	ready   bool
}

func (p *effectAliasPending) set(request trustedActionRequest, result effects.Result, facts []*semanticpb.EffectFact, flavor effects.Flavor) {
	request.aliasPending = nil
	p.request, p.result, p.facts, p.flavor, p.ready = request, result, facts, flavor, true
}

// An approval request is not evidence that the tool ran. Observe-mode
// downgrades are already reflected in Action at the final commit point.
func aliasVerdictCanRun(v *ToolInspectVerdict) bool {
	return v != nil && (v.Action == guardrailActionAllow || v.Action == guardrailActionAlert)
}

func (p *effectAliasPending) commit() {
	if p != nil && p.ready {
		sessionEffectAliases.remember(p.request, p.result, p.facts, p.flavor)
	}
}

// Only calls with bounded alias-key fields need a pending recorder. The
// storage path validates their contents after the verdict.
func deferEffectAlias(request trustedActionRequest) bool {
	return request.Connector != "" && len(request.Connector) <= 64 &&
		request.sessionID != "" && len(request.sessionID) <= effectAliasMaxSessionBytes &&
		request.Input.ActiveHome != "" && len(request.Input.ActiveHome) <= effectAliasMaxPathBytes
}

func aliasKey(request trustedActionRequest) (effectAliasKey, bool) {
	key := effectAliasKey{
		connector: strings.TrimSpace(request.Connector),
		session:   strings.TrimSpace(request.sessionID),
		home:      request.Input.ActiveHome,
	}
	return key, key.connector != "" && len(key.connector) <= 64 &&
		key.session != "" && len(key.session) <= effectAliasMaxSessionBytes &&
		key.home != "" && len(key.home) <= effectAliasMaxPathBytes
}

func (m *effectAliasMemo) uses(request trustedActionRequest, result effects.Result) []effectAliasUse {
	key, ok := aliasKey(request)
	if !ok {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	session := m.sessions[key]
	if session == nil {
		return nil
	}
	now := time.Now()
	if now.Sub(session.at) > effectAliasTTL {
		delete(m.sessions, key)
		return nil
	}
	var uses []effectAliasUse
	for i, e := range result.Effects {
		if e.TargetState != effects.TargetStateKnown || e.RoleState != effects.RoleStateKnown || len(e.Reasons) != 0 {
			continue
		}
		var kind decide.ProofKind
		switch e.Kind {
		case effects.KindRead:
			kind = decide.KindRead
		case effects.KindWrite:
			kind = decide.KindWrite
		case effects.KindAppend:
			kind = decide.KindAppend
		default:
			continue
		}
		if len(e.Target.Path) > effectAliasMaxPathBytes {
			continue
		}
		entry, found := session.aliases[e.Target.Path]
		if !found {
			continue
		}
		if now.Sub(entry.at) > effectAliasTTL {
			delete(session.aliases, e.Target.Path)
			continue
		}
		entry.at = now
		session.aliases[e.Target.Path] = entry
		session.at = now
		p := entry.proof
		p.Kind = kind
		uses = append(uses, effectAliasUse{proof: p, effect: i})
	}
	return uses
}

func (m *effectAliasMemo) remember(request trustedActionRequest, result effects.Result, facts []*semanticpb.EffectFact, flavor effects.Flavor) {
	key, ok := aliasKey(request)
	if !ok {
		return
	}
	relevant, hasLink := false, false
	for _, e := range result.Effects {
		if e.Kind == effects.KindDelete || aliasReplacedByWrite(e) {
			relevant = true
		}
		if e.Kind == effects.KindLink && e.LinkTarget {
			relevant, hasLink = true, true
		}
	}
	if !relevant {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions == nil {
		if !hasLink {
			return
		}
		m.sessions = make(map[effectAliasKey]*effectAliasSession)
	}
	session := m.sessions[key]
	if session == nil && !hasLink {
		return
	}
	now := time.Now()
	for k, s := range m.sessions {
		if now.Sub(s.at) > effectAliasTTL {
			delete(m.sessions, k)
		}
	}
	session = m.sessions[key]
	if session != nil {
		for _, e := range result.Effects {
			if (e.Kind == effects.KindDelete || aliasReplacedByWrite(e)) && e.Target.Path != "" {
				delete(session.aliases, e.Target.Path)
			}
		}
	}
	for i, e := range result.Effects {
		if !e.LinkTarget || e.Kind != effects.KindLink || e.Cond || i+1 >= len(result.Effects) || i >= len(facts) {
			continue
		}
		at := result.Effects[i+1]
		if at.Kind != effects.KindLink || at.LinkTarget || at.Cond || at.Origin.Command != e.Origin.Command ||
			len(at.Target.Path) > effectAliasMaxPathBytes ||
			!effectrules.CanonicalAbsolute(at.Target.Path, flavor) {
			continue
		}
		proof, known := knownAliasCredential(facts[i])
		if session == nil && !known {
			continue
		}
		if session == nil {
			if len(m.sessions) >= effectAliasSessionLimit {
				m.evictOldestSession()
			}
			session = &effectAliasSession{aliases: make(map[string]effectAliasEntry)}
			m.sessions[key] = session
		}
		// A later link at the same alias supersedes the old member, including a
		// link to a non-credential target.
		delete(session.aliases, at.Target.Path)
		if known {
			if len(session.aliases) >= effectAliasPerSessionLimit {
				evictOldestAlias(session)
			}
			session.aliases[at.Target.Path] = effectAliasEntry{proof: proof, at: now}
		}
		session.at = now
	}
}

// A rename replaces the alias directory entry. An ordinary cp or shell
// redirect follows a destination symlink and leaves the alias in place.
func aliasReplacedByWrite(e effects.Effect) bool {
	return e.Kind == effects.KindWrite && e.Origin.Program == "mv"
}

func knownAliasCredential(f *semanticpb.EffectFact) (decide.Proof, bool) {
	if f.GetTargetState() != "known" || f.GetRoleState() != "known" {
		return decide.Proof{}, false
	}
	set := decide.CredentialSet(effectCredentialMemberTail(f.GetTarget().GetPath()))
	if set == "" {
		return decide.Proof{}, false
	}
	for _, match := range f.GetTarget().GetProtected() {
		if match.GetSet() != effectrules.SetCredentials || match.GetState() != "known" {
			continue
		}
		target := decide.TargetCredential
		switch match.GetReason() {
		case "exact":
		case "other_home":
			target = decide.TargetOtherHomeCredential
		default:
			continue
		}
		return decide.Proof{Kind: decide.KindRead, Target: target, Certainty: decide.CertKnown,
			Set: set, Source: effectProofSource}, true
	}
	return decide.Proof{}, false
}

func (m *effectAliasMemo) evictOldestSession() {
	var oldest effectAliasKey
	var first time.Time
	for key, session := range m.sessions {
		if first.IsZero() || session.at.Before(first) {
			oldest, first = key, session.at
		}
	}
	delete(m.sessions, oldest)
}
func evictOldestAlias(session *effectAliasSession) {
	var oldest string
	var first time.Time
	for path, entry := range session.aliases {
		if first.IsZero() || entry.at.Before(first) {
			oldest, first = path, entry.at
		}
	}
	delete(session.aliases, oldest)
}
