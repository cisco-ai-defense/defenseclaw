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

// Package asks keeps Substrate asks and decisions on the gateway leader
// (PLAN 5.4: asks, approvals and pending outcomes are leader state).
//
// An ask is raised by the callout (through the gateway's callout route) or
// the gateway for one actor; its person answers it from the launcher
// (approvals) or the inline ask row, an administrator as themselves. A
// once approval lets exactly one request through (Use takes it); an always
// approval of a host adds it to the actor's registration (Approved), and
// the controller adds it to the actor's policy on its next pass. Revoke
// takes an always approval back (GAP-0492): its asks answer no request any
// more, and the host leaves the registration (OnRevoke), so the controller
// drops it from the policy on its next pass. A decision is a verdict that
// was not a plain allow (a block, an alert, an ask and its answer), kept so
// a person can see what happened to their actors. Users see only their own
// asks and decisions; the gateway passes the caller's owner key, and the
// store filters by it.
package asks

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// Leader methods.
const (
	MethodAskOpen        = leader.MethodAskOpen
	MethodAskResolve     = leader.MethodAskResolve
	MethodAskList        = "AskList"
	MethodAskUse         = "AskUse"
	MethodAskRevoke      = "AskRevoke"
	MethodDecisionRecord = "DecisionRecord"
	MethodDecisionList   = "DecisionList"
)

// States of an ask.
const (
	StatePending  = "pending"
	StateApproved = "approved"
	StateDenied   = "denied"
	StateExpired  = "expired"
	// StateRevoked is an always approval its person or an administrator
	// took back (GAP-0492): it answers no request any more.
	StateRevoked = "revoked"
)

const (
	maxAsks          = 10000
	maxDecisions     = 20000
	decisionsKept    = 5000 // loaded back after a restart
	DefaultAskExpiry = 30 * time.Minute
)

// Ask is one question waiting for a person.
type Ask struct {
	ID       string `json:"id"`
	Atespace string `json:"atespace"`
	Actor    string `json:"actor"`
	UID      string `json:"uid"`
	OwnerID  string `json:"owner_id"`
	// Profile is the actor's profile when the ask was raised: an Always
	// approval covers later actors of the same person and profile only.
	Profile string `json:"profile,omitempty"`
	// Kind is egress (a host) or tool.
	Kind string `json:"kind"`
	Host string `json:"host,omitempty"`
	Tool string `json:"tool,omitempty"`
	// Rule is the egress rule that asked: "ask_hosts:<pattern>" (an
	// approval covers the host) or "url_rules:<name>" (an approval covers
	// that rule only, its methods and path prefix; GAP-0177). Empty: a host
	// ask from a callout that names no rule.
	Rule     string    `json:"rule,omitempty"`
	Summary  string    `json:"summary,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	State    string    `json:"state"`
	// DecidedBy is the deciding person's owner key. Always keeps the
	// approval for every later request of this actor and for later runs of
	// the same person and profile (the gateway's callout ask route answers
	// their asks for the same host or rule with it, GAP-0387); without it
	// the approval lets one request through, and UsedAt is when that
	// request took it (GAP-0484).
	DecidedBy string    `json:"decided_by,omitempty"`
	DecidedAt time.Time `json:"decided_at,omitzero"`
	Always    bool      `json:"always,omitempty"`
	UsedAt    time.Time `json:"used_at,omitzero"`
	// RevokedBy and RevokedAt are who took an always approval back, and
	// when (GAP-0492).
	RevokedBy string    `json:"revoked_by,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitzero"`
	Note      string    `json:"note,omitempty"`
	// Unattended marks an ask an unattended actor queued (D12
	// unattended_asks: queue): nobody is watching the run, so a person
	// decides from `asks`, and the timeout denies it.
	Unattended bool `json:"unattended,omitempty"`
	// TimeoutSeconds, when over 0, replaces the store's expiry for this ask
	// (the profile's ask_timeout, at most 24 h).
	TimeoutSeconds int64 `json:"timeout_seconds,omitempty"`
}

// MaxAskTimeout bounds Ask.TimeoutSeconds (config ask_timeout).
const MaxAskTimeout = 24 * time.Hour

// KindSecretBinding is an administrator ask for a person's own secret
// binding to a host no template covers (B1 S4). It has no actor: Tool is
// the binding name, Rule is BindingRule(id), and only an administrator
// decides it (the person who asked sees it and waits).
const KindSecretBinding = "secret_binding"

// MaxBindingAskTimeout bounds a secret_binding ask
// (self_service_secrets.ask_timeout, at most 168h).
const MaxBindingAskTimeout = 168 * time.Hour

const bindingRulePrefix = "binding:"

// BindingRule is the Rule of the secret_binding ask for binding id.
func BindingRule(id string) string { return bindingRulePrefix + id }

// KindGitPush is a person's ask to push an actor's work to its origin as
// a branch (B2 2.4, substrate pull --push-branch). Host is the git host,
// Tool the branch and Rule GitPushRule(repo, head). Its approval adds no
// host to the actor's policy and answers again only for the same head
// (RV4-7); with Always it covers the same person, profile and host.
const KindGitPush = "git_push"

const gitPushRulePrefix = "git_push:"

// GitPushRule is the Rule of the git_push ask for repo (the path on its
// host, such as team/app) at the pushed commit head.
func GitPushRule(repo, head string) string { return gitPushRulePrefix + repo + "@" + head }

// BindingID is the binding a secret_binding ask is about, "" for any
// other ask.
func (a Ask) BindingID() string {
	if a.Kind != KindSecretBinding {
		return ""
	}
	id, _ := strings.CutPrefix(a.Rule, bindingRulePrefix)
	return id
}

// Decision is one verdict that was not a plain allow.
type Decision struct {
	At        time.Time `json:"at"`
	Atespace  string    `json:"atespace"`
	Actor     string    `json:"actor"`
	UID       string    `json:"uid"`
	OwnerID   string    `json:"owner_id,omitempty"`
	Source    string    `json:"source"` // hook, ask, callout
	Connector string    `json:"connector,omitempty"`
	Event     string    `json:"event,omitempty"`
	Tool      string    `json:"tool,omitempty"`
	Verdict   string    `json:"verdict"`
	Reason    string    `json:"reason,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	DecidedBy string    `json:"decided_by,omitempty"`
}

// ResolveRequest answers an ask.
type ResolveRequest struct {
	ID       string `json:"id"`
	Decision string `json:"decision"` // approve or deny
	Always   bool   `json:"always,omitempty"`
	Note     string `json:"note,omitempty"`
	// CallerID is the deciding person; Admin lets them answer any ask.
	CallerID string `json:"caller_id"`
	Admin    bool   `json:"admin,omitempty"`
}

// ListRequest lists asks or decisions. OwnerID "" is every owner (the
// gateway sends it only for an administrator's all=1).
type ListRequest struct {
	OwnerID     string `json:"owner_id"`
	All         bool   `json:"all,omitempty"`
	PendingOnly bool   `json:"pending_only,omitempty"`
	Atespace    string `json:"atespace,omitempty"`
	Actor       string `json:"actor,omitempty"`
	Limit       int    `json:"limit,omitempty"`
}

// ErrNotFound is an ask that does not exist or is not the caller's.
var ErrNotFound = errors.New("asks: no such ask")

// ErrDecided is an ask that is no longer pending.
var ErrDecided = errors.New("asks: the ask was already answered")

// ErrUsed is an approval that lets no more requests through: a once
// approval another request took, or one older than OnceWindow, or an ask
// that was not approved.
var ErrUsed = errors.New("asks: the approval was already used")

// OnceWindow is how long after its answer a once approval waits for the
// one request it lets through (the held request, or the agent's retry
// after the hold ended).
const OnceWindow = 10 * time.Minute

// UseRequest takes an approval for one request of the actor UID.
type UseRequest struct {
	ID  string `json:"id"`
	UID string `json:"uid"`
}

// RevokeRequest takes back the standing (always) approvals of Host for the
// actor UID (GAP-0492): its always-approved asks, and the host in the
// actor's registration (Store.OnRevoke).
type RevokeRequest struct {
	Atespace string `json:"atespace"`
	Actor    string `json:"actor"`
	UID      string `json:"uid"`
	// OwnerID is the actor's person, for the decision record.
	OwnerID string `json:"owner_id,omitempty"`
	Host    string `json:"host"`
	// Profile is the actor's profile. An always approval that the same
	// person gave on an earlier actor of this profile answers this actor
	// too (the callout ask route, GAP-0387), so the revoke takes it back
	// as well. "" takes back the actor's own approvals only.
	Profile string `json:"profile,omitempty"`
	// CallerID is the person taking the approval back; Admin lets them take
	// back anyone's.
	CallerID string `json:"caller_id"`
	Admin    bool   `json:"admin,omitempty"`
}

// RevokeResult is what a revoke took back.
type RevokeResult struct {
	// Asks are the always approvals that answer no request any more.
	Asks []Ask `json:"asks"`
	// Registration is set when the host left the actor's registration, and
	// so leaves its policy on the controller's next pass.
	Registration bool `json:"registration,omitempty"`
}

// IsNotFound reads either form of the error: the store's wire error (in
// the leader process) or the client's sentinel.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) || wireCode(err) == "not_found" }

// ErrAdminOnly is an ask only an administrator may answer.
var ErrAdminOnly = errors.New("asks: only an administrator answers this ask")

// IsAdminOnly reports a person answering an ask only an administrator may
// answer (a secret_binding ask, even their own).
func IsAdminOnly(err error) bool {
	return errors.Is(err, ErrAdminOnly) || wireCode(err) == "admin_only"
}

// IsDecided reports an ask that was already answered.
func IsDecided(err error) bool { return errors.Is(err, ErrDecided) || wireCode(err) == "decided" }

// IsUsed reports an approval that lets no more requests through.
func IsUsed(err error) bool { return errors.Is(err, ErrUsed) || wireCode(err) == "used" }

func wireCode(err error) string {
	var we *leader.WireError
	if errors.As(err, &we) {
		return we.Code
	}
	return ""
}

// Store is the leader's ask and decision store. Asks are kept one file
// each under Dir; decisions are appended to Dir/decisions.jsonl and the
// last decisionsKept are loaded back on start.
type Store struct {
	Dir string
	// OnApprove runs when an ask is approved always (it adds the host to
	// the actor's registration); an error fails the answer. A once
	// approval never runs it: it is not a standing approval (GAP-0484).
	OnApprove func(ctx context.Context, a Ask) error
	// OnRevoke runs first on a revoke: it removes the host from the actor's
	// registration and reports whether the registration had it; an error
	// fails the revoke (GAP-0492).
	OnRevoke func(ctx context.Context, in RevokeRequest) (bool, error)
	Expiry   time.Duration
	Now      func() time.Time

	mu   sync.Mutex
	asks map[string]*Ask
	// deciding holds the asks with a decision in flight (between the
	// pending check and the write): a second decision is refused and the
	// expiry leaves them alone, so only one answer is ever recorded and
	// returned as a success (RV4 F1).
	deciding  map[string]bool
	decisions []Decision
	log       *os.File
}

// Open loads the store from dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "asks"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{Dir: dir, asks: map[string]*Ask{}}
	entries, _ := os.ReadDir(filepath.Join(dir, "asks"))
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, "asks", e.Name()))
		if err != nil {
			continue
		}
		var a Ask
		if json.Unmarshal(raw, &a) == nil && a.ID != "" {
			s.asks[a.ID] = &a
		}
	}
	if f, err := os.Open(filepath.Join(dir, "decisions.jsonl")); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var d Decision
			if json.Unmarshal(sc.Bytes(), &d) == nil {
				s.decisions = append(s.decisions, d)
			}
		}
		_ = f.Close()
		if len(s.decisions) > decisionsKept {
			s.decisions = s.decisions[len(s.decisions)-decisionsKept:]
		}
	}
	log, err := os.OpenFile(filepath.Join(dir, "decisions.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	s.log = log
	return s, nil
}

// NewMemory is a store without files (tests).
func NewMemory() *Store { return &Store{asks: map[string]*Ask{}} }

// Close closes the decision log.
func (s *Store) Close() error {
	if s.log != nil {
		return s.log.Close()
	}
	return nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) persist(a *Ask) {
	if s.Dir == "" {
		return
	}
	raw, _ := json.Marshal(a)
	p := filepath.Join(s.Dir, "asks", a.ID+".json")
	_ = os.WriteFile(p+".tmp", raw, 0o600)
	_ = os.Rename(p+".tmp", p)
}

func (s *Store) remove(id string) {
	delete(s.asks, id)
	if s.Dir != "" {
		_ = os.Remove(filepath.Join(s.Dir, "asks", id+".json"))
	}
}

// expire marks pending asks past their time expired (and records it).
func (s *Store) expire(now time.Time) {
	for _, a := range s.asks {
		if a.State == StatePending && !a.Expires.IsZero() && now.After(a.Expires) && !s.deciding[a.ID] {
			a.State, a.DecidedAt = StateExpired, now
			s.persist(a)
			s.appendLocked(Decision{At: now, Atespace: a.Atespace, Actor: a.Actor, UID: a.UID, OwnerID: a.OwnerID,
				Source: "ask", Tool: firstNonEmpty(a.Tool, a.Host), Verdict: "expired", Reason: "nobody answered the ask in time"})
		}
	}
	if len(s.asks) > maxAsks {
		ids := make([]string, 0, len(s.asks))
		for id, a := range s.asks {
			if a.State != StatePending {
				ids = append(ids, id)
			}
		}
		sort.Slice(ids, func(i, j int) bool { return s.asks[ids[i]].Created.Before(s.asks[ids[j]].Created) })
		for _, id := range ids {
			if len(s.asks) <= maxAsks*9/10 {
				break
			}
			s.remove(id)
		}
	}
}

// Open raises an ask. The ID is minted here.
func (s *Store) OpenAsk(_ context.Context, a Ask) (Ask, error) {
	maxTimeout := MaxAskTimeout
	if a.Kind == KindSecretBinding {
		// No actor: the binding stands in for it, so the same binding is
		// asked about once and the per-actor cap counts per binding.
		if a.OwnerID == "" || a.Host == "" || a.Tool == "" || a.BindingID() == "" {
			return Ask{}, &leader.WireError{Code: leader.CodeBadRequest, Message: "a binding ask names its owner, binding, name and host"}
		}
		a.Atespace, a.Actor, a.UID, a.Unattended = "", "", a.Rule, false
		maxTimeout = MaxBindingAskTimeout
	} else if a.Atespace == "" || a.UID == "" || (a.Host == "" && a.Tool == "") {
		return Ask{}, &leader.WireError{Code: leader.CodeBadRequest, Message: "an ask names its actor and a host or tool"}
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	now := s.now()
	exp := s.Expiry
	if exp <= 0 {
		exp = DefaultAskExpiry
	}
	if t := time.Duration(a.TimeoutSeconds) * time.Second; a.TimeoutSeconds > 0 {
		exp = min(t, maxTimeout)
	}
	a.ID, a.Created, a.Expires, a.State = "ask-"+hex.EncodeToString(b), now, now.Add(exp), StatePending
	a.DecidedBy, a.DecidedAt, a.Always, a.UsedAt = "", time.Time{}, false, time.Time{}
	if a.Kind == "" {
		a.Kind = "egress"
		if a.Host == "" {
			a.Kind = "tool"
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(now)
	pending := 0
	for _, o := range s.asks {
		if o.State == StatePending && o.UID == a.UID {
			if o.Host == a.Host && o.Tool == a.Tool && o.Rule == a.Rule {
				return *o, nil // the same question is asked once
			}
			pending++
		}
	}
	if pending >= 32 {
		return Ask{}, &leader.WireError{Code: leader.CodeUnavailable, Message: "this actor has too many asks waiting"}
	}
	s.asks[a.ID] = &a
	s.persist(&a)
	return a, nil
}

// Resolve answers an ask for its owner, or for an administrator.
func (s *Store) Resolve(ctx context.Context, in ResolveRequest) (Ask, error) {
	decision := strings.ToLower(strings.TrimSpace(in.Decision))
	if decision != "approve" && decision != "deny" {
		return Ask{}, &leader.WireError{Code: leader.CodeBadRequest, Message: "decision is approve or deny"}
	}
	s.mu.Lock()
	now := s.now()
	s.expire(now)
	a, ok := s.asks[in.ID]
	if !ok || in.CallerID == "" || (!in.Admin && a.OwnerID != in.CallerID) {
		s.mu.Unlock()
		return Ask{}, &leader.WireError{Code: "not_found", Message: ErrNotFound.Error()}
	}
	if a.State != StatePending {
		s.mu.Unlock()
		return Ask{}, &leader.WireError{Code: "decided", Message: ErrDecided.Error()}
	}
	if a.Kind == KindSecretBinding && !in.Admin {
		s.mu.Unlock()
		return Ask{}, &leader.WireError{Code: "admin_only", Message: ErrAdminOnly.Error()}
	}
	if s.deciding[in.ID] {
		s.mu.Unlock()
		return Ask{}, &leader.WireError{Code: "decided", Message: ErrDecided.Error()}
	}
	if s.deciding == nil {
		s.deciding = map[string]bool{}
	}
	s.deciding[in.ID] = true
	out := *a
	s.mu.Unlock()
	out.State, out.DecidedBy, out.DecidedAt, out.Note = StateDenied, in.CallerID, now, truncate(in.Note, 512)
	if decision == "approve" {
		out.State, out.Always = StateApproved, in.Always
		if out.Kind == KindSecretBinding {
			// The gateway moves the binding (it writes the binding store);
			// no registration changes and nothing is kept for later runs.
			out.Always = false
		} else if s.OnApprove != nil && out.Always {
			if err := s.OnApprove(ctx, out); err != nil {
				s.mu.Lock()
				delete(s.deciding, in.ID)
				s.mu.Unlock()
				return Ask{}, err
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.deciding, in.ID)
	cur, ok := s.asks[in.ID]
	if !ok || cur.State != StatePending {
		// The actor's close got there first (CloseActor): this answer is
		// not recorded, and the caller is told so (RV4 F1).
		return Ask{}, &leader.WireError{Code: "decided", Message: ErrDecided.Error()}
	}
	*cur = out
	s.persist(cur)
	s.appendLocked(Decision{At: now, Atespace: out.Atespace, Actor: out.Actor, UID: out.UID, OwnerID: out.OwnerID,
		Source: "ask", Tool: firstNonEmpty(out.Tool, out.Host), Verdict: out.State, Reason: out.Note, DecidedBy: in.CallerID})
	return out, nil
}

// Use takes the approval of ask ID for one request of the actor UID. An
// always approval answers every request and is not changed; a once
// approval answers the first request that takes it, within OnceWindow of
// its answer, and ErrUsed every later one (GAP-0484). The callout asks
// for each request, and the gateway calls Use before it answers approved,
// so no request rides on another's once approval.
func (s *Store) Use(_ context.Context, in UseRequest) (Ask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.asks[in.ID]
	if !ok || in.UID == "" || a.UID != in.UID {
		return Ask{}, &leader.WireError{Code: "not_found", Message: ErrNotFound.Error()}
	}
	now := s.now()
	switch {
	case a.State != StateApproved:
	case a.Always:
		return *a, nil
	case a.UsedAt.IsZero() && now.Before(a.DecidedAt.Add(OnceWindow)):
		a.UsedAt = now
		s.persist(a)
		return *a, nil
	}
	return Ask{}, &leader.WireError{Code: "used", Message: ErrUsed.Error()}
}

// Revoke takes back the always approvals of in.Host for the actor in.UID
// (GAP-0492): OnRevoke removes the host from the registration, and every
// always-approved ask of that host turns revoked, so neither the policy nor
// the callout lets a request through on it any more. Without Admin only
// the caller's own approvals are taken back. ErrNotFound when there was
// nothing to take back.
func (s *Store) Revoke(ctx context.Context, in RevokeRequest) (RevokeResult, error) {
	in.Host = strings.ToLower(strings.TrimSpace(in.Host))
	if in.Atespace == "" || in.UID == "" || in.Host == "" || in.CallerID == "" {
		return RevokeResult{}, &leader.WireError{Code: leader.CodeBadRequest, Message: "a revoke names its actor, a host and the caller"}
	}
	out := RevokeResult{Asks: []Ask{}}
	if s.OnRevoke != nil {
		removed, err := s.OnRevoke(ctx, in)
		if err != nil {
			return RevokeResult{}, err
		}
		out.Registration = removed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, a := range s.asks {
		if a.Host != in.Host || a.State != StateApproved || !a.Always || (!in.Admin && a.OwnerID != in.CallerID) {
			continue
		}
		// The actor's own approvals, and an approval the same person gave
		// on an earlier actor of the same profile: the callout answers this
		// actor (and every later run) with it too (GAP-0387), so leaving it
		// in force would leave the host open after the revoke.
		own := a.UID == in.UID && a.Atespace == in.Atespace
		earlier := in.Profile != "" && in.OwnerID != "" && a.Kind != "tool" && a.OwnerID == in.OwnerID && a.Profile == in.Profile
		if !own && !earlier {
			continue
		}
		a.State, a.RevokedBy, a.RevokedAt = StateRevoked, in.CallerID, now
		s.persist(a)
		out.Asks = append(out.Asks, *a)
	}
	if len(out.Asks) == 0 && !out.Registration {
		return RevokeResult{}, &leader.WireError{Code: "not_found", Message: ErrNotFound.Error()}
	}
	sort.Slice(out.Asks, func(i, j int) bool { return out.Asks[i].Created.Before(out.Asks[j].Created) })
	s.appendLocked(Decision{At: now, Atespace: in.Atespace, Actor: in.Actor, UID: in.UID, OwnerID: in.OwnerID,
		Source: "ask", Tool: in.Host, Verdict: StateRevoked, Reason: "the always approval was taken back", DecidedBy: in.CallerID})
	return out, nil
}

// List lists asks.
func (s *Store) List(_ context.Context, in ListRequest) ([]Ask, error) {
	if in.OwnerID == "" && !in.All {
		return nil, &leader.WireError{Code: leader.CodeBadRequest, Message: "a list names its owner"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(s.now())
	out := []Ask{}
	for _, a := range s.asks {
		if (in.OwnerID != "" && a.OwnerID != in.OwnerID) || (in.PendingOnly && a.State != StatePending) ||
			(in.Atespace != "" && a.Atespace != in.Atespace) || (in.Actor != "" && a.Actor != in.Actor) {
			continue
		}
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

// CloseActor ends every pending ask of the actor UID (E16: a crashed or
// deleted actor asks nothing any more) with state expired and reason, and
// records one decision per ask, as an answer is recorded, whose event is
// code (actor_crashed, actor_reverted, actor_deleted; GAP-0526). It returns
// the asks it closed.
func (s *Store) CloseActor(uid, code, reason string) []Ask {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var closed []Ask
	for _, a := range s.asks {
		if a.UID != uid || a.State != StatePending {
			continue
		}
		a.State, a.DecidedAt, a.Note = StateExpired, now, truncate(reason, 512)
		s.persist(a)
		s.appendLocked(Decision{At: now, Atespace: a.Atespace, Actor: a.Actor, UID: a.UID, OwnerID: a.OwnerID,
			Source: "ask", Event: code, Tool: firstNonEmpty(a.Tool, a.Host), Verdict: StateExpired, Reason: a.Note})
		closed = append(closed, *a)
	}
	sort.Slice(closed, func(i, j int) bool { return closed[i].Created.Before(closed[j].Created) })
	return closed
}

// Pending lists the actor UIDs with an ask waiting (the idle check).
func (s *Store) Pending() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(s.now())
	seen := map[string]bool{}
	var out []string
	for _, a := range s.asks {
		if a.State == StatePending && !seen[a.UID] {
			seen[a.UID] = true
			out = append(out, a.UID)
		}
	}
	return out
}

// Record keeps a decision.
func (s *Store) Record(_ context.Context, d Decision) (struct{}, error) {
	if d.UID == "" || d.Verdict == "" {
		return struct{}{}, &leader.WireError{Code: leader.CodeBadRequest, Message: "a decision names its actor and verdict"}
	}
	if d.At.IsZero() || d.At.After(s.now()) {
		d.At = s.now()
	}
	d.Reason = truncate(d.Reason, 1024)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendLocked(d)
	return struct{}{}, nil
}

func (s *Store) appendLocked(d Decision) {
	s.decisions = append(s.decisions, d)
	if len(s.decisions) > maxDecisions {
		s.decisions = append([]Decision(nil), s.decisions[len(s.decisions)-decisionsKept:]...)
	}
	if s.log != nil {
		raw, _ := json.Marshal(d)
		_, _ = s.log.Write(append(raw, '\n'))
	}
}

// Decisions lists decisions, newest first.
func (s *Store) Decisions(_ context.Context, in ListRequest) ([]Decision, error) {
	if in.OwnerID == "" && !in.All {
		return nil, &leader.WireError{Code: leader.CodeBadRequest, Message: "a list names its owner"}
	}
	limit := in.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Decision{}
	for i := len(s.decisions) - 1; i >= 0 && len(out) < limit; i-- {
		d := s.decisions[i]
		if (in.OwnerID != "" && d.OwnerID != in.OwnerID) || (in.Atespace != "" && d.Atespace != in.Atespace) ||
			(in.Actor != "" && d.Actor != in.Actor) {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

// Serve registers the methods on the leader server.
func Serve(srv *leader.Server, s *Store) {
	srv.Handle(MethodAskOpen, leader.Typed(s.OpenAsk))
	srv.Handle(MethodAskResolve, leader.Typed(s.Resolve))
	srv.HandleRead(MethodAskList, leader.Typed(s.List))
	srv.Handle(MethodAskUse, leader.Typed(s.Use))
	srv.Handle(MethodAskRevoke, leader.Typed(s.Revoke))
	srv.Handle(MethodDecisionRecord, leader.Typed(s.Record))
	srv.HandleRead(MethodDecisionList, leader.Typed(s.Decisions))
}

// Client is the store over the leader transport (gateway replicas).
type Client struct{ Leader *leader.Client }

func (c *Client) OpenAsk(ctx context.Context, a Ask) (Ask, error) {
	var out Ask
	return out, c.Leader.Call(ctx, MethodAskOpen, leader.NewRequestID(), a, &out)
}

func (c *Client) Resolve(ctx context.Context, in ResolveRequest) (Ask, error) {
	var out Ask
	err := c.Leader.Call(ctx, MethodAskResolve, leader.NewRequestID(), in, &out)
	var we *leader.WireError
	if errors.As(err, &we) {
		switch we.Code {
		case "not_found":
			return Ask{}, ErrNotFound
		case "decided":
			return Ask{}, ErrDecided
		}
	}
	return out, err
}

func (c *Client) Use(ctx context.Context, in UseRequest) (Ask, error) {
	var out Ask
	err := c.Leader.Call(ctx, MethodAskUse, leader.NewRequestID(), in, &out)
	var we *leader.WireError
	if errors.As(err, &we) {
		switch we.Code {
		case "not_found":
			return Ask{}, ErrNotFound
		case "used":
			return Ask{}, ErrUsed
		}
	}
	return out, err
}

func (c *Client) Revoke(ctx context.Context, in RevokeRequest) (RevokeResult, error) {
	var out RevokeResult
	err := c.Leader.Call(ctx, MethodAskRevoke, leader.NewRequestID(), in, &out)
	var we *leader.WireError
	if errors.As(err, &we) && we.Code == "not_found" {
		return RevokeResult{}, ErrNotFound
	}
	return out, err
}

func (c *Client) List(ctx context.Context, in ListRequest) ([]Ask, error) {
	var out []Ask
	return out, c.Leader.Call(ctx, MethodAskList, leader.NewRequestID(), in, &out)
}

func (c *Client) Record(ctx context.Context, d Decision) (struct{}, error) {
	return struct{}{}, c.Leader.Call(ctx, MethodDecisionRecord, leader.NewRequestID(), d, nil)
}

func (c *Client) Decisions(ctx context.Context, in ListRequest) ([]Decision, error) {
	var out []Decision
	return out, c.Leader.Call(ctx, MethodDecisionList, leader.NewRequestID(), in, &out)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// HostWide reports whether an approval of an ask raised by rule covers its
// whole host (an ask_hosts rule, or no rule named): such an approval joins
// the actor's approved hosts. A url_rules ask asks about some methods and a
// path prefix only, so its approval covers that rule alone (GAP-0177). A
// git_push ask is about one push, never the host's egress.
func HostWide(rule string) bool {
	return !strings.HasPrefix(rule, "url_rules:") && !strings.HasPrefix(rule, gitPushRulePrefix)
}
