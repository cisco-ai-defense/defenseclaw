// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package chainstate keeps the stateful findings of Agent Substrate actors on
// the gateway leader (PLAN §5.4): tool-chain windows, the tool judge's
// session intent, the actors' running-time clocks and their lifecycle (fork,
// revert, suspend, delete, crash).
//
// Gateway replicas are stateless: each hook's chain operations go to the
// leader over the leader transport (ChainObserve), the judge's intent through
// IntentGet/IntentPut, the egress callout's observed steps through
// ChainEgress, and the controller's lifecycle events through ChainLifecycle.
//
// On the leader:
//   - one audit store per atespace (<dir>/chains/<atespace>.db), so the
//     4,096-partition cap applies per atespace; finished actors (deleted, or
//     suspended past retention) are marked least recently used and go first;
//   - every actor is one connector instance (audit.ToolChainSubstrateInstanceID)
//     with a window per session and one actor window (the #1391 root tables
//     keyed on the verified actor UID), so rotating session ids cannot empty it;
//   - a per-actor lock orders the actor's parallel calls;
//   - time is the actor's running time at the gateway's receive time (never a
//     guest timestamp, E15): a suspend stops the actor's clock;
//   - pending outcomes expire on the repository's TTL; a crash closes the
//     actor's asks (OnCrashed) (E16).
package chainstate

import (
	"errors"
	"regexp"
	"strings"
)

// Leader methods this package serves besides leader.MethodChainObserve,
// leader.MethodIntentGet and leader.MethodIntentPut.
const (
	MethodChainLifecycle = "ChainLifecycle"
	MethodChainEgress    = "ChainEgress"
)

// Actor is a verified actor: the atespace and the live actor UID from the
// actor token (never a request claim).
type Actor struct {
	Atespace string `json:"atespace"`
	UID      string `json:"uid"`
}

var (
	atespaceRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	uidRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// Validate checks the actor's names (the atespace names a store file).
func (a Actor) Validate() error {
	if !atespaceRE.MatchString(a.Atespace) {
		return errors.New("chainstate: invalid atespace")
	}
	if !uidRE.MatchString(a.UID) || strings.Contains(a.UID, "..") {
		return errors.New("chainstate: invalid actor uid")
	}
	return nil
}

func (a Actor) key() string { return a.Atespace + "/" + a.UID }

// Scope selects an actor's session windows or its actor window.
type Scope string

// Scopes.
const (
	ScopeSession Scope = "session"
	ScopeActor   Scope = "actor"
)

// Op is one repository operation of the hook chain stage.
type Op string

// Ops.
const (
	OpObserve Op = "observe"
	OpResolve Op = "resolve"
	OpPrepare Op = "prepare"
	OpDiscard Op = "discard"
	OpReset   Op = "reset"
	OpAttach  Op = "attach"
)

// Join is the event an operation joins on.
type Join struct {
	SemanticEventID  string `json:"semantic_event_id"`
	EventName        string `json:"event_name,omitempty"`
	InputFingerprint string `json:"input_fingerprint"`
	// ReceivedUnixNano is the gateway's receive time (wall clock); the
	// leader turns it into the actor's running time.
	ReceivedUnixNano int64 `json:"received_unix_nano"`
	// SessionDigest is audit.ToolChainSubstrateSessionDigest of the
	// connector and session id.
	SessionDigest string `json:"session_digest"`
}

// ObserveRequest is the ChainObserve body. Input and the answer's Result are
// gob encodings of the audit input and result types: several of their
// fields (keyed value digests, SQL sources) are excluded from JSON on
// purpose, and the leader needs them.
type ObserveRequest struct {
	Actor Actor  `json:"actor"`
	Scope Scope  `json:"scope"`
	Op    Op     `json:"op"`
	Join  *Join  `json:"join,omitempty"`
	Input []byte `json:"input"`
}

// ObserveResponse is the ChainObserve answer.
type ObserveResponse struct {
	Result []byte `json:"result,omitempty"`
}

// Intent operations (IntentPut).
const (
	IntentPrompt = "prompt"
	IntentAppend = "append"
	IntentReset  = "reset"
	IntentTask   = "task"
)

// IntentRequest is the IntentGet and IntentPut body. Key is the judge's
// session state key; Text a bounded prompt or task; Tool and Args a call.
type IntentRequest struct {
	Actor Actor  `json:"actor"`
	Op    string `json:"op,omitempty"`
	Key   string `json:"key,omitempty"`
	Text  string `json:"text,omitempty"`
	Tool  string `json:"tool,omitempty"`
	Args  string `json:"args,omitempty"`
}

// IntentCall is one recorded call in an IntentResponse.
type IntentCall struct {
	Tool string `json:"tool"`
	Args string `json:"args"`
}

// IntentResponse is a session's context before the call.
type IntentResponse struct {
	UserIntent string       `json:"user_intent,omitempty"`
	Prior      []IntentCall `json:"prior,omitempty"`
	// Task is true when UserIntent is the launcher-registered task text.
	Task bool `json:"task,omitempty"`
}

// Lifecycle events (the controller's view of an actor).
const (
	LifecycleSuspended = "suspended"
	LifecycleResumed   = "resumed"
	LifecycleForked    = "forked"
	LifecycleReverted  = "reverted"
	LifecycleDeleted   = "deleted"
	LifecycleCrashed   = "crashed"
)

// LifecycleEvent is the ChainLifecycle body. A fork names its Parent.
type LifecycleEvent struct {
	Actor  Actor  `json:"actor"`
	Event  string `json:"event"`
	Parent *Actor `json:"parent,omitempty"`
	// AtUnixNano is when the controller saw the event; zero is the leader's
	// receive time.
	AtUnixNano int64 `json:"at_unix_nano,omitempty"`
}

// LifecycleResult reports what a lifecycle event changed.
type LifecycleResult struct {
	CopiedEvents int `json:"copied_events,omitempty"`
	Barriers     int `json:"barriers,omitempty"`
}

// EgressRequest is the ChainEgress body: one request the callout saw.
type EgressRequest struct {
	Actor      Actor  `json:"actor"`
	Host       string `json:"host"`
	Method     string `json:"method"`
	AtUnixNano int64  `json:"at_unix_nano"`
}

// EgressVerdict is the ChainEgress answer.
type EgressVerdict struct {
	Deny     bool     `json:"deny,omitempty"`
	Rule     string   `json:"rule,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Detected []string `json:"detected,omitempty"`
}
