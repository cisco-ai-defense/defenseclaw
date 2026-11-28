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
//   - one audit store per actor (<dir>/chains/<atespace>/<uid>.db), so every
//     expiry, prune and LRU in it runs on that actor's own running-time
//     clock; at most MaxActors actors per atespace (a retired actor, then
//     the least recently used, is evicted); a deleted actor is purged, and
//     an actor suspended or silent past PurgeAfter too, unless its window
//     still holds a secret read;
//   - every actor is one connector instance (audit.ToolChainSubstrateInstanceID)
//     with a window per session and one actor window (the #1391 root tables
//     keyed on the verified actor UID), so rotating session ids cannot empty it;
//   - a per-actor lock orders the actor's parallel calls;
//   - time is the actor's running time, counted from its own requests at
//     the leader's receive time (never a guest timestamp, E15), a gap
//     between two counting at most ActiveGap: whatever stops the actor
//     stops its clock, with no event needed (GAP-0292); a suspend or resume
//     only decides retention, and one older than the last applied is
//     ignored;
//   - a revert puts a mutation barrier into the actor's windows, but not
//     into an actor window that holds a secret read (GAP-0292);
//   - a forked actor starts from its parent's windows the first time the
//     leader sees it (parent from the verified registration), whatever
//     arrives first;
//   - pending outcomes expire on the repository's TTL; a crash closes the
//     actor's asks (OnCrashed) (E16).
package chainstate

import (
	"errors"
	"regexp"
	"strings"
)

// Leader methods this package serves besides leader.MethodChainObserve,
// leader.MethodIntentGet, leader.MethodIntentPut and the inspect-once record
// (MethodHistorySeen, MethodHistoryRecord).
const (
	MethodChainLifecycle  = "ChainLifecycle"
	MethodChainEgress     = "ChainEgress"
	MethodChainUnrecorded = "ChainUnrecorded"
	// MethodChainRunning is the controller's report of the actors it saw
	// running (substrate-1 GAP-0539).
	MethodChainRunning = "ChainRunning"
)

// RunningRequest is the ChainRunning body: the actors the controller saw in
// state RUNNING on its last pass. Each counts as running at the leader's
// receive time, so wall time while an actor runs is its running time even
// when the actor makes no request (GAP-0539). At most MaxRunningActors.
type RunningRequest struct {
	Actors []Actor `json:"actors"`
}

// MaxRunningActors bounds one ChainRunning report; the controller splits a
// longer list.
const MaxRunningActors = 2048

// UnrecordedRequest says a gateway replica could not put one of the actor's
// tool steps in its chain window (SUBSTRATE-CHAIN-UNRECORDED): the egress
// check can't link a later request to it, so the next egress checks carry
// Why for the chain window (substrate-1 GAP-0339).
type UnrecordedRequest struct {
	Actor Actor  `json:"actor"`
	Why   string `json:"why"`
	// Uncleared marks a step that was recorded, a credentials read that
	// started the secret-read chain at its proposal because no result can
	// be tied to the call: Why is added to the refusal reason of the
	// chain's egress, so the person knows why (GAP-0338).
	Uncleared bool `json:"uncleared,omitempty"`
}

// maxUnrecordedWhy bounds the reason the leader keeps.
const maxUnrecordedWhy = 240

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
	// Found is true when IntentGet found a context for the key or the
	// actor's task (intentstore.Reader's found).
	Found bool `json:"found,omitempty"`
}

// Lifecycle events (the controller's view of an actor).
const (
	LifecycleSuspended = "suspended"
	LifecycleResumed   = "resumed"
	LifecycleForked    = "forked"
	LifecycleReverted  = "reverted"
	LifecycleDeleted   = "deleted"
	LifecycleCrashed   = "crashed"
	// LifecycleCheckpointed and LifecycleUndone are the workspace events
	// the actor's owner reports through the gateway (defenseclaw substrate
	// checkpoint and undo, which run git inside the actor and which the
	// controller never sees): a checkpoint marks its place in the actor's
	// chain clock; an undo takes the facts about the files it reverted out
	// of the artifact chains (substrate-1:GAP-0476).
	LifecycleCheckpointed = "checkpointed"
	LifecycleUndone       = "undone"
)

// MaxUndoFiles bounds the files one undo event names, removed and restored
// each; an undo that reverted more names the first ones, and the chains
// keep the facts about the rest (stricter, never laxer).
const MaxUndoFiles = 4096

// LifecycleEvent is the ChainLifecycle body. A fork names its Parent.
type LifecycleEvent struct {
	Actor  Actor  `json:"actor"`
	Event  string `json:"event"`
	Parent *Actor `json:"parent,omitempty"`
	// AtUnixNano is when the controller saw the event; zero is the leader's
	// receive time. A workspace event always takes the leader's time.
	AtUnixNano int64 `json:"at_unix_nano,omitempty"`
	// Checkpoint is the commit of the checkpoint a checkpointed event took
	// or an undone event went back to.
	Checkpoint string `json:"checkpoint,omitempty"`
	// Removed and Restored are the path digests
	// (guardrail.ToolChainPOSIXPathDigest) of the files an undone event
	// removed (added since the checkpoint) and put back (changed or deleted
	// since).
	Removed  []string `json:"removed,omitempty"`
	Restored []string `json:"restored,omitempty"`
}

// LifecycleResult reports what a lifecycle event changed.
type LifecycleResult struct {
	CopiedEvents int `json:"copied_events,omitempty"`
	// Skipped counts parent windows a fork did not copy because the child
	// already had them.
	Skipped  int `json:"skipped,omitempty"`
	Barriers int `json:"barriers,omitempty"`
	// Ignored is a suspend or resume older than the last one applied.
	Ignored bool `json:"ignored,omitempty"`
	// Forgotten counts the chain events an undone event changed.
	Forgotten int `json:"forgotten,omitempty"`
	// CheckpointUnknown: the leader has no mark for the undone event's
	// checkpoint (taken before this leader version, or its report failed),
	// so the facts about the files the undo put back stay.
	CheckpointUnknown bool `json:"checkpoint_unknown,omitempty"`
}

// EgressRequest is the ChainEgress body: one request the callout saw.
// Name is the actor's name, the identity atenet-egress gives the callout;
// Actor.UID is the incarnation the callout resolved it to (GAP-0234).
type EgressRequest struct {
	Actor  Actor  `json:"actor"`
	Name   string `json:"name"`
	Host   string `json:"host"`
	Method string `json:"method"`
}

// EgressVerdict is the ChainEgress answer. Stale says the UID is not the
// name's live incarnation (deleted, or replaced by a same-name actor): the
// callout resolves the name again and asks under the new UID. A stale
// answer also has Deny set, so a caller that does not know Stale refuses
// (GAP-0234).
type EgressVerdict struct {
	Stale    bool     `json:"stale,omitempty"`
	Deny     bool     `json:"deny,omitempty"`
	Rule     string   `json:"rule,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Detected []string `json:"detected,omitempty"`
	// Unrecorded is why one of the actor's tool steps in the chain window
	// is not in it (UnrecordedRequest): the callout refuses the request
	// where it refuses unchecked egress, else alerts (GAP-0339).
	Unrecorded string `json:"unrecorded,omitempty"`
}
