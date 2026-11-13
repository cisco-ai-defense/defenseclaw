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

package extproc

import (
	"context"
	"encoding/json"
	"time"
)

// ActorRef names the actor a request came from.
type ActorRef struct {
	Atespace string
	Name     string
	// UID is the live actor UID from its registration; empty when no
	// resolver is configured or DefenseClaw has no registration for it.
	UID string
	// Profile and Unattended come from the registration (GAP-0090): the
	// profile the gateway gave the actor, and a --task or --batch run.
	Profile    string
	Unattended bool
}

// Key is atespace/name, the identity the egress gateway gives.
func (a ActorRef) Key() string { return a.Atespace + "/" + a.Name }

// ActorRecord is what a UIDResolver knows of a live actor.
type ActorRecord struct {
	// UID is empty for an actor DefenseClaw has no registration for.
	UID        string
	Profile    string
	Unattended bool
}

// UIDResolver resolves an actor's name, the only identity atenet-egress
// gives the callout, to its current incarnation: the leader's registrations
// (GAP-0090). live is false for a deleted actor; an actor with no
// registration is live with an empty UID; err is an outage.
type UIDResolver interface {
	ResolveActor(ctx context.Context, atespace, name string) (rec ActorRecord, live bool, err error)
}

// AskOutcome is what became of an ask.
type AskOutcome string

// Ask outcomes.
const (
	AskApproved AskOutcome = "approved"
	AskDenied   AskOutcome = "denied"
	// AskPending is an ask nobody answered within the hold: the request is
	// refused and the agent told to retry once it is approved.
	AskPending AskOutcome = "pending"
)

// AskRequest is an ask the callout raises for an ask-required host.
type AskRequest struct {
	Actor   ActorRef
	Profile string
	Host    string
	Method  string
	// Rule is the ask_hosts pattern or URL rule that required it.
	Rule string
	// PathPrefix is the url rule's path prefix, for the person who answers
	// ("" for a host ask).
	PathPrefix string
	// UnattendedAsks is the profile's unattended_asks (deny or queue, D12).
	UnattendedAsks string
}

// AskResult is the outcome of an ask. ID is the ask's id for the refusal
// body; Reason is a short text for a denial.
type AskResult struct {
	Outcome AskOutcome
	ID      string
	Reason  string
}

// AskSink raises an ask, or finds the one already open or decided for the
// same actor and host, and waits for its outcome until ctx ends.
// AskClient implements it against the gateway callout ask route.
type AskSink interface {
	Ask(ctx context.Context, req AskRequest) (AskResult, error)
}

// StepObservedEgress is the chain step kind the callout emits.
const StepObservedEgress = "observed_egress"

// ChainStep is one observed egress request: the host and method, never a
// path, header or body.
type ChainStep struct {
	Kind    string
	Actor   ActorRef
	Host    string
	Method  string
	Allowed bool
	Time    time.Time
}

// ChainSink takes observed_egress steps into the actor's root chain window
// (A13's leader store). Calls come from one background worker.
type ChainSink interface {
	ObserveEgress(ctx context.Context, step ChainStep) error
}

// ChainVerdict is the outcome of a chain check.
type ChainVerdict struct {
	Deny   bool
	Rule   string
	Reason string
}

// ChainChecker reports an egress-type chain (a secret read, then egress)
// that the step would complete. It is called synchronously under the chain
// check budget, only for an actor with a UID; an error, a panic or the
// deadline is an unchecked step, which follows chain.failure_mode.
type ChainChecker interface {
	CheckEgress(ctx context.Context, step ChainStep) (ChainVerdict, error)
}

// ToolCall is one MCP JSON-RPC tools/call the callout found in a body.
type ToolCall struct {
	Actor ActorRef
	// Server is the MCP server name the admin gave the host (mcp_hosts
	// "host=name"), or the host.
	Server string
	Host   string
	// URL is scheme, host and path of the request, never the query.
	URL  string
	Tool string
	Args json.RawMessage
	// SessionID is the Mcp-Session-Id the actor sent, if any.
	SessionID string
	// RequestID ties the verdict to the callout's event.
	RequestID string
}

// ToolVerdict is the hook tool rules' verdict for a ToolCall.
type ToolVerdict struct {
	Block bool
	// Ask is a refusal until a person approves: the route answered ask.
	Ask bool
	// Alert is an allowed call the rules flagged (the hooks' alert action).
	Alert    bool
	Severity string
	Reason   string
	Findings []string
	// Source is the evaluation that decided (mcp_asset_policy, tool_rules,
	// none).
	Source string
}

// ToolJudge runs a tool call through the same MCP and tool rules the hooks
// use, the MCP asset policy included. VerdictClient is the adapter to the
// gateway's callout verdict route.
type ToolJudge interface {
	JudgeToolCall(ctx context.Context, call ToolCall) (ToolVerdict, error)
}

// PolicySource gives the policy for an actor. StaticPolicies picks the
// configured profile the actor's registration names (else the atespace's)
// and marks an unattended actor.
type PolicySource interface {
	PolicyFor(ctx context.Context, actor ActorRef) (*Policy, error)
}

// EventSink receives one event per decided request. Implementations must not
// block.
type EventSink interface {
	EgressEvent(Event)
}
