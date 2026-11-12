// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package engine decides which configured model a request goes to. It is
// pure Go with no gateway import: the gateway hands it a Request built from
// the parsed body and the verified caller, and applies the Decision. See
// plans/r110/streams/S1/DESIGN.md sections 2, 3, 15 and 16.
package engine

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Tri is a three-valued match answer (assignmentState on the gateway side).
type Tri int

const (
	No Tri = iota
	Maybe
	Yes
)

// Caller is the identity routing may use. Only a verified caller gets a
// profile overlay or gateway-held credentials; a request header never fills
// it.
type Caller struct {
	Verified      bool
	Key           string // stable subject key (uid, SID or principal); also set for unverified callers
	Source        string // subject source name, for records
	LookupFailed  bool
	GroupsUnknown bool
	// Matches answers a profile-style match against the caller facts.
	Matches func(config.ProfileMatch) Tri
}

// Listener names where a request arrived.
const (
	ListenerGuardrail = "guardrail"
	ListenerRouteOnly = "route_only"
)

// Credential classes of the inbound request (never the value).
const (
	CredentialNone    = "none"
	CredentialAPIKey  = "api_key"
	CredentialOAuth   = "oauth"
	CredentialBearer  = "bedrock_bearer"
	CredentialGateway = "gateway"
)

// Request is everything routing reads about one model call. Text is the
// classifier input: human-typed text only, already bounded by the caller.
type Request struct {
	Text              string
	APIFamily         string
	Connector         string
	Agent             string
	Listener          string
	Severity          string // pre-call guardrail severity, "" when none ran
	RequestedModel    string
	RequestedProvider string
	CredentialClass   string
	HasTools          bool
	ToolTurn          bool
	HasImages         bool
	LongContext       bool
	ConversationID    string
	// Profiles are the guardrail profiles the caller resolved to, in
	// assignment order (several when the profile meet combined them).
	Profiles      []string
	ProfileDigest string
	Caller        Caller
}

// Backend is one routing.models entry.
type Backend struct {
	Alias        string
	Provider     string
	Model        string
	BaseURL      string
	APIs         []string
	APIKeyEnv    string
	Credential   string
	Capabilities []string
	Bedrock      *config.RoutingBedrockAuthConfig
}

// Outcome of one decision.
const (
	OutcomeApplied     = "applied"
	OutcomeFallback    = "fallback"
	OutcomeDenied      = "denied"
	OutcomePassthrough = "passthrough"
)

// Decision sources.
const (
	SourceRules        = config.RoutingClassifierRules
	SourceSystemOne    = config.RoutingClassifierSystemOne
	SourceVLLMSR       = config.RoutingClassifierVLLMSR
	SourceUserOverride = "user_override"
	SourceSticky       = "sticky"
	SourceForce        = "force"
	SourceDefault      = "default"
)

// Failure codes (closed set; metric labels).
const (
	FailureNone           = "none"
	FailureTimeout        = "timeout"
	FailureUpstreamStatus = "upstream_status"
	FailureDecode         = "decode_failure"
	FailureUnknownAlias   = "unknown_alias"
	FailureCredential     = "credential_failure"
	FailureConfig         = "configuration_failure"
	FailureFiltered       = "filtered"
	FailureBreakerOpen    = "breaker_open"
	FailureLowConfidence  = "low_confidence"
	FailureNoCandidate    = "no_candidate"
)

// DenyReason is a managed-only refusal.
type DenyReason struct {
	Code    string
	Message string
}

// Decision is the routing outcome for one request.
type Decision struct {
	Outcome      string
	Backend      *Backend // nil unless Outcome is applied
	Source       string
	Category     string
	RuleID       string
	Candidate    string
	FilteredBy   string
	FailureCode  string
	Confidence   float64
	Deny         *DenyReason
	Warnings     []string
	RuleIDs      []string
	ChargeKeys   []string
	PolicyDigest string
	Latency      time.Duration

	verdict AdminVerdict
}

// ClassifyInput is what a classifier sees: no identity, no credentials.
type ClassifyInput struct {
	Text           string
	APIFamily      string
	Connector      string
	RequestedModel string
	HasTools       bool
	ToolTurn       bool
	HasImages      bool
	LongContext    bool
	// Signals are the keyword signals that matched Text.
	Signals map[string]bool
}

// ClassifyResult is a classifier answer. Aliases are candidates in order;
// when empty, Category maps through the policy categories.
type ClassifyResult struct {
	Category   string
	Aliases    []string
	Confidence float64 // 0..1; -1 when the classifier gives none
	RuleID     string
}

// Classifier is one routing classifier (rules, systemone, vllm_sr).
type Classifier interface {
	Name() string
	Classify(ctx context.Context, in ClassifyInput) (ClassifyResult, error)
}

// ClassifierError carries a closed failure code.
type ClassifierError struct {
	Code string
	Err  error
}

func (e *ClassifierError) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return e.Code + ": " + e.Err.Error()
}

func (e *ClassifierError) Unwrap() error { return e.Err }
