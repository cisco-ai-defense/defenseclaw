// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Policy is the effective routing policy of one request: routing.* tightened
// by routing.admin and the caller profile overlays.
type Policy struct {
	AllowedAliases    []string          `json:"allowed_aliases,omitempty"`
	DeniedProviders   []string          `json:"denied_providers,omitempty"`
	DefaultAlias      string            `json:"default_alias,omitempty"`
	Categories        map[string]string `json:"categories,omitempty"`
	AllowUserOverride bool              `json:"allow_user_override,omitempty"`
}

// Digest is a stable digest of the policy (sticky routing key, records).
func (p Policy) Digest() string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// AdminVerdict is the S11 evaluator answer (streams/S11/DESIGN.md v3).
type AdminVerdict struct {
	// Policy is the narrowed policy; never wider than the input.
	Policy Policy
	// Bind: a matching rule set allow, so a fallback to the original
	// request must also be inside it (managed deny otherwise).
	Bind bool
	// Force lists budget-downgrade aliases, first compatible wins.
	Force      []string
	Deny       *DenyReason
	Warnings   []string
	RuleIDs    []string
	ChargeKeys []string
}

// GateTarget is a forwarded exit the evaluator checks (a routed backend or
// the original request).
type GateTarget struct {
	Alias    string // "" for the original request
	Provider string
	Model    string
}

// AdminEvaluator is the seam S11 implements (internal/routingadmin). The
// zero evaluator (nil) narrows nothing.
type AdminEvaluator interface {
	// Active reports whether any admin rule or budget exists (no call
	// otherwise); NeedsCategory whether a rule matches on categories.
	Active() bool
	NeedsCategory() bool
	Evaluate(ctx context.Context, p Policy, r Request, category string, classifierFailed bool) AdminVerdict
	// Gate is called at every forwarded exit with the verdict.
	Gate(v AdminVerdict, target GateTarget, managed bool) *DenyReason
}
