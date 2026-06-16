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

package enforce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type PolicyEngine struct {
	store *audit.Store
}

func NewPolicyEngine(store *audit.Store) *PolicyEngine {
	return &PolicyEngine{store: store}
}

func (e *PolicyEngine) IsBlocked(targetType, name string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	return e.store.HasAction(targetType, name, "install", "block")
}

func (e *PolicyEngine) IsAllowed(targetType, name string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	return e.store.HasAction(targetType, name, "install", "allow")
}

func (e *PolicyEngine) IsQuarantined(targetType, name string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	return e.store.HasAction(targetType, name, "file", "quarantine")
}

func (e *PolicyEngine) Block(targetType, name, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetActionField(targetType, name, "install", "block", reason)
}

func (e *PolicyEngine) Allow(targetType, name, reason string) error {
	if e.store == nil {
		return nil
	}
	if err := e.store.SetActionField(targetType, name, "install", "allow", reason); err != nil {
		return err
	}
	// Clear residual auto-enforcement state (quarantine / disable) so the
	// allow actually takes full effect.  Only a manual Block can override.
	var errs []error
	if err := e.store.ClearActionField(targetType, name, "file"); err != nil {
		errs = append(errs, fmt.Errorf("clear file action: %w", err))
	}
	if err := e.store.ClearActionField(targetType, name, "runtime"); err != nil {
		errs = append(errs, fmt.Errorf("clear runtime action: %w", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("enforce: allow %s %q: partial cleanup: %v", targetType, name, errs)
	}
	return nil
}

func (e *PolicyEngine) Unblock(targetType, name string) error {
	if e.store == nil {
		return nil
	}
	return e.store.ClearActionField(targetType, name, "install")
}

func (e *PolicyEngine) Quarantine(targetType, name, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetActionField(targetType, name, "file", "quarantine", reason)
}

func (e *PolicyEngine) ClearQuarantine(targetType, name string) error {
	if e.store == nil {
		return nil
	}
	return e.store.ClearActionField(targetType, name, "file")
}

func (e *PolicyEngine) Disable(targetType, name, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetActionField(targetType, name, "runtime", "disable", reason)
}

func (e *PolicyEngine) Enable(targetType, name string) error {
	if e.store == nil {
		return nil
	}
	return e.store.ClearActionField(targetType, name, "runtime")
}

func (e *PolicyEngine) SetSourcePath(targetType, name, path string) {
	if e.store == nil {
		return
	}
	_ = e.store.SetSourcePath(targetType, name, path)
}

func (e *PolicyEngine) SetAction(targetType, name, sourcePath string, state audit.ActionState, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetAction(targetType, name, sourcePath, state, reason)
}

func (e *PolicyEngine) GetAction(targetType, name string) (*audit.ActionEntry, error) {
	if e.store == nil {
		return nil, nil
	}
	return e.store.GetAction(targetType, name)
}

func (e *PolicyEngine) ListBlocked() ([]audit.ActionEntry, error) {
	if e.store == nil {
		return nil, nil
	}
	return e.store.ListByAction("install", "block")
}

func (e *PolicyEngine) ListAllowed() ([]audit.ActionEntry, error) {
	if e.store == nil {
		return nil, nil
	}
	return e.store.ListByAction("install", "allow")
}

func (e *PolicyEngine) ListAll() ([]audit.ActionEntry, error) {
	if e.store == nil {
		return nil, nil
	}
	return e.store.ListAllActions()
}

func (e *PolicyEngine) ListByType(targetType string) ([]audit.ActionEntry, error) {
	if e.store == nil {
		return nil, nil
	}
	return e.store.ListActionsByType(targetType)
}

func (e *PolicyEngine) RemoveAction(targetType, name string) error {
	if e.store == nil {
		return nil
	}
	return e.store.RemoveAction(targetType, name)
}

// ----------------------------------------------------------------------------
// Connector-scoped enforcement helpers (N2 — per-connector mcp
// block/allow/unblock)
//
// The connector dimension lives in the audit store's per-connector "connector"
// column (the SK-4 foundation), which is distinct from the
// "@<connector>/<tool>" name-encoding the tool gate uses below. A bare entry
// (connector="") is GLOBAL — it applies to every connector; a non-empty
// connector NARROWS the entry to that peer.
//
// Reads resolve most-specific-wins: the connector-scoped entry is checked
// first, then the global entry falls through — so a global block still applies
// to every connector while a connector-scoped block applies only to its peer.
// Because the block check precedes the allow check at the gate, a global (or
// connector-scoped) block wins over a connector-scoped allow. Writes are
// exact-match on connector (the actions table is unique on
// (target_type, target_name, connector)). Mirrors the *_for_connector methods
// in cli/defenseclaw/enforce/policy.py.
// ----------------------------------------------------------------------------

// IsBlockedForConnector reports whether name is blocked for connector, checking
// the connector-scoped entry first and then the bare global entry.
func (e *PolicyEngine) IsBlockedForConnector(targetType, name, connector string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	if connector != "" {
		blocked, err := e.store.HasActionForConnector(targetType, name, connector, "install", "block")
		if err != nil {
			return false, err
		}
		if blocked {
			return true, nil
		}
	}
	return e.store.HasAction(targetType, name, "install", "block")
}

// IsAllowedForConnector reports whether name is allowed for connector, checking
// the connector-scoped entry first and then the bare global entry. Callers must
// consult IsBlockedForConnector first so a block wins over an allow.
func (e *PolicyEngine) IsAllowedForConnector(targetType, name, connector string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	if connector != "" {
		allowed, err := e.store.HasActionForConnector(targetType, name, connector, "install", "allow")
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return e.store.HasAction(targetType, name, "install", "allow")
}

// IsQuarantinedForConnector reports whether name is quarantined for connector,
// checking the connector-scoped entry first and then the bare global entry.
func (e *PolicyEngine) IsQuarantinedForConnector(targetType, name, connector string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	if connector != "" {
		q, err := e.store.HasActionForConnector(targetType, name, connector, "file", "quarantine")
		if err != nil {
			return false, err
		}
		if q {
			return true, nil
		}
	}
	return e.store.HasAction(targetType, name, "file", "quarantine")
}

// IsDisabledForConnector reports whether name is runtime-disabled for
// connector, checking the connector-scoped entry first and then the bare global
// entry.
func (e *PolicyEngine) IsDisabledForConnector(targetType, name, connector string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	if connector != "" {
		disabled, err := e.store.HasActionForConnector(targetType, name, connector, "runtime", "disable")
		if err != nil {
			return false, err
		}
		if disabled {
			return true, nil
		}
	}
	return e.store.HasAction(targetType, name, "runtime", "disable")
}

// BlockForConnector blocks name for connector (exact-match; connector="" = global).
func (e *PolicyEngine) BlockForConnector(targetType, name, connector, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetActionFieldForConnector(targetType, name, connector, "install", "block", reason)
}

// AllowForConnector allows name for connector and clears residual file/runtime
// enforcement (exact-match; connector="" = global). Mirrors Allow().
func (e *PolicyEngine) AllowForConnector(targetType, name, connector, reason string) error {
	if e.store == nil {
		return nil
	}
	if err := e.store.SetActionFieldForConnector(targetType, name, connector, "install", "allow", reason); err != nil {
		return err
	}
	var errs []error
	if err := e.store.ClearActionFieldForConnector(targetType, name, connector, "file"); err != nil {
		errs = append(errs, fmt.Errorf("clear file action: %w", err))
	}
	if err := e.store.ClearActionFieldForConnector(targetType, name, connector, "runtime"); err != nil {
		errs = append(errs, fmt.Errorf("clear runtime action: %w", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("enforce: allow %s %q connector %q: partial cleanup: %v", targetType, name, connector, errs)
	}
	return nil
}

// UnblockForConnector clears the install action for connector (exact-match;
// connector="" = global).
func (e *PolicyEngine) UnblockForConnector(targetType, name, connector string) error {
	if e.store == nil {
		return nil
	}
	return e.store.ClearActionFieldForConnector(targetType, name, connector, "install")
}

// RemoveActionForConnector removes all enforcement for connector (exact-match;
// connector="" = global).
func (e *PolicyEngine) RemoveActionForConnector(targetType, name, connector string) error {
	if e.store == nil {
		return nil
	}
	return e.store.RemoveActionForConnector(targetType, name, connector)
}

// ----------------------------------------------------------------------------
// Connector-scoped tool helpers (targetType="tool", key "@<connector>/<tool>")
//
// The "@" sigil keeps connector scoping distinct from the orthogonal
// "<source>/<tool>" source scoping used by the CLI. Runtime resolution order,
// for request connector C and tool T, is:
//
//	block @C/T → block T → allow @C/T → allow T → scan
//
// i.e. a global block still wins over a connector-scoped allow, because the
// gateway lanes consult IsToolBlockedForConnector before
// IsToolAllowedForConnector. Mirrors the Python PolicyEngine methods of the
// same name in cli/defenseclaw/enforce/policy.py.
// ----------------------------------------------------------------------------

// toolConnectorTarget builds the connector-scoped tool key "@<connector>/<tool>".
// Centralised so the read gate and any write surface stay in lockstep.
func toolConnectorTarget(toolName, connector string) string {
	if connector == "" {
		return toolName
	}
	return "@" + connector + "/" + toolName
}

// IsToolBlockedForConnector reports whether toolName is blocked for connector,
// checking the connector-scoped entry first and then the bare global entry.
func (e *PolicyEngine) IsToolBlockedForConnector(toolName, connector string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	if connector != "" {
		scoped := toolConnectorTarget(toolName, connector)
		blocked, err := e.store.HasAction("tool", scoped, "install", "block")
		if err != nil {
			return false, err
		}
		if blocked {
			return true, nil
		}
	}
	return e.store.HasAction("tool", toolName, "install", "block")
}

// IsToolAllowedForConnector reports whether toolName is allowed for connector,
// checking the connector-scoped entry first and then the bare global entry.
// Callers must consult IsToolBlockedForConnector first so a global block wins
// over a connector-scoped allow.
func (e *PolicyEngine) IsToolAllowedForConnector(toolName, connector string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	if connector != "" {
		scoped := toolConnectorTarget(toolName, connector)
		allowed, err := e.store.HasAction("tool", scoped, "install", "allow")
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return e.store.HasAction("tool", toolName, "install", "allow")
}

// BlockToolForConnector blocks toolName, optionally scoped to a connector.
func (e *PolicyEngine) BlockToolForConnector(toolName, connector, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetActionField("tool", toolConnectorTarget(toolName, connector), "install", "block", reason)
}

// AllowToolForConnector allows toolName, optionally scoped to a connector, and
// clears residual file/runtime enforcement (mirrors Allow()).
func (e *PolicyEngine) AllowToolForConnector(toolName, connector, reason string) error {
	if e.store == nil {
		return nil
	}
	target := toolConnectorTarget(toolName, connector)
	if err := e.store.SetActionField("tool", target, "install", "allow", reason); err != nil {
		return err
	}
	var errs []error
	if err := e.store.ClearActionField("tool", target, "file"); err != nil {
		errs = append(errs, fmt.Errorf("clear file action: %w", err))
	}
	if err := e.store.ClearActionField("tool", target, "runtime"); err != nil {
		errs = append(errs, fmt.Errorf("clear runtime action: %w", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("enforce: allow tool %q: partial cleanup: %v", target, errs)
	}
	return nil
}

// PolicyStableID returns a short stable identifier for the policy bundle
// rooted at policyDir (used in OTel spans and metrics).
func PolicyStableID(policyDir string) string {
	if policyDir == "" {
		return "none"
	}
	sum := sha256.Sum256([]byte(policyDir))
	return hex.EncodeToString(sum[:8])
}

// StartAdmissionDecideSpan opens span defenseclaw.admission.decide (child of any
// active span in ctx). Every runAdmission / admission gate path should pair
// this with EndAdmissionDecideSpan.
func StartAdmissionDecideSpan(ctx context.Context, targetType, targetID, policyID string) (context.Context, trace.Span) {
	tr := otel.Tracer("defenseclaw")
	ctx, span := tr.Start(ctx, "defenseclaw.admission.decide", trace.WithSpanKind(trace.SpanKindInternal))
	span.SetAttributes(
		attribute.String("target_type", targetType),
		attribute.String("target_id", targetID),
		attribute.String("policy_id", policyID),
	)
	return ctx, span
}

// EndAdmissionDecideSpan completes the admission.decide span with verdict fields.
func EndAdmissionDecideSpan(span trace.Span, verdict, reason, policyID string, err error) {
	if span == nil {
		return
	}
	if policyID != "" {
		span.SetAttributes(attribute.String("policy_id", policyID))
	}
	span.SetAttributes(
		attribute.String("verdict", verdict),
		attribute.String("reason", truncateAdmissionReason(reason)),
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End()
}

func truncateAdmissionReason(s string) string {
	const max = 512
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
