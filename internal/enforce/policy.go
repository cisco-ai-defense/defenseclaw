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
