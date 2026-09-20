// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package redaction

import "context"

// SinkPolicy is a per-call redaction override used by the
// cloud-controlled per-inspection redaction feature. The managed Cisco
// AI Defense inspect response carries a per-inspection
// is_redaction_enabled directive; in managed_enterprise that directive
// is authoritative for that occurrence and must override the configured
// destination profile both ways (force raw when the cloud says raw, force
// sensitive redaction when the cloud says redact).
//
// Callers that don't have a directive (or aren't managed_enterprise)
// pass SinkPolicyDefault, which uses the secure compatibility projection.
type SinkPolicy uint8

const (
	// SinkPolicyDefault uses the always-redacting compatibility projection.
	// It is used when there is no per-inspection directive or the deployment
	// is not managed_enterprise.
	SinkPolicyDefault SinkPolicy = iota
	// SinkPolicyRaw forces the raw value through. Set when the cloud directive is
	// is_redaction_enabled=false in managed_enterprise.
	SinkPolicyRaw
	// SinkPolicyRedact forces the sensitive compatibility projection. Set when
	// the cloud directive is is_redaction_enabled=true in managed_enterprise.
	SinkPolicyRedact
)

// StringForSink applies a SinkPolicy override on top of ForSinkString.
//   - SinkPolicyRaw    -> raw value (cloud is_redaction_enabled=false)
//   - SinkPolicyRedact -> sensitive projection (cloud=true)
//   - SinkPolicyDefault -> secure compatibility projection
func StringForSink(s string, p SinkPolicy) string {
	switch p {
	case SinkPolicyRaw:
		return s
	case SinkPolicyRedact:
		return redactString(s)
	default:
		return ForSinkString(s)
	}
}

// EntityForSink applies a SinkPolicy override on top of ForSinkEntity.
func EntityForSink(value string, p SinkPolicy) string {
	switch p {
	case SinkPolicyRaw:
		return value
	case SinkPolicyRedact:
		return redactEntity(value)
	default:
		return ForSinkEntity(value)
	}
}

// MessageContentForSink applies a SinkPolicy override on top of
// ForSinkMessageContent.
func MessageContentForSink(content string, p SinkPolicy) string {
	switch p {
	case SinkPolicyRaw:
		return content
	case SinkPolicyRedact:
		return redactMessageContent(content)
	default:
		return ForSinkMessageContent(content)
	}
}

// ReasonForSink applies a SinkPolicy override on top of ForSinkReason.
func ReasonForSink(reason string, p SinkPolicy) string {
	switch p {
	case SinkPolicyRaw:
		return reason
	case SinkPolicyRedact:
		return redactReason(reason)
	default:
		return ForSinkReason(reason)
	}
}

// EvidenceForSink applies a SinkPolicy override on top of
// ForSinkEvidence.
func EvidenceForSink(content string, matchStart, matchEnd int, p SinkPolicy) string {
	switch p {
	case SinkPolicyRaw:
		return content
	case SinkPolicyRedact:
		return redactEvidence(content, matchStart, matchEnd)
	default:
		return ForSinkEvidence(content, matchStart, matchEnd)
	}
}

// SinkPolicyForDirective maps a tri-state cloud directive
// (is_redaction_enabled) to a SinkPolicy. nil (no directive) yields
// SinkPolicyDefault; true (cloud says redact) yields SinkPolicyRedact;
// false (cloud says raw) yields SinkPolicyRaw.
//
// Callers are responsible for the managed_enterprise gating — pass nil
// (or don't call this) outside managed_enterprise so behavior stays on
// SinkPolicyDefault.
func SinkPolicyForDirective(redactionEnabled *bool) SinkPolicy {
	if redactionEnabled == nil {
		return SinkPolicyDefault
	}
	if *redactionEnabled {
		return SinkPolicyRedact
	}
	return SinkPolicyRaw
}

// sinkPolicyCtxKey is the private context key under which a fully
// resolved (already managed_enterprise-gated) SinkPolicy rides the
// request context. Lives in the redaction package — rather than in a
// single feature package — so the downstream sink helpers in
// internal/scanner and internal/audit can honor a per-inspection
// decision without importing internal/gateway (which would create a
// dependency cycle).
type sinkPolicyCtxKey struct{}

// WithSinkPolicy returns a child context carrying an already-resolved
// SinkPolicy for the downstream sink helpers to honor. The caller is
// responsible for the managed_enterprise gating before calling this;
// SinkPolicyFromContext returns whatever was stored (SinkPolicyDefault
// when nothing was).
func WithSinkPolicy(ctx context.Context, p SinkPolicy) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, sinkPolicyCtxKey{}, p)
}

// SinkPolicyFromContext returns the resolved SinkPolicy stamped by
// WithSinkPolicy, defaulting to SinkPolicyDefault when none is present
// (so non-inspection call paths keep today's behavior).
func SinkPolicyFromContext(ctx context.Context) SinkPolicy {
	if ctx == nil {
		return SinkPolicyDefault
	}
	if p, ok := ctx.Value(sinkPolicyCtxKey{}).(SinkPolicy); ok {
		return p
	}
	return SinkPolicyDefault
}
