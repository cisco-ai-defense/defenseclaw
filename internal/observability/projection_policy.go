// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

// ProjectionPolicy is an immutable, in-process override for the projection of
// one canonical occurrence. It is deliberately absent from the canonical wire
// envelope: the policy is local execution state, not source-reported telemetry
// and not an attribute that may be accepted from an imported record.
//
// The zero value is DefaultProjectionPolicy. The private representation keeps
// producers on the three reviewed constructors instead of accepting arbitrary
// numeric policy values.
type ProjectionPolicy struct {
	mode projectionPolicyMode
}

type projectionPolicyMode uint8

const (
	projectionPolicyDefault projectionPolicyMode = iota
	projectionPolicyRaw
	projectionPolicyRedact
)

// DefaultProjectionPolicy preserves each compiled destination profile.
func DefaultProjectionPolicy() ProjectionPolicy {
	return ProjectionPolicy{mode: projectionPolicyDefault}
}

// RawProjectionPolicy forces this occurrence through the built-in none profile.
func RawProjectionPolicy() ProjectionPolicy {
	return ProjectionPolicy{mode: projectionPolicyRaw}
}

// RedactProjectionPolicy forces this occurrence through the built-in sensitive
// profile, independently of the destination's configured profile.
func RedactProjectionPolicy() ProjectionPolicy {
	return ProjectionPolicy{mode: projectionPolicyRedact}
}

func (policy ProjectionPolicy) IsDefault() bool { return policy.mode == projectionPolicyDefault }
func (policy ProjectionPolicy) IsRaw() bool     { return policy.mode == projectionPolicyRaw }
func (policy ProjectionPolicy) IsRedact() bool  { return policy.mode == projectionPolicyRedact }

func (policy ProjectionPolicy) valid() bool {
	return policy.IsDefault() || policy.IsRaw() || policy.IsRedact()
}
