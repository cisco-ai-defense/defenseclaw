// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package destinationtest owns the content-free wire contract shared by the
// operator CLI helper and the gateway's local-only compliance endpoint.
package destinationtest

import "regexp"

const (
	EndpointPath    = "/api/v1/observability/destination-test/activity"
	MaxEncodedBytes = 2048
)

var (
	stableName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	probeID    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type Activity struct {
	Phase        string `json:"phase"`
	Destination  string `json:"destination"`
	ProbeID      string `json:"probe_id"`
	Mode         string `json:"mode"`
	Result       string `json:"result"`
	FailureClass string `json:"failure_class,omitempty"`
}

type ValidationError struct{}

func (*ValidationError) Error() string { return "invalid destination-test activity" }

func (activity Activity) Validate() error {
	if !stableName.MatchString(activity.Destination) || !probeID.MatchString(activity.ProbeID) {
		return &ValidationError{}
	}
	if activity.Mode != "handshake" && activity.Mode != "write_probe" {
		return &ValidationError{}
	}
	switch activity.Phase {
	case "attempt":
		if activity.Result != "attempted" || activity.FailureClass != "" {
			return &ValidationError{}
		}
	case "outcome":
		switch activity.Result {
		case "succeeded":
			if activity.FailureClass != "" {
				return &ValidationError{}
			}
		case "failed":
			if !validFailureClass(activity.FailureClass) {
				return &ValidationError{}
			}
		default:
			return &ValidationError{}
		}
	default:
		return &ValidationError{}
	}
	return nil
}

func validFailureClass(value string) bool {
	switch value {
	case "audit_unavailable",
		"authentication_failed",
		"connection_failed",
		"credential_unavailable",
		"dns_failed",
		"internal_failure",
		"invalid_destination",
		"not_found",
		"protocol_failed",
		"remote_rejected",
		"timeout",
		"tls_failed",
		"unsafe_endpoint",
		"unsupported":
		return true
	default:
		return false
	}
}
