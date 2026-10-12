// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"context"
	"encoding/json"
	"time"
)

// The gateway checks the groups and users the guardrail profile assignments
// name in the background, at start and after each reload, and /health says
// profile_assignment_check_pending until the first check has finished. A
// lifecycle command that read /health right after it applied a config got no
// warning for a group or a SID that selects nobody (GAP-0306, GAP-0409).

// ProfileAssignmentCheckPending reports a /health body whose first profile
// assignment check is still running.
func ProfileAssignmentCheckPending(body []byte) bool {
	var health struct {
		Pending bool `json:"profile_assignment_check_pending"`
	}
	return json.Unmarshal(body, &health) == nil && health.Pending
}

// SettledGatewayHealth reads /health with fetch, and reads it again every
// interval, at most attempts times, while the profile assignment check is
// pending. It returns the last body read; the first read's error is returned
// as is.
func SettledGatewayHealth(ctx context.Context, fetch func() ([]byte, error), interval time.Duration, attempts int) ([]byte, error) {
	body, err := fetch()
	for attempt := 0; err == nil && attempt < attempts && ProfileAssignmentCheckPending(body); attempt++ {
		select {
		case <-ctx.Done():
			return body, nil
		case <-time.After(interval):
		}
		next, nextErr := fetch()
		if nextErr != nil {
			break
		}
		body = next
	}
	return body, err
}
