// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"strings"
	"time"
)

const (
	HookGuardianMaxAge     = 5 * time.Minute
	HookGuardianFutureSkew = time.Minute
)

// ValidateHookGuardianFreshness prevents a stopped guardian from leaving a
// once-healthy authorization record green indefinitely. Callers supply now so
// boundary and skew behavior remains deterministic in tests.
func ValidateHookGuardianFreshness(updatedAt string, now time.Time) error {
	timestamp, err := time.Parse(time.RFC3339, strings.TrimSpace(updatedAt))
	if err != nil {
		return fmt.Errorf("invalid updated_at: %w", err)
	}
	now = now.UTC()
	timestamp = timestamp.UTC()
	if timestamp.After(now.Add(HookGuardianFutureSkew)) {
		return fmt.Errorf("updated_at %s is more than %s in the future", timestamp.Format(time.RFC3339), HookGuardianFutureSkew)
	}
	if now.Sub(timestamp) > HookGuardianMaxAge {
		return fmt.Errorf("updated_at %s is stale (older than %s)", timestamp.Format(time.RFC3339), HookGuardianMaxAge)
	}
	return nil
}
