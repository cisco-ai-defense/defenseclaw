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
	HookGuardianFutureSkew = 5 * time.Minute
)

// ValidateHookGuardianFreshness prevents a stopped guardian from leaving a
// once-healthy authorization record green indefinitely. Callers supply now so
// boundary and skew behavior remains deterministic in tests.
//
// NTP-jump note (T5.5): both writer and reader consult wall-clock
// (time.Now()) so a system-clock correction between write and read
// can inflate or invert the delta. HookGuardianMaxAge and
// HookGuardianFutureSkew are symmetric at 5 minutes each — chosen to
// absorb NTP step corrections of that size in either direction. A
// larger step (rare in practice on managed hosts that boot with a
// bad RTC and then jump multiple minutes after ntpd catches up) will
// still surface as either "stale" or "future"; the guardian is
// expected to re-publish on its next interval regardless, so the
// worst case is a single interval of transient unhealthy state
// followed by self-recovery. If NTP-driven false stales become a
// real operator pain-point we can plumb a monotonic generation
// counter through the on-disk manifest — deferred as follow-up
// scope because it requires a schema bump.
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
