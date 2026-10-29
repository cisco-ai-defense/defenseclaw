// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const enterpriseHookReasonMax = 1024

// enterpriseHookTargetUnavailable reports a failure that means the user is
// not reachable right now rather than that something is wrong: no active
// session to act as the user, or a profile folder that is not there (a
// detached FSLogix or roaming profile, a renamed folder).
func enterpriseHookTargetUnavailable(err error) bool {
	return err != nil &&
		(enterprisehooks.IsWindowsTargetSessionUnavailable(err) || errors.Is(err, os.ErrNotExist))
}

func enterpriseHookBoundReason(reason string) string {
	reason = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(reason))
	if len(reason) > enterpriseHookReasonMax {
		reason = reason[:enterpriseHookReasonMax]
	}
	if reason == "" {
		reason = "unavailable"
	}
	return reason
}

func enterpriseHookTargetHealthUnit(row enterpriseHookReconcileRow) string {
	return enterpriseHookUnit(row.Connector, row.SID)
}

func enterpriseHookUnit(connectorName, sid string) string {
	return strings.ToLower(strings.TrimSpace(connectorName)) + "@" + strings.ToUpper(strings.TrimSpace(sid))
}

// enterpriseHookTargetHealthTracker logs a failed or pending target once per
// streak, so a target that stays unavailable for days does not repeat the
// same line every tick. The target is still retried on every tick.
type enterpriseHookTargetHealthTracker struct {
	mu      sync.Mutex
	streaks map[string]struct{}
}

var enterpriseHookTargetHealth = &enterpriseHookTargetHealthTracker{}

func (tracker *enterpriseHookTargetHealthTracker) observe(row enterpriseHookReconcileRow, reason string) {
	unit := enterpriseHookTargetHealthUnit(row)
	tracker.mu.Lock()
	if tracker.streaks == nil {
		tracker.streaks = map[string]struct{}{}
	}
	_, logged := tracker.streaks[unit]
	tracker.streaks[unit] = struct{}{}
	tracker.mu.Unlock()
	if logged {
		return
	}
	managed.EmitResilienceEvent(managed.MarkerSkip, map[string]string{
		"unit":   unit,
		"path":   strings.TrimSpace(row.UserHome),
		"reason": enterpriseHookBoundReason(reason) + "; retried every reconcile",
	})
}

func (tracker *enterpriseHookTargetHealthTracker) clear(row enterpriseHookReconcileRow) {
	tracker.mu.Lock()
	delete(tracker.streaks, enterpriseHookTargetHealthUnit(row))
	tracker.mu.Unlock()
}

// enterpriseHookEnrollmentManifest returns the manifest whose enabled rows
// the Guardian publishes into machine policy this tick: every row except a
// failed target that was never protected (including a signed-out user who
// is waiting for a session).
// Disabled and removed rows are untouched, so revocation is unchanged.
func enterpriseHookEnrollmentManifest(
	manifest enterprisehooks.Manifest,
	rows []enterpriseHookReconcileRow,
	unenrolled map[string]struct{},
) enterprisehooks.Manifest {
	drop := make(map[string]struct{}, len(unenrolled))
	for unit := range unenrolled {
		drop[unit] = struct{}{}
	}
	if len(drop) == 0 {
		return manifest
	}
	reduced := manifest
	reduced.Targets = make([]enterprisehooks.ManifestTarget, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		if target.IsEnabled() {
			if _, skip := drop[enterpriseHookUnit(target.Connector, target.SID)]; skip {
				continue
			}
		}
		reduced.Targets = append(reduced.Targets, target)
	}
	return reduced
}
