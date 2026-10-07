// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

// etaMinWindow is how long a burn-in window must run before its rate gives
// an ETA; before that the progress reads "measuring".
const etaMinWindow = 24 * time.Hour

// burnInProgress is one enrolled user's burn-in, in the terms an
// administrator plans with: covered agent-hours of the needed ones, and the
// calendar time until ready at the rate so far.
type burnInProgress struct {
	Covered, Needed time.Duration
	// Percent is Covered of Needed, 0-100 (100 when no burn-in is needed).
	Percent int
	Ready   bool
	// ETA is the calendar time until ready; HasETA is false while
	// Measuring (the window is younger than etaMinWindow), with no agent
	// use yet, and for users with no anchored agent.
	ETA       time.Duration
	HasETA    bool
	Measuring bool
	// Reset is set when a would-block hit restarted the window.
	Reset bool
	// NoAgent is set for a user with no anchored agent (nothing accrues).
	NoAgent bool
}

// progressOf computes a user's burn-in from the helper's per-user status and
// burnin.json at now. Burn-in accrues only while an anchored agent of the
// user runs, so the ETA is (needed - covered) / (covered / window age).
func progressOf(user kernelpolicy.UIDStatus, record *kernelpolicy.UIDRecord, now time.Time) burnInProgress {
	p := burnInProgress{
		Covered: time.Duration(user.CoveredSeconds) * time.Second,
		Needed:  time.Duration(user.NeededSeconds) * time.Second,
	}
	p.NoAgent = user.State == kernelpolicy.UIDInactive && user.Reason == kernelpolicy.ReasonNoAnchors
	switch {
	case p.Needed <= 0:
		p.Percent, p.Ready = 100, true
	case p.Covered >= p.Needed:
		p.Percent, p.Ready = 100, true
	default:
		p.Percent = int(math.Floor(100 * float64(p.Covered) / float64(p.Needed)))
	}
	if record != nil {
		for _, hit := range record.WouldBlock {
			if hit != nil && !hit.Last.IsZero() && !hit.Last.Before(record.WindowStart.Add(-time.Second)) {
				p.Reset = true
			}
		}
	}
	if p.Ready || p.NoAgent || record == nil || record.WindowStart.IsZero() {
		return p
	}
	age := now.Sub(record.WindowStart)
	switch {
	case age < etaMinWindow:
		p.Measuring = true
	case p.Covered > 0:
		rate := float64(p.Covered) / float64(age)
		p.ETA, p.HasETA = time.Duration(float64(p.Needed-p.Covered)/rate), true
	}
	return p
}

// nextReady is the shortest ETA of the users still in burn-in, as of now.
func nextReady(state kernelpolicy.State, now time.Time) (time.Duration, bool) {
	best, found := time.Duration(0), false
	for _, user := range state.UIDs {
		if user.State == kernelpolicy.UIDEnforcing {
			continue
		}
		p := progressOf(user, state.BurnIn.UIDs[strconv.Itoa(user.UID)], now)
		if p.HasETA && (!found || p.ETA < best) {
			best, found = p.ETA, true
		}
	}
	return best, found
}

// humanDuration is a calendar duration in the words the ETA uses: "~1 hour",
// "~5 hours" under two days, "~9 days" after.
func humanDuration(d time.Duration) string {
	hours := d.Hours()
	switch {
	case hours < 1.5:
		return "~1 hour"
	case hours < 48:
		return fmt.Sprintf("~%d hours", int(math.Round(hours)))
	}
	return fmt.Sprintf("~%d days", int(math.Round(hours/24)))
}
