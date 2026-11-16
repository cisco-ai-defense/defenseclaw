//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import "time"

// A managed service that exits this many times within the window is in a
// restart loop. Each start is recorded; a process that stays up for the
// stable period clears the record.
const (
	managedRestartLoopThreshold = 3
	managedRestartLoopWindow    = 10 * time.Minute
	managedRestartStableAfter   = 10 * time.Minute
	managedRestartHoldMinDelay  = 30 * time.Second
	managedRestartHoldMaxDelay  = 5 * time.Minute
)

// managedServiceStartLedger is the start record persisted in runtime/.
type managedServiceStartLedger struct {
	Starts    []int64 `json:"starts"`
	LastCause string  `json:"last_cause,omitempty"`
}

// record adds a start at now and forgets starts outside the window.
func (ledger *managedServiceStartLedger) record(now time.Time) {
	ledger.prune(now)
	ledger.Starts = append(ledger.Starts, now.Unix())
}

func (ledger *managedServiceStartLedger) prune(now time.Time) {
	kept := ledger.Starts[:0]
	for _, start := range ledger.Starts {
		if age := now.Sub(time.Unix(start, 0)); age >= 0 && age <= managedRestartLoopWindow {
			kept = append(kept, start)
		}
	}
	ledger.Starts = kept
}

// inLoop reports whether the recent starts make a restart loop.
func (ledger managedServiceStartLedger) inLoop(now time.Time) bool {
	recent := 0
	for _, start := range ledger.Starts {
		if age := now.Sub(time.Unix(start, 0)); age >= 0 && age <= managedRestartLoopWindow {
			recent++
		}
	}
	return recent >= managedRestartLoopThreshold
}

// managedRestartHoldDelay is the wait before a held service retries: it
// doubles with every start past the threshold, within the bounds.
func managedRestartHoldDelay(starts int) time.Duration {
	delay := managedRestartHoldMinDelay
	for extra := starts - managedRestartLoopThreshold; extra > 0 && delay < managedRestartHoldMaxDelay; extra-- {
		delay *= 2
	}
	if delay > managedRestartHoldMaxDelay {
		delay = managedRestartHoldMaxDelay
	}
	return delay
}
