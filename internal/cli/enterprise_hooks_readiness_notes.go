// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"sync"
	"sync/atomic"
)

// enterpriseHookGuardianWatching is set for the life of the guardian's watch
// loop (runEnterpriseHooksWatch), from before its first reconcile. The
// Windows guardian does not fail a Copilot row on the account's Claude Code
// user settings: its own pass migrates them, and a failing row would only
// reinstall the runtime every pass (GAP-1540).
var enterpriseHookGuardianWatching atomic.Bool

// enterpriseHookReadinessNotes collects, for one `enterprise hooks readiness`
// run (Setup's live readiness), the findings a target check reports as
// warnings instead of failing its row: an account's Claude Code user settings
// that the Windows migration cannot finish. One account's file never fails
// Install or Upgrade for the whole host. It is nil outside readiness, so
// `enterprise hooks verify` and ensure still fail the row and name the file
// (GAP-1540, LEAD DECISION 03:34).
var enterpriseHookReadinessNotes atomic.Pointer[enterpriseHookNoteSet]

// enterpriseHookNoteSet is a de-duplicated, ordered list of notes, safe for
// concurrent target checks. A nil set holds nothing.
type enterpriseHookNoteSet struct {
	mu    sync.Mutex
	notes []string
}

func (s *enterpriseHookNoteSet) add(note string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.notes {
		if existing == note {
			return
		}
	}
	s.notes = append(s.notes, note)
}

func (s *enterpriseHookNoteSet) list() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.notes...)
}

// enterpriseHookVerifyWarnings is what a verify or readiness run reports
// under `warnings`: its excused rows, then the readiness notes.
func enterpriseHookVerifyWarnings(run enterpriseHookVerifyRun, notes *enterpriseHookNoteSet) []string {
	warnings := make([]string, 0, len(run.Excused))
	for _, row := range run.Excused {
		warnings = append(warnings, enterpriseHookTargetLabel(row)+": "+row.Error+enterpriseHookVerifyExcusedNote(run, row))
	}
	return append(warnings, notes.list()...)
}
