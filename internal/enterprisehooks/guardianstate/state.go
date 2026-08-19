// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package guardianstate is the out-of-band state file the hook-guardian
// service writes to signal its `waiting_for_targets` / `ready` state to
// the gateway sidecar. See spec 003 (docs/specs/003-windows-deferred-config/)
// § Data flow.
//
// Contract:
//
//   - Guardian writes exactly one of the string literals
//     `waiting_for_targets` or `ready` at every state transition
//     using write-to-temp + rename so a partial write is impossible.
//
//   - Sidecar reads best-effort every ~5 s to update the health
//     snapshot's `configuration.state` field. A missing file or
//     unreadable body maps to StateUnknown, which the sidecar's
//     collapsing rule treats as `waiting_for_targets` (safe default —
//     never a false-positive `ready`).
//
//   - Uninstall removes the entire `<StateRoot>\hook-guardian\`
//     directory (via the transactional path in
//     packaging/windows/DefenseClawEnterprise.psm1:6003-6086), so the
//     state file goes with it.
//
// This package deliberately has no dependency on internal/gateway to
// avoid an import cycle: the sidecar imports guardianstate, and the
// guardian (which lives under internal/cli/) imports guardianstate,
// but neither imports the other.

package guardianstate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// State names — the exact bytes the guardian writes and the sidecar
// reads. Match the ConfigurationState values in
// internal/gateway/health.go so a change to either constant is caught
// at build time by the sidecar's mapping table (see WriteState +
// ReadState).
const (
	StateWaitingForTargets = "waiting_for_targets"
	StateReady             = "ready"
	// StateUnknown is what ReadState returns when the file is missing,
	// unreadable, or has a body that doesn't match a known literal.
	// Callers apply the safe-default collapsing rule.
	StateUnknown = ""
)

// FileName is the state file's basename under the guardian's state
// root directory. Constant so tests and callers don't guess.
const FileName = ".state"

// PathForStateRoot returns the full state file path for a given
// hook-guardian state root. The state root is
// `<StateRoot>\hook-guardian\` on Windows (matches the runtime layout
// in DefenseClawEnterprise.psm1); pass the containing directory here,
// not the state file itself.
func PathForStateRoot(stateRoot string) string {
	return filepath.Join(stateRoot, FileName)
}

// ReadState reads the state file at the given path. Returns
// StateUnknown when the file does not exist, cannot be opened,
// exceeds a safety byte limit, or holds a body that is not a known
// literal. Never returns an error — read-side callers treat any
// failure as StateUnknown and apply the safe default.
//
// The read is bounded to 128 bytes; a legitimate state file is
// ≤ len("waiting_for_targets\n") = 20 bytes. A larger file is either
// a mistake or an attempt to consume unbounded RAM in the sidecar's
// hot path; discard it.
func ReadState(path string) string {
	f, err := os.Open(path) // #nosec G304 — path derives from install-time layout, not user input.
	if err != nil {
		return StateUnknown
	}
	defer f.Close()

	var buf [128]byte
	n, err := f.Read(buf[:])
	if err != nil && n == 0 {
		return StateUnknown
	}
	// Reject a state file that exceeded the 128-byte read: if there is
	// another byte after our buffer, the file is oversized and we
	// don't want to trust its contents.
	var extra [1]byte
	if m, _ := f.Read(extra[:]); m > 0 {
		return StateUnknown
	}

	body := strings.TrimSpace(string(buf[:n]))
	switch body {
	case StateWaitingForTargets:
		return StateWaitingForTargets
	case StateReady:
		return StateReady
	default:
		return StateUnknown
	}
}

// WriteState atomically writes `state` to the file at `path`. Uses
// write-to-temp + rename so a concurrent reader never sees a partial
// body. Returns an error only on I/O failure; caller decides whether
// to propagate or log-and-continue.
//
// Callers pass one of StateWaitingForTargets or StateReady. Any other
// value returns a validation error so a typo doesn't ship a
// state string the sidecar won't recognise.
func WriteState(path, state string) error {
	if state != StateWaitingForTargets && state != StateReady {
		return fmt.Errorf("guardianstate: refusing to write unknown state %q", state)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, FileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("guardianstate: create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup on any error path below. The final Rename
	// succeeds only if we haven't returned; a leftover .tmp-* file
	// is cheap for the next writer to overwrite.
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	// One-line ASCII body plus LF. The sidecar's ReadState trims
	// whitespace so the newline is cosmetic; keep it for `type` /
	// `cat` friendliness on the Windows box during triage.
	if _, err := tmp.WriteString(state + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("guardianstate: write body: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("guardianstate: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("guardianstate: rename %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}
