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
//     `waiting_for_targets` or `ready` using write-to-temp + rename so a
//     partial write is impossible. It publishes `waiting_for_targets`
//     when it starts (before its first reconcile) and when it stops,
//     publishes the outcome of every reconcile (`ready` only for a clean
//     reconcile with no failed target and no state-publication error),
//     and re-publishes a `ready` at least every RefreshInterval.
//
//   - Sidecar reads best-effort every ~5 s to update the health
//     snapshot's `configuration.state` field through ReadCurrentState. A
//     missing file, unreadable body, or a `ready` whose modification time
//     is more than ReadyMaxAge away from now maps to StateUnknown, which
//     the sidecar's collapsing rule treats as `waiting_for_targets` (safe
//     default — never a false-positive `ready`). The age bound is what
//     keeps a guardian that crashed, was killed, or has not started yet
//     after a reinstall from leaving a stale `ready` behind: the
//     directory survives guardian restarts and non-purge uninstall.
//
//   - Writer and reader resolve the path through the single helper
//     PathForDataDir, which places the file in the protected hook
//     guardian authorization directory
//     (managed.HookGuardianAuthorizationDir): `<StateRoot>\hook-guardian-state`
//     on Windows and `/opt/cisco/secureclient/defenseclaw/hook-guardian-state`
//     on macOS, both selected by DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR in the
//     gateway AND guardian service environments. That directory is
//     writable only by SYSTEM/Administrators (root on macOS) and readable
//     by the gateway, so the gateway can observe the state without being
//     able to forge it. Neither the manifest directory (administrator-only,
//     not gateway-readable on Windows) nor the gateway-writable data_dir is
//     a valid location.
//
//   - The state is diagnostic health only. It never authorizes a target,
//     enrollment, or enforcement decision.
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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// FileName is the state file's basename inside the protected hook
// guardian authorization directory. Constant so tests and callers don't
// guess.
const FileName = ".state"

// RefreshInterval is the longest a running guardian waits before
// re-publishing a `ready` state, independent of its --interval, so a
// healthy guardian's file never ages past ReadyMaxAge.
const RefreshInterval = time.Minute

// ReadyMaxAge bounds how long a published `ready` is honored without the
// guardian re-publishing it. It is several RefreshIntervals so a slow
// reconcile does not flap the health surface, and short enough that a
// guardian which stopped without retracting `ready` (crash, kill, or a
// reinstall whose guardian has not started) falls back to
// `waiting_for_targets` within minutes.
const ReadyMaxAge = 5 * RefreshInterval

// PathForDataDir returns the one state file path both the guardian
// (writer) and the gateway sidecar (reader) use. Both processes load the
// same managed config and receive the same DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR,
// so resolving through managed.HookGuardianAuthorizationDir(cfg.DataDir)
// lands on the same protected directory on every platform; without the
// environment override the shared default is `<data_dir>-hook-guardian`,
// which still agrees on both sides and stays outside the gateway-writable
// data_dir.
func PathForDataDir(dataDir string) string {
	return filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), FileName)
}

// Encode returns the exact bytes WriteState and the protected guardian
// writer publish for state. It rejects any literal the sidecar cannot map
// so a typo never ships a state string the reader won't recognise.
func Encode(state string) ([]byte, error) {
	if state != StateWaitingForTargets && state != StateReady {
		return nil, fmt.Errorf("guardianstate: refusing to write unknown state %q", state)
	}
	// One-line ASCII body plus LF. The sidecar's ReadState trims
	// whitespace so the newline is cosmetic; keep it for `type` /
	// `cat` friendliness on the Windows box during triage.
	return []byte(state + "\n"), nil
}

// PathForPlatform is the single state-file path both the guardian (writer)
// and the gateway (reader) use. The standalone Unix guardian writes it
// inside its root-owned authorization directory, which the unprivileged
// gateway can read but not write; every other deployment keeps the
// PathForDataDir location.
func PathForPlatform(standaloneUnix bool, dataDir, authDir string) string {
	if standaloneUnix {
		return filepath.Join(authDir, FileName)
	}
	return PathForDataDir(dataDir)
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
	state, _ := readStateFile(path)
	return state
}

// ReadCurrentState is ReadState plus the freshness rule the gateway
// sidecar applies: a `ready` whose modification time is more than
// ReadyMaxAge before (or after, for a clock step) `now` is reported as
// StateUnknown. `waiting_for_targets` is returned regardless of age
// because it already collapses to the safe default.
func ReadCurrentState(path string, now time.Time) string {
	state, modTime := readStateFile(path)
	if state != StateReady {
		return state
	}
	age := now.Sub(modTime)
	if age > ReadyMaxAge || age < -ReadyMaxAge {
		return StateUnknown
	}
	return StateReady
}

// readStateFile returns the recognised literal and the modification time
// of the same open handle the body was read from.
func readStateFile(path string) (string, time.Time) {
	f, err := os.Open(path) // #nosec G304 — path derives from install-time layout, not user input.
	if err != nil {
		return StateUnknown, time.Time{}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return StateUnknown, time.Time{}
	}

	var buf [128]byte
	n, err := f.Read(buf[:])
	if err != nil && n == 0 {
		return StateUnknown, time.Time{}
	}
	// Reject a state file that exceeded the 128-byte read: if there is
	// another byte after our buffer, the file is oversized and we
	// don't want to trust its contents.
	var extra [1]byte
	if m, _ := f.Read(extra[:]); m > 0 {
		return StateUnknown, time.Time{}
	}

	body := strings.TrimSpace(string(buf[:n]))
	switch body {
	case StateWaitingForTargets:
		return StateWaitingForTargets, info.ModTime()
	case StateReady:
		return StateReady, info.ModTime()
	default:
		return StateUnknown, time.Time{}
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
	body, err := Encode(state)
	if err != nil {
		return err
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

	if _, err := tmp.Write(body); err != nil {
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
