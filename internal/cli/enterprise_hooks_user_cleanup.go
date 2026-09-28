// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Per-user cleanup of DefenseClaw's own registrations and plugins after a
// user loses enrollment (Windows standalone per-user connectors). The
// guardian runs each connector's teardown as the user, which edits only
// DefenseClaw-owned entries. A user who is signed out has no session token
// to act under, so the cleanup is recorded in this protected ledger and
// retried on every reconcile, including the one a sign-in triggers. The
// standalone Unix guardian records its cleanups in the same ledger
// (enterprise_hooks_user_cleanup_unix.go).

const (
	enterpriseHookUserCleanupFile     = managed.HookGuardianUserCleanupFile
	enterpriseHookUserCleanupVersion  = 1
	enterpriseHookUserCleanupMaxBytes = 4 << 20
	enterpriseHookUserCleanupMax      = 4096
	enterpriseHookUserCleanupErrorMax = 512
	// enterpriseHookUserCleanupRetryInterval spaces retries of an entry
	// whose last attempt failed; an entry waiting for sign-in is tried on
	// every reconcile.
	enterpriseHookUserCleanupRetryInterval = 5 * time.Minute
)

type enterpriseHookUserCleanup struct {
	Connector     string `json:"connector"`
	SID           string `json:"sid"`
	UID           int    `json:"uid,omitempty"` // a standalone Unix entry has no SID
	User          string `json:"user,omitempty"`
	UserHome      string `json:"user_home"`
	DataDir       string `json:"data_dir,omitempty"`
	RecordedAt    string `json:"recorded_at"`
	Attempts      int    `json:"attempts,omitempty"`
	LastAttemptAt string `json:"last_attempt_at,omitempty"`
	LastError     string `json:"last_error,omitempty"`
}

type enterpriseHookUserCleanupLedger struct {
	Version   int                         `json:"version"`
	UpdatedAt string                      `json:"updated_at"`
	Pending   []enterpriseHookUserCleanup `json:"pending"`
}

// enterpriseHookUserCleanupOutcome classifies one cleanup attempt.
type enterpriseHookUserCleanupOutcome int

const (
	// The registration was removed, or nothing is left to clean (the
	// profile is gone).
	enterpriseHookUserCleanupDone enterpriseHookUserCleanupOutcome = iota
	// The user has no session to act under; retried after sign-in.
	enterpriseHookUserCleanupPending
	// The attempt failed; retried on the next reconcile.
	enterpriseHookUserCleanupFailed
)

type enterpriseHookUserCleanupAttempt func(context.Context, enterpriseHookUserCleanup) (enterpriseHookUserCleanupOutcome, error)

type enterpriseHookUserCleanupResult struct {
	Removed []string
	Pending []string
	Failed  []string
}

func enterpriseHookUserCleanupKey(connectorName, sid string) string {
	return strings.ToLower(strings.TrimSpace(connectorName)) + "\x00" + strings.ToUpper(strings.TrimSpace(sid))
}

func enterpriseHookUserCleanupLabel(entry enterpriseHookUserCleanup) string {
	account := strings.TrimSpace(entry.SID)
	if account == "" {
		// A standalone Unix entry names the account instead.
		if account = strings.TrimSpace(entry.User); account == "" {
			account = fmt.Sprintf("uid %d", entry.UID)
		}
	}
	return strings.ToLower(strings.TrimSpace(entry.Connector)) + "/" + account
}

func enterpriseHookUserCleanupPath(dataDir string) string {
	return filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), enterpriseHookUserCleanupFile)
}

// enterpriseHookManifestAdmits reports whether (connector, SID) is an
// enabled manifest target.
func enterpriseHookManifestAdmits(manifest enterprisehooks.Manifest) func(string, string) bool {
	admitted := map[string]bool{}
	for _, target := range manifest.Targets {
		if target.IsEnabled() && strings.TrimSpace(target.SID) != "" {
			admitted[enterpriseHookUserCleanupKey(target.Connector, target.SID)] = true
		}
	}
	return func(connectorName, sid string) bool {
		return admitted[enterpriseHookUserCleanupKey(connectorName, sid)]
	}
}

// enterpriseHookUserCleanupFromRow turns a protected guardian row into a
// cleanup entry, or reports false when the row names no SID and home.
func enterpriseHookUserCleanupFromRow(row enterpriseHookReconcileRow, now time.Time) (enterpriseHookUserCleanup, bool) {
	entry := enterpriseHookUserCleanup{
		Connector:  strings.ToLower(strings.TrimSpace(row.Connector)),
		SID:        strings.TrimSpace(row.SID),
		User:       strings.TrimSpace(row.User),
		UserHome:   strings.TrimSpace(row.UserHome),
		RecordedAt: now.UTC().Format(time.RFC3339Nano),
	}
	if row.Result != nil {
		if entry.Connector == "" {
			entry.Connector = strings.ToLower(strings.TrimSpace(row.Result.Connector))
		}
		if entry.UserHome == "" {
			entry.UserHome = strings.TrimSpace(row.Result.UserHome)
		}
		entry.DataDir = strings.TrimSpace(row.Result.DataDir)
	}
	if entry.Connector == "" || entry.SID == "" || entry.UserHome == "" {
		return enterpriseHookUserCleanup{}, false
	}
	entry.UserHome = filepath.Clean(entry.UserHome)
	if entry.DataDir != "" {
		entry.DataDir = filepath.Clean(entry.DataDir)
	}
	return entry, true
}

// planEnterpriseHookUserCleanups adds every previously protected per-user
// row the manifest no longer admits to pending. A pending entry is dropped
// only once the manifest admits the user again and the guardian protects
// that row again (install owns the registration from then on). An entry the
// manifest re-admits before a successful reinstall (a signed-out user whose
// row is still deferred) stays recorded: nothing else records it, so a second
// revocation before that reinstall would otherwise lose the cleanup.
func planEnterpriseHookUserCleanups(
	pending []enterpriseHookUserCleanup,
	previous []enterpriseHookReconcileRow,
	admitted func(connectorName, sid string) bool,
	perUser func(connectorName string) bool,
	now time.Time,
) []enterpriseHookUserCleanup {
	protected := map[string]bool{}
	for _, row := range previous {
		connectorName := strings.TrimSpace(row.Connector)
		if connectorName == "" && row.Result != nil {
			connectorName = strings.TrimSpace(row.Result.Connector)
		}
		if sid := strings.TrimSpace(row.SID); connectorName != "" && sid != "" {
			protected[enterpriseHookUserCleanupKey(connectorName, sid)] = true
		}
	}
	planned := make([]enterpriseHookUserCleanup, 0, len(pending))
	seen := map[string]bool{}
	for _, entry := range pending {
		key := enterpriseHookUserCleanupKey(entry.Connector, entry.SID)
		if seen[key] || (protected[key] && admitted(entry.Connector, entry.SID)) {
			continue
		}
		seen[key] = true
		planned = append(planned, entry)
	}
	for _, row := range previous {
		entry, ok := enterpriseHookUserCleanupFromRow(row, now)
		if !ok || !perUser(entry.Connector) {
			continue
		}
		key := enterpriseHookUserCleanupKey(entry.Connector, entry.SID)
		if seen[key] || admitted(entry.Connector, entry.SID) {
			continue
		}
		seen[key] = true
		planned = append(planned, entry)
	}
	sortEnterpriseHookUserCleanups(planned)
	return planned
}

func sortEnterpriseHookUserCleanups(entries []enterpriseHookUserCleanup) {
	sort.SliceStable(entries, func(i, j int) bool {
		return enterpriseHookUserCleanupKey(entries[i].Connector, entries[i].SID) <
			enterpriseHookUserCleanupKey(entries[j].Connector, entries[j].SID)
	})
}

// runEnterpriseHookUserCleanups attempts every entry and returns the ones
// still to clean. A failed attempt records its error; an entry that is only
// waiting for its user to sign in is carried unchanged, so a waiting ledger
// is not rewritten on every reconcile.
func runEnterpriseHookUserCleanups(
	ctx context.Context,
	entries []enterpriseHookUserCleanup,
	attempt enterpriseHookUserCleanupAttempt,
	now time.Time,
) ([]enterpriseHookUserCleanup, enterpriseHookUserCleanupResult) {
	var result enterpriseHookUserCleanupResult
	remaining := make([]enterpriseHookUserCleanup, 0, len(entries))
	for _, entry := range entries {
		label := enterpriseHookUserCleanupLabel(entry)
		if ctx.Err() != nil || enterpriseHookUserCleanupBackingOff(entry, now) {
			remaining = append(remaining, entry)
			result.Pending = append(result.Pending, label)
			continue
		}
		outcome, err := attempt(ctx, entry)
		switch outcome {
		case enterpriseHookUserCleanupDone:
			result.Removed = append(result.Removed, label)
			continue
		case enterpriseHookUserCleanupPending:
			result.Pending = append(result.Pending, label)
		default:
			message := "cleanup failed"
			if err != nil {
				message = err.Error()
			}
			message = boundedEnterpriseHookUserCleanupText(message)
			result.Failed = append(result.Failed, label+": "+message)
			entry.Attempts++
			entry.LastAttemptAt = now.UTC().Format(time.RFC3339Nano)
			entry.LastError = message
		}
		remaining = append(remaining, entry)
	}
	return remaining, result
}

func enterpriseHookUserCleanupBackingOff(entry enterpriseHookUserCleanup, now time.Time) bool {
	if entry.LastError == "" {
		return false
	}
	last, err := time.Parse(time.RFC3339Nano, entry.LastAttemptAt)
	if err != nil {
		return false
	}
	elapsed := now.Sub(last)
	return elapsed >= 0 && elapsed < enterpriseHookUserCleanupRetryInterval
}

func boundedEnterpriseHookUserCleanupText(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= enterpriseHookUserCleanupErrorMax {
		return value
	}
	return value[:enterpriseHookUserCleanupErrorMax] + "..."
}

func sameEnterpriseHookUserCleanups(left, right []enterpriseHookUserCleanup) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// loadEnterpriseHookUserCleanups reads the protected ledger; a missing file
// is an empty ledger.
func loadEnterpriseHookUserCleanups(dataDir string) ([]enterpriseHookUserCleanup, error) {
	path := enterpriseHookUserCleanupPath(dataDir)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect per-user cleanup ledger %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("per-user cleanup ledger is not a regular file: %s", path)
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(path); err != nil {
		return nil, err
	}
	data, err := readEnterpriseHookBoundedFile(path, info, enterpriseHookUserCleanupMaxBytes, "per-user cleanup ledger")
	if err != nil {
		return nil, fmt.Errorf("read per-user cleanup ledger %s: %w", path, err)
	}
	var ledger enterpriseHookUserCleanupLedger
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ledger); err != nil {
		return nil, fmt.Errorf("parse per-user cleanup ledger %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse per-user cleanup ledger %s: trailing content", path)
	}
	if ledger.Version != enterpriseHookUserCleanupVersion || len(ledger.Pending) > enterpriseHookUserCleanupMax {
		return nil, fmt.Errorf("per-user cleanup ledger %s has an invalid schema", path)
	}
	for _, entry := range ledger.Pending {
		if strings.TrimSpace(entry.Connector) == "" || (strings.TrimSpace(entry.SID) == "" && entry.UID <= 0) ||
			!filepath.IsAbs(strings.TrimSpace(entry.UserHome)) {
			return nil, fmt.Errorf("per-user cleanup ledger %s contains an incomplete entry", path)
		}
	}
	return ledger.Pending, nil
}

// saveEnterpriseHookUserCleanups publishes the ledger (administrator-owned,
// not writable by the gateway service); an empty ledger removes the file.
func saveEnterpriseHookUserCleanups(dataDir string, pending []enterpriseHookUserCleanup, now time.Time) error {
	path := enterpriseHookUserCleanupPath(dataDir)
	if len(pending) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove empty per-user cleanup ledger: %w", err)
		}
		return nil
	}
	if len(pending) > enterpriseHookUserCleanupMax {
		// Keep the oldest records; a host with this many revoked users
		// is reported rather than grown without bound.
		pending = pending[:enterpriseHookUserCleanupMax]
	}
	data, err := json.MarshalIndent(enterpriseHookUserCleanupLedger{
		Version:   enterpriseHookUserCleanupVersion,
		UpdatedAt: now.UTC().Format(time.RFC3339Nano),
		Pending:   pending,
	}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := prepareEnterpriseHookAuthorizationDir(dataDir); err != nil {
		return err
	}
	if err := writeEnterpriseHookProtectedFile(path, data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return fmt.Errorf("protect per-user cleanup ledger: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return fmt.Errorf("set per-user cleanup ledger ownership: %w", err)
	}
	return enterpriseHookAuthorizationFileTrustCheck(path)
}

// reconcileEnterpriseHookUserCleanups is the guardian step: plan from the
// previous protected rows and the ledger, attempt every cleanup of a user the
// manifest does not enroll, log the outcome, and persist what is still
// pending. An error means the ledger
// could not be written, so the caller must not publish state that drops
// the revoked rows.
func reconcileEnterpriseHookUserCleanups(
	ctx context.Context,
	stderr io.Writer,
	dataDir string,
	manifest enterprisehooks.Manifest,
	perUser func(string) bool,
	attempt enterpriseHookUserCleanupAttempt,
	now time.Time,
) error {
	pending, err := loadEnterpriseHookUserCleanups(dataDir)
	damaged := err != nil
	if damaged {
		// A damaged ledger is replaced below; its entries are lost, which
		// is reported, but it must not stop protection repairs.
		fmt.Fprintf(stderr, "defenseclaw: enterprise per-user cleanup: %v (replacing it)\n", err)
		pending = nil
	}
	authorization, _, err := loadEnterpriseHookGuardianAuthorization(dataDir)
	if err != nil {
		return err
	}
	admitted := enterpriseHookManifestAdmits(manifest)
	planned := planEnterpriseHookUserCleanups(
		pending,
		authorization.ProtectedTargets,
		admitted,
		perUser,
		now,
	)
	known := map[string]bool{}
	for _, entry := range pending {
		known[enterpriseHookUserCleanupLabel(entry)] = true
	}
	// A recorded user the manifest enrolls again is waiting for its
	// reinstall: removing the registration now would undo that install, so
	// the entry is carried unchanged until the guardian protects the row
	// again (then it is dropped) or the user is revoked again (then it runs).
	var due, held []enterpriseHookUserCleanup
	for _, entry := range planned {
		if admitted(entry.Connector, entry.SID) {
			held = append(held, entry)
		} else {
			due = append(due, entry)
		}
	}
	remaining, result := runEnterpriseHookUserCleanups(ctx, due, attempt, now)
	remaining = append(remaining, held...)
	sortEnterpriseHookUserCleanups(remaining)
	for _, label := range result.Removed {
		fmt.Fprintf(stderr, "defenseclaw: enterprise per-user cleanup: removed DefenseClaw registration %s\n", label)
	}
	for _, label := range result.Pending {
		if !known[label] {
			fmt.Fprintf(stderr, "defenseclaw: enterprise per-user cleanup: %s has no active session; recorded for cleanup at next sign-in\n", label)
		}
	}
	for _, failure := range result.Failed {
		fmt.Fprintf(stderr, "defenseclaw: enterprise per-user cleanup: %s (will retry)\n", failure)
	}
	if !damaged && sameEnterpriseHookUserCleanups(pending, remaining) {
		return nil
	}
	return saveEnterpriseHookUserCleanups(dataDir, remaining, now)
}
