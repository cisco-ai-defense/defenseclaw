// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The standalone gateway keeps the session records in its protected data
// directory, which the hook cannot read. A gateway outage in fail mode open
// lets a clean scan through without the gateway (GAP-0346), so a session
// that the gateway blocked earlier (an unapproved hook at its start, since
// deleted while the agent still runs it) would be let through too. The hook
// therefore keeps a copy of every session block the gateway enforces under
// the account's home, and consults it before an open outage allows a call
// (final review, P1).

// localSessionDir is the account-home session directory for key; ok is
// false when there is no absolute home or the key names neither a session
// nor a process.
func localSessionDir(accountHome string, key SessionKey) (string, bool) {
	home := strings.TrimSpace(accountHome)
	if home == "" || !filepath.IsAbs(home) || !key.valid() {
		return "", false
	}
	return filepath.Join(home, ".defenseclaw", sessionDirName), true
}

// localSessionPaths returns the process record, then the session record, of
// key (each only when its ID is known).
func localSessionPaths(dir string, key SessionKey) (process, session string) {
	if key.Process != "" {
		process = sessionPathInDir(dir, key.Connector, sessionKindProcess, key.Process)
	}
	if key.Session != "" {
		session = sessionPathInDir(dir, key.Connector, sessionKindSession, key.Session)
	}
	return process, session
}

// WithSessionStartBlock sets decision.SessionBlock when decision blocks its
// session (a session start that found an unapproved hook or plugin, or
// whose scan stopped on a budget), for a scan the gateway could not record.
func WithSessionStartBlock(decision GuardDecision, sessionStart bool, now time.Time) GuardDecision {
	cause, _, ok := sessionStartBlockCause(decision, sessionStart)
	if !ok {
		return decision
	}
	stamp := now.UTC().Format(time.RFC3339)
	decision.SessionBlock = &SessionRecord{
		Started: stamp, State: ForeignHookStateHash(decision.Findings), Blocked: true, BlockedAt: stamp,
		Scope: cause.Scope, Path: cause.Path, Digest: cause.Digest, Reason: cause.Reason,
	}
	return decision
}

// MirrorForeignHookSessionBlock keeps the account-home copy of the gateway's
// answer for key: a session block (decision.SessionBlock) is written for the
// agent process and the session, keeping a block already there; an allow
// removes both, because the gateway holds no block for them. A denial of
// this call alone changes nothing. Best effort: the gateway stays the
// authority while it answers.
func MirrorForeignHookSessionBlock(accountHome string, key SessionKey, decision GuardDecision, now time.Time) error {
	dir, ok := localSessionDir(accountHome, key)
	if !ok {
		return nil
	}
	process, session := localSessionPaths(dir, key)
	var errs []error
	for _, path := range []string{process, session} {
		if path == "" {
			continue
		}
		if !decision.Deny {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		if decision.SessionBlock == nil {
			continue
		}
		if record, exists, err := readSessionRecord(path); err == nil && exists && record.Blocked && !sessionBlockExpired(record, now) {
			// A block keeps its BlockedAt.
			continue
		}
		record := *decision.SessionBlock
		record.Connector, record.Session, record.Process, record.Blocked = key.Connector, key.Session, key.Process, true
		stamp := now.UTC().Format(time.RFC3339)
		if record.BlockedAt == "" {
			record.BlockedAt = stamp
		}
		if record.Started == "" {
			record.Started, record.State = stamp, ForeignHookStateHash(nil)
		}
		if err := writeSessionRecord(path, record); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ApplyMirroredForeignHookSession is the session check of a call that a
// gateway outage in fail mode open lets through: decision (a scan that
// found no unapproved hook) stands only when the account-home copy holds no
// unexpired block for the agent process or the session. A record that
// exists but cannot be read, an account without a home, or a key that names
// neither a session nor a process (which the gateway refuses too) denies
// the call. A session start of another agent process (a restarted agent
// resuming the session) is not held by the session's block, as in
// ApplyForeignHookSession.
func ApplyMirroredForeignHookSession(accountHome string, key SessionKey, sessionStart bool, decision GuardDecision, now time.Time) GuardDecision {
	dir, ok := localSessionDir(accountHome, key)
	if !ok {
		return sessionUnavailableDecision(decision)
	}
	process, session := localSessionPaths(dir, key)
	for _, path := range []string{process, session} {
		if path == "" {
			continue
		}
		record, exists, err := readSessionRecord(path)
		if err != nil {
			return sessionUnavailableDecision(decision)
		}
		if !exists || !record.Blocked || sessionBlockExpired(record, now) {
			continue
		}
		if path == session && sessionStart && key.Process != "" && record.Process != key.Process {
			continue
		}
		result := stickySessionDecision(decision, key.Connector, record)
		result.SessionBlock = &record
		return result
	}
	return decision
}
