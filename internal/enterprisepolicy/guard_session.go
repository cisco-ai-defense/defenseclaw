// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Per-session foreign-hook state.
//
// Claude Code, Codex and Copilot CLI read their hooks when a session starts
// and keep running them for the rest of the session, even after the file
// that defined a hook changes or disappears; OpenCode and Amp load plugins
// once per process. Checking the files on every call therefore misses a
// foreign hook that was present when the session started and was deleted
// afterwards. So the hook records a snapshot at SessionStart (the hash of
// the foreign-hook state it found) and, when an unapproved hook or plugin
// was present then, keeps denying that session's tool calls until the agent
// restarts, for at most sessionRecordTTL. A session-start scan that stops
// on its file, byte, referenced-path or time budget blocks the same way,
// because the agent may have loaded a hook from a source the scan never
// reached. A hook found later in a session, or a file the scan cannot
// verify, denies only the call that found it.
//
// A snapshot is keyed twice: by the agent's session ID from the hook
// payload, and by the agent process that runs the hook
// (internal/agentprocess). The process key carries the state across the
// sessions one process runs (a cleared, compacted or resumed session keeps
// the hooks the process loaded); the session key covers an agent whose
// process cannot be named. A restarted agent that resumes a session starts
// clean; the process that held the old hooks stays blocked. Without a
// process identity a restart cannot be told from a clear, compact or resume
// inside the process that loaded the hook, so a blocked session stays
// blocked through a session start with the same session ID; only a new
// session ID starts clean.
//
// Standalone records live in the gateway's protected data directory, in a
// namespace chosen from the transport-verified caller uid or SID. The
// account-home path remains available to callers outside that profile.

const (
	sessionDirName = "foreign-hook-sessions"
	// sessionRecordLimit bounds one record.
	sessionRecordLimit = 16 << 10
	// sessionRecordTTL is how long a record is kept after it was written,
	// and how long a block lasts after BlockedAt. A blocked record is never
	// rewritten, so repeated denials extend neither.
	sessionRecordTTL = 7 * 24 * time.Hour
	// sessionDirLimit bounds the records kept per user.
	sessionDirLimit = 512
	// sessionIDLimit bounds a session ID or process identity.
	sessionIDLimit = 512
)

// SessionKey names one agent session.
type SessionKey struct {
	Connector string
	// Session is the agent's session ID from the hook payload ("" when the
	// payload has none).
	Session string
	// Process is the identity of the agent process running the hook ("" when
	// it cannot be named).
	Process string
}

func (k SessionKey) valid() bool {
	return strings.TrimSpace(k.Connector) != "" && (k.Session != "" || k.Process != "") &&
		len(k.Session) <= sessionIDLimit && len(k.Process) <= sessionIDLimit
}

// SessionRecord is one snapshot.
type SessionRecord struct {
	Version   int    `json:"v"`
	Connector string `json:"connector"`
	Session   string `json:"session,omitempty"`
	Process   string `json:"process,omitempty"`
	// Started is when the snapshot was taken and State the hash of the
	// foreign-hook state then (ForeignHookStateHash).
	Started string `json:"started"`
	State   string `json:"state"`
	// Blocked is set when the session started with an unapproved hook or
	// plugin present; Scope, Path, Digest and Reason describe the first
	// one, and BlockedAt is when the block was recorded.
	Blocked   bool   `json:"blocked"`
	BlockedAt string `json:"blocked_at,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Path      string `json:"path,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// ForeignHookStateHash hashes the foreign-hook state a scan found: every
// finding's scope, path, event, digest and approval, in a stable order. A
// scan with no findings hashes to the same value every time.
func ForeignHookStateHash(findings []Finding) string {
	lines := make([]string, 0, len(findings))
	for _, finding := range findings {
		lines = append(lines, strings.Join([]string{
			finding.Connector, finding.Scope, finding.Path, finding.Event, finding.Digest, fmt.Sprint(finding.Allowed),
		}, "\x00"))
	}
	sort.Strings(lines)
	return "sha256:" + sha256Hex([]byte(strings.Join(lines, "\n")))
}

// isBlockableFinding reports whether a finding is an unapproved hook entry
// or plugin, as opposed to a source the scan could not verify (a file it
// cannot read or parse, or a scan limit; see unreadableFinding). An
// unverifiable source denies the call but does not block the session.
// Plugin findings name no event, so the reason tells them apart.
func isBlockableFinding(f Finding) bool {
	return !f.Allowed && !strings.HasPrefix(f.Reason, "cannot verify")
}

// hasBlockableFindings reports whether a decision holds a finding that
// blocks the session.
func hasBlockableFindings(decision GuardDecision) bool {
	for _, f := range decision.Findings {
		if isBlockableFinding(f) {
			return true
		}
	}
	return false
}

// SessionUpdate is one hook invocation's input to the session state.
type SessionUpdate struct {
	// AccountHome is the account's home from the system account database.
	AccountHome string
	// StateDir selects gateway-owned storage. When set, failures to read or
	// write the record deny the call instead of falling back to a fresh scan.
	StateDir string
	Key      SessionKey
	// SessionStart marks the agent's session-start event, where the
	// snapshot is taken and the only event that records a block.
	SessionStart bool
	// Decision is this invocation's scan result.
	Decision GuardDecision
	Now      time.Time
}

// SessionPath is the record for one key kind and ID under accountHome.
func SessionPath(accountHome, connector, kind, id string) string {
	return sessionPathInDir(filepath.Join(accountHome, ".defenseclaw", sessionDirName), connector, kind, id)
}

func sessionPathInDir(dir, connector, kind, id string) string {
	name := kind + "-" + sha256Hex([]byte(connector + "\x00" + kind + "\x00" + id))[:40] + ".json"
	return filepath.Join(dir, name)
}

const (
	sessionKindProcess = "p"
	sessionKindSession = "s"
)

// ApplyForeignHookSession combines this invocation's scan with the
// session's recorded state and returns the decision to enforce:
//   - a session start that finds an unapproved hook or plugin, or whose
//     scan stopped on a budget before it checked every source
//     (GuardDecision.Incomplete), is recorded as a block for the session and
//     its agent process, and its message says the block lasts until the
//     agent restarts;
//   - a call of a session or process blocked earlier is denied, even when
//     the files are clean now (the agent may still run the hook), until
//     sessionRecordTTL after the block;
//   - otherwise the snapshot is recorded (replaced at a session start) and
//     the scan's own decision stands: a hook found after the session start,
//     or a file the scan cannot verify, denies this call only.
//
// A record that exists but cannot be read denies the call without
// recording a block. With StateDir (the standalone gateway path), a failed
// read or write always denies the call. The account-home path writes best
// effort.
func ApplyForeignHookSession(update SessionUpdate) GuardDecision {
	decision := update.Decision
	home := strings.TrimSpace(update.AccountHome)
	strict := update.StateDir != ""
	dir := filepath.Join(home, ".defenseclaw", sessionDirName)
	if strict {
		dir = update.StateDir
	}
	key := update.Key
	if !filepath.IsAbs(dir) || !key.valid() || (!strict && (home == "" || !filepath.IsAbs(home))) {
		if strict {
			return sessionUnavailableDecision(decision)
		}
		return decision
	}
	now := update.Now
	if now.IsZero() {
		now = time.Now()
	}
	type loaded struct {
		path   string
		record SessionRecord
		exists bool
	}
	load := func(kind, id string) (loaded, error) {
		if id == "" {
			return loaded{}, nil
		}
		path := sessionPathInDir(dir, key.Connector, kind, id)
		record, exists, err := readSessionRecord(path)
		if strict && err == nil && exists && !validGatewaySessionRecord(record, key, kind) {
			err = fmt.Errorf("invalid session record")
		}
		if err == nil && exists && sessionBlockExpired(record, now) {
			// The block ended sessionRecordTTL after it was recorded,
			// however often it denied since.
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) && strict {
				return loaded{path: path}, removeErr
			}
			return loaded{path: path}, nil
		}
		return loaded{path: path, record: record, exists: exists}, err
	}
	process, processErr := load(sessionKindProcess, key.Process)
	session, sessionErr := load(sessionKindSession, key.Session)
	if strict && (processErr != nil || sessionErr != nil) {
		return sessionUnavailableDecision(decision)
	}
	// An unreadable account-home record denies this call. It is not a
	// foreign hook, so it is not carried to the other key as a block.
	switch {
	case processErr != nil:
		return stickySessionDecision(decision, key.Connector, *unverifiableSessionRecord(key, process.path, processErr))
	case sessionErr != nil:
		return stickySessionDecision(decision, key.Connector, *unverifiableSessionRecord(key, session.path, sessionErr))
	}
	if strict {
		newRecords := 0
		for _, entry := range []loaded{process, session} {
			if entry.path != "" && !entry.exists {
				newRecords++
			}
		}
		if err := gatewaySessionCapacity(dir, now, newRecords, process.path, session.path); err != nil {
			return sessionUnavailableDecision(decision)
		}
	}
	write := func(path string, record SessionRecord) bool {
		if err := writeSessionRecord(path, record); err != nil {
			return !strict
		}
		return true
	}

	var sticky *SessionRecord
	if process.exists && process.record.Blocked {
		sticky = &process.record
	}
	if sticky == nil && session.exists && session.record.Blocked {
		// A session start of another agent process (a restarted agent
		// resuming the session) loaded its hooks from the files the scan
		// just checked, so its snapshot replaces the session's. The process
		// that held the old hooks stays blocked through its own record. The
		// same process continuing (a clear, compact or resume inside the
		// agent) keeps the block, and so does a start whose process cannot
		// be named: it may be the process that loaded the hook.
		restarted := update.SessionStart && key.Process != "" && session.record.Process != key.Process
		if restarted {
			session.exists = false
		} else {
			sticky = &session.record
		}
	}

	state := ForeignHookStateHash(decision.Findings)
	stamp := now.UTC().Format(time.RFC3339)
	fresh := func(existing loaded) SessionRecord {
		record := SessionRecord{Version: 1, Connector: key.Connector, Session: key.Session, Process: key.Process, Started: stamp, State: state}
		if existing.exists && existing.record.Started != "" {
			// Keep the snapshot taken when the session started.
			record.Started, record.State = existing.record.Started, existing.record.State
		}
		return record
	}

	blockable := hasBlockableFindings(decision)
	if decision.Deny && update.SessionStart && (blockable || decision.Incomplete) {
		// The block names the first unapproved hook or plugin; a scan that
		// stopped on a budget without reaching one names where it stopped
		// (the last finding).
		cause, note := Finding{}, sessionBlockNote
		for _, finding := range decision.Findings {
			if isBlockableFinding(finding) {
				cause = finding
				break
			}
		}
		if !blockable {
			note = sessionIncompleteNote
			for _, finding := range decision.Findings {
				if !finding.Allowed {
					cause = finding
				}
			}
			cause.Reason = incompleteScanReason + strings.TrimPrefix(cause.Reason, "cannot verify hook file: ")
		}
		blocked := func(existing loaded) SessionRecord {
			record := fresh(existing)
			record.Blocked, record.BlockedAt = true, stamp
			record.Scope, record.Path, record.Digest, record.Reason = cause.Scope, cause.Path, cause.Digest, cause.Reason
			return record
		}
		for _, entry := range []loaded{process, session} {
			if entry.path == "" || (entry.exists && entry.record.Blocked) {
				// A block keeps its BlockedAt.
				continue
			}
			if !write(entry.path, blocked(entry)) {
				return sessionUnavailableDecision(decision)
			}
		}
		decision.Reason = strings.TrimSpace(decision.Reason) + " " + note
		return decision
	}

	if sticky != nil {
		// Carry the block to the other key (a new session of a blocked
		// process, or the process of a blocked session), so it holds even
		// when one of them cannot be named on a later call.
		for _, entry := range []loaded{process, session} {
			if entry.path == "" || (entry.exists && entry.record.Blocked) {
				continue
			}
			if entry.exists && entry.record.Process != "" && key.Process != "" && entry.record.Process != key.Process {
				// Another agent process's clean snapshot of this session
				// (a restarted agent resumed it): leave it to that process.
				continue
			}
			carried := *sticky
			carried.Session, carried.Process = key.Session, key.Process
			if entry.exists && entry.record.Started != "" {
				carried.Started, carried.State = entry.record.Started, entry.record.State
			}
			if !write(entry.path, carried) {
				return sessionUnavailableDecision(decision)
			}
		}
		result := stickySessionDecision(decision, key.Connector, *sticky)
		if key.Process == "" {
			result.Reason += " " + sessionUnknownProcessNote
		}
		return result
	}

	if process.path != "" && !process.exists {
		if !write(process.path, fresh(process)) {
			return sessionUnavailableDecision(decision)
		}
	}
	if session.path != "" && (!session.exists || update.SessionStart) {
		record := fresh(loaded{})
		if !write(session.path, record) {
			return sessionUnavailableDecision(decision)
		}
	}
	if update.SessionStart && !strict {
		pruneSessionRecords(dir, now)
	}
	return decision
}

func validGatewaySessionRecord(record SessionRecord, key SessionKey, kind string) bool {
	if record.Version != 1 || record.Connector != key.Connector || record.Started == "" ||
		len(record.State) != len("sha256:")+64 || !strings.HasPrefix(record.State, "sha256:") ||
		record.Blocked && record.Reason == "" && record.Path == "" {
		return false
	}
	if _, err := time.Parse(time.RFC3339, record.Started); err != nil {
		return false
	}
	if kind == sessionKindProcess {
		return record.Process == key.Process
	}
	return record.Session == key.Session
}

func sessionUnavailableDecision(decision GuardDecision) GuardDecision {
	decision.Deny = true
	decision.Reason = "enterprise_foreign_hook_blocked: DefenseClaw cannot verify this agent session's hook record. Remove any unapproved hook and restart the agent."
	return decision
}

// sessionBlockNote ends every denial the session state applies to.
const sessionBlockNote = "The agent can keep running a hook it loaded when the session started, even after the file changes, so DefenseClaw blocks tool calls for the rest of this session: after removing the hook, restart the agent."

// sessionIncompleteNote ends a denial for a session whose start scan stopped
// on a budget.
const sessionIncompleteNote = "The agent can keep running a hook it loaded from a file DefenseClaw did not check, so DefenseClaw blocks tool calls for the rest of this session: remove unneeded hook files, then restart the agent."

// sessionUnknownProcessNote ends a session denial when the agent process
// cannot be named: only a new session ID starts clean then.
const sessionUnknownProcessNote = "DefenseClaw cannot identify the agent process, so the block also holds when the restarted agent resumes this session: start a new session."

// incompleteScanReason starts the Reason of a block recorded because the
// session-start scan stopped on a budget.
const incompleteScanReason = "incomplete scan: "

func unverifiableSessionRecord(key SessionKey, path string, err error) *SessionRecord {
	return &SessionRecord{
		Connector: key.Connector,
		Blocked:   true,
		Path:      path,
		Reason:    "cannot verify hook file: " + err.Error(),
	}
}

// stickySessionDecision denies a call because an earlier call of the same
// session or agent process was denied for a foreign hook. Such a block is
// recorded when the session starts, so the first prompt the user sends may
// already get this message.
func stickySessionDecision(decision GuardDecision, connector string, record SessionRecord) GuardDecision {
	var cause string
	note := sessionBlockNote
	switch {
	case strings.HasPrefix(record.Reason, incompleteScanReason):
		cause = "When this agent session started, DefenseClaw's hook scan stopped before it checked every hook file (" + strings.TrimPrefix(record.Reason, incompleteScanReason) + ")."
		note = sessionIncompleteNote
	case strings.HasPrefix(record.Reason, "cannot verify"):
		// This call's own record could not be read.
		what := strings.TrimPrefix(record.Reason, "cannot verify hook file: ")
		if record.Path != "" && !strings.Contains(what, record.Path) {
			what = record.Path + ": " + what
		}
		cause = "DefenseClaw could not verify this session's hooks (" + what + ")."
	default:
		what := "defined a hook"
		if record.Reason == "plugin" || record.Reason == "plugin directory" {
			what = "added a plugin"
		}
		scope := record.Scope
		if scope == "" {
			scope = "hook"
		}
		cause = fmt.Sprintf("When this agent session started, the %s file %s %s (digest sha256:%s). %s",
			scope, record.Path, what, record.Digest, foreignHookAdvice(connector, record.Reason))
	}
	decision.Deny = true
	decision.Reason = fmt.Sprintf(
		"enterprise_foreign_hook_blocked: your organization blocks %s hooks it has not approved, because they can change a tool call after DefenseClaw checks it. %s %s",
		connector, cause, note,
	)
	decision.Findings = append([]Finding{{
		Connector: connector,
		Scope:     record.Scope,
		Path:      record.Path,
		Digest:    record.Digest,
		Reason:    "blocked since earlier in this session: " + record.Reason,
	}}, decision.Findings...)
	return decision
}

// readSessionRecord reads one record without following links. A missing
// record does not exist; anything else that cannot be read or decoded is an
// error.
func readSessionRecord(path string) (SessionRecord, bool, error) {
	data, exists, err := readGuardFileLimit(path, sessionRecordLimit)
	if !exists && err == nil {
		return SessionRecord{}, false, nil
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return SessionRecord{}, false, nil
		}
		return SessionRecord{}, true, err
	}
	var record SessionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return SessionRecord{}, true, fmt.Errorf("%s: %w", path, err)
	}
	// The record is the user's: bound what a denial message repeats.
	return record.bounded(), true, nil
}

// writeSessionRecord replaces one record atomically.
func writeSessionRecord(path string, record SessionRecord) error {
	record.Version = 1
	data, err := json.Marshal(record.bounded())
	if err != nil {
		return err
	}
	return writePrivateUserFile(path, data)
}

// writePrivateUserFile replaces a small file in the user's data directory
// atomically, refusing a directory or file that is a link.
func writePrivateUserFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// sessionBlockExpired reports a blocked record whose block was recorded
// more than sessionRecordTTL ago. A record without a readable BlockedAt
// (from an older release) keeps its block until it is pruned.
func sessionBlockExpired(record SessionRecord, now time.Time) bool {
	if !record.Blocked {
		return false
	}
	blockedAt, err := time.Parse(time.RFC3339, record.BlockedAt)
	return err == nil && now.Sub(blockedAt) > sessionRecordTTL
}

// pruneSessionRecords removes records written more than sessionRecordTTL ago and,
// past sessionDirLimit records, the oldest ones.
func pruneSessionRecords(dir string, now time.Time) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return
	}
	handle, err := os.Open(dir)
	if err != nil {
		return
	}
	entries, _ := handle.ReadDir(4 * sessionDirLimit)
	_ = handle.Close()
	type aged struct {
		path string
		mod  time.Time
	}
	var kept []aged
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if strings.HasPrefix(name, ".") {
			// A temporary file a crashed writer left behind.
			if now.Sub(info.ModTime()) > time.Hour {
				_ = os.Remove(path)
			}
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		// A blocked record is never rewritten, so its modification time is
		// no earlier than its BlockedAt.
		if now.Sub(info.ModTime()) > sessionRecordTTL {
			_ = os.Remove(path)
			continue
		}
		kept = append(kept, aged{path, info.ModTime()})
	}
	if len(kept) <= sessionDirLimit {
		return
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].mod.Before(kept[j].mod) })
	for _, entry := range kept[:len(kept)-sessionDirLimit] {
		_ = os.Remove(entry.path)
	}
}

// gatewaySessionCapacity expires old gateway records and makes room for
// newRecords within the per-user limit. Over the limit it evicts the oldest
// records that do not block: a clean record only holds a snapshot that no
// enforcement check compares, so dropping it lets nobody around a block. A
// live blocked record (and one that cannot be read) is never evicted, so a
// caller that can create any number of session IDs still cannot push a block
// out; only when such records alone fill the directory is the new record
// refused.
func gatewaySessionCapacity(dir string, now time.Time, newRecords int, activePaths ...string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if newRecords > sessionDirLimit {
			return fmt.Errorf("session record limit reached")
		}
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("session store directory unavailable")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type candidate struct {
		path string
		mod  time.Time
	}
	var candidates []candidate
	kept := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(dir, name)
		active := false
		for _, current := range activePaths {
			if current == path {
				active = true
				break
			}
		}
		if !active && now.Sub(info.ModTime()) > sessionRecordTTL {
			if err := os.Remove(path); err != nil {
				return err
			}
			continue
		}
		kept++
		if !active {
			candidates = append(candidates, candidate{path, info.ModTime()})
		}
	}
	excess := kept + newRecords - sessionDirLimit
	if excess <= 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].mod.Before(candidates[j].mod) })
	for _, entry := range candidates {
		if excess == 0 {
			break
		}
		record, exists, err := readSessionRecord(entry.path)
		if err != nil || (exists && record.Blocked && !sessionBlockExpired(record, now)) {
			continue
		}
		if err := os.Remove(entry.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		excess--
	}
	if excess > 0 {
		return fmt.Errorf("session record limit reached")
	}
	return nil
}

func (r SessionRecord) bounded() SessionRecord {
	clip := func(value string) string {
		value = strings.Map(func(c rune) rune {
			if c < 0x20 || c == 0x7f {
				return ' '
			}
			return c
		}, value)
		if len(value) > blockFieldLimit {
			value = value[:blockFieldLimit]
		}
		return value
	}
	r.Connector, r.Session, r.Process = clip(r.Connector), clip(r.Session), clip(r.Process)
	r.Started, r.State, r.BlockedAt = clip(r.Started), clip(r.State), clip(r.BlockedAt)
	r.Scope, r.Path, r.Digest, r.Reason = clip(r.Scope), clip(r.Path), clip(r.Digest), clip(r.Reason)
	return r
}
