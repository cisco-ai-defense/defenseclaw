// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// hookGuardianRestoresFile records, in the guardian's data directory, when
// the standalone hook guardian (Windows, Linux, macOS) last put back each
// target's hooks
// because they no longer verified, for example after a standard user
// emptied the hooks block of their Hermes config. An agent reads its hooks
// when it starts, and Hermes keeps the callbacks it loaded for the life of
// the process: a session started while the hooks were gone kept running
// without DefenseClaw after the guardian restored the file, while status
// and verify read complete (GAP-0440 on Windows, GAP-0499 on Linux and
// macOS). Status, verify and ensure name that account's sessions of the
// connector that started before the restore. A Windows target is keyed by
// its SID, a Linux or macOS one by its uid.
//
// It is its own file: the guardian's state and authorization records keep
// the schema a prior binary reads strictly. enterprisehooks owns its schema
// and its one reader, which internal/enterpriseunix uses too.
const hookGuardianRestoresFile = enterprisehooks.GuardianRestoresFile

// hookGuardianRestoresMaxBytes bounds the record, which holds one entry per
// enrolled target at most. The writer keeps it under the bound, which the
// reader enforces.
const hookGuardianRestoresMaxBytes = enterprisehooks.GuardianRestoresMaxBytes

// enterpriseHookGuardianRestoreReadBackoff spaces the retries of a failed
// read of the record. Tests shorten it.
var enterpriseHookGuardianRestoreReadBackoff = append([]time.Duration(nil), enterprisehooks.GuardianRestoreReadBackoff...)

// enterpriseHookGuardianRestoreRecordReader reads and checks the record once;
// tests replace it. Content failures (enterprisehooks.
// ErrGuardianRestoreRecordInvalid) may be replaced by the next pass; read
// failures may still hide earlier entries, so the recorder preserves the
// file.
var enterpriseHookGuardianRestoreRecordReader = enterprisehooks.ReadGuardianRestoreRecord

// enterpriseHookGuardianRestoreNow is the clock that dates the enrolled
// targets of an invalid record the recorder replaces; tests set it.
var enterpriseHookGuardianRestoreNow = time.Now

// The guardian is a long-lived watch loop, so memory carries restores across
// passes. A one-shot reconcile or guardian restart before a readable record
// can still lose them. It is keyed by enterpriseHookGuardianRestorePendingKey
// of the record path, so two spellings of one path share their entries.
var enterpriseHookGuardianRestorePending = struct {
	sync.Mutex
	byPath map[string]map[string]enterpriseHookGuardianRestore
}{byPath: make(map[string]map[string]enterpriseHookGuardianRestore)}

// enterpriseHookGuardianRestorePendingKey keys the pending restores of the
// record at path: on Windows a pass that spelled the data directory another
// way (case, the \\?\ prefix, an 8.3 short name) kept its own pending set,
// so a later readable pass of the other spelling did not record it
// (GAP-0626).
func enterpriseHookGuardianRestorePendingKey(path string) string {
	return winpath.ComparisonKey(path)
}

type enterpriseHookGuardianRestore = enterprisehooks.GuardianRestore

type enterpriseHookGuardianRestoreRecord = enterprisehooks.GuardianRestoreRecord

// enterpriseHookGuardianRestoresEnabled is true for the standalone guardian
// only; on Secure Client the guardian writes no restore record.
var enterpriseHookGuardianRestoresEnabled = func() bool { return false }

func enterpriseHookGuardianRestoreKey(sid, connectorName string) string {
	return windowsEnterpriseManifestRowKey(enterprisehooks.ManifestTarget{SID: sid, Connector: connectorName})
}

// enterpriseHookGuardianRestoreUIDKey keys a Linux or macOS target.
func enterpriseHookGuardianRestoreUIDKey(uid int, connectorName string) string {
	return "uid:" + strconv.Itoa(uid) + "\x00" + strings.ToLower(strings.TrimSpace(connectorName))
}

// enterpriseHookGuardianRestoreEntryKey is the entry's SID key, its uid key,
// or "" for an entry that names neither.
func enterpriseHookGuardianRestoreEntryKey(entry enterpriseHookGuardianRestore) string {
	if sid := strings.TrimSpace(entry.SID); sid != "" {
		return enterpriseHookGuardianRestoreKey(sid, entry.Connector)
	}
	if entry.UID != nil && *entry.UID > 0 {
		return enterpriseHookGuardianRestoreUIDKey(*entry.UID, entry.Connector)
	}
	return ""
}

// enterpriseHookGuardianRestoreUserKey names a Linux or macOS target by
// account name and connector, or "" without a name.
func enterpriseHookGuardianRestoreUserKey(user, connectorName string) string {
	user = strings.TrimSpace(user)
	if user == "" {
		return ""
	}
	return "user:" + user + "\x00" + strings.ToLower(strings.TrimSpace(connectorName))
}

// enterpriseHookGuardianRestoreRowKey keys a reconcile row like its entry.
func enterpriseHookGuardianRestoreRowKey(row enterpriseHookReconcileRow) string {
	entry := enterpriseHookGuardianRestore{SID: row.SID, Connector: row.Connector}
	if row.UID > 0 {
		uid := row.UID
		entry.UID = &uid
	}
	return enterpriseHookGuardianRestoreEntryKey(entry)
}

// The caller holds enterpriseHookGuardianRestorePending while changing its
// map; pathKey is enterpriseHookGuardianRestorePendingKey of the record path.
func mergeEnterpriseHookGuardianRestorePending(pathKey string, restored []enterpriseHookGuardianRestore) {
	if len(restored) == 0 {
		return
	}
	pending := enterpriseHookGuardianRestorePending.byPath[pathKey]
	if pending == nil {
		pending = make(map[string]enterpriseHookGuardianRestore, len(restored))
		enterpriseHookGuardianRestorePending.byPath[pathKey] = pending
	}
	for _, entry := range restored {
		key := enterpriseHookGuardianRestoreEntryKey(entry)
		if old, ok := pending[key]; !ok || !entry.RestoredAtTime().Before(old.RestoredAtTime()) {
			pending[key] = entry
		}
	}
}

func enterpriseHookGuardianRestoreEntriesEqual(a, b enterpriseHookGuardianRestore) bool {
	if a.SID != b.SID || a.User != b.User || a.Connector != b.Connector || a.RestoredAt != b.RestoredAt {
		return false
	}
	if a.UID == nil || b.UID == nil {
		return a.UID == nil && b.UID == nil
	}
	return *a.UID == *b.UID
}

// recordEnterpriseHookGuardianRestores dates the targets this reconcile put
// back (restored, from rows that verified before and were repaired) and
// keeps the earlier entries of the other targets in rows. An entry whose
// target left the manifest is dropped, so the record stays bounded. A row
// this pass could not resolve to a uid (a pending or failed identity lookup
// on Linux or macOS, for example during a directory outage) still enrolls
// its account's target, so its entry stays: dropping it lost the restore of
// a still-running session for good, as later clean passes repair nothing
// (GAP-0499). A row whose account identity changed (RevokeProtection) keeps
// nothing: the old uid may belong to another account now. A failed read or
// write is logged and returned; the guardian's pass reports it and retries
// with its repair backoff instead of waiting for the interval pass.
//
// A record whose content is invalid (not JSON, another version, over the
// bound) may have held restores of any enrolled target. Replacing it with
// this pass's restores alone, often none, turned the unknown restart status
// that status reported for it into a clean one (GAP-0626). The replacement
// dates every enrolled target at this pass instead, so status names each of
// their sessions that started before it, as it would for a real restore.
func recordEnterpriseHookGuardianRestores(
	stderr io.Writer,
	dataDir string,
	rows []enterpriseHookReconcileRow,
	restored []enterpriseHookGuardianRestore,
) error {
	dataDir = strings.TrimSpace(dataDir)
	if !enterpriseHookGuardianRestoresEnabled() || dataDir == "" {
		return nil
	}
	path := filepath.Join(dataDir, hookGuardianRestoresFile)
	normalized := make([]enterpriseHookGuardianRestore, 0, len(restored))
	for _, entry := range restored {
		entry.SID = strings.ToUpper(strings.TrimSpace(entry.SID))
		entry.Connector = strings.ToLower(strings.TrimSpace(entry.Connector))
		if enterpriseHookGuardianRestoreEntryKey(entry) != "" {
			normalized = append(normalized, entry)
		}
	}
	// The key may touch the file system (an 8.3 name on Windows), so it is
	// computed before the lock that every pass's recorder waits on.
	pathKey := enterpriseHookGuardianRestorePendingKey(path)
	// Hold the lock through the read and write, so another pass cannot add an
	// entry between this pass's pending snapshot and its successful clear.
	enterpriseHookGuardianRestorePending.Lock()
	defer enterpriseHookGuardianRestorePending.Unlock()
	enrolled := make(map[string]bool, len(rows))
	unresolved := map[string]bool{}
	for _, row := range rows {
		if key := enterpriseHookGuardianRestoreRowKey(row); key != "" {
			enrolled[key] = true
		} else if key := enterpriseHookGuardianRestoreUserKey(row.User, row.Connector); key != "" && !row.RevokeProtection {
			unresolved[key] = true
		}
	}
	entries := map[string]enterpriseHookGuardianRestore{}
	changed := false
	var invalidErr error
	if record, err := readEnterpriseHookGuardianRestoreRecordRetrying(path); err == nil {
		for _, entry := range record.Targets {
			key := enterpriseHookGuardianRestoreEntryKey(entry)
			if key == "" || (!enrolled[key] && !unresolved[enterpriseHookGuardianRestoreUserKey(entry.User, entry.Connector)]) {
				changed = true
				continue
			}
			entries[key] = entry
		}
	} else if errors.Is(err, enterprisehooks.ErrGuardianRestoreRecordInvalid) {
		invalidErr = err
		changed = true
		now := enterpriseHookGuardianRestoreNow().UTC().Format(time.RFC3339Nano)
		for _, row := range rows {
			if row.RevokeProtection {
				continue
			}
			entry := enterpriseHookGuardianRestore{
				SID:        strings.ToUpper(strings.TrimSpace(row.SID)),
				User:       strings.TrimSpace(row.User),
				Connector:  strings.ToLower(strings.TrimSpace(row.Connector)),
				RestoredAt: now,
			}
			if row.UID > 0 {
				uid := row.UID
				entry.UID = &uid
			}
			if key := enterpriseHookGuardianRestoreEntryKey(entry); key != "" {
				entries[key] = entry
			}
		}
	} else if !os.IsNotExist(err) {
		mergeEnterpriseHookGuardianRestorePending(pathKey, normalized)
		fmt.Fprintf(stderr, "[hook-guardian] warn: could not read the restore record in %s: %v; record left unchanged, this pass's restored targets are kept in memory and recorded once it can be read (status reports restart status unknown until then)\n", path, err)
		return err
	}
	// Pending entries obey the same enrollment rule as entries on disk.
	combined := make(map[string]enterpriseHookGuardianRestore, len(normalized))
	fromCurrent := make(map[string]bool, len(normalized))
	for key, entry := range enterpriseHookGuardianRestorePending.byPath[pathKey] {
		if !enrolled[key] && !unresolved[enterpriseHookGuardianRestoreUserKey(entry.User, entry.Connector)] {
			delete(enterpriseHookGuardianRestorePending.byPath[pathKey], key)
			continue
		}
		combined[key] = entry
	}
	for _, entry := range normalized {
		key := enterpriseHookGuardianRestoreEntryKey(entry)
		if old, ok := combined[key]; !ok || !entry.RestoredAtTime().Before(old.RestoredAtTime()) {
			combined[key] = entry
			fromCurrent[key] = true
		}
	}
	for key, entry := range combined {
		old, exists := entries[key]
		if fromCurrent[key] {
			entries[key] = entry
			changed = true
		} else if !exists || !entry.RestoredAtTime().Before(old.RestoredAtTime()) {
			if !exists || !enterpriseHookGuardianRestoreEntriesEqual(entry, old) {
				changed = true
			}
			entries[key] = entry
		}
	}
	if !changed {
		delete(enterpriseHookGuardianRestorePending.byPath, pathKey)
		return nil
	}
	record := enterpriseHookGuardianRestoreRecord{Version: 1, Targets: make([]enterpriseHookGuardianRestore, 0, len(entries))}
	for _, entry := range entries {
		record.Targets = append(record.Targets, entry)
	}
	data, dropped, err := marshalEnterpriseHookGuardianRestoreRecord(record)
	if err == nil {
		if dropped > 0 {
			fmt.Fprintf(stderr, "[hook-guardian] warn: the restore record in %s would pass %d bytes; dropped its %d oldest entries\n", path, hookGuardianRestoresMaxBytes, dropped)
		}
		err = writeEnterpriseHookProtectedFile(path, data)
	}
	if err != nil {
		mergeEnterpriseHookGuardianRestorePending(pathKey, normalized)
		fmt.Fprintf(stderr, "[hook-guardian] warn: could not record the restored targets in %s: %v\n", path, err)
		return err
	}
	delete(enterpriseHookGuardianRestorePending.byPath, pathKey)
	if invalidErr != nil {
		fmt.Fprintf(stderr, "[hook-guardian] warn: replaced the restore record in %s that could not be parsed: %v; every enrolled target is dated at this pass, so status names their sessions that started before it\n", path, invalidErr)
	}
	return nil
}

// marshalEnterpriseHookGuardianRestoreRecord serializes record, sorted by
// key, within hookGuardianRestoresMaxBytes: a larger record is refused by
// both readers, so status would name no restore at all. Past the bound it
// drops the oldest restores first and returns how many it dropped.
func marshalEnterpriseHookGuardianRestoreRecord(record enterpriseHookGuardianRestoreRecord) ([]byte, int, error) {
	sortByKey := func() {
		sort.Slice(record.Targets, func(i, j int) bool {
			return enterpriseHookGuardianRestoreEntryKey(record.Targets[i]) < enterpriseHookGuardianRestoreEntryKey(record.Targets[j])
		})
	}
	sortByKey()
	data, err := json.Marshal(record)
	if err != nil || len(data) < hookGuardianRestoresMaxBytes {
		return append(data, '\n'), 0, err
	}
	// Newest first; keep the longest prefix whose entries fit.
	sort.SliceStable(record.Targets, func(i, j int) bool {
		return record.Targets[i].RestoredAtTime().After(record.Targets[j].RestoredAtTime())
	})
	empty, _ := json.Marshal(enterpriseHookGuardianRestoreRecord{Version: record.Version, Targets: []enterpriseHookGuardianRestore{}})
	size, keep := len(empty)+1, 0
	for _, entry := range record.Targets {
		encoded, err := json.Marshal(entry)
		if err != nil {
			return nil, 0, err
		}
		if size+len(encoded)+1 > hookGuardianRestoresMaxBytes {
			break
		}
		size += len(encoded) + 1
		keep++
	}
	dropped := len(record.Targets) - keep
	record.Targets = record.Targets[:keep]
	sortByKey()
	data, err = json.Marshal(record)
	return append(data, '\n'), dropped, err
}

// readEnterpriseHookGuardianRestoreRecordRetrying reads the record, retrying
// a failed read with a short backoff; a missing or content-invalid record is
// not retried.
func readEnterpriseHookGuardianRestoreRecordRetrying(path string) (enterpriseHookGuardianRestoreRecord, error) {
	return enterprisehooks.ReadGuardianRestoreRecordRetrying(path, enterpriseHookGuardianRestoreRecordReader, enterpriseHookGuardianRestoreReadBackoff)
}

// readEnterpriseHookGuardianRestores returns when the guardian last put back
// each target's hooks, keyed as windowsEnterpriseManifestRowKey (Windows) or
// enterpriseHookGuardianRestoreUIDKey; nil without a record. A record that
// stays unreadable or invalid after the retries is an error, so the caller
// reports the restart status unknown instead of "no restore".
func readEnterpriseHookGuardianRestores(dataDir string) (map[string]time.Time, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil, nil
	}
	record, err := readEnterpriseHookGuardianRestoreRecordRetrying(filepath.Join(dataDir, hookGuardianRestoresFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	restores := make(map[string]time.Time, len(record.Targets))
	for _, entry := range record.Targets {
		at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(entry.RestoredAt))
		key := enterpriseHookGuardianRestoreEntryKey(entry)
		if err != nil || key == "" {
			continue
		}
		restores[key] = at
	}
	return restores, nil
}
