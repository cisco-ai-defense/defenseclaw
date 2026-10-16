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
// the schema a prior binary reads strictly.
const hookGuardianRestoresFile = "hook_guardian_restores.json"

// hookGuardianRestoresMaxBytes bounds the record, which holds one entry per
// enrolled target at most. The writer keeps it under the bound, which both
// readers (here and internal/enterpriseunix) enforce.
const hookGuardianRestoresMaxBytes = 1 << 20

// enterpriseHookGuardianRestoreReadBackoff spaces the retries of a failed
// read of the record: on Windows a reader can meet a sharing violation while
// the guardian replaces it. Tests shorten it.
var enterpriseHookGuardianRestoreReadBackoff = []time.Duration{10 * time.Millisecond, 40 * time.Millisecond, 150 * time.Millisecond}

// enterpriseHookGuardianRestoreRecordReader reads and checks the record once;
// tests replace it.
var enterpriseHookGuardianRestoreRecordReader = readEnterpriseHookGuardianRestoreRecord

// Content failures may be replaced by the next restore. Read failures may
// still hide earlier entries, so the recorder must preserve the file.
var errEnterpriseHookGuardianRestoreRecordInvalid = errors.New("invalid hook guardian restore record")

// The guardian is a long-lived watch loop, so memory carries restores across
// passes. A one-shot reconcile or guardian restart before a readable record
// can still lose them.
var enterpriseHookGuardianRestorePending = struct {
	sync.Mutex
	byPath map[string]map[string]enterpriseHookGuardianRestore
}{byPath: make(map[string]map[string]enterpriseHookGuardianRestore)}

type enterpriseHookGuardianRestore struct {
	SID        string `json:"sid,omitempty"`
	UID        *int   `json:"uid,omitempty"`
	User       string `json:"user,omitempty"`
	Connector  string `json:"connector"`
	RestoredAt string `json:"restored_at"`
}

type enterpriseHookGuardianRestoreRecord struct {
	Version int                             `json:"version"`
	Targets []enterpriseHookGuardianRestore `json:"targets"`
}

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

// key is the entry's SID key, its uid key, or "" for an entry that names
// neither.
func (entry enterpriseHookGuardianRestore) key() string {
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
	return entry.key()
}

func enterpriseHookGuardianRestoreTime(entry enterpriseHookGuardianRestore) time.Time {
	at, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(entry.RestoredAt))
	return at
}

// The caller holds enterpriseHookGuardianRestorePending while changing its map.
func mergeEnterpriseHookGuardianRestorePending(path string, restored []enterpriseHookGuardianRestore) {
	if len(restored) == 0 {
		return
	}
	pending := enterpriseHookGuardianRestorePending.byPath[path]
	if pending == nil {
		pending = make(map[string]enterpriseHookGuardianRestore, len(restored))
		enterpriseHookGuardianRestorePending.byPath[path] = pending
	}
	for _, entry := range restored {
		key := entry.key()
		if old, ok := pending[key]; !ok || !enterpriseHookGuardianRestoreTime(entry).Before(enterpriseHookGuardianRestoreTime(old)) {
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
// nothing: the old uid may belong to another account now. It is best
// effort: a failed read or write is logged and returned.
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
		if entry.key() != "" {
			normalized = append(normalized, entry)
		}
	}
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
			key := entry.key()
			if key == "" || (!enrolled[key] && !unresolved[enterpriseHookGuardianRestoreUserKey(entry.User, entry.Connector)]) {
				changed = true
				continue
			}
			entries[key] = entry
		}
	} else if errors.Is(err, errEnterpriseHookGuardianRestoreRecordInvalid) {
		invalidErr = err
		changed = true
	} else if !os.IsNotExist(err) {
		mergeEnterpriseHookGuardianRestorePending(path, normalized)
		fmt.Fprintf(stderr, "[hook-guardian] warn: could not read the restore record in %s: %v; record left unchanged, this pass's restored targets are kept in memory and recorded once it can be read (Windows status reports restart status unknown until then)\n", path, err)
		return err
	}
	// Pending entries obey the same enrollment rule as entries on disk.
	combined := make(map[string]enterpriseHookGuardianRestore, len(normalized))
	fromCurrent := make(map[string]bool, len(normalized))
	for key, entry := range enterpriseHookGuardianRestorePending.byPath[path] {
		if !enrolled[key] && !unresolved[enterpriseHookGuardianRestoreUserKey(entry.User, entry.Connector)] {
			delete(enterpriseHookGuardianRestorePending.byPath[path], key)
			continue
		}
		combined[key] = entry
	}
	for _, entry := range normalized {
		key := entry.key()
		if old, ok := combined[key]; !ok || !enterpriseHookGuardianRestoreTime(entry).Before(enterpriseHookGuardianRestoreTime(old)) {
			combined[key] = entry
			fromCurrent[key] = true
		}
	}
	for key, entry := range combined {
		old, exists := entries[key]
		if fromCurrent[key] {
			entries[key] = entry
			changed = true
		} else if !exists || !enterpriseHookGuardianRestoreTime(entry).Before(enterpriseHookGuardianRestoreTime(old)) {
			if !exists || !enterpriseHookGuardianRestoreEntriesEqual(entry, old) {
				changed = true
			}
			entries[key] = entry
		}
	}
	if !changed {
		delete(enterpriseHookGuardianRestorePending.byPath, path)
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
		mergeEnterpriseHookGuardianRestorePending(path, normalized)
		fmt.Fprintf(stderr, "[hook-guardian] warn: could not record the restored targets in %s: %v\n", path, err)
		return err
	}
	delete(enterpriseHookGuardianRestorePending.byPath, path)
	if invalidErr != nil {
		fmt.Fprintf(stderr, "[hook-guardian] warn: replaced the restore record in %s that could not be parsed: %v\n", path, invalidErr)
	}
	return nil
}

// marshalEnterpriseHookGuardianRestoreRecord serializes record, sorted by
// key, within hookGuardianRestoresMaxBytes: a larger record is refused by
// both readers, so status would name no restore at all. Past the bound it
// drops the oldest restores first and returns how many it dropped.
func marshalEnterpriseHookGuardianRestoreRecord(record enterpriseHookGuardianRestoreRecord) ([]byte, int, error) {
	sortByKey := func() {
		sort.Slice(record.Targets, func(i, j int) bool { return record.Targets[i].key() < record.Targets[j].key() })
	}
	sortByKey()
	data, err := json.Marshal(record)
	if err != nil || len(data) < hookGuardianRestoresMaxBytes {
		return append(data, '\n'), 0, err
	}
	// Newest first; keep the longest prefix whose entries fit.
	sort.SliceStable(record.Targets, func(i, j int) bool {
		return enterpriseHookGuardianRestoreTime(record.Targets[i]).After(enterpriseHookGuardianRestoreTime(record.Targets[j]))
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

func readEnterpriseHookGuardianRestoreRecord(path string) (enterpriseHookGuardianRestoreRecord, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return enterpriseHookGuardianRestoreRecord{}, err
	}
	if info.Mode().IsRegular() && info.Size() > hookGuardianRestoresMaxBytes {
		return enterpriseHookGuardianRestoreRecord{}, fmt.Errorf("%w: hook guardian restore record exceeds %d-byte limit", errEnterpriseHookGuardianRestoreRecordInvalid, hookGuardianRestoresMaxBytes)
	}
	data, err := readEnterpriseHookBoundedFile(path, info, hookGuardianRestoresMaxBytes, "hook guardian restore record")
	if err != nil {
		return enterpriseHookGuardianRestoreRecord{}, err
	}
	var record enterpriseHookGuardianRestoreRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return enterpriseHookGuardianRestoreRecord{}, fmt.Errorf("%w: %v", errEnterpriseHookGuardianRestoreRecordInvalid, err)
	}
	if record.Version != 1 {
		return enterpriseHookGuardianRestoreRecord{}, fmt.Errorf("%w: hook guardian restore record has version %d", errEnterpriseHookGuardianRestoreRecordInvalid, record.Version)
	}
	return record, nil
}

// readEnterpriseHookGuardianRestoreRecordRetrying reads the record, retrying
// a failed read with a short backoff; a missing or content-invalid record is
// not retried.
func readEnterpriseHookGuardianRestoreRecordRetrying(path string) (enterpriseHookGuardianRestoreRecord, error) {
	record, err := enterpriseHookGuardianRestoreRecordReader(path)
	for _, wait := range enterpriseHookGuardianRestoreReadBackoff {
		if err == nil || os.IsNotExist(err) || errors.Is(err, errEnterpriseHookGuardianRestoreRecordInvalid) {
			break
		}
		time.Sleep(wait)
		record, err = enterpriseHookGuardianRestoreRecordReader(path)
	}
	return record, err
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
		key := entry.key()
		if err != nil || key == "" {
			continue
		}
		restores[key] = at
	}
	return restores, nil
}
