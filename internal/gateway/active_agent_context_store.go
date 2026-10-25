// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// A session's authenticated InstructionsLoaded events and startup file
// identities prove which instruction files it loaded. A running agent does
// not send them again after a gateway restart. The gateway keeps this proof
// in one small file under its data directory. The security-state rule
// already protects that file (tamper.detector_state_write covers
// cache/), and restores it for a session it holds no state for. A missing,
// unreadable or invalid record leaves the session with no startup snapshot.

const maxInstructionLoadRecordBytes = 1 << 20

// maxInstructionLoadRecords and maxInstructionLoadStoreBytes bound the saved
// records. They hold far more sessions than the in-memory cache
// (maxActiveAgentContextSessions), so a session the cache evicts restores
// its first sighting from its record until it ends: churn through newer
// sessions never turns a file it created into one that was there before it.
// Only when the saved sessions that never ended pass these bounds does the
// oldest one lose its record; its next call then takes a new first sighting,
// which protects every instruction file that exists then (never fewer).
const (
	maxInstructionLoadRecords    = 16 * maxActiveAgentContextSessions
	maxInstructionLoadStoreBytes = 64 << 20
)

type instructionLoadRecord struct {
	Scope string `json:"scope,omitempty"`
	// Caller is the verified caller the session belongs to
	// (activeAgentContextKey.caller); empty on a per-user gateway.
	Caller               string   `json:"caller,omitempty"`
	Connector            string   `json:"connector"`
	Session              string   `json:"session"`
	Files                []string `json:"files,omitempty"`
	CaseInsensitiveFiles []string `json:"case_insensitive_files,omitempty"`
	// LoadedIdentities maps each loaded file to its identity. It replaced
	// the identity-keyed "identities" map of unreleased 1.0.4 candidates,
	// which kept one of two hard-linked names (GAP-1414); such a record
	// restores without client identities.
	LoadedIdentities map[string]string `json:"loaded_identities,omitempty"`
	StartupFiles     map[string]string `json:"startup_files,omitempty"`
	StartupKnown     bool              `json:"startup_known,omitempty"`
	StartupDirs      []string          `json:"startup_dirs,omitempty"`
	StartupDirIDs    map[string]string `json:"startup_dir_ids,omitempty"`
	// AwaitingStart: the session's calls came before any start of it
	// (activeAgentContextSession.awaitingStart). A record without it is a
	// started session's, as every record of earlier builds is.
	AwaitingStart bool `json:"awaiting_start,omitempty"`
}

func (a *APIServer) instructionLoadDir() string {
	if a == nil || a.scannerCfg == nil || strings.TrimSpace(a.scannerCfg.DataDir) == "" {
		return ""
	}
	return filepath.Join(a.scannerCfg.DataDir, "cache", "instruction-loads")
}

func instructionLoadRecordPath(dir string, key activeAgentContextKey) string {
	name := key.scope + "\x00" + key.connector + "\x00" + key.sessionID
	if key.caller != "" {
		// A per-user gateway's record keeps the name earlier builds gave it.
		name += "\x00caller\x00" + key.caller
	}
	sum := sha256.Sum256([]byte(name))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
}

// saveInstructionLoads records authenticated loads and the startup snapshot.
// It removes the record after SessionEnd or without either kind of proof.
func (a *APIServer) saveInstructionLoads(key activeAgentContextKey) {
	dir := a.instructionLoadDir()
	if dir == "" {
		return
	}
	a.activeAgentContext.storeMu.Lock()
	defer a.activeAgentContext.storeMu.Unlock()
	record := instructionLoadRecordPath(dir, key)
	session, ok := a.activeAgentContext.sessionKey(key)
	if !ok || len(session.files) == 0 && !session.startupKnown {
		_ = os.Remove(record)
		return
	}
	data, err := json.Marshal(instructionLoadRecord{
		Scope: key.scope, Caller: key.caller, Connector: key.connector, Session: key.sessionID,
		Files: session.files, CaseInsensitiveFiles: session.caseInsensitiveFiles,
		LoadedIdentities: session.identities, StartupFiles: session.startupFiles,
		StartupKnown: session.startupKnown, StartupDirs: session.startupDirs,
		StartupDirIDs: session.startupDirIDs, AwaitingStart: session.awaitingStart,
	})
	if err != nil || len(data) > maxInstructionLoadRecordBytes || os.MkdirAll(dir, 0o700) != nil {
		return
	}
	temp, err := os.CreateTemp(dir, ".record-*")
	if err != nil {
		return
	}
	_, writeErr := temp.Write(data)
	closeErr := temp.Close()
	if writeErr != nil || closeErr != nil || os.Rename(temp.Name(), record) != nil {
		_ = os.Remove(temp.Name())
		return
	}
	pruneInstructionLoads(dir)
}

// pruneInstructionLoads keeps the newest records within
// maxInstructionLoadRecords and maxInstructionLoadStoreBytes; a session that
// never sent SessionEnd ages out.
func pruneInstructionLoads(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type record struct {
		name    string
		modTime int64
		size    int64
	}
	var records []record
	var total int64
	for _, entry := range entries {
		if info, err := entry.Info(); err == nil && info.Mode().IsRegular() && strings.HasSuffix(entry.Name(), ".json") {
			records = append(records, record{entry.Name(), info.ModTime().UnixNano(), info.Size()})
			total += info.Size()
		}
	}
	if len(records) <= maxInstructionLoadRecords && total <= maxInstructionLoadStoreBytes {
		return
	}
	slices.SortFunc(records, func(left, right record) int {
		switch {
		case left.modTime < right.modTime:
			return -1
		case left.modTime > right.modTime:
			return 1
		}
		return strings.Compare(left.name, right.name)
	})
	for len(records) > 0 && (len(records) > maxInstructionLoadRecords || total > maxInstructionLoadStoreBytes) {
		_ = os.Remove(filepath.Join(dir, records[0].name))
		total -= records[0].size
		records = records[1:]
	}
}

// restoreInstructionLoads gives a session the gateway holds no state for
// (after a restart, or after the cache evicted it) the loads it recorded.
func (a *APIServer) restoreInstructionLoads(key activeAgentContextKey) {
	dir := a.instructionLoadDir()
	if dir == "" {
		return
	}
	if _, ok := a.activeAgentContext.sessionKey(key); ok {
		return
	}
	name := instructionLoadRecordPath(dir, key)
	record, ok := readInstructionLoadRecord(name, key)
	if !ok {
		return
	}
	now := a.activeAgentContext.currentTime()
	a.activeAgentContext.restoreKey(key, record, now)
	// A session that is back in use is the newest to keep.
	_ = os.Chtimes(name, now, now)
}

func readInstructionLoadRecord(name string, key activeAgentContextKey) (instructionLoadRecord, bool) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxInstructionLoadRecordBytes {
		return instructionLoadRecord{}, false
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return instructionLoadRecord{}, false
	}
	var record instructionLoadRecord
	if json.Unmarshal(data, &record) != nil || record.Scope != key.scope || record.Caller != key.caller ||
		record.Connector != key.connector || record.Session != key.sessionID ||
		!record.StartupKnown && len(record.Files) == 0 ||
		len(record.Files) > maxActiveAgentContextFiles ||
		len(record.LoadedIdentities) > maxActiveAgentContextFiles {
		return instructionLoadRecord{}, false
	}
	for _, file := range record.Files {
		if !recordedInstructionFile(file) {
			return instructionLoadRecord{}, false
		}
	}
	for _, file := range record.CaseInsensitiveFiles {
		if !slices.Contains(record.Files, file) {
			return instructionLoadRecord{}, false
		}
	}
	for file, identity := range record.LoadedIdentities {
		if !recordedFileIdentity(identity) || !slices.Contains(record.Files, file) {
			return instructionLoadRecord{}, false
		}
	}
	if len(record.StartupFiles) > maxStartupInstructionFiles || len(record.StartupDirs) > maxStartupDirectories ||
		(len(record.StartupFiles) > 0 || len(record.StartupDirs) > 0 || len(record.StartupDirIDs) > 0) && !record.StartupKnown {
		return instructionLoadRecord{}, false
	}
	// The snapshot is read back exactly as instructionSnapshot records it
	// (recordedStartupDir, recordedStartupFile): every instruction name,
	// openclaw.json included, so one recorded file never drops the record.
	for _, dir := range record.StartupDirs {
		if !recordedStartupDir(dir) {
			return instructionLoadRecord{}, false
		}
	}
	for dir, identity := range record.StartupDirIDs {
		if !slices.Contains(record.StartupDirs, dir) || !recordedFileIdentity(identity) {
			return instructionLoadRecord{}, false
		}
	}
	for file, identity := range record.StartupFiles {
		if !recordedStartupFile(file) || !recordedFileIdentity(identity) {
			return instructionLoadRecord{}, false
		}
	}
	return record, true
}

func recordedFileIdentity(identity string) bool {
	return identity != "" && len(identity) <= 64 && strings.Trim(identity, "0123456789abcdef:") == ""
}

// recordedInstructionFile reports a loaded file as seedKey and seedSandboxKey
// record it: an absolute path, in the host's or a sandbox's spelling, of an
// instruction file name.
func recordedInstructionFile(file string) bool {
	if file == "" || len(file) > maxActiveAgentContextPathSize || strings.TrimSpace(file) != file ||
		!filepath.IsAbs(file) && !path.IsAbs(file) {
		return false
	}
	_, ok := canonicalActiveAgentFileName(path.Base(strings.ReplaceAll(file, `\`, "/")))
	return ok
}
