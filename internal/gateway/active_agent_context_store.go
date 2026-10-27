// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
// oldest one lose its record. Its first sighting is lost then, and the
// pruned index (instructionLoadPrunedName) says so: its next call takes no
// new first sighting, which would make a file it created look like one that
// was there before it. The index keeps the identities of the files the
// first sighting recorded: those stay protected by identity in every tier.
// Any other instruction file of the session keeps the call-time proof
// (existence): a block in the strict tier, a warning with an audit row in
// default and permissive.
const (
	maxInstructionLoadRecords    = 16 * maxActiveAgentContextSessions
	maxInstructionLoadStoreBytes = 64 << 20
)

// The pruned index lists the record names of sessions whose first sighting
// the bounds pruned, least recently used first, one per line with the
// identities that sighting proved (the record name, a space, the identities
// comma separated), until the session starts again or ends. A call of a
// listed session makes it the newest entry again (instructionFirstSightingLost),
// so a session in use keeps its place. Past the byte bound the oldest
// entries keep their name alone: the session stays lost and never takes a
// new first sighting while it lives; only the identities it proved fall to
// the call-time proof. Only past the entry bound (sixteen times the saved
// records) is the least recently used session dropped, with a log line: its
// next call takes a new first sighting, which protects every instruction
// file there then (a loss is only ever applied to the session that owned
// it). An index that cannot be read is taken as empty, the same way, and
// replaced on the next write.
const (
	instructionLoadPrunedName     = "pruned"
	maxInstructionLoadPruned      = 16 * maxInstructionLoadRecords
	maxInstructionLoadPrunedBytes = 8 << 20
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
	return filepath.Join(dir, instructionLoadRecordName(key)+".json")
}

// instructionLoadRecordName is the name of key's record without its
// extension, as the pruned index lists it.
func instructionLoadRecordName(key activeAgentContextKey) string {
	name := key.scope + "\x00" + key.connector + "\x00" + key.sessionID
	if key.caller != "" {
		// A per-user gateway's record keeps the name earlier builds gave it.
		name += "\x00caller\x00" + key.caller
	}
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
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
	saved := err == nil && len(data) <= maxInstructionLoadRecordBytes && writeInstructionLoadFile(dir, record, data)
	a.activeAgentContext.markSavedKey(key, saved)
	if saved {
		a.activeAgentContext.pruneInstructionLoadsLocked(dir)
	}
}

// writeInstructionLoadFile replaces name, a file of dir, with data.
func writeInstructionLoadFile(dir, name string, data []byte) bool {
	if os.MkdirAll(dir, 0o700) != nil {
		return false
	}
	temp, err := os.CreateTemp(dir, ".record-*")
	if err != nil {
		return false
	}
	_, writeErr := temp.Write(data)
	closeErr := temp.Close()
	if writeErr != nil || closeErr != nil || os.Rename(temp.Name(), name) != nil {
		_ = os.Remove(temp.Name())
		return false
	}
	return true
}

// pruneInstructionLoadsLocked keeps the newest records within
// maxInstructionLoadRecords and maxInstructionLoadStoreBytes; a session that
// never sent SessionEnd ages out. A pruned record that held a first sighting
// goes into the pruned index. The caller holds storeMu.
func (cache *activeAgentContextCache) pruneInstructionLoadsLocked(dir string) {
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
	cache.loadPrunedLocked(dir)
	changed := false
	for len(records) > 0 && (len(records) > maxInstructionLoadRecords || total > maxInstructionLoadStoreBytes) {
		name := filepath.Join(dir, records[0].name)
		identities, sighted := instructionLoadRecordSighted(name)
		if os.Remove(name) == nil && sighted {
			cache.addPrunedLocked(strings.TrimSuffix(records[0].name, ".json"), identities)
			changed = true
		}
		total -= records[0].size
		records = records[1:]
	}
	if changed {
		cache.writePrunedLocked(dir)
	}
}

// instructionLoadRecordSighted reports whether the record name holds a
// startup snapshot (a first sighting), with the identities it proves
// (lostIdentities). One that cannot be read is taken to, proving none.
func instructionLoadRecordSighted(name string) ([]string, bool) {
	data, err := os.ReadFile(name)
	if err != nil || len(data) > maxInstructionLoadRecordBytes {
		return nil, true
	}
	var record struct {
		StartupKnown     bool              `json:"startup_known"`
		StartupFiles     map[string]string `json:"startup_files"`
		LoadedIdentities map[string]string `json:"loaded_identities"`
	}
	if json.Unmarshal(data, &record) != nil {
		return nil, true
	}
	return lostIdentities(record.StartupFiles, record.LoadedIdentities), record.StartupKnown
}

// addPrunedLocked lists name in the pruned index with the identities its
// first sighting proved, as the newest entry. Past the byte bound the
// oldest entries keep their name alone (still lost); past the entry bound
// the least recently used ones are dropped. The caller holds storeMu.
func (cache *activeAgentContextCache) addPrunedLocked(name string, identities []string) {
	cache.removePrunedLocked(name)
	cache.pruned[name] = identities
	cache.prunedOrder = append(cache.prunedOrder, name)
	cache.prunedBytes += len(prunedIndexLine(name, identities)) + 1
	for index := 0; cache.prunedBytes > maxInstructionLoadPrunedBytes && index < len(cache.prunedOrder)-1; index++ {
		oldest := cache.prunedOrder[index]
		if proved := cache.pruned[oldest]; len(proved) != 0 {
			cache.prunedBytes -= len(prunedIndexLine(oldest, proved)) - len(oldest)
			cache.pruned[oldest] = nil
		}
	}
	dropped := 0
	for len(cache.prunedOrder) > 0 &&
		(len(cache.prunedOrder) > maxInstructionLoadPruned || cache.prunedBytes > maxInstructionLoadPrunedBytes) {
		oldest := cache.prunedOrder[0]
		cache.prunedBytes -= len(prunedIndexLine(oldest, cache.pruned[oldest])) + 1
		delete(cache.pruned, oldest)
		cache.prunedOrder = cache.prunedOrder[1:]
		dropped++
	}
	if dropped > 0 {
		fmt.Fprintf(os.Stderr, "[instruction-protection] the pruned first-sighting index is full: %d least recently used session(s) take a new first sighting on their next call\n", dropped)
	}
}

// removePrunedLocked drops name from the pruned index and reports whether
// it was listed. The caller holds storeMu.
func (cache *activeAgentContextCache) removePrunedLocked(name string) bool {
	identities, listed := cache.pruned[name]
	if !listed {
		return false
	}
	cache.prunedBytes -= len(prunedIndexLine(name, identities)) + 1
	delete(cache.pruned, name)
	cache.prunedOrder = slices.DeleteFunc(cache.prunedOrder, func(pruned string) bool { return pruned == name })
	return true
}

func prunedIndexLine(name string, identities []string) string {
	if len(identities) == 0 {
		return name
	}
	return name + " " + strings.Join(identities, ",")
}

// loadPrunedLocked reads the pruned index once per process. The caller
// holds storeMu.
func (cache *activeAgentContextCache) loadPrunedLocked(dir string) {
	if cache.prunedLoaded {
		return
	}
	cache.prunedLoaded = true
	cache.pruned = make(map[string][]string)
	cache.prunedOrder, cache.prunedBytes = nil, 0
	info, err := os.Lstat(filepath.Join(dir, instructionLoadPrunedName))
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxInstructionLoadPrunedBytes {
		return
	}
	data, err := os.ReadFile(filepath.Join(dir, instructionLoadPrunedName))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, list, _ := strings.Cut(line, " ")
		if len(name) != sha256.Size*2 || strings.Trim(name, "0123456789abcdef") != "" {
			continue
		}
		var identities []string
		for _, identity := range strings.Split(list, ",") {
			if recordedFileIdentity(identity) {
				identities = append(identities, identity)
			}
		}
		cache.addPrunedLocked(name, identities)
	}
}

// writePrunedLocked saves the pruned index. The caller holds storeMu.
func (cache *activeAgentContextCache) writePrunedLocked(dir string) {
	name := filepath.Join(dir, instructionLoadPrunedName)
	lines := make([]string, 0, len(cache.prunedOrder))
	for _, pruned := range cache.prunedOrder {
		lines = append(lines, prunedIndexLine(pruned, cache.pruned[pruned]))
	}
	if len(lines) == 0 {
		_ = os.Remove(name)
		return
	}
	_ = writeInstructionLoadFile(dir, name, []byte(strings.Join(lines, "\n")+"\n"))
}

// instructionFirstSightingLost reports whether key's first sighting is gone,
// with the identities it still proves: the bounds pruned its record
// (pruneInstructionLoadsLocked), or this process lost it
// (rememberLostLocked). A later event of the session (a CwdChanged, a load)
// does not bring it back. A session asked about is in use: it becomes the
// newest entry, so the bounds drop it last.
func (a *APIServer) instructionFirstSightingLost(key activeAgentContextKey) ([]string, bool) {
	if identities, lost := a.activeAgentContext.lostKey(key); lost {
		return identities, true
	}
	dir := a.instructionLoadDir()
	if dir == "" {
		return nil, false
	}
	cache := &a.activeAgentContext
	cache.storeMu.Lock()
	defer cache.storeMu.Unlock()
	cache.loadPrunedLocked(dir)
	name := instructionLoadRecordName(key)
	identities, pruned := cache.pruned[name]
	// The index is written again at most once per half of its entries.
	if pruned && slices.Index(cache.prunedOrder, name) < len(cache.prunedOrder)/2 {
		cache.addPrunedLocked(name, identities)
		cache.writePrunedLocked(dir)
	}
	return slices.Clone(identities), pruned
}

// clearInstructionSightingLoss drops key from the pruned index when the
// session starts again or ends: a new start takes its own snapshot, and a
// session ID used after an end is a new session.
func (a *APIServer) clearInstructionSightingLoss(key activeAgentContextKey) {
	dir := a.instructionLoadDir()
	if dir == "" {
		return
	}
	cache := &a.activeAgentContext
	cache.storeMu.Lock()
	defer cache.storeMu.Unlock()
	cache.loadPrunedLocked(dir)
	if cache.removePrunedLocked(instructionLoadRecordName(key)) {
		cache.writePrunedLocked(dir)
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
		// A record this session cannot restore (unreadable or invalid) held
		// state the session had: its first sighting is lost, and what it
		// proved is not known.
		if _, err := os.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			a.activeAgentContext.loseKey(key, nil)
		}
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
