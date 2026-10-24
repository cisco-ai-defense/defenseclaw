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

type instructionLoadRecord struct {
	Scope                string            `json:"scope,omitempty"`
	Connector            string            `json:"connector"`
	Session              string            `json:"session"`
	Files                []string          `json:"files,omitempty"`
	CaseInsensitiveFiles []string          `json:"case_insensitive_files,omitempty"`
	Identities           map[string]string `json:"identities,omitempty"`
	StartupFiles         map[string]string `json:"startup_files,omitempty"`
	StartupKnown         bool              `json:"startup_known,omitempty"`
	StartupDirs          []string          `json:"startup_dirs,omitempty"`
}

func (a *APIServer) instructionLoadDir() string {
	if a == nil || a.scannerCfg == nil || strings.TrimSpace(a.scannerCfg.DataDir) == "" {
		return ""
	}
	return filepath.Join(a.scannerCfg.DataDir, "cache", "instruction-loads")
}

func instructionLoadRecordPath(dir string, key activeAgentContextKey) string {
	sum := sha256.Sum256([]byte(key.scope + "\x00" + key.connector + "\x00" + key.sessionID))
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
		Scope: key.scope, Connector: key.connector, Session: key.sessionID,
		Files: session.files, CaseInsensitiveFiles: session.caseInsensitiveFiles,
		Identities: session.identities, StartupFiles: session.startupFiles,
		StartupKnown: session.startupKnown, StartupDirs: session.startupDirs,
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

// pruneInstructionLoads keeps the newest records of as many sessions as the
// in-memory cache holds; a session that never sent SessionEnd ages out.
func pruneInstructionLoads(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= maxActiveAgentContextSessions {
		return
	}
	type record struct {
		name    string
		modTime int64
	}
	var records []record
	for _, entry := range entries {
		if info, err := entry.Info(); err == nil && info.Mode().IsRegular() && strings.HasSuffix(entry.Name(), ".json") {
			records = append(records, record{entry.Name(), info.ModTime().UnixNano()})
		}
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
	for len(records) > maxActiveAgentContextSessions {
		_ = os.Remove(filepath.Join(dir, records[0].name))
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
	record, ok := readInstructionLoadRecord(instructionLoadRecordPath(dir, key), key)
	if !ok {
		return
	}
	a.activeAgentContext.restoreKey(key, record, a.activeAgentContext.currentTime())
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
	if json.Unmarshal(data, &record) != nil || record.Scope != key.scope ||
		record.Connector != key.connector || record.Session != key.sessionID ||
		!record.StartupKnown && len(record.Files) == 0 ||
		len(record.Files) > maxActiveAgentContextFiles ||
		len(record.Identities) > maxActiveAgentContextFiles {
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
	for identity, file := range record.Identities {
		if identity == "" || len(identity) > 64 || strings.Trim(identity, "0123456789abcdef:") != "" ||
			!slices.Contains(record.Files, file) {
			return instructionLoadRecord{}, false
		}
	}
	if len(record.StartupFiles) > maxStartupInstructionFiles || len(record.StartupDirs) > maxStartupDirectories ||
		(len(record.StartupFiles) > 0 || len(record.StartupDirs) > 0) && !record.StartupKnown {
		return instructionLoadRecord{}, false
	}
	for _, dir := range record.StartupDirs {
		// A directory is recorded as instructionDirectoryKey spells it: the
		// parent of an instruction file, so "c:" for a Windows drive root.
		if dir == "" || strings.HasSuffix(dir, "/") && dir != "/" ||
			!recordedInstructionFile(strings.TrimSuffix(dir, "/")+"/AGENTS.md") {
			return instructionLoadRecord{}, false
		}
	}
	for file, identity := range record.StartupFiles {
		if !recordedInstructionFile(file) || len(identity) > 64 || identity == "" ||
			strings.Trim(identity, "0123456789abcdef:") != "" {
			return instructionLoadRecord{}, false
		}
	}
	return record, true
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
