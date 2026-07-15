// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const activeConnectorFile = "active_connector.json"
const hookContractLockFile = "hook_contract_lock.json"
const agentSelectionFile = "agent_selection.json"

const (
	agentSelectionSchemaVersion = 1
	agentSelectionMaxBytes      = 64 << 10
	hookContractLockMaxBytes    = 2 << 20
	agentSelectionMaxLifetime   = 15 * time.Minute
	agentSelectionClockSkew     = 5 * time.Minute
)

type agentSelectionReceipt struct {
	SchemaVersion int                               `json:"schema_version"`
	UpdatedAt     string                            `json:"updated_at"`
	Selections    map[string]agentSelectionEvidence `json:"selections"`
}

type agentSelectionEvidence struct {
	Connector         string `json:"connector"`
	Source            string `json:"source"`
	Executable        string `json:"executable"`
	RawVersion        string `json:"raw_version"`
	NormalizedVersion string `json:"normalized_version"`
	SHA256            string `json:"sha256"`
	SelectedAt        string `json:"selected_at"`
	ExpiresAt         string `json:"expires_at"`
}

// Version 2 stores physically shared hook artifacts once at the lock root.
const hookContractLockVersion = 2

var activeConnectorStateMu sync.Mutex

// activeConnectorStateVersion is the schema version written by
// SaveActiveConnectors. Version 2 introduced the multi-connector "names"
// set. Version 3 adds connector-scoped inactive tombstones so a running hook
// guard can distinguish intentional teardown from missing/corrupt state
// without suppressing unrelated connectors. Version-less / "name"-only files
// are the legacy pre-v2 layout that LoadActiveConnectors migrates on read.
const activeConnectorStateVersion = 3

// connectorState is the on-disk shape of active_connector.json.
//
// Names is the canonical active-connector set (v2+). Name is retained as a
// mirror of the primary (Names[0]) and is still WRITTEN so cross-language and
// older readers keep working — notably the Python boot drift detector
// (cli/defenseclaw/bootstrap.py::_running_connector_name reads "name") and any
// pre-v2 gateway binary that only understands the single "name" field. On
// read, Names wins; a legacy file with only "name" is surfaced as a
// one-element set.
type connectorState struct {
	Version       int      `json:"version,omitempty"`
	Names         []string `json:"names,omitempty"`
	InactiveNames []string `json:"inactive_names,omitempty"`
	UpdatedAt     string   `json:"updated_at,omitempty"`
	Name          string   `json:"name,omitempty"`
}

type hookContractLock struct {
	Version                 int                              `json:"version"`
	UpdatedAt               string                           `json:"updated_at"`
	SharedHookScriptDigests map[string]string                `json:"shared_hook_script_digests,omitempty"`
	Connectors              map[string]HookContractLockEntry `json:"connectors"`
}

// HookContractLockEntry is the persisted reproduction record for the hook
// surface that setup actually installed. It intentionally stores raw and
// normalized agent versions, the resolved contract, and hook script digests so
// doctor/setup can detect "the agent binary changed underneath us" instead of
// silently applying stale capabilities to a new upstream hook protocol.
type HookContractLockEntry struct {
	Connector              string             `json:"connector"`
	RawAgentVersion        string             `json:"raw_agent_version,omitempty"`
	NormalizedAgentVersion string             `json:"normalized_agent_version,omitempty"`
	AgentExecutable        string             `json:"agent_executable,omitempty"`
	AgentExecutableSource  string             `json:"agent_executable_source,omitempty"`
	AgentExecutableSHA256  string             `json:"agent_executable_sha256,omitempty"`
	ContractID             string             `json:"contract_id,omitempty"`
	CompatibilityStatus    string             `json:"compatibility_status,omitempty"`
	CompatibilityReason    string             `json:"compatibility_reason,omitempty"`
	HookScriptVersion      string             `json:"hook_script_version,omitempty"`
	HookScriptDigests      map[string]string  `json:"hook_script_digests,omitempty"`
	Locations              ConnectorLocations `json:"locations,omitempty"`
	DefenseClawVersion     string             `json:"defenseclaw_version,omitempty"`
	HookFailMode           string             `json:"hook_fail_mode,omitempty"`
	UpdatedAt              string             `json:"updated_at"`
}

// LoadActiveConnector reads the previously active connector name from
// <dataDir>/active_connector.json. Returns "" if the file does not
// exist or is unreadable.
func LoadActiveConnector(dataDir string) string {
	names := LoadActiveConnectors(dataDir)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// LoadActiveConnectors reads the full active-connector set from
// <dataDir>/active_connector.json. Returns nil if the file is absent or
// unreadable. A v2+ file is read from "names"; a legacy ("name"-only) file is
// migrated on read into a one-element set so the next SaveActiveConnectors
// rewrites it in the current form.
func LoadActiveConnectors(dataDir string) []string {
	names, _, err := ReadActiveConnectorState(dataDir)
	if err != nil {
		return nil
	}
	return names
}

// ReadActiveConnectorState reads the active connector set without collapsing
// an explicitly empty state file into the same result as a missing or corrupt
// file. Callers that need teardown intent must use ConnectorExplicitlyInactive;
// an empty active set alone never suppresses a connector guard.
func ReadActiveConnectorState(dataDir string) (names []string, exists bool, err error) {
	data, err := os.ReadFile(filepath.Join(dataDir, activeConnectorFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var state connectorState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, true, err
	}
	if len(state.Names) > 0 {
		return normalizeConnectorSet(state.Names), true, nil
	}
	if trimmed := strings.TrimSpace(state.Name); trimmed != "" {
		return []string{trimmed}, true, nil
	}
	return nil, true, nil
}

// ConnectorExplicitlyInactive reports whether name has a connector-scoped
// inactive tombstone. Missing, corrupt, legacy, and merely empty state are not
// treated as intentional teardown: the hook guard continues to heal in those
// cases. An explicit active entry wins over a stale inactive entry.
func ConnectorExplicitlyInactive(dataDir, name string) bool {
	data, err := os.ReadFile(filepath.Join(dataDir, activeConnectorFile))
	if err != nil {
		return false
	}
	var state connectorState
	if err := json.Unmarshal(data, &state); err != nil {
		return false
	}
	want := strings.TrimSpace(name)
	for _, active := range activeNamesFromState(state) {
		if strings.EqualFold(strings.TrimSpace(active), strings.TrimSpace(name)) {
			return false
		}
	}
	for _, inactive := range state.InactiveNames {
		if strings.EqualFold(strings.TrimSpace(inactive), want) {
			return true
		}
	}
	return false
}

// SaveActiveConnector persists a single active connector. It is a backward-
// compatible shim over SaveActiveConnectors so existing callers (and the
// single-connector boot path) keep their exact contract.
func SaveActiveConnector(dataDir, name string) error {
	return SaveActiveConnectors(dataDir, []string{name})
}

// SaveActiveConnectors persists the active-connector set to
// <dataDir>/active_connector.json so the next sidecar boot can detect added
// or removed connectors and reconcile teardown. Names are trimmed, de-duped,
// and sorted for a stable representation. Existing inactive tombstones are
// preserved unless names explicitly reactivates that connector. The primary
// (Names[0]) is mirrored into the legacy "name" field for cross-language/older
// readers.
func SaveActiveConnectors(dataDir string, names []string) error {
	path := filepath.Join(dataDir, activeConnectorFile)
	return withActiveConnectorStateLock(path, func() error {
		set := normalizeConnectorSet(names)
		inactive := loadInactiveConnectorNames(path)
		inactive = withoutConnectorNames(inactive, set)
		return writeConnectorState(path, set, inactive)
	})
}

// MarkConnectorInactive atomically revokes one connector's runtime ownership
// before its agent configuration is removed. The returned restore function
// reinstates the exact previous bytes when no concurrent writer intervened;
// otherwise it merges the rollback into the newer state. This lets teardown
// proceed through recoverable state corruption while still rolling back only
// its ownership change if connector cleanup fails.
func MarkConnectorInactive(dataDir, name string) (restore func() error, err error) {
	path := filepath.Join(dataDir, activeConnectorFile)
	var original, marked []byte
	var existed, originalValid, originallyActive, originallyInactive bool
	want := strings.TrimSpace(name)
	err = withActiveConnectorStateLock(path, func() error {
		var readErr error
		original, readErr = os.ReadFile(path)
		existed = true
		if readErr != nil {
			if !os.IsNotExist(readErr) {
				return readErr
			}
			existed = false
			original = nil
		}

		var state connectorState
		if existed {
			if json.Unmarshal(original, &state) == nil {
				originalValid = true
				originallyActive = containsConnectorName(activeNamesFromState(state), want)
				originallyInactive = containsConnectorName(state.InactiveNames, want)
			} else {
				state = connectorState{}
			}
		}
		// Corrupt JSON is recoverable here: teardown writes a valid,
		// connector-scoped tombstone and the restore closure retains the exact
		// original bytes if subsequent agent cleanup fails before another
		// runtime-state writer commits newer information.
		active := withoutConnectorNames(activeNamesFromState(state), []string{want})
		inactive := append(append([]string(nil), state.InactiveNames...), want)
		var marshalErr error
		marked, marshalErr = marshalConnectorState(active, inactive)
		if marshalErr != nil {
			return marshalErr
		}
		return atomicWriteFile(path, marked, 0o600)
	})
	if err != nil {
		return nil, err
	}

	return func() error {
		return withActiveConnectorStateLock(path, func() error {
			current, readErr := os.ReadFile(path)
			if readErr != nil && !os.IsNotExist(readErr) {
				return readErr
			}
			// No writer touched the state after MarkConnectorInactive. Restore
			// the exact previous representation, including corrupt legacy bytes.
			if readErr == nil && bytes.Equal(current, marked) {
				if !existed {
					return removeActiveConnectorStateFile(path)
				}
				return atomicWriteFile(path, original, 0o600)
			}

			// A concurrent state writer committed newer information. Preserve it
			// while undoing only this teardown's ownership change.
			var state connectorState
			if readErr == nil {
				if err := json.Unmarshal(current, &state); err != nil {
					return err
				}
			}
			active := activeNamesFromState(state)
			inactive := withoutConnectorNames(state.InactiveNames, []string{want})
			if originalValid && originallyActive && !containsConnectorName(active, want) {
				active = append(active, want)
			}
			if originalValid && originallyInactive && !containsConnectorName(inactive, want) {
				inactive = append(inactive, want)
			}
			if !existed && len(active) == 0 && len(inactive) == 0 {
				return removeActiveConnectorStateFile(path)
			}
			return writeConnectorState(path, active, inactive)
		})
	}, nil
}

func loadInactiveConnectorNames(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var state connectorState
	if json.Unmarshal(data, &state) != nil {
		return nil
	}
	return normalizeConnectorSet(state.InactiveNames)
}

func writeConnectorState(path string, active, inactive []string) error {
	data, err := marshalConnectorState(active, inactive)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

func marshalConnectorState(active, inactive []string) ([]byte, error) {
	state := connectorState{
		Version:       activeConnectorStateVersion,
		Names:         normalizeConnectorSet(active),
		InactiveNames: normalizeConnectorSet(inactive),
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if len(state.Names) > 0 {
		state.Name = state.Names[0]
	}
	return json.Marshal(state)
}

func containsConnectorName(names []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, candidate := range names {
		if strings.EqualFold(strings.TrimSpace(candidate), want) {
			return true
		}
	}
	return false
}

func withoutConnectorNames(names, removed []string) []string {
	out := make([]string, 0, len(names))
	for _, candidate := range names {
		if !containsConnectorName(removed, candidate) {
			out = append(out, candidate)
		}
	}
	return normalizeConnectorSet(out)
}

func activeNamesFromState(state connectorState) []string {
	if len(state.Names) > 0 {
		return normalizeConnectorSet(state.Names)
	}
	if trimmed := strings.TrimSpace(state.Name); trimmed != "" {
		return []string{trimmed}
	}
	return nil
}

// normalizeConnectorSet trims, drops empties, de-dupes, and sorts connector
// names into a stable set. Case is preserved to keep the singular
// save/load round-trip contract unchanged.
func normalizeConnectorSet(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ClearActiveConnector removes the state file (used on full teardown
// when guardrails are disabled).
func ClearActiveConnector(dataDir string) {
	_ = RemoveActiveConnectorState(dataDir)
}

// RemoveActiveConnectorState removes the runtime ownership marker and reports
// filesystem failures. ClearActiveConnector retains its historical best-effort
// signature; teardown rollback uses this strict variant so it never silently
// leaves an explicit inactive marker after connector removal failed.
func RemoveActiveConnectorState(dataDir string) error {
	path := filepath.Join(dataDir, activeConnectorFile)
	return withActiveConnectorStateLock(path, func() error {
		return removeActiveConnectorStateFile(path)
	})
}

func withActiveConnectorStateLock(path string, fn func() error) error {
	activeConnectorStateMu.Lock()
	defer activeConnectorStateMu.Unlock()
	// Use a persistent owned lock inode. Removing an advisory lock file on
	// release can split waiters across different inodes and defeat mutual
	// exclusion; withOwnedFileLock also validates ownership and link safety.
	return withOwnedFileLock(path+".lock", fn)
}

func removeActiveConnectorStateFile(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func LoadHookContractLockEntry(dataDir, connectorName string) HookContractLockEntry {
	lock := loadHookContractLock(dataDir)
	if lock.Connectors == nil {
		return HookContractLockEntry{}
	}
	connectorName = normalizeConnectorName(connectorName)
	entry := lock.Connectors[connectorName]
	if runtime.GOOS == "windows" && connectorName == "codex" {
		if _, ok := supersedingCodexSetupSelection(dataDir, entry); ok {
			// An explicit setup action selected and protected newer executable
			// evidence. Treat the previous lock as absent for this one repair so
			// the normal compatibility-drift gate does not block the operation
			// whose purpose is to refresh that lock. The old bytes remain on disk
			// until Setup succeeds and SaveFreshHookContractLockEntry atomically
			// replaces only the Codex entry.
			return HookContractLockEntry{}
		}
	}
	return entry
}

func SaveHookContractLockEntry(dataDir string, entry HookContractLockEntry) error {
	return saveHookContractLockEntry(dataDir, entry, false)
}

// SaveFreshHookContractLockEntry persists the same contract evidence as
// SaveHookContractLockEntry but forces an atomic rewrite when the evidence is
// otherwise unchanged. Gateway boot uses this narrow variant as its durable
// readiness acknowledgement; ordinary callers retain idempotent no-op saves.
func SaveFreshHookContractLockEntry(dataDir string, entry HookContractLockEntry) error {
	return saveHookContractLockEntry(dataDir, entry, true)
}

func saveHookContractLockEntry(dataDir string, entry HookContractLockEntry, forceRefresh bool) error {
	if strings.TrimSpace(dataDir) == "" || strings.TrimSpace(entry.Connector) == "" {
		return nil
	}
	path := filepath.Join(dataDir, hookContractLockFile)
	return withFileLock(path, func() error {
		entry.Connector = normalizeConnectorName(entry.Connector)
		entry.HookScriptDigests = cloneHookScriptDigests(entry.HookScriptDigests)
		lock, err := loadHookContractLockForUpdate(dataDir)
		if err != nil {
			return fmt.Errorf("load hook contract lock for update: %w", err)
		}
		if err := validateHookRuntimeStateForContract(dataDir, entry.Connector, entry.HookFailMode); err != nil {
			return fmt.Errorf("validate hook runtime state for contract: %w", err)
		}
		if lock.Connectors == nil {
			lock.Connectors = map[string]HookContractLockEntry{}
		}
		shared := takeSharedHookScriptDigests(entry.HookScriptDigests)
		expectedShared := len(genericHookScripts) + len(hookHelperScripts)
		if len(shared) > 0 && len(shared) != expectedShared {
			return fmt.Errorf("incomplete shared hook digest set: got %d, want %d", len(shared), expectedShared)
		}
		lockChanged := false
		if len(shared) > 0 {
			if !reflect.DeepEqual(lock.SharedHookScriptDigests, shared) {
				lock.SharedHookScriptDigests = shared
				lockChanged = true
			}
			if lock.Version != hookContractLockVersion {
				lock.Version = hookContractLockVersion
				lockChanged = true
			}
		}
		if len(lock.SharedHookScriptDigests) > 0 {
			for name, peer := range lock.Connectors {
				if removeSharedHookScriptDigests(peer.HookScriptDigests) {
					lock.Connectors[name] = peer
					lockChanged = true
				}
			}
		}
		if launcherDigest := entry.HookScriptDigests[windowsHookBinaryName]; launcherDigest != "" {
			for name, peer := range lock.Connectors {
				if peer.HookScriptDigests == nil {
					peer.HookScriptDigests = map[string]string{}
				}
				if peer.HookScriptDigests[windowsHookBinaryName] != launcherDigest {
					peer.HookScriptDigests[windowsHookBinaryName] = launcherDigest
					lock.Connectors[name] = peer
					lockChanged = true
				}
			}
		}
		removeSharedHookScriptDigests(entry.HookScriptDigests)
		entryChanged := true
		if previous, ok := lock.Connectors[entry.Connector]; ok {
			previousComparison, entryComparison := previous, entry
			previousComparison.UpdatedAt, entryComparison.UpdatedAt = "", ""
			if reflect.DeepEqual(previousComparison, entryComparison) {
				entryChanged = false
				entry.UpdatedAt = previous.UpdatedAt
			}
		}
		if !entryChanged && !lockChanged && !forceRefresh {
			return nil
		}
		nowTime := time.Now().UTC()
		now := nowTime.Format(time.RFC3339)
		if forceRefresh {
			now = nowTime.Format(time.RFC3339Nano)
			if now == entry.UpdatedAt {
				now = nowTime.Add(time.Nanosecond).Format(time.RFC3339Nano)
			}
		}
		if entry.UpdatedAt == "" || forceRefresh {
			entry.UpdatedAt = now
		}
		lock.UpdatedAt = now
		lock.Connectors[entry.Connector] = entry
		data, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			return err
		}
		return atomicWriteFile(path, append(data, '\n'), 0o600)
	})
}

func ClearHookContractLockEntry(dataDir, connectorName string) error {
	if strings.TrimSpace(dataDir) == "" {
		return nil
	}
	connectorName = normalizeConnectorName(connectorName)
	path := filepath.Join(dataDir, hookContractLockFile)
	return withFileLock(path, func() error {
		lock, err := loadHookContractLockForUpdate(dataDir)
		if err != nil {
			return fmt.Errorf("load hook contract lock for clear: %w", err)
		}
		_, exists := lock.Connectors[connectorName]
		if exists {
			delete(lock.Connectors, connectorName)
			if len(lock.Connectors) == 0 {
				lock.SharedHookScriptDigests = nil
			}
			lock.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		hookDir := filepath.Join(dataDir, "hooks")
		if _, statErr := os.Stat(hookDir); os.IsNotExist(statErr) {
			if !exists {
				return nil
			}
			body, marshalErr := json.MarshalIndent(lock, "", "  ")
			if marshalErr != nil {
				return marshalErr
			}
			return atomicWriteFile(path, append(body, '\n'), 0o600)
		} else if statErr != nil {
			return fmt.Errorf("inspect hook runtime directory: %w", statErr)
		}
		runtimePath := filepath.Join(hookDir, hookConfigSidecarName)
		return withFileLock(runtimePath, func() error {
			snapshots, err := clearHookConfigSidecarEntryLocked(hookDir, connectorName)
			if err != nil {
				return fmt.Errorf("clear hook runtime state for %s: %w", connectorName, err)
			}
			if !exists {
				return nil
			}
			body, err := json.MarshalIndent(lock, "", "  ")
			if err != nil {
				return err
			}
			if err := atomicWriteFile(path, append(body, '\n'), 0o600); err != nil {
				if restoreErr := restoreHookRuntimeFiles(snapshots); restoreErr != nil {
					return fmt.Errorf("write cleared hook contract lock: %v (%v)", err, restoreErr)
				}
				return fmt.Errorf("write cleared hook contract lock: %w", err)
			}
			return nil
		})
	})
}

func NewHookContractLockEntry(opts SetupOpts, conn Connector, defenseClawVersion string) HookContractLockEntry {
	name := ""
	if conn != nil {
		name = conn.Name()
	}
	resolution := ResolveHookContract(name, opts.AgentVersion)
	contract := resolution.Contract
	if opts.HookContractID != "" {
		if pinned, ok := hookContractByID(name, opts.HookContractID); ok {
			contract = pinned
		}
	}
	entry := HookContractLockEntry{
		Connector:              normalizeConnectorName(name),
		RawAgentVersion:        resolution.RawVersion,
		NormalizedAgentVersion: resolution.NormalizedVersion,
		ContractID:             contract.ContractID,
		CompatibilityStatus:    resolution.Status,
		CompatibilityReason:    resolution.Reason,
		HookScriptVersion:      contract.HookScriptVersion,
		HookScriptDigests:      HookScriptDigests(opts, conn),
		Locations:              ResolvedConnectorLocations(opts, conn),
		DefenseClawVersion:     defenseClawVersion,
		HookFailMode:           normalizeHookFailMode(opts.HookFailMode),
		UpdatedAt:              time.Now().UTC().Format(time.RFC3339),
	}
	if runtime.GOOS == "windows" && entry.Connector == "codex" {
		executable, digest, ok := setupSelectedAgentExecutableEvidence(opts.AgentExecutable)
		if ok {
			entry.AgentExecutable = executable
			entry.AgentExecutableSource = "setup-selected"
			entry.AgentExecutableSHA256 = digest
		}
	}
	if opts.HookContractID != "" {
		entry.ContractID = opts.HookContractID
	}
	return entry
}

// setupSelectedAgentExecutableEvidence binds the exact regular executable
// selected by Setup to the versioned hook-contract entry. Runtime policy
// inspection revalidates the protected source, path, product, ACL, and digest;
// this stable hash prevents an in-place replacement from inheriting trust.
func setupSelectedAgentExecutableEvidence(path string) (string, string, bool) {
	path = strings.TrimSpace(path)
	if path == "" || strings.ContainsAny(path, "\x00\r\n") || !filepath.IsAbs(path) {
		return "", "", false
	}
	path = filepath.Clean(path)
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return "", "", false
	}
	file, err := os.Open(path)
	if err != nil {
		return "", "", false
	}
	openedBefore, openedBeforeErr := file.Stat()
	if openedBeforeErr != nil || openedBefore.Mode()&os.ModeSymlink != 0 ||
		!openedBefore.Mode().IsRegular() || !os.SameFile(before, openedBefore) {
		_ = file.Close()
		return "", "", false
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	openedAfter, openedAfterErr := file.Stat()
	closeErr := file.Close()
	after, statErr := os.Lstat(path)
	if copyErr != nil || openedAfterErr != nil || closeErr != nil || statErr != nil ||
		openedAfter.Mode()&os.ModeSymlink != 0 || !openedAfter.Mode().IsRegular() ||
		after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() ||
		!os.SameFile(before, openedAfter) || !os.SameFile(openedAfter, after) ||
		before.Size() != openedBefore.Size() || openedBefore.Size() != openedAfter.Size() ||
		openedAfter.Size() != after.Size() ||
		!before.ModTime().Equal(openedBefore.ModTime()) ||
		!openedBefore.ModTime().Equal(openedAfter.ModTime()) ||
		!openedAfter.ModTime().Equal(after.ModTime()) {
		return "", "", false
	}
	return path, hex.EncodeToString(hash.Sum(nil)), true
}

func ResolvedConnectorLocations(opts SetupOpts, conn Connector) ConnectorLocations {
	loc := ConnectorLocations{
		WorkspaceDir: strings.TrimSpace(opts.WorkspaceDir),
	}
	if conn == nil {
		return loc
	}
	if hp, ok := conn.(HookCapabilityProvider); ok {
		caps := hp.HookCapabilities(opts)
		loc.HookConfigPaths = uniqueNonEmptyStrings(append(loc.HookConfigPaths, caps.ConfigPath))
	}
	for _, path := range hookRuntimeArtifactPaths(opts, conn) {
		loc.HookScriptPaths = append(loc.HookScriptPaths, path)
	}
	loc.HookScriptPaths = uniqueNonEmptyStrings(loc.HookScriptPaths)

	cp, ok := conn.(ConnectorCapabilityProvider)
	if !ok {
		return loc
	}
	caps := cp.Capabilities(opts)
	loc.HookConfigPaths = uniqueNonEmptyStrings(append(loc.HookConfigPaths, caps.Hooks.ConfigPath))
	loc.TelemetryConfigPaths = uniqueNonEmptyStrings(caps.Telemetry.ConfigPaths)
	loc.Surfaces = map[string]SurfaceLocations{
		"mcp":     surfaceLocations(caps.MCP),
		"skills":  surfaceLocations(caps.Skills),
		"rules":   surfaceLocations(caps.Rules),
		"plugins": surfaceLocations(caps.Plugins),
		"agents":  surfaceLocations(caps.Agents),
	}
	return loc
}

func surfaceLocations(cap SurfaceCapability) SurfaceLocations {
	return SurfaceLocations{
		Supported:      cap.Supported,
		Scope:          cap.Scope,
		ConfigPaths:    uniqueNonEmptyStrings(cap.ConfigPaths),
		ReadPaths:      uniqueNonEmptyStrings(cap.ReadPaths),
		WritePaths:     uniqueNonEmptyStrings(cap.WritePaths),
		InstallTargets: uniqueNonEmptyStrings(cap.InstallTargets),
		DiscoveryOnly:  cap.DiscoveryOnly,
		RequiresOptIn:  cap.RequiresOptIn,
		Notes:          append([]string(nil), cap.Notes...),
	}
}

func HookContractLockDrifted(previous, current HookContractLockEntry) bool {
	return HookContractCompatibilityDrifted(previous, current)
}

// HookContractCompatibilityDrifted reports only upstream compatibility
// changes: the installed agent version or the selected hook contract changed.
// It deliberately excludes generated hook-script digests.
//
// A digest mismatch means an installed DefenseClaw hook is stale or was
// edited. Connector Setup is the repair path for that state, so rejecting
// startup before Setup runs makes an explicit setup/restart unable to refresh
// the hook. Callers that need the broader integrity signal (for doctor/status)
// should continue to use HookContractLockDrifted.
func HookContractCompatibilityDrifted(previous, current HookContractLockEntry) bool {
	if strings.TrimSpace(previous.Connector) == "" {
		return false
	}
	if previous.RawAgentVersion != "" && current.RawAgentVersion != "" && previous.RawAgentVersion != current.RawAgentVersion {
		return true
	}
	if previous.NormalizedAgentVersion != "" && current.NormalizedAgentVersion != "" && previous.NormalizedAgentVersion != current.NormalizedAgentVersion {
		return true
	}
	if previous.ContractID != "" && current.ContractID != "" && previous.ContractID != current.ContractID {
		return true
	}
	// Hook script digests are intentionally not a boot/reconcile drift gate:
	// changed script bytes are the thing setup/guardian repair is supposed to
	// overwrite. Treat only agent/contract identity changes as contract drift.
	return false
}

func HookScriptDigests(opts SetupOpts, conn Connector) map[string]string {
	if conn == nil || strings.TrimSpace(opts.DataDir) == "" {
		return nil
	}
	out := map[string]string{}
	for _, path := range hookRuntimeArtifactPaths(opts, conn) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		out[filepath.Base(path)] = "sha256:" + hex.EncodeToString(sum[:])
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sharedHookScriptName(name string) bool {
	for _, candidate := range genericHookScripts {
		if name == candidate {
			return true
		}
	}
	for _, candidate := range hookHelperScripts {
		if name == candidate {
			return true
		}
	}
	return false
}

func cloneHookScriptDigests(digests map[string]string) map[string]string {
	if digests == nil {
		return nil
	}
	cloned := make(map[string]string, len(digests))
	for name, digest := range digests {
		cloned[name] = digest
	}
	return cloned
}

func takeSharedHookScriptDigests(digests map[string]string) map[string]string {
	shared := map[string]string{}
	for name, digest := range digests {
		if sharedHookScriptName(name) {
			shared[name] = digest
		}
	}
	if len(shared) == 0 {
		return nil
	}
	return shared
}

func removeSharedHookScriptDigests(digests map[string]string) bool {
	changed := false
	for name := range digests {
		if sharedHookScriptName(name) {
			delete(digests, name)
			changed = true
		}
	}
	return changed
}

func hookRuntimeArtifactPaths(opts SetupOpts, conn Connector) []string {
	var paths []string
	if provider, ok := conn.(HookRuntimeArtifactProvider); ok {
		paths = append(paths, provider.HookRuntimeArtifacts(opts)...)
	} else {
		paths = append(paths, hookScriptPathsForConnector(opts, conn)...)
		for _, name := range hookHelperScripts {
			paths = append(paths, filepath.Join(opts.DataDir, "hooks", name))
		}
	}
	if runtime.GOOS == "windows" && conn != nil {
		name := normalizeConnectorName(conn.Name())
		if name == "claudecode" || name == "codex" {
			paths = append(paths, defenseclawHookBinary())
		}
	}
	return uniqueNonEmptyStrings(paths)
}

func LoadCachedAgentVersion(dataDir, connectorName string) string {
	if runtime.GOOS == "windows" && normalizeConnectorName(connectorName) == "codex" {
		if entry, exists := loadProtectedCodexContractEntry(dataDir); exists {
			if validCodexAgentExecutableEvidence(entry) {
				return strings.TrimSpace(entry.RawAgentVersion)
			}
			// Once a Codex contract exists it is the only runtime authority.
			// Missing/legacy executable evidence requires an explicit repair and
			// must never fall back to an automatic discovery cache or receipt.
			return ""
		}
		if selection, ok := loadSetupAgentSelection(dataDir, "codex"); ok {
			return selection.RawVersion
		}
		return ""
	}
	signal, ok := loadCachedAgentSignal(dataDir, connectorName)
	if !ok {
		return ""
	}
	return strings.TrimSpace(signal.Version)
}

// LoadCachedAgentExecutable is retained as a compatibility name for setup
// callers. On Windows, Codex never reads agent_discovery.json here: an existing
// install uses only its protected, version/contract-bound lock entry, while a
// fresh install may consume the short-lived setup-selected receipt. The policy
// inspector revalidates source, product, path, ACL, and digest before launch.
// Other platforms retain their established discovery-cache behavior.
func LoadCachedAgentExecutable(dataDir, connectorName string) string {
	if runtime.GOOS == "windows" && normalizeConnectorName(connectorName) == "codex" {
		if entry, exists := loadProtectedCodexContractEntry(dataDir); exists {
			if validCodexAgentExecutableEvidence(entry) {
				return strings.TrimSpace(entry.AgentExecutable)
			}
			return ""
		}
		if selection, ok := loadSetupAgentSelection(dataDir, "codex"); ok {
			return selection.Executable
		}
		return ""
	}
	signal, ok := loadCachedAgentSignal(dataDir, connectorName)
	if !ok {
		return ""
	}
	return strings.TrimSpace(signal.BinaryPath)
}

func loadProtectedCodexContractEntry(dataDir string) (HookContractLockEntry, bool) {
	path := filepath.Join(dataDir, hookContractLockFile)
	_, statErr := os.Lstat(path)
	fileExists := statErr == nil || !os.IsNotExist(statErr)
	data, valid := readStablePrivateStateFile(dataDir, hookContractLockFile, hookContractLockMaxBytes)
	if !valid {
		return HookContractLockEntry{}, fileExists
	}
	var lock hookContractLock
	if err := json.Unmarshal(data, &lock); err != nil || lock.Version < 1 || lock.Version > hookContractLockVersion {
		// The file exists but is malformed/unsupported. Return exists=true so
		// callers fail closed instead of treating it as a fresh installation.
		return HookContractLockEntry{}, true
	}
	entry, ok := lock.Connectors["codex"]
	if !ok {
		return HookContractLockEntry{}, false
	}
	if _, supersedes := supersedingCodexSetupSelection(dataDir, entry); supersedes {
		// The short-lived receipt is explicit repair authority, not discovery
		// cache authority. Returning exists=false makes the existing callers use
		// that receipt and lets policy validation re-check its exact path, ACL,
		// version, and digest before any hook registration is changed.
		return HookContractLockEntry{}, false
	}
	return entry, true
}

// supersedingCodexSetupSelection returns a fresh explicit setup receipt only
// when it can safely replace the existing Windows Codex lock. Invalid or
// expired receipts are rejected by loadSetupAgentSelection. A valid lock keeps
// authority unless the receipt is newer, or was written in the same timestamp
// tick with different evidence. Matching evidence never displaces a freshly
// persisted lock, which hands authority back to hook_contract_lock.json as soon
// as Setup succeeds.
func supersedingCodexSetupSelection(
	dataDir string,
	entry HookContractLockEntry,
) (agentSelectionEvidence, bool) {
	selection, ok := loadSetupAgentSelection(dataDir, "codex")
	if !ok {
		return agentSelectionEvidence{}, false
	}
	if !validCodexAgentExecutableEvidence(entry) {
		return selection, true
	}

	selectedAt, selectedErr := time.Parse(time.RFC3339, selection.SelectedAt)
	lockedAt, lockedErr := time.Parse(time.RFC3339, entry.UpdatedAt)
	if selectedErr != nil {
		return agentSelectionEvidence{}, false
	}
	if lockedErr != nil || selectedAt.After(lockedAt) {
		return selection, true
	}
	if selectedAt.Equal(lockedAt) && !codexSelectionMatchesLock(selection, entry) {
		return selection, true
	}
	return agentSelectionEvidence{}, false
}

func codexSelectionMatchesLock(selection agentSelectionEvidence, entry HookContractLockEntry) bool {
	return strings.TrimSpace(selection.RawVersion) == strings.TrimSpace(entry.RawAgentVersion) &&
		strings.TrimSpace(selection.NormalizedVersion) == strings.TrimSpace(entry.NormalizedAgentVersion) &&
		sameCodexExecutablePath(selection.Executable, entry.AgentExecutable) &&
		strings.EqualFold(selection.SHA256, entry.AgentExecutableSHA256)
}

func validCodexAgentExecutableEvidence(entry HookContractLockEntry) bool {
	if entry.Connector != "codex" ||
		entry.AgentExecutableSource != "setup-selected" ||
		strings.ContainsAny(entry.AgentExecutable, "\x00\r\n") ||
		!filepath.IsAbs(entry.AgentExecutable) ||
		filepath.Clean(entry.AgentExecutable) != entry.AgentExecutable ||
		!validLowerHexSHA256(entry.AgentExecutableSHA256) ||
		entry.NormalizedAgentVersion == "" || entry.ContractID == "" {
		return false
	}
	resolution := ResolveHookContract("codex", entry.RawAgentVersion)
	return resolution.Status == HookCompatibilityKnown &&
		resolution.NormalizedVersion == entry.NormalizedAgentVersion &&
		resolution.Contract.ContractID == entry.ContractID &&
		entry.CompatibilityStatus == resolution.Status
}

func loadSetupAgentSelection(dataDir, connectorName string) (agentSelectionEvidence, bool) {
	connectorName = normalizeConnectorName(connectorName)
	data, exists := readStablePrivateStateFile(dataDir, agentSelectionFile, agentSelectionMaxBytes)
	if !exists {
		return agentSelectionEvidence{}, false
	}
	var receipt agentSelectionReceipt
	if err := json.Unmarshal(data, &receipt); err != nil ||
		receipt.SchemaVersion != agentSelectionSchemaVersion ||
		receipt.Selections == nil {
		return agentSelectionEvidence{}, false
	}
	if _, err := time.Parse(time.RFC3339, receipt.UpdatedAt); err != nil {
		return agentSelectionEvidence{}, false
	}
	selection, ok := receipt.Selections[connectorName]
	if !ok || selection.Connector != connectorName ||
		selection.Source != "setup-selected" ||
		strings.ContainsAny(selection.Executable, "\x00\r\n") ||
		!filepath.IsAbs(selection.Executable) ||
		filepath.Clean(selection.Executable) != selection.Executable ||
		!validLowerHexSHA256(selection.SHA256) ||
		strings.TrimSpace(selection.RawVersion) == "" ||
		strings.TrimSpace(selection.NormalizedVersion) == "" {
		return agentSelectionEvidence{}, false
	}
	selectedAt, selectedErr := time.Parse(time.RFC3339, selection.SelectedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, selection.ExpiresAt)
	now := time.Now().UTC()
	if selectedErr != nil || expiresErr != nil || selectedAt.After(now.Add(agentSelectionClockSkew)) ||
		!expiresAt.After(now) || !expiresAt.After(selectedAt) ||
		expiresAt.Sub(selectedAt) > agentSelectionMaxLifetime {
		return agentSelectionEvidence{}, false
	}
	resolution := ResolveHookContract(connectorName, selection.RawVersion)
	if resolution.Status != HookCompatibilityKnown ||
		resolution.NormalizedVersion != selection.NormalizedVersion {
		return agentSelectionEvidence{}, false
	}
	return selection, true
}

func readStablePrivateStateFile(dataDir, name string, limit int64) ([]byte, bool) {
	if strings.TrimSpace(dataDir) == "" || !filepath.IsAbs(dataDir) || filepath.Base(name) != name {
		return nil, false
	}
	path := filepath.Join(dataDir, name)
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() > limit {
		return nil, false
	}
	if runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0 {
		return nil, false
	}
	if err := hookAPIValidateDirectory(filepath.Clean(dataDir)); err != nil {
		return nil, false
	}
	if err := hookAPIValidateOwner(path, before); err != nil {
		return nil, false
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	openedBefore, openedBeforeErr := file.Stat()
	if openedBeforeErr != nil || openedBefore.Mode()&os.ModeSymlink != 0 ||
		!openedBefore.Mode().IsRegular() || !os.SameFile(before, openedBefore) {
		_ = file.Close()
		return nil, false
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	openedAfter, openedAfterErr := file.Stat()
	closeErr := file.Close()
	after, statErr := os.Lstat(path)
	if readErr != nil || openedAfterErr != nil || closeErr != nil || statErr != nil || int64(len(data)) > limit ||
		openedAfter.Mode()&os.ModeSymlink != 0 || !openedAfter.Mode().IsRegular() ||
		after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() ||
		!os.SameFile(before, openedAfter) || !os.SameFile(openedAfter, after) ||
		before.Size() != openedBefore.Size() || openedBefore.Size() != openedAfter.Size() ||
		openedAfter.Size() != after.Size() ||
		!before.ModTime().Equal(openedBefore.ModTime()) ||
		!openedBefore.ModTime().Equal(openedAfter.ModTime()) ||
		!openedAfter.ModTime().Equal(after.ModTime()) {
		return nil, false
	}
	return data, true
}

func validLowerHexSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

type cachedAgentSignal struct {
	Version    string `json:"version"`
	BinaryPath string `json:"binary_path"`
}

func loadCachedAgentSignal(dataDir, connectorName string) (cachedAgentSignal, bool) {
	if strings.TrimSpace(dataDir) == "" {
		return cachedAgentSignal{}, false
	}
	data, err := os.ReadFile(filepath.Join(dataDir, "agent_discovery.json"))
	if err != nil {
		return cachedAgentSignal{}, false
	}
	var payload struct {
		Agents map[string]cachedAgentSignal `json:"agents"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return cachedAgentSignal{}, false
	}
	if payload.Agents == nil {
		return cachedAgentSignal{}, false
	}
	signal, ok := payload.Agents[normalizeConnectorName(connectorName)]
	if !ok {
		return cachedAgentSignal{}, false
	}
	return signal, true
}

func loadHookContractLock(dataDir string) hookContractLock {
	if strings.TrimSpace(dataDir) == "" {
		return hookContractLock{Version: 1, Connectors: map[string]HookContractLockEntry{}}
	}
	data, err := os.ReadFile(filepath.Join(dataDir, hookContractLockFile))
	if err != nil {
		return hookContractLock{Version: 1, Connectors: map[string]HookContractLockEntry{}}
	}
	var lock hookContractLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return hookContractLock{Version: 1, Connectors: map[string]HookContractLockEntry{}}
	}
	if lock.Connectors == nil {
		lock.Connectors = map[string]HookContractLockEntry{}
	}
	if lock.Version == 0 {
		lock.Version = 1
	}
	return lock
}

func loadHookContractLockForUpdate(dataDir string) (hookContractLock, error) {
	empty := hookContractLock{Version: 1, Connectors: map[string]HookContractLockEntry{}}
	if strings.TrimSpace(dataDir) == "" {
		return empty, nil
	}
	data, err := os.ReadFile(filepath.Join(dataDir, hookContractLockFile))
	if os.IsNotExist(err) {
		return empty, nil
	}
	if err != nil {
		return hookContractLock{}, err
	}
	var lock hookContractLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return hookContractLock{}, err
	}
	if lock.Version == 0 {
		lock.Version = 1
	}
	if lock.Version < 1 || lock.Version > hookContractLockVersion {
		return hookContractLock{}, fmt.Errorf("unsupported hook contract lock version %d", lock.Version)
	}
	if lock.Connectors == nil {
		lock.Connectors = map[string]HookContractLockEntry{}
	}
	return lock, nil
}
