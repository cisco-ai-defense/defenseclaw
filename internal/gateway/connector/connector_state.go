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
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

const activeConnectorFile = "active_connector.json"
const hookContractLockFile = "hook_contract_lock.json"

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
	Version    int                              `json:"version"`
	UpdatedAt  string                           `json:"updated_at"`
	Connectors map[string]HookContractLockEntry `json:"connectors"`
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
	ContractID             string             `json:"contract_id,omitempty"`
	CompatibilityStatus    string             `json:"compatibility_status,omitempty"`
	CompatibilityReason    string             `json:"compatibility_reason,omitempty"`
	HookScriptVersion      string             `json:"hook_script_version,omitempty"`
	HookScriptDigests      map[string]string  `json:"hook_script_digests,omitempty"`
	Locations              ConnectorLocations `json:"locations,omitempty"`
	DefenseClawVersion     string             `json:"defenseclaw_version,omitempty"`
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
	return lock.Connectors[normalizeConnectorName(connectorName)]
}

func SaveHookContractLockEntry(dataDir string, entry HookContractLockEntry) error {
	if strings.TrimSpace(dataDir) == "" || strings.TrimSpace(entry.Connector) == "" {
		return nil
	}
	entry.Connector = normalizeConnectorName(entry.Connector)
	if entry.UpdatedAt == "" {
		entry.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	lock := loadHookContractLock(dataDir)
	if lock.Version == 0 {
		lock.Version = 1
	}
	if lock.Connectors == nil {
		lock.Connectors = map[string]HookContractLockEntry{}
	}
	if previous, ok := lock.Connectors[entry.Connector]; ok {
		previousComparison := previous
		entryComparison := entry
		previousComparison.UpdatedAt = ""
		entryComparison.UpdatedAt = ""
		if reflect.DeepEqual(previousComparison, entryComparison) {
			return nil
		}
	}
	if entry.UpdatedAt == "" {
		entry.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	lock.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	lock.Connectors[entry.Connector] = entry
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWriteFile(filepath.Join(dataDir, hookContractLockFile), data, 0o600)
}

func ClearHookContractLockEntry(dataDir, connectorName string) error {
	lock := loadHookContractLock(dataDir)
	if len(lock.Connectors) == 0 {
		return nil
	}
	delete(lock.Connectors, normalizeConnectorName(connectorName))
	lock.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWriteFile(filepath.Join(dataDir, hookContractLockFile), data, 0o600)
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
		UpdatedAt:              time.Now().UTC().Format(time.RFC3339),
	}
	if opts.HookContractID != "" {
		entry.ContractID = opts.HookContractID
	}
	return entry
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
	if HookContractCompatibilityDrifted(previous, current) {
		return true
	}
	if len(previous.HookScriptDigests) > 0 && len(current.HookScriptDigests) > 0 {
		for name, digest := range previous.HookScriptDigests {
			if current.HookScriptDigests[name] != "" && current.HookScriptDigests[name] != digest {
				return true
			}
		}
	}
	return false
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

func hookRuntimeArtifactPaths(opts SetupOpts, conn Connector) []string {
	if provider, ok := conn.(HookRuntimeArtifactProvider); ok {
		return uniqueNonEmptyStrings(provider.HookRuntimeArtifacts(opts))
	}
	return hookScriptPathsForConnector(opts, conn)
}

func LoadCachedAgentVersion(dataDir, connectorName string) string {
	if strings.TrimSpace(dataDir) == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dataDir, "agent_discovery.json"))
	if err != nil {
		return ""
	}
	var payload struct {
		Agents map[string]struct {
			Version string `json:"version"`
		} `json:"agents"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return ""
	}
	if payload.Agents == nil {
		return ""
	}
	signal, ok := payload.Agents[normalizeConnectorName(connectorName)]
	if !ok {
		return ""
	}
	return strings.TrimSpace(signal.Version)
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
