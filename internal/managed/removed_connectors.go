// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// HookGuardianRemovedConnectorsFile, next to the authorization ledger, is
	// the administrator-owned record of the connectors an administrator took
	// off the roster that an account had been enrolled for. The hook guardian
	// writes it (as LocalSystem) once the account's per-user files of the
	// connector are removed, and drops an entry when the connector is on the
	// roster for that account again, or the account is gone. Status, verify,
	// the account's own status, doctor and the TUI answer read it to say the
	// connector is not managed for the account; without it the connector row
	// would just vanish, and nothing recorded that the account had it.
	HookGuardianRemovedConnectorsFile = "removed-connectors.json"
	// RemovedConnectorsVersion is the record's schema version.
	RemovedConnectorsVersion = 1
	// RemovedConnectorsMaxBytes bounds a read of the record.
	RemovedConnectorsMaxBytes = 1 << 20
	// RemovedConnectorsMax bounds the number of entries.
	RemovedConnectorsMax = 4096
	// NotManagedRemovedFromRoster is the state every renderer shows for a
	// removed connector: neither protected nor pending, because the
	// administrator removed it from the roster and DefenseClaw no longer
	// governs it for the account. Its leftover hook calls are allowed.
	NotManagedRemovedFromRoster = "not managed (removed from roster)"
)

// RemovedConnector is one account's removed connector.
type RemovedConnector struct {
	Connector string `json:"connector"`
	SID       string `json:"sid"`
	User      string `json:"user,omitempty"`
	UserHome  string `json:"user_home,omitempty"`
	RemovedAt string `json:"removed_at"`
}

// RemovedConnectors is the record file.
type RemovedConnectors struct {
	Version   int                `json:"version"`
	UpdatedAt string             `json:"updated_at"`
	Removed   []RemovedConnector `json:"removed"`
}

// RemovedConnectorsPath is the record's path for the service data directory.
func RemovedConnectorsPath(dataDir string) string {
	return filepath.Join(HookGuardianAuthorizationDir(dataDir), HookGuardianRemovedConnectorsFile)
}

// RemovedConnectorKey is the identity of one entry: connector and SID, with
// the connector in lower case and the SID in upper case.
func RemovedConnectorKey(connector, sid string) string {
	return strings.ToLower(strings.TrimSpace(connector)) + "\x00" + strings.ToUpper(strings.TrimSpace(sid))
}

// ParseRemovedConnectors strictly decodes the record: no unknown field, no
// trailing content, the known version, a bounded list of complete entries.
func ParseRemovedConnectors(data []byte) ([]RemovedConnector, error) {
	if len(data) > RemovedConnectorsMaxBytes {
		return nil, fmt.Errorf("removed connectors record exceeds %d bytes", RemovedConnectorsMaxBytes)
	}
	var record RemovedConnectors
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("parse removed connectors record: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse removed connectors record: trailing content")
	}
	if record.Version != RemovedConnectorsVersion || len(record.Removed) > RemovedConnectorsMax {
		return nil, errors.New("removed connectors record has an invalid schema")
	}
	for _, entry := range record.Removed {
		if strings.TrimSpace(entry.Connector) == "" || strings.TrimSpace(entry.SID) == "" || strings.TrimSpace(entry.RemovedAt) == "" {
			return nil, errors.New("removed connectors record contains an incomplete entry")
		}
	}
	return record.Removed, nil
}

// MarshalRemovedConnectors encodes entries, sorted, as the record.
func MarshalRemovedConnectors(entries []RemovedConnector, updatedAt string) ([]byte, error) {
	sorted := append([]RemovedConnector(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return RemovedConnectorKey(sorted[i].Connector, sorted[i].SID) < RemovedConnectorKey(sorted[j].Connector, sorted[j].SID)
	})
	data, err := json.MarshalIndent(RemovedConnectors{Version: RemovedConnectorsVersion, UpdatedAt: updatedAt, Removed: sorted}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// RemovedConnectorsForSID returns the connectors recorded as removed for one
// account, in lower case and sorted, skipping the ones in stillOnRoster.
func RemovedConnectorsForSID(entries []RemovedConnector, sid string, stillOnRoster func(string) bool) []string {
	var names []string
	seen := map[string]bool{}
	for _, entry := range entries {
		name := strings.ToLower(strings.TrimSpace(entry.Connector))
		if !strings.EqualFold(strings.TrimSpace(entry.SID), strings.TrimSpace(sid)) || seen[name] ||
			(stillOnRoster != nil && stillOnRoster(name)) {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
