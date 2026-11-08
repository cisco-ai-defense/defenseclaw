// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// The removed-connectors record (managed.HookGuardianRemovedConnectorsFile)
// says which accounts had a connector the administrator then took off the
// roster. The hook guardian writes it as LocalSystem, in the protected
// guardian state beside the authorization ledger, once the account's
// per-user files of the connector are gone; status, verify, the account's own
// status, doctor and the TUI answer render it as managed.NotManagedRemovedFromRoster.
//
// It ages out on the guardian pass after either of these: the connector is on
// the roster again for that account (the manifest admits it, or the config
// publishes the connector again), so the connector's own state replaces the
// record; or the account is gone (its profile was removed with the account,
// so nothing can read the answer). It never ages out by time: an account that
// has not signed in for months still has the connector removed.

// loadEnterpriseHookRemovedConnectors reads the record; a missing file is an
// empty record.
func loadEnterpriseHookRemovedConnectors(dataDir string) ([]managed.RemovedConnector, error) {
	path := managed.RemovedConnectorsPath(dataDir)
	info, err := pathidentity.LstatPinned(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect removed connectors record %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("removed connectors record is not a regular file: %s", path)
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(path); err != nil {
		return nil, err
	}
	data, err := readEnterpriseHookBoundedFile(path, info, managed.RemovedConnectorsMaxBytes, "removed connectors record")
	if err != nil {
		return nil, fmt.Errorf("read removed connectors record %s: %w", path, err)
	}
	return managed.ParseRemovedConnectors(data)
}

// saveEnterpriseHookRemovedConnectors publishes the record (administrator
// owned, not writable by the gateway service); an empty list removes the file.
func saveEnterpriseHookRemovedConnectors(dataDir string, entries []managed.RemovedConnector, now time.Time) error {
	path := managed.RemovedConnectorsPath(dataDir)
	if len(entries) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove empty removed connectors record: %w", err)
		}
		return nil
	}
	if len(entries) > managed.RemovedConnectorsMax {
		entries = entries[:managed.RemovedConnectorsMax]
	}
	data, err := managed.MarshalRemovedConnectors(entries, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if _, err := prepareEnterpriseHookAuthorizationDir(dataDir); err != nil {
		return err
	}
	if err := writeEnterpriseHookProtectedFile(path, data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return fmt.Errorf("protect removed connectors record: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return fmt.Errorf("set removed connectors record ownership: %w", err)
	}
	return enterpriseHookAuthorizationFileTrustCheck(path)
}

// recordEnterpriseHookRemovedConnector adds (or refreshes) one account's
// removed connector. An unreadable record is replaced: it holds no secret and
// the guardian rebuilds it from the next removal.
func recordEnterpriseHookRemovedConnector(dataDir string, entry managed.RemovedConnector, now time.Time) error {
	entries, err := loadEnterpriseHookRemovedConnectors(dataDir)
	if err != nil {
		entries = nil
	}
	key := managed.RemovedConnectorKey(entry.Connector, entry.SID)
	kept := make([]managed.RemovedConnector, 0, len(entries)+1)
	for _, existing := range entries {
		if managed.RemovedConnectorKey(existing.Connector, existing.SID) != key {
			kept = append(kept, existing)
		}
	}
	entry.Connector = strings.ToLower(strings.TrimSpace(entry.Connector))
	entry.SID = strings.TrimSpace(entry.SID)
	entry.RemovedAt = now.UTC().Format(time.RFC3339Nano)
	return saveEnterpriseHookRemovedConnectors(dataDir, append(kept, entry), now)
}

// pruneEnterpriseHookRemovedConnectors drops the entries whose connector is on
// the roster again for the account (the manifest admits it, or the loaded
// config publishes the connector again) or whose account is gone.
func pruneEnterpriseHookRemovedConnectors(
	dataDir string,
	manifest enterprisehooks.Manifest,
	published func(connector string) bool,
	accountGone func(sid string) bool,
	now time.Time,
) error {
	entries, err := loadEnterpriseHookRemovedConnectors(dataDir)
	if err != nil || len(entries) == 0 {
		return nil
	}
	admitted := enterpriseHookManifestAdmits(manifest)
	kept := make([]managed.RemovedConnector, 0, len(entries))
	for _, entry := range entries {
		if admitted(entry.Connector, entry.SID) || (published != nil && published(entry.Connector)) ||
			(accountGone != nil && accountGone(entry.SID)) {
			continue
		}
		kept = append(kept, entry)
	}
	if len(kept) == len(entries) {
		return nil
	}
	return saveEnterpriseHookRemovedConnectors(dataDir, kept, now)
}
