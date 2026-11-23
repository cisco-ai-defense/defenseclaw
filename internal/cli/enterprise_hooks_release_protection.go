// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// enterpriseHookReleaseProtectionFile is the guardian's record, in its
// protected authorization folder beside the ledger, of the managed Windows
// targets this release has protected (installed or verified OK), with the
// hook-contract lock and entry times the guardian's own result recorded for
// each. It is its own file, so the strict v1 ledger and activation schemas a
// prior binary reads stay as they are. Only the guardian (LocalSystem) writes
// it, with the ledger's protected writer and access list.
//
// A signed-out target whose hook-contract lock names another release waits
// for its account's next sign-in instead of failing (the other-release
// waits). The lock is in the account's own DefenseClaw folder, which the
// account can write, so the release it names counts only for a target this
// release has not yet protected: after a 1.0.10 -> 1.0.11 upgrade an account
// the 1.0.11 guardian already protected could edit its lock back to 1.0.10,
// strip its hooks and sign out, and read as awaiting sign-in (GAP-1762).
//
// The record names the ledger generation it was written for (the ledger's
// updated_at) and the one it was built on. It counts only while the ledger
// is one of those two generations: another guardian (an earlier release
// after a rollback) that published since may have re-rendered a target with
// the times this record holds (GAP-1763). A record whose ledger write
// failed (a crash, a failed replace) is ahead of the ledger it was built on
// and still counts for it: its targets come from that ledger's rows and the
// pass's own, and the times must match the published row (GAP-1885).
const enterpriseHookReleaseProtectionFile = "release_protection.json"

// enterpriseHookReleaseProtectionMaxBytes bounds the read: one short entry
// per enrolled account and connector.
const enterpriseHookReleaseProtectionMaxBytes = 4 << 20

type enterpriseHookReleaseProtection struct {
	SchemaVersion int    `json:"schema_version"`
	Release       string `json:"release"`
	// Generation is the ledger updated_at this record was written for.
	Generation string `json:"generation"`
	// BaseGeneration is the ledger updated_at it was built on.
	BaseGeneration string                                 `json:"base_generation,omitempty"`
	Targets        []enterpriseHookReleaseProtectedTarget `json:"targets"`
}

type enterpriseHookReleaseProtectedTarget struct {
	Connector      string `json:"connector"`
	SID            string `json:"sid"`
	LockUpdatedAt  string `json:"hook_contract_lock_updated_at,omitempty"`
	EntryUpdatedAt string `json:"hook_contract_entry_updated_at,omitempty"`
}

var (
	// enterpriseHookReleaseProtectionRecorded reports a guardian that keeps
	// the record: the managed Windows one, the only one with other-release
	// waits. Tests replace it.
	enterpriseHookReleaseProtectionRecorded = func() bool { return runtime.GOOS == "windows" }
	// enterpriseHookReconcileTargetLockRelease names the other release a
	// target's hook-contract lock carries (on the standalone profile only
	// when the machine release history names it). Tests replace it.
	enterpriseHookReconcileTargetLockRelease = enterprisehooks.WindowsProtectedTargetFromOtherRelease
)

// enterpriseHookTargetReleaseNotProtectedHere is
// enterpriseHookReconcileTargetRelease: the other release a target's lock
// names, counted only when this release has not protected the target since
// the guardian last recorded its protection (enterpriseHookTargetProtectedHere).
// Any error reading either is not another release, so every other-release
// wait stays a failure.
func enterpriseHookTargetReleaseNotProtectedHere(opts enterprisehooks.InstallOptions) (string, bool, error) {
	written, other, err := enterpriseHookReconcileTargetLockRelease(opts)
	if err != nil || !other {
		return "", false, err
	}
	protected, err := enterpriseHookTargetProtectedHere(opts)
	if err != nil || protected {
		return "", false, err
	}
	return written, true, nil
}

// enterpriseHookTargetProtectedHere reports that this release protected the
// target and that the guardian ledger's protected row for it is still the
// one this release recorded: the row's lock and entry times equal the ones
// this release's record holds for the target. Another guardian that protected
// the target since (an earlier release after a rollback, which re-rendered
// it and recorded new times) makes it no: its lock may then rightly name that
// release. So does a ledger generation the record was not written for: an
// earlier guardian that published since may have re-rendered the target with
// the same recovery times (GAP-1763 c). A record ahead of the ledger it was
// built on (its ledger write failed) counts for that ledger (GAP-1885). Both
// records are SYSTEM-written; the account can write neither.
func enterpriseHookTargetProtectedHere(opts enterprisehooks.InstallOptions) (bool, error) {
	if !enterpriseHookReleaseProtectionRecorded() {
		return false, nil
	}
	if cfg == nil || strings.TrimSpace(cfg.DataDir) == "" {
		return false, errors.New("enterprise hooks: no data directory configured, so the guardian cannot tell whether this release already protected the target")
	}
	connectorName := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	sid := strings.ToUpper(strings.TrimSpace(opts.OwnerSID))
	if connectorName == "" || sid == "" {
		return false, errors.New("enterprise hooks: the target has no connector or SID, so the guardian cannot tell whether this release already protected it")
	}
	record, exists, err := loadEnterpriseHookReleaseProtection(managed.HookGuardianAuthorizationDir(cfg.DataDir))
	if err != nil || !exists || record.Release != enterpriseHookThisRelease() {
		return false, err
	}
	var recorded *enterpriseHookReleaseProtectedTarget
	for i := range record.Targets {
		if record.Targets[i].Connector == connectorName && record.Targets[i].SID == sid {
			recorded = &record.Targets[i]
			break
		}
	}
	if recorded == nil {
		return false, nil
	}
	authorization, _, err := loadEnterpriseHookGuardianAuthorization(cfg.DataDir)
	if err != nil {
		return false, err
	}
	if authorization.UpdatedAt == "" || record.Generation == "" ||
		(record.Generation != authorization.UpdatedAt && record.BaseGeneration != authorization.UpdatedAt) {
		return false, nil
	}
	for _, row := range authorization.ProtectedTargets {
		if !strings.EqualFold(strings.TrimSpace(row.SID), sid) ||
			enterpriseHookReleaseProtectionConnector(row) != connectorName {
			continue
		}
		lock, entry := enterpriseHookReleaseProtectionTimes(row)
		return lock == recorded.LockUpdatedAt && entry == recorded.EntryUpdatedAt, nil
	}
	return false, nil
}

// recordEnterpriseHookReleaseProtection writes the record for the ledger
// generation the guardian is about to publish (generation, the ledger's
// updated_at), built on base, the ledger generation published now. The
// guardian writes it before the ledger and the activation receipt, so a pass
// whose record write fails publishes nothing and says so, instead of
// publishing a ledger the record does not cover (GAP-1763 a).
//
// A target counts as protected by this release when this pass protected it
// (OK, not pending or removed) or installed it (a result with lock times)
// even if its row then failed: that install wrote this release's lock, so
// the account must not be able to forge an older one (GAP-1763 d). A row
// that failed is bound to the ledger row the pass publishes for the target
// (the protection carried forward), and is left out when there is none.
// The record's earlier targets are kept, bound to their ledger rows, when it
// is this release's and was written for base, or built on it (its own
// ledger write failed); one with no ledger row is left out. A record
// that does not read back trusted and well formed is rebuilt with every
// protected ledger row, so a target failing now keeps its protection
// instead of being able to wait (GAP-1763 b): that only ever turns an
// other-release wait into a failure.
func recordEnterpriseHookReleaseProtection(
	authorizationDir string,
	base enterpriseHookGuardianAuthorization,
	generation string,
	protected []enterpriseHookReconcileRow,
	rows []enterpriseHookReconcileRow,
) error {
	if !enterpriseHookReleaseProtectionRecorded() {
		return nil
	}
	release := enterpriseHookThisRelease()
	key := func(connectorName, sid string) string { return connectorName + "\x00" + sid }
	ledger := map[string]enterpriseHookReconcileRow{}
	for _, row := range protected {
		connectorName := enterpriseHookReleaseProtectionConnector(row)
		sid := strings.ToUpper(strings.TrimSpace(row.SID))
		if connectorName != "" && sid != "" {
			ledger[key(connectorName, sid)] = row
		}
	}
	targets := map[string]enterpriseHookReleaseProtectedTarget{}
	add := func(connectorName, sid string, row enterpriseHookReconcileRow) {
		lock, entry := enterpriseHookReleaseProtectionTimes(row)
		targets[key(connectorName, sid)] = enterpriseHookReleaseProtectedTarget{
			Connector: connectorName, SID: sid, LockUpdatedAt: lock, EntryUpdatedAt: entry,
		}
	}
	previous, exists, loadErr := loadEnterpriseHookReleaseProtection(authorizationDir)
	switch {
	case exists && loadErr != nil:
		for _, row := range ledger {
			add(enterpriseHookReleaseProtectionConnector(row), strings.ToUpper(strings.TrimSpace(row.SID)), row)
		}
	case exists && previous.Release == release && previous.Generation != "" &&
		(previous.Generation == base.UpdatedAt || previous.BaseGeneration == base.UpdatedAt):
		// Bound to the ledger row the pass publishes: the same times when
		// the record was written for base, and the protection base carries
		// when it was written for a generation that was never published.
		for _, target := range previous.Targets {
			if row, ok := ledger[key(target.Connector, target.SID)]; ok {
				add(target.Connector, target.SID, row)
			}
		}
	}
	for _, row := range rows {
		if row.Pending || row.Removed {
			continue
		}
		installed := row.Result != nil && strings.TrimSpace(row.Result.HookContractLockUpdatedAt) != ""
		if !row.OK && !installed {
			continue
		}
		connectorName := enterpriseHookReleaseProtectionConnector(row)
		sid := strings.ToUpper(strings.TrimSpace(row.SID))
		if connectorName == "" || sid == "" {
			continue
		}
		if !row.OK {
			carried, ok := ledger[key(connectorName, sid)]
			if !ok {
				continue
			}
			row = carried
		}
		add(connectorName, sid, row)
	}
	record := enterpriseHookReleaseProtection{
		SchemaVersion: 1, Release: release, Generation: generation, BaseGeneration: base.UpdatedAt,
		Targets: []enterpriseHookReleaseProtectedTarget{},
	}
	for _, target := range targets {
		record.Targets = append(record.Targets, target)
	}
	sort.Slice(record.Targets, func(i, j int) bool {
		if record.Targets[i].Connector != record.Targets[j].Connector {
			return record.Targets[i].Connector < record.Targets[j].Connector
		}
		return record.Targets[i].SID < record.Targets[j].SID
	})
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := filepath.Join(authorizationDir, enterpriseHookReleaseProtectionFile)
	if err := writeEnterpriseHookProtectedFile(path, data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return fmt.Errorf("make hook guardian release protection record readable: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return fmt.Errorf("set hook guardian release protection record ownership: %w", err)
	}
	return enterpriseHookAuthorizationFileTrustCheck(path)
}

// loadEnterpriseHookReleaseProtection reads the record through the trusted
// published-record reader of the ledger. An absent record is not an error.
func loadEnterpriseHookReleaseProtection(authorizationDir string) (enterpriseHookReleaseProtection, bool, error) {
	path := filepath.Join(authorizationDir, enterpriseHookReleaseProtectionFile)
	data, exists, err := readEnterpriseHookPublishedRecord(
		path,
		"hook guardian release protection record",
		enterpriseHookReleaseProtectionMaxBytes,
		enterpriseHookAuthorizationFileTrustCheck,
	)
	if err != nil || !exists {
		return enterpriseHookReleaseProtection{}, exists, err
	}
	var record enterpriseHookReleaseProtection
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return enterpriseHookReleaseProtection{}, true, fmt.Errorf("parse hook guardian release protection record %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return enterpriseHookReleaseProtection{}, true, fmt.Errorf("parse hook guardian release protection record %s: trailing content", path)
	}
	if record.SchemaVersion != 1 {
		return enterpriseHookReleaseProtection{}, true, fmt.Errorf("hook guardian release protection record %s has unsupported schema_version %d", path, record.SchemaVersion)
	}
	for _, target := range record.Targets {
		if target.Connector == "" || target.Connector != strings.ToLower(strings.TrimSpace(target.Connector)) ||
			target.SID == "" || target.SID != strings.ToUpper(strings.TrimSpace(target.SID)) {
			return enterpriseHookReleaseProtection{}, true, fmt.Errorf("hook guardian release protection record %s has an incomplete target", path)
		}
	}
	return record, true, nil
}

// enterpriseHookThisRelease is this binary's release as the record names it.
func enterpriseHookThisRelease() string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(version.Current().BinaryVersion)), "v")
}

func enterpriseHookReleaseProtectionConnector(row enterpriseHookReconcileRow) string {
	connectorName := strings.ToLower(strings.TrimSpace(row.Connector))
	if connectorName == "" && row.Result != nil {
		connectorName = strings.ToLower(strings.TrimSpace(row.Result.Connector))
	}
	return connectorName
}

func enterpriseHookReleaseProtectionTimes(row enterpriseHookReconcileRow) (lock, entry string) {
	if row.Result == nil {
		return "", ""
	}
	return strings.TrimSpace(row.Result.HookContractLockUpdatedAt), strings.TrimSpace(row.Result.HookContractEntryUpdatedAt)
}
