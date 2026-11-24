// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The enrolled-accounts record, next to the protection ledger in the
// administrator-only guardian folder, lists every account the guardian has
// protected (rel-1-0-10 GAP-1733 review 2). "First adoption", the rule that
// skips an account whose canonical folder holds a per-user DefenseClaw
// install, is decided per account and for good, not from the account's
// current ledger rows. The ledger keeps only the rows of current manifest
// targets, and the managed folder of an adopted account is writable by that
// account: a user whose only rows are per-user connectors (Hermes, Amp,
// OpenCode) could drop them by moving the agent aside, plant the per-user
// entry, restore the agent and be skipped as never protected.
//
// The record only grows: an account is added the first time one of its rows
// is protected, and when the guardian reads a per-user entry in its folder
// as tamper (the fail-closed rule of a removed ledger, so the decision
// outlasts the pass that made it). It is removed only when the guardian
// confirms its account is gone (enterpriseHookEnrolledAccountGone): on
// Windows a removed profile alone is not enough, because an FSLogix-style
// profile disk that is detached looks the same (GAP-2133). Earlier releases neither read nor
// write it, so the ledger and activation schemas stay as they were, and a
// host that upgrades starts it from the ledger rows at its first publish.
const (
	enterpriseHookEnrolledAccountsFile     = managed.HookGuardianEnrolledAccountsFile
	enterpriseHookEnrolledAccountsVersion  = 1
	enterpriseHookEnrolledAccountsMaxBytes = 4 << 20
)

type enterpriseHookEnrolledAccountsRecord struct {
	Version   int      `json:"version"`
	UpdatedAt string   `json:"updated_at"`
	Accounts  []string `json:"accounts"`
}

// enterpriseHookEnrolledAccountKey is the record key of an account: its SID
// in the canonical form ConvertSidToStringSid renders (GAP-1800), so two
// spellings of one SID name one account. A value that is not a SID string
// keeps the upper-case key earlier builds wrote.
func enterpriseHookEnrolledAccountKey(sid string) string {
	sid = strings.TrimSpace(sid)
	if canonical, ok := enterpriseHookCanonicalSIDString(sid); ok {
		return canonical
	}
	return strings.ToUpper(sid)
}

// enterpriseHookCanonicalSIDString parses S-R-I-S1-...-Sn as
// ConvertStringSidToSid reads it (each number decimal or 0x hex, at most 15
// subauthorities) and renders it as ConvertSidToStringSid does: an
// uppercase S, decimal numbers without leading zeros, and an identifier
// authority of 2^32 or more as 0x and 12 hex digits.
func enterpriseHookCanonicalSIDString(sid string) (string, bool) {
	parts := strings.Split(sid, "-")
	if len(parts) < 3 || len(parts) > 3+15 || (parts[0] != "S" && parts[0] != "s") {
		return "", false
	}
	number := func(part string, bits int) (uint64, bool) {
		base := 10
		if len(part) > 2 && (part[:2] == "0x" || part[:2] == "0X") {
			part, base = part[2:], 16
		}
		if part == "" || len(part) > 20 {
			return 0, false
		}
		value, err := strconv.ParseUint(part, base, bits)
		return value, err == nil
	}
	revision, ok := number(parts[1], 8)
	if !ok || revision != 1 {
		return "", false
	}
	authority, ok := number(parts[2], 48)
	if !ok {
		return "", false
	}
	out := make([]string, 0, len(parts))
	out = append(out, "S", "1")
	if authority >= 1<<32 {
		out = append(out, fmt.Sprintf("0x%012X", authority))
	} else {
		out = append(out, strconv.FormatUint(authority, 10))
	}
	for _, part := range parts[3:] {
		value, ok := number(part, 32)
		if !ok {
			return "", false
		}
		out = append(out, strconv.FormatUint(value, 10))
	}
	return strings.Join(out, "-"), true
}

// loadEnterpriseHookEnrolledAccounts reads the record in authorizationDir. A
// missing record is an empty set.
func loadEnterpriseHookEnrolledAccounts(authorizationDir string) (map[string]bool, error) {
	path := filepath.Join(authorizationDir, enterpriseHookEnrolledAccountsFile)
	data, exists, err := readEnterpriseHookPublishedRecord(path, "enrolled accounts record",
		enterpriseHookEnrolledAccountsMaxBytes, enterpriseHookAuthorizationFileTrustCheck)
	if err != nil || !exists {
		return map[string]bool{}, err
	}
	var record enterpriseHookEnrolledAccountsRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return map[string]bool{}, fmt.Errorf("parse enrolled accounts record %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return map[string]bool{}, fmt.Errorf("parse enrolled accounts record %s: trailing content", path)
	}
	if record.Version != enterpriseHookEnrolledAccountsVersion {
		return map[string]bool{}, fmt.Errorf("enrolled accounts record %s has unsupported version %d", path, record.Version)
	}
	accounts := make(map[string]bool, len(record.Accounts))
	for _, sid := range record.Accounts {
		key := enterpriseHookEnrolledAccountKey(sid)
		if key == "" {
			return map[string]bool{}, fmt.Errorf("enrolled accounts record %s contains an empty account", path)
		}
		accounts[key] = true
	}
	return accounts, nil
}

// enterpriseHookEnrolledAccountsRecordProblem names an enrolled-accounts
// record in authorizationDir that cannot be read, or is "". Such a record is
// fail-closed (every account counts as enrolled) and is never replaced, so
// verify and Setup readiness name it as a warning instead of staying silent
// (GAP-1800). A record the guardian is replacing at that moment is not named.
func enterpriseHookEnrolledAccountsRecordProblem(authorizationDir string) string {
	if strings.TrimSpace(authorizationDir) == "" {
		return ""
	}
	_, err := loadEnterpriseHookEnrolledAccounts(authorizationDir)
	if err == nil || enterpriseHookGuardianRecordBusy(err) {
		return ""
	}
	path := filepath.Join(authorizationDir, enterpriseHookEnrolledAccountsFile)
	return fmt.Sprintf("the hook guardian's enrolled-accounts record cannot be read (%v): every account counts as enrolled, "+
		"so a per-user DefenseClaw install in an account's managed folder is reported as tamper, and the guardian "+
		"does not replace the record; an administrator can remove %s, which the guardian then writes again "+
		"from its protection ledger", err, path)
}

// enterpriseHookPerUserInstallTamperRow reports a row the guardian failed as
// tamper of a per-user install entry in an enrolled account's folder.
func enterpriseHookPerUserInstallTamperRow(row enterpriseHookReconcileRow) bool {
	return strings.HasPrefix(strings.TrimSpace(row.Error), enterpriseHookAccountPerUserInstallTamper)
}

// recordEnterpriseHookEnrolledAccounts adds to the record in
// authorizationDir the accounts of the ledger the pass read (previous), of
// the ledger it writes (protected) and of its tamper rows, and removes the
// accounts of its rows whose account or profile is confirmed gone. It writes
// only a change, and writes nothing for a pass with no account (the
// standalone Unix rows carry a UID, not an account SID). A record that cannot
// be read is never replaced: every reader then counts every account as
// enrolled, until an administrator removes it.
func recordEnterpriseHookEnrolledAccounts(authorizationDir, now string, previous, protected, rows []enterpriseHookReconcileRow) error {
	recorded, err := loadEnterpriseHookEnrolledAccounts(authorizationDir)
	if err != nil {
		return nil
	}
	next := make(map[string]bool, len(recorded))
	for sid := range recorded {
		next[sid] = true
	}
	add := func(sid string) {
		if key := enterpriseHookEnrolledAccountKey(sid); key != "" {
			next[key] = true
		}
	}
	for _, row := range previous {
		add(row.SID)
	}
	for _, row := range protected {
		add(row.SID)
	}
	for _, row := range rows {
		if enterpriseHookPerUserInstallTamperRow(row) {
			add(row.SID)
		}
	}
	for _, row := range rows {
		if row.Removed && enterpriseHookEnrolledAccountGone(row) {
			delete(next, enterpriseHookEnrolledAccountKey(row.SID))
		}
	}
	changed := len(next) != len(recorded)
	for sid := range next {
		if !recorded[sid] {
			changed = true
		}
	}
	if !changed {
		return nil
	}
	accounts := make([]string, 0, len(next))
	for sid := range next {
		accounts = append(accounts, sid)
	}
	sort.Strings(accounts)
	data, err := json.MarshalIndent(enterpriseHookEnrolledAccountsRecord{
		Version:   enterpriseHookEnrolledAccountsVersion,
		UpdatedAt: now,
		Accounts:  accounts,
	}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := filepath.Join(authorizationDir, enterpriseHookEnrolledAccountsFile)
	if err := writeEnterpriseHookProtectedFile(path, data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return fmt.Errorf("protect enrolled accounts record: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return fmt.Errorf("set enrolled accounts record ownership: %w", err)
	}
	return enterpriseHookAuthorizationFileTrustCheck(path)
}
