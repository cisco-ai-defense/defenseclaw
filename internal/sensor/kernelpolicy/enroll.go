// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const manifestLimit = 4 << 20

// Enrolled is one enabled row of the guardian manifest (targets.yaml): a
// user, their uid and home, and the connector the administrator enrolled
// them for. A row without a connector still names a home for the observe
// policy and never an anchor.
type Enrolled struct {
	User      string
	UID       int
	Home      string
	Connector string
	// MachinePolicy is set on a row WithMachinePolicy added: an eligible
	// account enrolled for a connector on vendor machine policy, which has no
	// row in targets.yaml.
	MachinePolicy bool
}

// Enrollment is the parsed manifest, with the machine-policy rows of the
// eligible accounts once WithMachinePolicy added them.
type Enrollment struct {
	Rows []Enrolled
	// named holds the (user, connector) and (uid, connector) pairs a
	// manifest row names, enabled or not: where the manifest speaks for a
	// connector, it decides, and no machine-policy row is added.
	named map[string]bool
}

// UserLookup resolves a user name to its uid and home when the manifest row
// does not carry them.
type UserLookup func(name string) (uid int, home string, err error)

type manifestFile struct {
	Targets []struct {
		User      string `yaml:"user"`
		UserHome  string `yaml:"user_home"`
		UID       *int   `yaml:"uid"`
		Connector string `yaml:"connector"`
		Enabled   *bool  `yaml:"enabled"`
	} `yaml:"targets"`
}

// LoadEnrollment reads the guardian manifest. A missing manifest is an empty
// enrollment (no homes, no uids, no controls policy), never an error: a host
// that has not enrolled anyone has nothing to protect yet. An untrusted or
// unparseable manifest is an error, and the caller keeps its previous
// enrollment rather than guess.
//
// trust is the root-owned-file check (managed.ValidateTrustedFilePath in the
// helper); nil skips it, for tests.
func LoadEnrollment(path string, trust func(string) error, lookup UserLookup) (Enrollment, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return Enrollment{}, nil
	}
	if trust != nil {
		if err := trust(path); err != nil {
			return Enrollment{}, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return Enrollment{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, manifestLimit+1))
	if err != nil {
		return Enrollment{}, err
	}
	if len(data) > manifestLimit {
		return Enrollment{}, fmt.Errorf("guardian manifest exceeds %d bytes", manifestLimit)
	}
	return ParseEnrollment(data, lookup)
}

// ParseEnrollment parses manifest bytes.
func ParseEnrollment(data []byte, lookup UserLookup) (Enrollment, error) {
	var out Enrollment
	if len(bytes.TrimSpace(data)) == 0 {
		return out, nil
	}
	var manifest manifestFile
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return Enrollment{}, fmt.Errorf("parse guardian manifest: %w", err)
	}
	seen := map[Enrolled]bool{}
	out.named = map[string]bool{}
	for _, target := range manifest.Targets {
		row := Enrolled{
			User:      strings.TrimSpace(target.User),
			Home:      strings.TrimSpace(target.UserHome),
			Connector: strings.ToLower(strings.TrimSpace(target.Connector)),
			UID:       -1,
		}
		if target.UID != nil {
			row.UID = *target.UID
		}
		if row.Connector != "" {
			if row.User != "" {
				out.named[userKey(row.User, row.Connector)] = true
			}
			if row.UID > 0 {
				out.named[uidKey(row.UID, row.Connector)] = true
			}
		}
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		if (row.UID < 0 || row.Home == "") && row.User != "" && lookup != nil {
			if uid, home, err := lookup(row.User); err == nil {
				if row.UID < 0 {
					row.UID = uid
				}
				if row.Home == "" {
					row.Home = home
				}
			}
		}
		// A row that names no real user or no usable home protects nothing
		// and must never put a path or a uid into a policy. uid 0 is never
		// enrolled: root's lineage is not an enrolled agent user.
		if row.UID <= 0 || row.Home == "" || !filepath.IsAbs(row.Home) || filepath.Clean(row.Home) == "/" {
			continue
		}
		row.Home = filepath.Clean(row.Home)
		if row.Connector != "" {
			out.named[uidKey(row.UID, row.Connector)] = true
		}
		if !seen[row] {
			seen[row] = true
			out.Rows = append(out.Rows, row)
		}
	}
	out.sortRows()
	return out, nil
}

func (e *Enrollment) sortRows() {
	sort.Slice(e.Rows, func(i, j int) bool {
		a, b := e.Rows[i], e.Rows[j]
		if a.UID != b.UID {
			return a.UID < b.UID
		}
		if a.Connector != b.Connector {
			return a.Connector < b.Connector
		}
		return a.Home < b.Home
	})
}

func userKey(user, connector string) string { return "user:" + strings.ToLower(user) + "|" + connector }

func uidKey(uid int, connector string) string { return "uid:" + strconv.Itoa(uid) + "|" + connector }

// EligibleAccountsFileName is the enumerator's root-only record of the
// accounts that passed every enrollment filter and whose home is available
// (enterprisehooks.UnixEligibleAccountsFileName), next to the manifest.
const EligibleAccountsFileName = "eligible-accounts.json"

// EligibleAccountsPath is the eligible-accounts record next to manifest.
func EligibleAccountsPath(manifest string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(manifest)), EligibleAccountsFileName)
}

// EligibleAccount is one account of the eligible-accounts record.
type EligibleAccount struct {
	User string `json:"user"`
	UID  int    `json:"uid"`
	Home string `json:"home"`
}

// LoadEligibleAccounts reads the enumerator's eligible-accounts record with
// the manifest's trust check. A missing record is no account; an untrusted
// or unparseable one is an error, and the caller keeps its previous
// enrollment rather than guess.
func LoadEligibleAccounts(path string, trust func(string) error) ([]EligibleAccount, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("eligible accounts record path must be absolute: %q", path)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if trust != nil {
		if err := trust(path); err != nil {
			return nil, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, manifestLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > manifestLimit {
		return nil, fmt.Errorf("eligible accounts record exceeds %d bytes", manifestLimit)
	}
	return ParseEligibleAccounts(data)
}

// ParseEligibleAccounts parses the record (version 1). An account without a
// name, with uid 0 or below, or without a usable home is dropped.
func ParseEligibleAccounts(data []byte) ([]EligibleAccount, error) {
	var record struct {
		Version  int               `json:"version"`
		Accounts []EligibleAccount `json:"accounts"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("parse eligible accounts record: %w", err)
	}
	if record.Version != 1 {
		return nil, fmt.Errorf("eligible accounts record version %d is not supported", record.Version)
	}
	var out []EligibleAccount
	for _, account := range record.Accounts {
		account.User, account.Home = strings.TrimSpace(account.User), strings.TrimSpace(account.Home)
		if account.User == "" || account.UID <= 0 || !filepath.IsAbs(account.Home) || filepath.Clean(account.Home) == "/" {
			continue
		}
		account.Home = filepath.Clean(account.Home)
		out = append(out, account)
	}
	return out, nil
}

// WithMachinePolicy returns the enrollment with a row for every eligible
// account and machine-policy connector that the manifest names no row for,
// enabled or not. The enumerator gives a connector on vendor machine policy
// per-user rows only with enrollment.unenrolled_users: deny, yet its hooks
// run for every eligible account; without these rows its agents are never
// anchored. A row anchors only an installed command-line agent, so an account
// without the agent gets nothing but the observe policy's view of its home.
// Desktop and IDE surfaces stay observe-only (IsCLIConnector), and an account
// whose manifest rows name another home is left to the manifest: a second home
// for one uid would anchor binaries the manifest never named.
func (e Enrollment) WithMachinePolicy(accounts []EligibleAccount, connectors []string) Enrollment {
	if len(accounts) == 0 || len(connectors) == 0 {
		return e
	}
	out := Enrollment{Rows: append([]Enrolled(nil), e.Rows...), named: e.named}
	seen := map[[2]any]bool{}
	for _, row := range out.Rows {
		seen[[2]any{row.UID, row.Connector}] = true
	}
	for _, account := range accounts {
		if home := e.HomeOf(account.UID); home != "" && home != account.Home {
			continue
		}
		for _, connector := range connectors {
			if !IsCLIConnector(connector) {
				continue
			}
			key := [2]any{account.UID, connector}
			if seen[key] || e.named[userKey(account.User, connector)] || e.named[uidKey(account.UID, connector)] {
				continue
			}
			seen[key] = true
			out.Rows = append(out.Rows, Enrolled{User: account.User, UID: account.UID, Home: account.Home,
				Connector: connector, MachinePolicy: true})
		}
	}
	out.sortRows()
	return out
}

// UIDs returns the distinct enrolled uids, ascending.
func (e Enrollment) UIDs() []int {
	seen := map[int]bool{}
	var out []int
	for _, row := range e.Rows {
		if !seen[row.UID] {
			seen[row.UID] = true
			out = append(out, row.UID)
		}
	}
	sort.Ints(out)
	return out
}

// HomeOf returns the manifest home of uid.
func (e Enrollment) HomeOf(uid int) string {
	for _, row := range e.Rows {
		if row.UID == uid {
			return row.Home
		}
	}
	return ""
}

// UserOf returns the user name recorded for uid.
func (e Enrollment) UserOf(uid int) string {
	for _, row := range e.Rows {
		if row.UID == uid && row.User != "" {
			return row.User
		}
	}
	return ""
}

// Connectors returns the distinct connectors enrolled for uid, sorted.
func (e Enrollment) Connectors(uid int) []string {
	seen := map[string]bool{}
	var out []string
	for _, row := range e.Rows {
		if row.UID == uid && row.Connector != "" && !seen[row.Connector] {
			seen[row.Connector] = true
			out = append(out, row.Connector)
		}
	}
	sort.Strings(out)
	return out
}

// MachinePolicyConnectors returns the connectors uid is enrolled for through
// vendor machine policy only (no manifest row), sorted.
func (e Enrollment) MachinePolicyConnectors(uid int) []string {
	manifest := map[string]bool{}
	for _, row := range e.Rows {
		if row.UID == uid && !row.MachinePolicy {
			manifest[row.Connector] = true
		}
	}
	var out []string
	for _, connector := range e.Connectors(uid) {
		if !manifest[connector] {
			out = append(out, connector)
		}
	}
	return out
}

// ConnectorsDigest identifies the connector set of uid. A user that gains or
// loses a connector starts a new burn-in.
func (e Enrollment) ConnectorsDigest(uid int) string {
	sum := sha256.Sum256([]byte(strings.Join(e.Connectors(uid), ",")))
	return hex.EncodeToString(sum[:8])
}

// Has reports whether uid is enrolled.
func (e Enrollment) Has(uid int) bool {
	for _, row := range e.Rows {
		if row.UID == uid {
			return true
		}
	}
	return false
}

// cliConnectors are the connectors whose agent runs as a CLI process the
// kernel controls can anchor. Desktop and IDE surfaces (the Cursor IDE, Kiro
// IDE, Antigravity, VS Code hosts) are deliberately absent: they are
// observe-only. The names of the executables and the version directories
// mirror the enumerator's probes (enterprisehooks unixAgentProbes); a test
// keeps the two from drifting.
var cliConnectors = map[string]cliProbe{
	"claudecode": {binaries: []string{"claude"}, versionDirs: []string{".local/share/claude/versions"}},
	"codex":      {binaries: []string{"codex"}},
	"cursor":     {binaries: []string{"cursor-agent"}, versionDirs: []string{".local/share/cursor-agent/versions"}},
	"copilot":    {binaries: []string{"copilot"}},
	"opencode":   {binaries: []string{"opencode"}},
	"amp":        {binaries: []string{"amp"}},
	"devin":      {binaries: []string{"devin"}},
	"hermes":     {binaries: []string{"hermes"}},
	"openhands":  {binaries: []string{"openhands"}},
	"omnigent":   {binaries: []string{"omnigent"}},
	"kiro":       {binaries: []string{"kiro-cli"}},
}

type cliProbe struct {
	binaries    []string
	versionDirs []string
}

// IsCLIConnector reports whether connector is anchorable.
func IsCLIConnector(connector string) bool {
	_, ok := cliConnectors[connector]
	return ok
}
