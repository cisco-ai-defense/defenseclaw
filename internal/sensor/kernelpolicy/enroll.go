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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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
}

// Enrollment is the parsed manifest.
type Enrollment struct {
	Rows []Enrolled
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
	for _, target := range manifest.Targets {
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		row := Enrolled{
			User:      strings.TrimSpace(target.User),
			Home:      strings.TrimSpace(target.UserHome),
			Connector: strings.ToLower(strings.TrimSpace(target.Connector)),
			UID:       -1,
		}
		if target.UID != nil {
			row.UID = *target.UID
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
		if !seen[row] {
			seen[row] = true
			out.Rows = append(out.Rows, row)
		}
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		a, b := out.Rows[i], out.Rows[j]
		if a.UID != b.UID {
			return a.UID < b.UID
		}
		if a.Connector != b.Connector {
			return a.Connector < b.Connector
		}
		return a.Home < b.Home
	})
	return out, nil
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
