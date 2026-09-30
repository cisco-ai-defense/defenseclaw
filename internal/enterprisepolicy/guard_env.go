// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Environment-redirected user config.
//
// An agent may read its user-level config from a directory its environment
// names (CLAUDE_CONFIG_DIR, CODEX_HOME, COPILOT_HOME, XDG_CONFIG_HOME,
// OPENCODE_CONFIG, OPENCODE_CONFIG_DIR, APPDATA, HERMES_HOME) or from a HOME
// that is not the account's home. The hook runs inside the agent's
// environment and scans those locations; the guardian's cleanup does not
// have that environment. So the hook records the redirects it sees in the user's
// data directory, and the cleanup, running as the user, cleans the
// recorded locations too. A redirect no DefenseClaw hook has run with is
// not cleaned (the hook still denies while a foreign hook is there). Like
// the block records the file is the user's and advisory; the cleanup only
// ever acts with the user's own permissions.

const (
	envRecordFile  = "foreign-hook-env.json"
	envRecordLimit = 64 << 10
	// envRedirectLimit bounds the redirects kept per connector (the most
	// recently seen win).
	envRedirectLimit = 8
	// envValueLimit bounds one recorded path.
	envValueLimit = 1024
	// envRefreshAfter is how old a redirect's last-seen time gets before a
	// hook that sees it again rewrites the record.
	envRefreshAfter = 24 * time.Hour
)

// EnvRedirect is one set of redirects an agent ran with: the environment
// values that moved a user config location, and homes other than the
// account's.
type EnvRedirect struct {
	Homes []string          `json:"homes,omitempty"`
	Vars  map[string]string `json:"vars,omitempty"`
	Seen  string            `json:"seen,omitempty"`
}

type envRecord struct {
	Version    int                      `json:"v"`
	Connectors map[string][]EnvRedirect `json:"connectors"`
}

// EnvRecordPath is the redirect record under accountHome.
func EnvRecordPath(accountHome string) string {
	return filepath.Join(accountHome, ".defenseclaw", envRecordFile)
}

// inlineEnvKeys are environment values that are content, not locations.
var inlineEnvKeys = map[string]bool{"OPENCODE_CONFIG_CONTENT": true}

// ObservedEnvRedirect returns the redirect req's environment and homes
// apply to req.Connector's user config: every absolute location value the
// connector's sources read, and every home besides the account's, when at
// least one user source lies somewhere the defaults do not reach. A
// relative value is resolved against the agent's working directory, which
// the cleanup does not know, so it is not recorded (the hook still scans
// it).
func ObservedEnvRedirect(req GuardRequest) (EnvRedirect, bool) {
	accountHome := strings.TrimSpace(req.AccountHome)
	if accountHome == "" || !filepath.IsAbs(accountHome) {
		return EnvRedirect{}, false
	}
	read := map[string]string{}
	observed := req
	observed.WorkingDir, observed.WorkingDirs = "", nil
	observed.Getenv = func(key string) string {
		value := req.getenv(key)
		if value != "" {
			read[key] = value
		}
		return value
	}
	defaults := req
	defaults.Home, defaults.Homes = accountHome, nil
	defaults.WorkingDir, defaults.WorkingDirs = "", nil
	defaults.Getenv = nil
	known := userSourcePaths(defaults)
	moved := false
	for _, path := range userSourcePaths(observed) {
		if filepath.IsAbs(path) && !containsPath(known, path) {
			moved = true
			break
		}
	}
	if !moved {
		return EnvRedirect{}, false
	}
	redirect := EnvRedirect{}
	for key, value := range read {
		if inlineEnvKeys[key] || !filepath.IsAbs(value) || len(value) > envValueLimit {
			continue
		}
		if redirect.Vars == nil {
			redirect.Vars = map[string]string{}
		}
		redirect.Vars[key] = filepath.Clean(value)
	}
	for _, home := range req.homes() {
		if !samePath(home, filepath.Clean(accountHome)) && len(home) <= envValueLimit {
			redirect.Homes = appendDistinctPath(redirect.Homes, home)
		}
	}
	if len(redirect.Vars) == 0 && len(redirect.Homes) == 0 {
		return EnvRedirect{}, false
	}
	return redirect, true
}

func userSourcePaths(req GuardRequest) []string {
	var out []string
	for _, source := range guardSources(req) {
		if source.scope == ScopeUser {
			out = appendDistinctPath(out, filepath.Clean(source.path))
		}
	}
	return out
}

func (r EnvRedirect) same(other EnvRedirect) bool {
	if len(r.Vars) != len(other.Vars) || len(r.Homes) != len(other.Homes) {
		return false
	}
	for key, value := range r.Vars {
		if otherValue, ok := other.Vars[key]; !ok || !samePath(value, otherValue) {
			return false
		}
	}
	for _, home := range r.Homes {
		if !containsPath(other.Homes, home) {
			return false
		}
	}
	return true
}

// RecordEnvRedirect adds redirect to the user's record for connector (best
// effort). The file is rewritten only for a redirect it does not hold yet,
// or one last seen more than a day ago.
func RecordEnvRedirect(accountHome, connector string, redirect EnvRedirect, now time.Time) error {
	if strings.TrimSpace(accountHome) == "" || !filepath.IsAbs(accountHome) || strings.TrimSpace(connector) == "" {
		return nil
	}
	path := EnvRecordPath(accountHome)
	record, err := readEnvRecord(path)
	if err != nil {
		// An unreadable record is replaced; it only ever widens the cleanup.
		record = envRecord{}
	}
	if record.Connectors == nil {
		record.Connectors = map[string][]EnvRedirect{}
	}
	stamp := now.UTC().Format(time.RFC3339)
	list := record.Connectors[connector]
	for i, existing := range list {
		if !existing.same(redirect) {
			continue
		}
		if seen, err := time.Parse(time.RFC3339, existing.Seen); err == nil && now.Sub(seen) < envRefreshAfter {
			return nil
		}
		list = append(list[:i], list[i+1:]...)
		break
	}
	redirect.Seen = stamp
	list = append([]EnvRedirect{redirect}, list...)
	if len(list) > envRedirectLimit {
		list = list[:envRedirectLimit]
	}
	record.Connectors[connector] = list
	record.Version = 1
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(data) > envRecordLimit {
		return fmt.Errorf("%s would exceed %d bytes", path, envRecordLimit)
	}
	return writePrivateUserFile(path, data)
}

// LoadEnvRedirects returns the redirects recorded for connector. Every
// value is checked again: only absolute, clean locations are returned.
func LoadEnvRedirects(accountHome, connector string) ([]EnvRedirect, error) {
	if strings.TrimSpace(accountHome) == "" || !filepath.IsAbs(accountHome) {
		return nil, errors.New("environment redirects need an absolute home directory")
	}
	record, err := readEnvRecord(EnvRecordPath(accountHome))
	if err != nil {
		return nil, err
	}
	var out []EnvRedirect
	for _, redirect := range record.Connectors[connector] {
		clean := EnvRedirect{Seen: redirect.Seen}
		keys := make([]string, 0, len(redirect.Vars))
		for key := range redirect.Vars {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := redirect.Vars[key]
			if !validEnvKey(key) || inlineEnvKeys[key] || !validRecordedPath(value) {
				continue
			}
			if clean.Vars == nil {
				clean.Vars = map[string]string{}
			}
			clean.Vars[key] = filepath.Clean(value)
		}
		for _, home := range redirect.Homes {
			if validRecordedPath(home) {
				clean.Homes = appendDistinctPath(clean.Homes, filepath.Clean(home))
			}
		}
		if len(clean.Vars) > 0 || len(clean.Homes) > 0 {
			out = append(out, clean)
		}
		if len(out) == envRedirectLimit {
			break
		}
	}
	return out, nil
}

func validEnvKey(key string) bool {
	if key == "" || len(key) > 64 {
		return false
	}
	for _, r := range key {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

func validRecordedPath(value string) bool {
	if value == "" || len(value) > envValueLimit || !filepath.IsAbs(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// request returns base with the redirect's environment and homes: the
// cleanup's view of the agent that ran with them.
func (r EnvRedirect) request(base GuardRequest) GuardRequest {
	vars := r.Vars
	base.Getenv = func(key string) string { return vars[key] }
	base.Homes = append([]string(nil), r.Homes...)
	return base
}

func readEnvRecord(path string) (envRecord, error) {
	data, exists, err := readGuardFileLimit(path, envRecordLimit)
	if err != nil {
		return envRecord{}, err
	}
	if !exists {
		return envRecord{}, nil
	}
	var record envRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return envRecord{}, fmt.Errorf("%s: %w", path, err)
	}
	return record, nil
}
