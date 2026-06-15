// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import "strings"

// RegistrySource describes one external skill / MCP catalog source the
// operator has registered with `defenseclaw registry add`. Sync runs
// fetch + scan against the source's manifest, persists per-entry
// verdicts under ~/.defenseclaw/registries/<id>/index.json, and
// auto-promotes clean entries into AssetPolicy.{Skill,MCP}.Registry
// with Reason="registry:<id>" so admission can attribute the rule
// back to its source. The on-disk YAML is owned by the Python CLI's
// _config_to_dict / _merge_registries pair (see
// cli/defenseclaw/config.py); the Go side mirrors the shape so the
// gateway can read operator-edited registries without going through
// the CLI.
//
// Field semantics match cli/defenseclaw/config.py::RegistrySource —
// keep the two in lockstep when extending the schema.
type RegistrySource struct {
	ID      string `mapstructure:"id"       yaml:"id"`
	Kind    string `mapstructure:"kind"     yaml:"kind"`
	URL     string `mapstructure:"url"      yaml:"url,omitempty"`
	Content string `mapstructure:"content"  yaml:"content"`
	AuthEnv string `mapstructure:"auth_env" yaml:"auth_env,omitempty"`
	Enabled bool   `mapstructure:"enabled"  yaml:"enabled"`
	// AutoSync and SyncIntervalHours are RESERVED for a future
	// scheduled-sync implementation. Persisted today so an operator
	// config rewrite is not needed when v2 lands, but no runtime
	// component reads them — `defenseclaw registry sync --all`
	// (cron-driven if needed) is the only ingest path right now.
	AutoSync          bool   `mapstructure:"auto_sync"           yaml:"auto_sync,omitempty"`
	SyncIntervalHours int    `mapstructure:"sync_interval_hours" yaml:"sync_interval_hours,omitempty"`
	LastSync          string `mapstructure:"last_sync"           yaml:"last_sync,omitempty"`
	LastStatus        string `mapstructure:"last_status"         yaml:"last_status,omitempty"`
}

// RegistriesConfig groups every registered registry source. Stored at
// the top level under `registries:` so future fields (cron schedule,
// global timeouts, signature verification mode) land alongside
// sources without breaking back-compat for existing configs.
type RegistriesConfig struct {
	Sources []RegistrySource `mapstructure:"sources" yaml:"sources,omitempty"`
}

// KnownRegistryKinds is the allow-list of recognised source kinds.
// Anything outside this set is rejected at validation time so a typo
// in `kind:` surfaces immediately rather than silently producing an
// empty manifest at sync time. Kept in sync with REGISTRY_KINDS in
// cli/defenseclaw/config.py.
var KnownRegistryKinds = []string{
	"clawhub",
	"smithery",
	"skills_sh",
	"http_yaml",
	"http_json",
	"git",
	"file",
}

// KnownRegistryContentTypes is the allow-list of declared content
// types — clawhub publishes skills, smithery publishes MCPs, and the
// generic adapters can serve either or both.
var KnownRegistryContentTypes = []string{"skill", "mcp", "both"}

// IsKnownRegistryKind reports whether kind is one of the recognised
// source kinds. Comparison is case-insensitive after trimming.
func IsKnownRegistryKind(kind string) bool {
	k := strings.ToLower(strings.TrimSpace(kind))
	for _, known := range KnownRegistryKinds {
		if known == k {
			return true
		}
	}
	return false
}

// IsKnownRegistryContent reports whether content is one of the
// recognised content types.
func IsKnownRegistryContent(content string) bool {
	c := strings.ToLower(strings.TrimSpace(content))
	for _, known := range KnownRegistryContentTypes {
		if known == c {
			return true
		}
	}
	return false
}
