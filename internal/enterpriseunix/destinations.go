// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// describeDestinations lists, for status, the observability destinations the
// installed config.yaml compiles to with each one's effective redaction
// profiles. `defenseclaw observability plan` is a per-user command a managed
// install does not offer, so this is where an administrator reads which
// profile a destination such as Galileo exports under (GAP-1105). A config
// that does not compile is reported by config_rejected; the list is left out.
func (l *lifecycle) describeDestinations() {
	env, r := l.env, l.result
	if r.Action != ActionStatus {
		return
	}
	path := env.P(env.Layout.ConfigPath)
	raw, err := readBounded(path, maxInputBytes)
	if err != nil {
		return
	}
	summaries, local, err := config.SummarizeObservabilityV8(path, raw, env.P(env.Layout.DataDir))
	if err != nil {
		return
	}
	r.Destinations = enterprisestatus.DestinationsFromSummaries(summaries)
	r.AuditStore = describeAuditStore(local)
}

// describeAuditStore is the audit store line of status: the retention, the
// size cap and the size of audit.db with its WAL on disk. defenseclaw status,
// doctor and the TUI show the retention and cap per user but are refused on
// a managed computer, and the gateway status printed only the retention, so
// an applied max_store_mb showed nowhere (GAP-0141).
func describeAuditStore(local config.ObservabilityV8EffectiveLocal) *enterprisestatus.AuditStore {
	store := &enterprisestatus.AuditStore{RetentionDays: local.RetentionDays, MaxStoreMB: local.MaxStoreMB}
	if local.Path == "" {
		return store
	}
	db, err := os.Lstat(local.Path)
	if err != nil || !db.Mode().IsRegular() {
		return store
	}
	size := db.Size()
	if wal, walErr := os.Lstat(local.Path + "-wal"); walErr == nil && wal.Mode().IsRegular() {
		size += wal.Size()
	}
	store.SizeBytes = &size
	return store
}
