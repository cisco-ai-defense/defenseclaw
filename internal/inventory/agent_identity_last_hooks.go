// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// AgentLastHooksByUID is, per uid, the newest last_seen of records (Unix
// nanoseconds): the uid's last hook the agent ledger recorded. Rows whose
// user id is not a uid, or that name no time, are left out.
func AgentLastHooksByUID(records []AgentIdentityRecord) map[int]int64 {
	hooks := make(map[int]int64, len(records))
	for _, record := range records {
		uid, err := strconv.Atoi(strings.TrimSpace(record.UserID))
		if err != nil || uid < 0 || record.LastSeen.IsZero() {
			continue
		}
		if at := record.LastSeen.UnixNano(); at > hooks[uid] {
			hooks[uid] = at
		}
	}
	return hooks
}

// AgentLedgerRowWindow is how long the agent ledger keeps the rows of a uid
// that runs no hook: the default local retention window
// (config.ObservabilityV8DefaultRetentionDays, PruneAgentIdentities). Tests
// replace it.
var AgentLedgerRowWindow = time.Duration(config.ObservabilityV8DefaultRetentionDays) * 24 * time.Hour

// AgentLedgerSightingBound is the latest time, by the agent ledger's hooks
// (AgentLastHooksByUID; nil while the ledger cannot be read), at which a
// build before this one can have last seen uid's holder: its last hook, or,
// when a readable ledger has no row of the uid, the start of the ledger's
// row window, because the holder's rows were pruned for running no hook in
// it (GAP-2069). 0 when the ledger cannot be read.
func AgentLedgerSightingBound(hooks map[int]int64, uid int, now time.Time) int64 {
	if hooks == nil {
		return 0
	}
	if at := hooks[uid]; at > 0 {
		return at
	}
	return now.Add(-AgentLedgerRowWindow).UnixNano()
}

// ReadAgentLastHooks is AgentLastHooksByUID of every row, live and retired,
// of the agent ledger at dbPath, read without writing to it: the root
// guardian reads the gateway's ledger this way, so it never creates,
// migrates or takes over the file.
func ReadAgentLastHooks(ctx context.Context, dbPath string) (map[int]int64, error) {
	clean := filepath.Clean(strings.TrimSpace(dbPath))
	if !filepath.IsAbs(clean) {
		return nil, fmt.Errorf("inventory: ledger path %q is not absolute", dbPath)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("inventory: %s is not a regular file", clean)
	}
	uriPath := filepath.ToSlash(clean)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath // a Windows drive path: file:///C:/...
	}
	dsn := (&url.URL{Scheme: "file", Path: uriPath, RawQuery: "mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("inventory: open %s read-only: %w", clean, err)
	}
	defer db.Close() //nolint:errcheck
	db.SetMaxOpenConns(1)
	var records []AgentIdentityRecord
	for _, table := range []string{"agent_identities", "agent_identities_retired"} {
		var name string
		switch err := db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name); {
		case errors.Is(err, sql.ErrNoRows):
			continue
		case err != nil:
			return nil, fmt.Errorf("inventory: read %s: %w", clean, err)
		}
		rows, err := db.QueryContext(ctx, `SELECT user_id, last_seen FROM `+table)
		if err != nil {
			return nil, fmt.Errorf("inventory: read %s: %w", clean, err)
		}
		for rows.Next() {
			var record AgentIdentityRecord
			var last string
			if err := rows.Scan(&record.UserID, &last); err != nil {
				rows.Close() //nolint:errcheck
				return nil, fmt.Errorf("inventory: read %s: %w", clean, err)
			}
			record.LastSeen, _ = time.Parse(agentIdentityTimeLayout, last)
			records = append(records, record)
		}
		err = rows.Err()
		rows.Close() //nolint:errcheck
		if err != nil {
			return nil, fmt.Errorf("inventory: read %s: %w", clean, err)
		}
	}
	return AgentLastHooksByUID(records), nil
}
