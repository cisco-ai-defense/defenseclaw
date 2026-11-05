// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package coworkaudit answers one question for administrator status and
// verify: when did each account last send a Claude Cowork hook event? It
// reads the gateway's audit store read-only, bounded in time and rows. It is
// its own package so the SQLite driver stays out of the small binaries that
// import internal/enterprisestatus.
package coworkaudit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"

	_ "modernc.org/sqlite"
)

// QueryTimeout bounds the lookup; a store that does not answer within it
// leaves the accounts unknown.
var QueryTimeout = 5 * time.Second

// maxAccounts bounds the accounts read; tests lower it.
var maxAccounts = 256

// ErrUnavailable: the store cannot be read without changing it.
var ErrUnavailable = errors.New("the audit store is not available read-only")

// lastEventsQuery groups the claudecode hook rows that carry
// "surface":"cowork" (the hook audit envelope of a Cowork call: the
// envelope's surface member, or its extra.surface) by the OS-derived caller
// identity. instr() keeps the JSON parse to Cowork rows.
const lastEventsQuery = `SELECT
	COALESCE(json_extract(structured_json, '$."user.id"'), ''),
	COALESCE(json_extract(structured_json, '$."defenseclaw.user.name"'), ''),
	MAX(timestamp)
FROM audit_events
WHERE connector = 'claudecode'
	AND instr(structured_json, '"surface":"cowork"') > 0
	AND (json_extract(structured_json, '$.surface') = 'cowork'
		OR json_extract(structured_json, '$.extra.surface') = 'cowork')
GROUP BY 1, 2
ORDER BY 3 DESC
LIMIT ?`

// LastEvents returns each account's last Cowork hook event in the audit
// store at path. The store is opened read-only with query_only. A store in
// WAL mode whose shared-memory file is missing (no gateway has it open) is
// not opened: a read-only open as root would create that file with root's
// ownership, which the gateway's own account could not open.
// truncated says more accounts exist than the maxAccounts returned.
func LastEvents(ctx context.Context, path string) (events []enterprisestatus.CoworkAccountEvent, truncated bool, err error) {
	if !filepath.IsAbs(path) {
		return nil, false, fmt.Errorf("%w: %s is not an absolute path", ErrUnavailable, path)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%w: %s is not a regular file", ErrUnavailable, path)
	}
	if _, err := os.Lstat(path + "-wal"); err == nil {
		if _, err := os.Lstat(path + "-shm"); err != nil {
			return nil, false, fmt.Errorf("%w: %s-shm is missing", ErrUnavailable, path)
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path),
		RawQuery: "mode=ro&_pragma=busy_timeout(2000)&_pragma=query_only(1)"}).String()
	if !strings.HasPrefix(dsn, "file:///") {
		dsn = strings.Replace(dsn, "file://", "file:///", 1) // a Windows drive path
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, false, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.QueryContext(ctx, lastEventsQuery, maxAccounts+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []enterprisestatus.CoworkAccountEvent
	for rows.Next() {
		var id, name string
		var stamp any
		if err := rows.Scan(&id, &name, &stamp); err != nil {
			return nil, false, err
		}
		at, ok := parseStamp(stamp)
		if !ok {
			continue
		}
		if len(out) == maxAccounts {
			truncated = true
			break
		}
		out = append(out, enterprisestatus.CoworkAccountEvent{UserID: id, UserName: name, At: at})
	}
	return out, truncated, rows.Err()
}

// parseStamp reads a timestamp column as the SQLite driver returns it.
func parseStamp(value any) (time.Time, bool) {
	switch v := value.(type) {
	case time.Time:
		return v.UTC(), !v.IsZero()
	case []byte:
		return parseStamp(string(v))
	case string:
		for _, layout := range []string{
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05.999999999Z07:00",
			time.RFC3339Nano,
			"2006-01-02 15:04:05.999999999",
			"2006-01-02 15:04:05",
		} {
			if at, err := time.Parse(layout, strings.TrimSpace(v)); err == nil {
				return at.UTC(), true
			}
		}
	}
	return time.Time{}, false
}
