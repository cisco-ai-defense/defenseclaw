// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // state.vscdb reader
)

// readStateDBValue reads one ItemTable value from a VS Code state database.
// The database is opened read-only and immutable, so the read takes no
// lock and never writes a journal next to a running editor's file, and the
// whole read is bounded by timeout.
func readStateDBValue(path, key string, timeout time.Duration) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	db, err := sql.Open("sqlite", stateDBURI(path))
	if err != nil {
		return nil, false
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var value sql.RawBytes
	var out []byte
	rows, err := db.QueryContext(ctx, `SELECT value FROM ItemTable WHERE key = ? LIMIT 1`, key)
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&value); err != nil {
			return nil, false
		}
		if len(value) > 4<<20 {
			return nil, false
		}
		out = append([]byte{}, value...)
	}
	if rows.Err() != nil {
		return nil, false
	}
	return out, true
}

// stateDBURI builds a file: URI for path with mode=ro&immutable=1.
func stateDBURI(path string) string {
	slashed := filepath.ToSlash(path)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed // C:/Users/... on Windows
	}
	u := url.URL{Scheme: "file", Path: slashed, RawQuery: "mode=ro&immutable=1"}
	return u.String()
}
