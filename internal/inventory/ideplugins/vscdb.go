// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // state.vscdb reader
)

// readStateDBValue reads one ItemTable value from a VS Code state database.
// The database is opened read-only so SQLite sees uncheckpointed WAL changes
// from a running editor without writing to its database. The read is
// bounded by timeout.
func readStateDBValue(path, key string, timeout time.Duration) ([]byte, bool) {
	const maxDBBytes = 64 << 20
	const maxValueBytes = 4 << 20
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxDBBytes {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	db, err := sql.Open("sqlite", stateDBURI(path))
	if err != nil {
		return nil, false
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var table string
	if err := db.QueryRowContext(ctx, `SELECT type FROM sqlite_schema WHERE name = 'ItemTable' LIMIT 1`).Scan(&table); err != nil || table != "table" {
		return nil, false
	}
	var size sql.NullInt64
	err = db.QueryRowContext(ctx, `SELECT length(value) FROM ItemTable WHERE key = ? LIMIT 1`, key).Scan(&size)
	if err == sql.ErrNoRows {
		return nil, true
	}
	if err != nil || (size.Valid && size.Int64 > maxValueBytes) {
		return nil, false
	}
	var value []byte
	// substr bounds the bytes returned even if the database changes after length().
	err = db.QueryRowContext(ctx, `SELECT substr(value, 1, ?) FROM ItemTable WHERE key = ? LIMIT 1`, maxValueBytes+1, key).Scan(&value)
	if err != nil || len(value) > maxValueBytes {
		return nil, false
	}
	return value, true
}

// stateDBURI builds a read-only file: URI that includes live WAL changes.
func stateDBURI(path string) string {
	slashed := filepath.ToSlash(path)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed // C:/Users/... on Windows
	}
	u := url.URL{Scheme: "file", Path: slashed, RawQuery: "mode=ro"}
	return u.String()
}
