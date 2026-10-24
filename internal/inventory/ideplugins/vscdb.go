// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // state.vscdb reader
)

// stateDBMaxBytes bounds a state database and its WAL file.
const stateDBMaxBytes = 64 << 20

// readStateDBValue reads one ItemTable value from a VS Code state database.
// The database is opened read-only so SQLite sees uncheckpointed WAL changes
// from a running editor without writing to its database. The read is
// bounded by timeout.
func readStateDBValue(path, key string, timeout time.Duration) ([]byte, bool) {
	const maxValueBytes = 4 << 20
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > stateDBMaxBytes {
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

// confinedStateDB returns the path to read the state database db from, and
// a func that removes what it made. SQLite opens db and its -wal file by
// name, after the checks on the folders above them, so a scan that must
// stay in the home copies both, through handles openedInPlace verified,
// into a private folder and reads the copy: a folder swapped in between
// cannot put another profile's disabled list on this home's plugins
// (GAP-1138). ok is false when the files cannot be verified; the enabled
// state is then unknown.
func (s *scanner) confinedStateDB(db string) (path string, done func(), ok bool) {
	if s.limits.FollowSymlinks || s.layout.home == "" {
		return db, func() {}, true
	}
	dir, err := os.MkdirTemp("", "defenseclaw-vscdb-")
	if err != nil {
		return "", nil, false
	}
	done = func() { _ = os.RemoveAll(dir) }
	path = filepath.Join(dir, "state.vscdb")
	if !s.copyInPlace(db, path, true) || !s.copyInPlace(db+"-wal", path+"-wal", false) {
		done()
		return "", nil, false
	}
	return path, done, true
}

// copyInPlace copies src, opened as openedInPlace requires, to a new file
// dst. A missing src is copied as nothing unless required.
func (s *scanner) copyInPlace(src, dst string, required bool) bool {
	if _, err := s.stat(src); errors.Is(err, os.ErrNotExist) {
		return !required
	}
	f, ok := s.openFile(src)
	if !ok {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > stateDBMaxBytes || !s.openedInPlace(f, src) {
		return false
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false
	}
	n, err := io.Copy(out, io.LimitReader(f, stateDBMaxBytes+1))
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return err == nil && n <= stateDBMaxBytes
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
