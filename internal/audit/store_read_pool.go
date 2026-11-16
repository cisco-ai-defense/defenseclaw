// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const auditReadPoolSize = 4

// openReadPool opens and checks each read-only WAL connection before the store
// becomes ready. The DSN applies the same mode and pragmas to replacements.
func (s *Store) openReadPool() (_ *sql.DB, err error) {
	db, err := openAuditReadOnlyWithTimeout(s.dbPath,
		"&_pragma=mmap_size(0)&_pragma=cache_size(-20000)", auditBusyTimeoutMillis)
	if err != nil {
		return nil, fmt.Errorf("audit: open read pool: %w", err)
	}
	db.SetMaxOpenConns(auditReadPoolSize)
	db.SetMaxIdleConns(auditReadPoolSize)
	db.SetConnMaxLifetime(0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conns := make([]*sql.Conn, 0, auditReadPoolSize)
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
		if err != nil {
			_ = db.Close()
		}
	}()
	for range auditReadPoolSize {
		conn, openErr := db.Conn(ctx)
		if openErr != nil {
			return nil, fmt.Errorf("audit: open read-only WAL connection: %w", openErr)
		}
		conns = append(conns, conn)
		var queryOnly, timeout, mmapSize int64
		var journalMode string
		for _, check := range []struct {
			pragma string
			dest   any
		}{
			{"query_only", &queryOnly},
			{"busy_timeout", &timeout},
			{"mmap_size", &mmapSize},
			{"journal_mode", &journalMode},
		} {
			if checkErr := conn.QueryRowContext(ctx, "PRAGMA "+check.pragma).Scan(check.dest); checkErr != nil {
				return nil, fmt.Errorf("audit: verify read pool %s: %w", check.pragma, checkErr)
			}
		}
		if queryOnly != 1 || timeout != auditBusyTimeoutMillis || mmapSize != 0 || !strings.EqualFold(journalMode, "wal") {
			return nil, fmt.Errorf("audit: read pool pragmas are not ready (query_only=%d busy_timeout=%d mmap_size=%d journal_mode=%s)", queryOnly, timeout, mmapSize, journalMode)
		}
	}
	if err := revalidateHardenedAuditSQLite(s.dbPathGuard); err != nil {
		return nil, fmt.Errorf("audit: revalidate database paths for read pool: %w", err)
	}
	return db, nil
}

func (s *Store) queryPool() *sql.DB {
	if s.readDB != nil {
		return s.readDB
	}
	return s.db
}
