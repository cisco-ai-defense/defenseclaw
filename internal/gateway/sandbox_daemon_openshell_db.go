// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// gatewayDBReadTimeout bounds the read of the account's gateway database.
const gatewayDBReadTimeout = 3 * time.Second

// readGatewayDBMigration is the newest migration the OpenShell gateway
// database at path records as applied (sqlx's _sqlx_migrations), read
// read-only; exists is false when there is no database.
func readGatewayDBMigration(ctx context.Context, path string) (level int, exists bool, err error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, true, err
	}
	if !info.Mode().IsRegular() {
		return 0, true, fmt.Errorf("%s is not a regular file", path)
	}
	ctx, cancel := context.WithTimeout(ctx, gatewayDBReadTimeout)
	defer cancel()
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path),
		RawQuery: "mode=ro&_pragma=busy_timeout(2000)&_pragma=query_only(1)"}).String()
	if !strings.HasPrefix(dsn, "file:///") {
		dsn = strings.Replace(dsn, "file://", "file:///", 1)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return 0, true, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var newest sql.NullInt64
	if err := db.QueryRowContext(ctx, "SELECT MAX(version) FROM _sqlx_migrations WHERE success").Scan(&newest); err != nil {
		return 0, true, err
	}
	return int(newest.Int64), true, nil
}

// setupConflict is why the pinned setup release version cannot run for this
// account, with what the account can do about it: its gateway database was
// migrated by a newer OpenShell, and OpenShell has no down migration
// (rel-1-0-10:GAP-1781). Both are "" when there is no conflict: a release
// GatewayDBMigrations does not know, no database, or one that cannot be read
// (the gateway itself then says what is wrong).
func (o *accountOpenShell) setupConflict(ctx context.Context, version string) (reason, recovery string) {
	pinned, known := openshell.GatewayDBMigrations[version]
	if !known || o.home == "" || o.gatewayDB == nil {
		return "", ""
	}
	level, exists, err := o.gatewayDB(ctx, openshell.GatewayDBPath(o.home))
	if err != nil {
		o.logf("read the migrations of your OpenShell gateway database: %v", err)
		return "", ""
	}
	if !exists || level <= pinned {
		return "", ""
	}
	newer := openshell.ReleaseOfMigration(level)
	return openshell.GatewayDBNewerText(newer, version), openshell.GatewayDBRecovery(newer)
}

// SetupConflict is setupConflict of the organization's setup pin, for the
// daemon's status and doctor (managedStatusFor); "" outside setup mode.
func (o *accountOpenShell) SetupConflict(ctx context.Context, s sandboxrelay.DaemonSettings) (reason, recovery string) {
	if s.Enterprise.Install != config.EnterpriseOpenShellInstallSetup {
		return "", ""
	}
	return o.setupConflict(ctx, s.Enterprise.Version)
}

// openShellConflictReporter is the daemonOpenShell that can say why the
// organization's pinned OpenShell cannot run for the account.
type openShellConflictReporter interface {
	SetupConflict(ctx context.Context, s sandboxrelay.DaemonSettings) (reason, recovery string)
}

var _ openShellConflictReporter = (*accountOpenShell)(nil)
