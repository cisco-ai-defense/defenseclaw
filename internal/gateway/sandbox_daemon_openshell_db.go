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
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
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

// SetupConflict is why the organization's OpenShell cannot run for the
// account, for the daemon's status and doctor (managedStatusFor): the
// setup pin's (setupConflict), else the administrator's own gateway's
// (prerequisiteConflict).
func (o *accountOpenShell) SetupConflict(ctx context.Context, s sandboxrelay.DaemonSettings) (reason, recovery string) {
	if s.Enterprise.Install != config.EnterpriseOpenShellInstallSetup {
		return o.prerequisiteConflict(ctx, s)
	}
	return o.setupConflict(ctx, s.Enterprise.Version)
}

// prerequisiteConflict is setupConflict for a gateway that runs the
// administrator's openshell-gateway (install: prerequisite), at whatever
// release the administrator installed: it is read from the binary
// (`--version`). An administrator who put back an older OpenShell over a
// database a newer one migrated left the account's gateway unable to
// start, with nothing said (rel-1-0-10:GAP-2070). It errs toward refusing:
// a release GatewayDBMigrations does not know counts at the level of the
// oldest known release at or above it (older than every known one: the
// oldest one's), and a binary whose release cannot be read, over a
// database that is there, is a conflict too. No database, or one that
// cannot be read (the gateway itself then says what is wrong), is none.
func (o *accountOpenShell) prerequisiteConflict(ctx context.Context, s sandboxrelay.DaemonSettings) (reason, recovery string) {
	if o.home == "" || o.gatewayDB == nil {
		return "", ""
	}
	binary := o.gatewayBinary(s)
	if binary == "" {
		// Prepare refuses a missing administrator OpenShell on its own.
		return "", ""
	}
	level, exists, err := o.gatewayDB(ctx, openshell.GatewayDBPath(o.home))
	if err != nil {
		o.logf("read the migrations of your OpenShell gateway database: %v", err)
		return "", ""
	}
	if !exists || level <= 0 {
		return "", ""
	}
	version, verr := o.adminGatewayVersion(ctx, binary)
	if verr != nil {
		return fmt.Sprintf("DefenseClaw could not read the release of your organization's OpenShell gateway (%v), so it does not start it over your OpenShell database, "+
			"which a newer OpenShell may have migrated", verr), "ask IT to check the OpenShell they installed for sandboxes (enterprise.openshell, install: prerequisite)"
	}
	if ceiling, known := migrationCeiling(version); !known || level <= ceiling {
		return "", ""
	}
	newer := openshell.ReleaseOfMigration(level)
	return openshell.GatewayDBNewerText(newer, version), openshell.GatewayDBRecovery(newer)
}

// migrationCeiling is the newest gateway database migration OpenShell
// release v can know: its own GatewayDBMigrations level, else the level of
// the oldest known release above it (a release older than every known one
// gets the oldest one's). known is false for a release newer than every
// known one, or one that does not parse: nothing bounds it.
func migrationCeiling(v string) (ceiling int, known bool) {
	pv, err := openshell.ParseVersion(v)
	if err != nil {
		return 0, false
	}
	best, found := openshell.Version{}, false
	for release := range openshell.GatewayDBMigrations {
		r, err := openshell.ParseVersion(release)
		if err != nil || r.Compare(pv) < 0 {
			continue
		}
		if !found || r.Compare(best) < 0 {
			best, found, ceiling = r, true, openshell.GatewayDBMigrations[release]
		}
	}
	return ceiling, found
}

// gatewayVersionPattern finds the release in `openshell-gateway --version`.
var gatewayVersionPattern = lazyregexp.New(`\bv?(\d+\.\d+\.\d+(?:[-+~][0-9A-Za-z.\-]+)?)\b`)

// adminGatewayVersion is the release the administrator's gateway binary
// says it is, read once per binary path and file state.
func (o *accountOpenShell) adminGatewayVersion(ctx context.Context, binary string) (string, error) {
	key := binary
	if info, err := os.Stat(binary); err == nil {
		key = fmt.Sprintf("%s|%d|%d", binary, info.Size(), info.ModTime().UnixNano())
	}
	o.mu.Lock()
	if o.adminVersionKey == key && o.adminVersion != "" {
		v := o.adminVersion
		o.mu.Unlock()
		return v, nil
	}
	o.mu.Unlock()
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := o.run(vctx, binary, []string{"--version"}, nil)
	if err != nil {
		return "", commandError(filepath.Base(binary)+" --version", out, err)
	}
	m := gatewayVersionPattern.FindStringSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("%s --version printed no release: %q", filepath.Base(binary), firstOutputLine(out))
	}
	o.mu.Lock()
	o.adminVersionKey, o.adminVersion = key, m[1]
	o.mu.Unlock()
	return m[1], nil
}

// openShellConflictReporter is the daemonOpenShell that can say why the
// organization's pinned OpenShell cannot run for the account.
type openShellConflictReporter interface {
	SetupConflict(ctx context.Context, s sandboxrelay.DaemonSettings) (reason, recovery string)
}

var _ openShellConflictReporter = (*accountOpenShell)(nil)
