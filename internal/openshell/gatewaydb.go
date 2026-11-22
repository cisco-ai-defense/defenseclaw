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

package openshell

import (
	"fmt"
	"path/filepath"
	"sort"
)

// GatewayDBMigrations is the newest gateway database migration each
// OpenShell release applies: the highest version in the database's sqlx
// _sqlx_migrations table once that release's gateway started on it
// (crates/openshell-server/migrations/sqlite of the release tag). A gateway
// refuses a database a newer release migrated further ("migration N was
// previously applied but is missing"), and OpenShell has no down migration,
// so a lower setup-mode pin cannot run for an account whose gateway a newer
// release already started (rel-1-0-10:GAP-1781). Every TarballPins release
// has an entry; add one with each new pin.
var GatewayDBMigrations = map[string]int{
	"0.1.6": 8,
	"0.1.7": 9,
	"0.1.8": 9,
	"0.1.9": 10,
}

// GatewayDBRel is the account's OpenShell gateway database below its state
// home (DefaultStateHome), where the managed exec shim starts the gateway.
var GatewayDBRel = filepath.Join("openshell", "gateway", "openshell.db")

// GatewayDBPath is the gateway database of the account whose home is home.
func GatewayDBPath(home string) string {
	return filepath.Join(DefaultStateHome(home), GatewayDBRel)
}

// ReleaseOfMigration names the oldest release GatewayDBMigrations knows that
// migrates a gateway database to level, else "a release newer than <the
// newest known>".
func ReleaseOfMigration(level int) string {
	releases := make([]string, 0, len(GatewayDBMigrations))
	for release := range GatewayDBMigrations {
		releases = append(releases, release)
	}
	sort.Slice(releases, func(i, j int) bool { return mustParse(releases[i]).Compare(mustParse(releases[j])) < 0 })
	for _, release := range releases {
		if GatewayDBMigrations[release] >= level {
			return release
		}
	}
	return "a release newer than " + releases[len(releases)-1]
}

// GatewayDBNewerText is the one sentence status, doctor and a refused run
// say when the account's gateway database was migrated by the newer release
// newer, which the pinned release have cannot open.
func GatewayDBNewerText(newer, have string) string {
	return fmt.Sprintf("OpenShell database was migrated by a newer OpenShell (%s); this OpenShell (%s) cannot open it", newer, have)
}

// GatewayDBRecovery is what the account can do about GatewayDBNewerText:
// move the database aside, which loses the gateway's sandbox records, or
// have the organization pin newer again.
func GatewayDBRecovery(newer string) string {
	return "ask IT to pin OpenShell " + newer + " or newer again (enterprise.openshell.version); or, only if you can lose OpenShell's records of " +
		"your sandboxes, stop your sandboxes and move ~/.local/state/openshell/gateway/openshell.db (with openshell.db-wal and " +
		"openshell.db-shm beside it) to another folder: the next sandbox command then starts this OpenShell on a new database, " +
		"and the stopped containers of the sandboxes it no longer knows stay in docker until you remove them (`docker rm`)"
}
