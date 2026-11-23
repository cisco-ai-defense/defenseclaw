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

//go:build linux || darwin

package gateway

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// writeGatewayDB writes an OpenShell gateway database at the account's path
// with migrations 1..level applied, as sqlx records them.
func writeGatewayDB(t *testing.T, home string, level int) string {
	t.Helper()
	// The path spelled out, so the test also runs on the code before the
	// fix (fail-before).
	path := filepath.Join(home, ".local", "state", "openshell", "gateway", "openshell.db")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE _sqlx_migrations (version BIGINT PRIMARY KEY, description TEXT NOT NULL,
		installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, success BOOLEAN NOT NULL, checksum BLOB NOT NULL, execution_time BIGINT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for v := 1; v <= level; v++ {
		if _, err := db.Exec(`INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES (?, 'm', 1, x'00', 1)`, v); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// rel-1-0-10:GAP-1781: the daemon never installs a lower setup pin over a
// gateway database a newer OpenShell migrated, and never starts a gateway
// that cannot open it (that start only timed out after 90 s). It refuses
// with the cause and the way back, and status and doctor say the same
// (SetupConflict). A database the pin can open, or none, is installed over
// as before.
func TestGAP1781DaemonRefusesLowerPinOverMigratedDB(t *testing.T) {
	fastGatewayWaits(t)
	r := newOpenShellRig(t, "linux")
	// 0.1.9's gateway leaves migration 10; 0.1.6's knows 8.
	writeGatewayDB(t, r.o.home, 10)
	s := setupSettings()
	s.Enterprise.Version = "0.1.6"
	_, err := r.o.Prepare(context.Background(), s)
	want := "OpenShell database was migrated by a newer OpenShell (0.1.9); this OpenShell (0.1.6) cannot open it"
	if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || !strings.Contains(fmtErr(err), openShellPrerequisiteReason) ||
		!strings.Contains(fmtErr(err), want) || !strings.Contains(fmtErr(err), "move ~/.local/state/openshell/gateway/openshell.db") {
		t.Fatalf("prepare over a migrated database: %v", err)
	}
	if len(r.installs) != 0 || len(r.ran()) != 0 {
		t.Fatalf("installed %v or ran %v over a migrated database", r.installs, r.ran())
	}

	// A database the pin can open, and no database, are installed over.
	for name, level := range map[string]int{"own level": 8, "none": -1} {
		r := newOpenShellRig(t, "linux")
		r.holder = func(int) int { return 5001 }
		r.registered = 17670
		if level >= 0 {
			writeGatewayDB(t, r.o.home, level)
		}
		if _, err := r.o.Prepare(context.Background(), s); err != nil || len(r.installs) != 1 {
			t.Errorf("%s: prepare %v, installs %v", name, err, r.installs)
		}
	}
}

// Status and doctor say what a refused run says (managedStatusFor).
func TestGAP1781SetupConflictForStatus(t *testing.T) {
	r := newOpenShellRig(t, "linux")
	writeGatewayDB(t, r.o.home, openshell.GatewayDBMigrations[openshell.InstallerVersion])
	s := setupSettings()
	s.Enterprise.Version = openshell.SupportedMin
	want := openshell.GatewayDBNewerText(openshell.InstallerVersion, openshell.SupportedMin)
	reason, recovery := r.o.SetupConflict(context.Background(), s)
	if reason != want || !strings.Contains(recovery, "ask IT to pin OpenShell "+openshell.InstallerVersion+" or newer") {
		t.Fatalf("status conflict = %q, %q", reason, recovery)
	}
	// Outside setup mode the daemon installs nothing, so there is nothing
	// to say.
	p := s
	p.Enterprise.Install = "prerequisite"
	if reason, _ := r.o.SetupConflict(context.Background(), p); reason != "" {
		t.Fatalf("prerequisite mode conflict = %q", reason)
	}
	// The newer pin opens it.
	s.Enterprise.Version = openshell.InstallerVersion
	if reason, _ := r.o.SetupConflict(context.Background(), s); reason != "" {
		t.Fatalf("conflict for the release that migrated it: %q", reason)
	}
}

func TestReadGatewayDBMigration(t *testing.T) {
	home := t.TempDir()
	if _, exists, err := readGatewayDBMigration(context.Background(), openshell.GatewayDBPath(home)); exists || err != nil {
		t.Fatalf("no database: exists=%v err=%v", exists, err)
	}
	path := writeGatewayDB(t, home, 10)
	level, exists, err := readGatewayDBMigration(context.Background(), path)
	if level != 10 || !exists || err != nil {
		t.Fatalf("read = %d %v %v", level, exists, err)
	}
	// Read-only: nothing beside the database is left.
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if e.Name() != "openshell.db" {
			t.Errorf("the read left %s", e.Name())
		}
	}
}
