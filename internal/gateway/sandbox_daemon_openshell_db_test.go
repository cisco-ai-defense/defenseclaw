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
	// In prerequisite mode the administrator's gateway at the release that
	// migrated it opens it (GAP-2070 covers the older one).
	p := s
	p.Enterprise.Install = "prerequisite"
	r.o.adminBinary = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	r.gatewayVersion = "openshell-gateway " + openshell.InstallerVersion
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

// rel-1-0-10:GAP-2070: on a managed computer whose gateway runs the
// administrator's OpenShell (install: prerequisite), the administrator put
// back an older OpenShell after an account's gateway had run a newer one:
// ensure and the daemon said nothing, and the account's gateway then could
// not open its database (migration N previously applied but missing).
// The daemon reads the release of the administrator's gateway binary and,
// over a database a newer release migrated, refuses the start and says
// why in status and doctor, as in setup mode. A release it does not know
// counts at the level of the oldest known release at or above it (older
// than every known one: the oldest one's), and a binary whose release it
// cannot read, over a database that is there, is refused too: the start
// is never shown safe by a guess.
func TestGAP2070PrerequisiteGatewayBelowTheAccountDatabase(t *testing.T) {
	fastGatewayWaits(t)
	rig := func(t *testing.T, version string, dbLevel int) *openShellRig {
		r := newOpenShellRig(t, "linux")
		r.o.adminBinary = func(name string) (string, error) { return "/usr/bin/" + name, nil }
		if version == "" {
			r.fail["openshell-gateway --version"] = "error: unknown flag"
		} else {
			r.gatewayVersion = "openshell-gateway " + version
		}
		if dbLevel >= 0 {
			writeGatewayDB(t, r.o.home, dbLevel)
		}
		return r
	}
	s := prerequisiteSettings()
	for _, tc := range []struct {
		name, version string
		level         int
		refuse        string // "" = no conflict
	}{
		{"0.1.3 over 0.1.9's database", "0.1.3", 10, openshell.GatewayDBNewerText("0.1.9", "0.1.3")},
		{"0.1.6 over 0.1.9's database", "0.1.6", 10, openshell.GatewayDBNewerText("0.1.9", "0.1.6")},
		{"0.1.9 over its own database", "0.1.9", 10, ""},
		{"0.1.3 over 0.1.6's database", "0.1.3", 8, ""},
		{"no database", "0.1.3", -1, ""},
		{"unreadable release over a database", "", 10, "could not read the release of your organization's OpenShell gateway"},
		{"unreadable release, no database", "", -1, ""},
	} {
		t.Run(strings.ReplaceAll(tc.name, " ", "_"), func(t *testing.T) {
			r := rig(t, tc.version, tc.level)
			reason, recovery := r.o.SetupConflict(context.Background(), s)
			if tc.refuse == "" {
				if reason != "" {
					t.Fatalf("conflict %q, want none", reason)
				}
				return
			}
			if !strings.Contains(reason, tc.refuse) || recovery == "" {
				t.Fatalf("status conflict = %q, %q; want %q with a way on", reason, recovery, tc.refuse)
			}
			_, err := r.o.Prepare(context.Background(), s)
			if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || !strings.Contains(fmtErr(err), tc.refuse) {
				t.Fatalf("prepare: %v, want the refusal %q", err, tc.refuse)
			}
			for _, c := range r.ran() {
				if strings.HasPrefix(c, "systemctl --user start ") {
					t.Fatalf("the gateway was started over a database it cannot open: %v", r.ran())
				}
			}
		})
	}
}
