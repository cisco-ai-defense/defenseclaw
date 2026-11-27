// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestSQLCutUnreadDangerTakesTheTruncatedRowFiveTiers (T23 review P3-1,
// GAP-2120, GAP-2122; DET111 rulings): an inline psql or mysql query padded
// past the SQL bounds (a statement past the 4 KiB word bound, or more
// statements than the SQL facts reader reads) leaves the rest unread. A
// statement there with a modeled server-program, server file read or
// drop/truncate keyword is read alone, so the padded call takes the cell of
// the same statement unpadded; one that cannot be read alone (itself past
// the bound) takes the truncated row (the GAP-0851 bound-only MEDIUM). A
// benign rest keeps the record (allow), and so do a 300-INSERT migration and
// the MySQL TRUNCATE(x, d) function, which is no TRUNCATE statement. On the
// Claude Code and Codex hook routes in the five tiers. At ac8b361121 every
// padded row was the record (allow); at 08e285b2a6 the padded rows took the
// truncated row (a block in strict, above the unpadded TRUNCATE alert) and
// TRUNCATE(price, 2) did too.
func TestSQLCutUnreadDangerTakesTheTruncatedRowFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX SQL client spelling")
	}
	cwd := t.TempDir()
	longStatement := "SELECT " + strings.Repeat("1+", 2600) + "1; "
	manyStatements := strings.Repeat("SELECT 1; ", 300)
	shapes := []struct{ name, padding string }{
		{"past the word bound", longStatement},
		{"past the statement cap", manyStatements},
	}
	rests := []string{
		"COPY t TO PROGRAM 'true';",
		"SELECT LOAD_FILE('/etc/shadow');",
		"SELECT LOAD_FILE('/etc/hostname');",
		"DROP DATABASE scratch;",
		"TRUNCATE TABLE scratch;",
		"truncate scratch;",
		"SELECT TRUNCATE(price, 2) FROM orders;",
		"SELECT 2;",
	}
	var migration strings.Builder
	for i := range 300 {
		fmt.Fprintf(&migration, "INSERT INTO items (id, name) VALUES (%d, 'item %d'); ", i, i)
	}
	unreadable := "COPY (SELECT " + strings.Repeat("1+", 2600) + "1) TO PROGRAM 'true';"
	for _, tier := range boundedTestTiers {
		for _, route := range r3PosixRoutesForReadRows() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, client := range []string{"psql -d app -c", "mysql app -e"} {
				call := func(query string) string { return client + " \"" + query + "\"" }
				if got, sev := route.decide(t, api, cwd, call(migration.String())); got != "allow" {
					t.Errorf("%s %s %s 300-INSERT migration: %s/%s, want allow", tier.name, route.connector, client, got, sev)
				}
				for _, rest := range rests {
					want, wantSev := route.decide(t, api, cwd, call(rest))
					for _, padding := range []string{longStatement, manyStatements, migration.String()} {
						if got, sev := route.decide(t, api, cwd, call(padding+rest)); got != want || sev != wantSev {
							t.Errorf("%s %s %s padded (%d bytes) %q: %s/%s, want the unpadded cell %s/%s",
								tier.name, route.connector, client, len(padding), rest, got, sev, want, wantSev)
						}
					}
				}
				for _, shape := range shapes {
					want := "alert"
					if tier.tier == bounded.TierStrict {
						want = "block"
					}
					if got, sev := route.decide(t, api, cwd, call(shape.padding+unreadable)); got != want || sev != "MEDIUM" {
						t.Errorf("%s %s %s %s + an unreadable COPY TO PROGRAM: %s/%s, want the truncated row %s/MEDIUM",
							tier.name, route.connector, client, shape.name, got, sev, want)
					}
				}
			}
		}
	}
}
