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
// DET111 ruling): an inline psql query padded past the SQL bounds (a
// statement past the 4 KiB word bound, or more statements than the SQL
// facts reader reads) leaves the rest unread. When that rest holds a
// modeled server-program, server file read or drop-database keyword, the
// cut takes the truncated row (the GAP-0851 bound-only MEDIUM), on the
// Claude Code and Codex hook routes in the five tiers; the same padding with
// a benign rest keeps the record (the verdict of the cut alone), and so does
// a benign migration of 300 INSERT statements, which the chunks read whole. At ac8b361121 every row was
// the record: allow with an INFO note.
func TestSQLCutUnreadDangerTakesTheTruncatedRowFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX psql spelling")
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
		"SELECT LOAD_FILE('/etc/hostname');",
		"DROP DATABASE scratch;",
		"TRUNCATE TABLE scratch;",
	}
	benign := "SELECT 2;"
	var migration strings.Builder
	for i := range 300 {
		fmt.Fprintf(&migration, "INSERT INTO items (id, name) VALUES (%d, 'item %d'); ", i, i)
	}
	for _, tier := range boundedTestTiers {
		for _, route := range r3PosixRoutesForReadRows() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, client := range []string{"psql -d app -c", "mysql app -e"} {
				for _, rest := range []string{"", "SELECT LOAD_FILE('/etc/hostname');"} {
					// The migration fits the chunk budget, so every statement
					// is read: alone it allows, and a statement after it gets
					// the verdict it gets alone (nothing is unread).
					got, sev := route.decide(t, api, cwd, client+" \""+migration.String()+rest+"\"")
					want, wantSev := "allow", ""
					if rest != "" {
						want, wantSev = route.decide(t, api, cwd, client+" \""+rest+"\"")
					}
					if got != want || wantSev != "" && sev != wantSev {
						t.Errorf("%s %s %s migration + %q: %s/%s, want %s/%s", tier.name, route.connector, client, rest, got, sev, want, wantSev)
					}
				}
			}
			for _, shape := range shapes {
				call := func(rest string) string { return "psql -d app -c \"" + shape.padding + rest + "\"" }
				base, baseSev := route.decide(t, api, cwd, call(benign))
				if base != "allow" {
					t.Errorf("%s %s %s benign rest: %s/%s, want the record (allow)", tier.name, route.connector, shape.name, base, baseSev)
				}
				for _, rest := range rests {
					got, sev := route.decide(t, api, cwd, call(rest))
					want := "alert"
					if tier.tier == bounded.TierStrict {
						want = "block"
					}
					if got != want || sev != "MEDIUM" {
						t.Errorf("%s %s %s %q: %s/%s, want the truncated row %s/MEDIUM", tier.name, route.connector, shape.name, rest, got, sev, want)
					}
				}
			}
		}
	}
}
