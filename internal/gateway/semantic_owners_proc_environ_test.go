// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A read of /proc/<pid>/environ narrowed by a grep to plain non-credential
// names shows the agent those lines only (s7-noise, rel-1-0-10:GAP-0018);
// every other read stays a finding.
func TestProcEnvironOwnerNarrowedReads(t *testing.T) {
	tests := []struct {
		name, command string
		want          bool // the owner finds the read
	}{
		{"filtered to one name", `cat /proc/408/environ | tr '\0' '\n' | grep INGEST_ENV`, false},
		{"filtered, case-insensitive fragment", `cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -i frag`, false},
		{"filtered to two names", `cat /proc/408/environ | tr '\0' '\n' | grep -E "INGEST_ENV|APP_MODE"`, false},
		{"anchored name", `cat /proc/408/environ | tr '\0' '\n' | grep '^APP_MODE='`, false},
		{"explicit pattern option", `cat /proc/408/environ | tr '\0' '\n' | grep -e INGEST_ENV`, false},
		{"strings and sort stages", `strings /proc/self/environ | sort | grep INGEST_ENV`, false},
		{"unfiltered read", `cat /proc/self/environ`, true},
		{"unfiltered pipe", `cat /proc/212/environ | tr '\0' '\n' | head -20`, true},
		{"credential name", `cat /proc/408/environ | tr '\0' '\n' | grep API_TOKEN`, true},
		{"credential word in an alternative", `cat /proc/408/environ | tr '\0' '\n' | grep -E "INGEST_ENV|DB_PASSWORD"`, true},
		{"connection string name", `cat /proc/408/environ | tr '\0' '\n' | grep POSTGRES_DSN`, true},
		{"short fragment", `cat /proc/408/environ | tr '\0' '\n' | grep PG`, true},
		{"inverted match", `cat /proc/408/environ | tr '\0' '\n' | grep -v INGEST_ENV`, true},
		{"context lines", `cat /proc/408/environ | tr '\0' '\n' | grep -A5 INGEST_ENV`, true},
		{"pattern file", `cat /proc/408/environ | tr '\0' '\n' | grep -f /tmp/names`, true},
		{"regex pattern", `cat /proc/408/environ | tr '\0' '\n' | grep 'INGEST.*'`, true},
		{"match all", `cat /proc/408/environ | tr '\0' '\n' | grep .`, true},
		{"file operand next to the pattern", `cat /proc/408/environ | tr '\0' '\n' | grep INGEST_ENV /tmp/other`, true},
		{"copy stage before the filter", `cat /proc/408/environ | tee /tmp/env | grep INGEST_ENV`, true},
		{"redirected read", `cat /proc/408/environ > /tmp/env; cat /tmp/env | grep INGEST_ENV`, true},
		{"filter is not downstream", `cat /proc/408/environ; echo x | grep INGEST_ENV`, true},
		{"second unfiltered read", `cat /proc/408/environ | grep INGEST_ENV; cat /proc/409/environ`, true},
		{"read by head", `head -c 4000 /proc/self/environ`, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(reconImpactCommand(test.command))
			owner := semanticOwnerForRule("PATH-PROC-ENVIRON")
			if got := owner.prerequisite(facts); got != test.want {
				t.Fatalf("prerequisite(%q) = %v, want %v; facts=%+v", test.command, got, test.want, facts.Commands)
			}
			if !test.want && !owner.suppressFallback(facts) {
				t.Fatalf("a narrowed read must keep the regex fallback quiet: %q (parse %+v)", test.command, facts.Parse)
			}
		})
	}
}
