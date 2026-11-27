// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The state pattern reading under the one bound rule (DET111 step 2).
//
// GAP-1017: a pattern under ~/.defenseclaw that matches more names than the
// reading spells (maxStateGlobMatches, 64) gave no reading at all and the call
// was judged on its literal words with no bound finding. It is now read up to
// the cap and the call is TRUNCATED (ACTION-COMPOUND-LIMIT, the unknown tier).
//
// GAP-1726: the work bound of the state patterns is shared by the patterns of
// one command, and each pattern listed its folders again, so decoy patterns
// over one large state folder used it up and a later cp a.txt
// ~/.defenseclaw/conf*.yaml had no reading. A folder is now listed and
// charged once per command; work that still runs out is TRUNCATED.
func TestStatePatternReadingReportsItsBounds(t *testing.T) {
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		home = filepath.ToSlash(home)
	}
	state := filepath.Join(home, ".defenseclaw")
	big := filepath.Join(state, "big")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{big, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string) {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(state, "config.yaml"))
	write(filepath.Join(project, "a.txt"))
	for i := 0; i < 70; i++ {
		write(filepath.Join(state, fmt.Sprintf("aa%03d.yaml", i)))
	}
	// One folder of 4,000 names: listing it costs 4,001 units of work.
	for i := 0; i < 4000; i++ {
		write(filepath.Join(big, fmt.Sprintf("n%04d", i)))
	}
	decoys := strings.Repeat("~/.defenseclaw/big/zz* ", 140)
	limited := func(findings []RuleFinding) bool {
		return slices.ContainsFunc(findings, func(f RuleFinding) bool {
			return canonicalTrustedRuleID(f.RuleID) == evaluationLimitRuleID
		})
	}
	installDefaultProfileConnector(t, "claudecode")
	for _, row := range []struct {
		id, command  string
		limit, block bool
	}{
		// 71 names match: the reading spells the first 64 and is TRUNCATED.
		{"GAP-1017 past the match cap", "cp a.txt ~/.defenseclaw/*.yaml", true, true},
		// 140 decoy patterns over one 4,000-name folder (560,140 units when
		// each lists it again, past 1<<19): the state pattern behind them
		// is read and its state write blocks.
		{"GAP-1726 decoys then the state write", "ls " + decoys + "; cp a.txt ~/.defenseclaw/conf*.yaml", false, true},
		{"GAP-1726 decoys, def* folder", "ls " + decoys + "; cp a.txt ~/.def*/config.yaml", false, true},
		{"GAP-1726 decoys, class", "ls " + decoys + "; cp a.txt ~/.defensecla[w]/conf[i]g.yaml", false, true},
		{"GAP-1726 decoys, tee", "ls " + decoys + "; echo x | tee ~/.def*/conf*.yaml", false, true},
		// Under the caps: no bound finding.
		{"under the caps", "cp a.txt ~/.defenseclaw/conf*.yaml", false, true},
		{"benign list under the caps", "ls ~/.defenseclaw/conf*.yaml", false, false},
	} {
		input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: project, ActiveHome: home}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, Connector: "claudecode", EnforcementCapable: true,
		})
		wantLimit := row.limit
		if runtime.GOOS == "windows" && strings.HasSuffix(row.command, "cp a.txt ~/.defenseclaw/conf*.yaml") {
			// A Windows host also reads the call as PowerShell, where Copy-Item
			// does not expand a wildcard destination: the state write's target
			// is known only at run time (provenPowerShellStateWrite, the unknown
			// tier of rel-1-0-10:GAP-1138), next to the state rule.
			wantLimit = true
		}
		if got := limited(findings); got != wantLimit {
			t.Errorf("%s: limit finding=%v, want %v (findings %v)", row.id, got, wantLimit, findingIDs(findings))
		}
		if blocked := gap0747Blocked(findings, row.block); blocked != row.block {
			t.Errorf("%s: block=%v, want %v (findings %v)", row.id, blocked, row.block, findingIDs(findings))
		}
	}
}
