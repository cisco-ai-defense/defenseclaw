// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv/hlinkmatrix"
)

// GAP-0293 class, the production verdict: an exported bash function in the
// agent's environment may only take an allow proof away. For every row of
// the dead-value proofs (GAP-0431, GAP-0403) and of the GAP-0293 corpus, in
// all four cells, the verdict with a function in the environment is at
// least as strict as the verdict without: no block becomes an allow.
// Allow-to-block moves (a declined proof) are counted and logged by case id.
func TestExportedFunctionNeverFlipsABlockToAllow(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	names := hlinkmatrix.DefaultNames()
	hlinkmatrix.Setup(t, f.project, f.keys, names)
	type row struct{ id, command string }
	var rows []row
	for _, r := range hlinkmatrix.DeadValueRows() {
		rows = append(rows, row{"dead/" + r.ID, r.Command})
	}
	for _, r := range gap0403Rows {
		rows = append(rows, row{"gap0403/" + r.name, r.command})
	}
	for _, r := range hlinkmatrix.Rows(names) {
		rows = append(rows, row{r.ID, r.Command})
	}
	if _, err := os.Stat(filepath.Join(f.project, "a.txt")); err != nil {
		for _, name := range []string{"a.txt", "b.txt"} {
			if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	run := func(exported bool) map[string]string {
		clearShellStartupEnv(t)
		gap0293SetStartup(t, exported)
		var payloads [][]byte
		for _, r := range rows {
			payloads = append(payloads, f.payload(t, r.command))
		}
		headers := f.clientHeaders(t, payloads)
		var calls []*hookCall
		for i, r := range rows {
			calls = append(calls, everyMode(r.id, payloads[i], headers[i])...)
		}
		f.answerCells(t, calls)
		out := map[string]string{}
		for _, call := range calls {
			out[call.name] = call.verdict
		}
		return out
	}
	clean := run(false)
	withFunction := run(true)
	var flipped, declined []string
	for name, before := range clean {
		after := withFunction[name]
		switch {
		case before == "block" && after != "block":
			flipped = append(flipped, name)
		case before != "block" && after == "block":
			declined = append(declined, name)
		}
	}
	sort.Strings(flipped)
	sort.Strings(declined)
	if len(flipped) > 0 {
		t.Errorf("%d cells went from block to %s with an exported function: %s", len(flipped), "allow", strings.Join(flipped, ", "))
	}
	t.Logf("cells=%d, allow->block (proof declined) %d", len(clean), len(declined))
	for _, name := range declined {
		if len(declined) <= 12 {
			t.Logf("declined: %s", name)
		}
	}
}
