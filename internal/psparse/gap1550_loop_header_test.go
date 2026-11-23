// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"strings"
	"testing"
)

// A command evaluated in a loop header runs before the loop body. The
// parenthesized foreach source is parsed as a (group) block, not as a command.
func TestGAP1550LoopHeaderPipelineReading(t *testing.T) {
	for _, row := range []struct {
		name, source, first string
	}{
		{"foreach credential", `foreach ($f in (Get-Content $HOME\.aws\credentials)) { Write-Output ready }`, `Get-Content $HOME\.aws\credentials`},
		{"foreach benign", `foreach ($f in (Get-ChildItem .)) { Write-Output ready }`, `Get-ChildItem .`},
		{"while", `while ((Get-Content $HOME\.aws\credentials)) { Write-Output ready }`, `Get-Content $HOME\.aws\credentials`},
		{"do while", `do { Write-Output ready } while ((Get-Content $HOME\.aws\credentials))`, `Get-Content $HOME\.aws\credentials`},
		{"for", `for ($i=0; (Get-Content $HOME\.aws\credentials); $i++) { Write-Output ready }`, `Get-Content $HOME\.aws\credentials`},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, changed, cut := ArgumentCommandReading(row.source)
			if !changed || cut.Any() || !strings.HasPrefix(got, row.first+"\n") {
				t.Fatalf("reading=%q changed=%v cut=%v, want header command %q first", got, changed, cut, row.first)
			}
		})
	}
}
