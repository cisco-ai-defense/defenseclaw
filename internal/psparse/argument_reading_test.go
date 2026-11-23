// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"strings"
	"testing"
)

func TestGAP0988PowerShellArgumentReadingOrder(t *testing.T) {
	for _, row := range []struct{ name, source, want string }{
		{"paren", "Write-Output (Get-Date)", "Get-Date\nWrite-Output 0"},
		{"array", "Write-Output @(Get-Date; Get-Location)", "Get-Date\nGet-Location\nWrite-Output 0"},
		{"subexpression", "Write-Output $(Get-Date)", "Get-Date\nWrite-Output 0"},
		{"invoked-block", "Write-Output (& { Get-Date })", "Get-Date\nWrite-Output 0"},
		{"dot-block", "Write-Output (. { Get-Date })", "Get-Date\nWrite-Output 0"},
		{"nested", "Write-Output (Write-Output (Get-Date))", "Get-Date\nWrite-Output 0\nWrite-Output 0"},
		{"quoted", "Write-Output \"$(Get-Date)\"", "Get-Date\nWrite-Output 0"},
		{"here-string", "Write-Output @\"\n$(Get-Date)\n\"@", "Get-Date\nWrite-Output 0"},
		{"pipeline", "Write-Output (Get-Date) | Out-String", "Get-Date\nWrite-Output 0 | Out-String"},
		{"value-pipeline", "\"$(Get-Date)\" | Out-String", "Get-Date\n0 | Out-String"},
		{"earlier-statement", "Get-Location; Write-Output (Get-Date)", "Get-Location\nGet-Date\nWrite-Output 0"},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, changed, cut := ArgumentCommandReading(row.source)
			if got != row.want || !changed || cut.Any() {
				t.Errorf("reading=%q changed=%v cut=%v, want %q", got, changed, cut, row.want)
			}
		})
	}
	for _, source := range []string{"Write-Output '(Get-Date)'", "Write-Output { Get-Date }", "Write-Output 123", "Write-Output (123)", "Write-Output @({ Get-Date })", "Write-Output x'$(Get-Date)'`u{41}"} {
		_, changed, cut := ArgumentCommandReading(source)
		if changed || cut.Any() {
			t.Errorf("data argument gained a reading: changed=%v cut=%v", changed, cut)
		}
	}
}
func TestGAP0988PowerShellArgumentReadingBounds(t *testing.T) {
	_, _, cut := ArgumentCommandReading(strings.Repeat(" ", 64<<10+1))
	if !cut.Has(bounded.Bytes) {
		t.Fatal("byte cap not reported")
	}
	_, _, cut = ArgumentCommandReading("Write-Output " + strings.Repeat("(", 80) + "Get-Date" + strings.Repeat(")", 80))
	if !cut.Has(bounded.Depth) {
		t.Fatal("depth cap not reported")
	}
}
