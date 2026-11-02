// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func TestGAP0458PowerShellSubexpressionLiteralBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		readOnly      bool
	}{
		{"single literal", `Write-Output $('hello')`, true},
		{"escaped literal", `Write-Output $('it''s fine')`, true},
		{"separate command", `Write-Output $('hello'; Remove-Item -Force ~/.defenseclaw; 'done')`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := powerShellSegmentReadOnly(tc.command); got != tc.readOnly {
				t.Fatalf("read-only = %t, want %t", got, tc.readOnly)
			}
		})
	}
}
