// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"strings"
	"testing"
)

// TestGAP1947PortReadsTheSameInputAsParse: red at ad6ab569dd (the port parsed
// a script past maxInput whole and nested past maxPortNesting, so a give-up
// paid for two full parses), green when the port declines both before it
// parses and Parse reads the call: past maxInput a truncated row that keeps
// the findings of its first maxInput bytes.
func TestGAP1947PortReadsTheSameInputAsParse(t *testing.T) {
	big := "Remove-Item C:\\Users\\alice\\proj\\o.txt\n" + strings.Repeat("Write-Output hello world\n", maxInput/25+8)
	if _, ok := FromPwshparse(big, Options{}); ok {
		t.Error("the port read an input past maxInput")
	}
	sc, port, err := ParseEffects(big, Options{})
	if err != nil || port || sc == nil {
		t.Fatalf("ParseEffects past maxInput: port=%v err=%v", port, err)
	}
	truncated := false
	for _, d := range sc.Diagnostics {
		truncated = truncated || d.Reason == ReasonTruncated
	}
	if !truncated {
		t.Errorf("no %s diagnostic past maxInput: %+v", ReasonTruncated, sc.Diagnostics)
	}
	if len(sc.Statements) == 0 {
		t.Error("the truncated read dropped the statements of its first maxInput bytes")
	}
	deep := strings.Repeat("(", maxPortNesting+1) + "1" + strings.Repeat(")", maxPortNesting+1)
	if _, ok := FromPwshparse(deep, Options{}); ok {
		t.Error("the port read nesting past maxPortNesting")
	}
	shallow := strings.Repeat("(", 64) + "1" + strings.Repeat(")", 64)
	if _, ok := FromPwshparse(shallow, Options{}); !ok {
		t.Error("the port declined nesting well inside maxPortNesting")
	}
}
