// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// The --json refusal shows the PowerShell call operator as a literal &, the
// same copy-pasteable command the human line shows, not \u0026 (GAP-2504).
func TestEnterpriseJSONKeepsPowerShellCallOperator(t *testing.T) {
	message := windowsManagedStandardUserViewAnswer("the AI discovery records", "enterprise windows discovery")
	if !strings.Contains(message, "`& '") {
		t.Fatalf("message has no call operator: %q", message)
	}
	var out bytes.Buffer
	writeManagedViewRefusalJSON(&out, &managedViewRefusal{code: "elevation_required", message: message})
	raw := out.String()
	if strings.Contains(raw, `\u0026`) || !strings.Contains(raw, "`& '") {
		t.Fatalf("raw JSON escapes the call operator: %s", raw)
	}
	var decoded struct {
		Errors []struct{ Message string } `json:"errors"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil || len(decoded.Errors) != 1 || decoded.Errors[0].Message != message {
		t.Fatalf("decoded %+v err %v", decoded, err)
	}
}
