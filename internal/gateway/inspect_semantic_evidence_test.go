// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// GAP-1602: a semantic rule finding (CMD-RM-RF) names the call it judged as
// its evidence, as reference/apis/gateway-api.mdx documents: redacted by
// default, raw with X-DefenseClaw-Reveal-PII: 1.
func TestInspectToolSemanticFindingCarriesEvidence(t *testing.T) {
	for _, reveal := range []bool{false, true} {
		api := testAPIServerWithConfig(t, "action")
		req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool",
			bytes.NewBufferString(`{"tool":"Bash","args":{"command":"rm -rf /"}}`))
		req.Header.Set("Content-Type", "application/json")
		if reveal {
			req.Header.Set("X-DefenseClaw-Reveal-PII", "1")
		}
		w := httptest.NewRecorder()
		api.handleInspectTool(w, req)
		var verdict ToolInspectVerdict
		if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil {
			t.Fatalf("decode verdict: %v: %s", err, w.Body.String())
		}
		found := false
		for _, f := range verdict.DetailedFindings {
			if f.RuleID != "CMD-RM-RF" {
				continue
			}
			found = true
			switch {
			case reveal && f.Evidence != "rm -rf /":
				t.Fatalf("revealed evidence = %q, want the judged command", f.Evidence)
			case !reveal && !strings.HasPrefix(f.Evidence, "<redacted-evidence"):
				t.Fatalf("default evidence = %q, want a redacted placeholder", f.Evidence)
			}
		}
		if !found {
			t.Fatalf("no CMD-RM-RF finding: %s", w.Body.String())
		}
	}
}
