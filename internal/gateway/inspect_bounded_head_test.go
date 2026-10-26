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

// GAP-1512, GAP-1841: the per-user generic inspect hooks send the bounded
// review of an oversized call as an 8 KiB head with the incomplete-review
// markers. The generic endpoint scans within its production 200 ms budget
// (inspectScanTimeout, no test override here), so that review gets a verdict:
// observe allows it with the oversize warning, action blocks it. A 450 KiB
// prefix, what the hooks sent before, ran past the budget and got 504.
func TestGenericInspectEightKiBBoundedHeadGetsAVerdictInTheScanBudget(t *testing.T) {
	head := strings.Repeat(`ls -la /tmp/project && echo build `, 8192/34)
	args, err := json.Marshal(map[string]string{"command": head})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"tool":"Bash","args":` + string(args) + `,"content_truncated":true,"bounded_prefix_review":true}`
	for _, tc := range []struct{ mode, want string }{{"observe", "allow"}, {"action", "block"}} {
		t.Run(tc.mode, func(t *testing.T) {
			api := testAPIServerWithConfig(t, tc.mode)
			api.inspectToolScanTimeout = 0 // the production budget
			// A loaded CI host can miss 200 ms once; an 8 KiB head fits it,
			// where a 450 KiB prefix never did (504 on every try).
			var reply *httptest.ResponseRecorder
			for attempt := 0; attempt < 3; attempt++ {
				request := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewBufferString(body))
				request.Header.Set("Content-Type", "application/json")
				reply = httptest.NewRecorder()
				api.handleInspectTool(reply, request)
				if reply.Code == http.StatusOK {
					break
				}
			}
			if reply.Code != http.StatusOK {
				t.Fatalf("status %d (want a verdict within the scan budget): %.300s", reply.Code, reply.Body.String())
			}
			var verdict ToolInspectVerdict
			if err := json.Unmarshal(reply.Body.Bytes(), &verdict); err != nil {
				t.Fatalf("body=%.300s", reply.Body.String())
			}
			if verdict.Action != tc.want || !strings.Contains(strings.Join(verdict.Findings, ","), hookOversizeUninspectedRuleID) {
				t.Fatalf("verdict %+v, want %s with the uninspected finding", verdict, tc.want)
			}
		})
	}
}
