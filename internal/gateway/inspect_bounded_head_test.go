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
// markers (the connector test bounds the request the hooks send). The
// generic endpoint answers that review with a verdict: observe allows it with
// the oversize warning, action blocks it. The 200 ms production budget is not
// held here: the race detector slows the scan past it on a busy CI host (an
// idle 64-core box scans 8 KiB in about 100 ms; a 450 KiB prefix, what the
// hooks sent before, took 4.6 s and got 504).
func TestGenericInspectEightKiBBoundedHeadGetsAVerdict(t *testing.T) {
	// One statement: a head of many statements is over the statement
	// budget, a block of its own that the review keeps (GAP-0146).
	head := "echo" + strings.Repeat(` build`, 8192/6)
	args, err := json.Marshal(map[string]string{"command": head})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"tool":"Bash","args":` + string(args) + `,"content_truncated":true,"bounded_prefix_review":true}`
	for _, tc := range []struct{ mode, want string }{{"observe", "allow"}, {"action", "block"}} {
		t.Run(tc.mode, func(t *testing.T) {
			api := testAPIServerWithConfig(t, tc.mode)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewBufferString(body))
			request.Header.Set("Content-Type", "application/json")
			reply := httptest.NewRecorder()
			api.handleInspectTool(reply, request)
			if reply.Code != http.StatusOK {
				t.Fatalf("status %d (want a verdict): %.300s", reply.Code, reply.Body.String())
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
