// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Lead decision 11-12 22:05Z: the HIGH build floor stays; an admin may
// accept one rule as a known false positive, with a reason, and the
// acceptance is in the signed statement.
func TestAcceptFindingAtTheBuildFloor(t *testing.T) {
	files := []tarFile{
		{path: "/home/agent/.mcp.json", mode: 0o644, uid: 1000, gid: 1000, data: `{"mcpServers":{"notes":{"command":"python3","args":["/opt/notes/server.py"]}}}`},
		{path: "/opt/notes/server.py", mode: 0o644, data: evilServer},
	}
	// Without the acceptance the floor blocks (TestMaliciousMCPBlocked).
	f := newFixture(t, files...)
	if _, err := f.build(t, nil); !errors.Is(err, ErrScanBlocked) {
		t.Fatalf("the floor did not block: %v", err)
	}
	// A reason is required.
	if _, err := f.build(t, func(o *BuildOptions) { o.AcceptFindings = []AcceptedFinding{{RuleID: "mcp-yara"}} }); err == nil {
		t.Fatal("an acceptance without a reason was taken")
	}
	// An acceptance that lifts nothing is refused (it would outlive its finding).
	if _, err := f.build(t, func(o *BuildOptions) {
		o.AcceptFindings = []AcceptedFinding{{RuleID: "no-such-rule", Reason: "x"}}
	}); err == nil || !strings.Contains(err.Error(), "lifts no blocked finding") {
		t.Fatalf("an unused acceptance: %v", err)
	}
	res, err := f.build(t, func(o *BuildOptions) {
		o.BuilderID = "release-admin@example.com"
		o.AcceptFindings = []AcceptedFinding{{RuleID: "mcp-yara", Reason: "the notes server reads no keys; YARA false positive on the docstring"}}
	})
	if err != nil {
		t.Fatalf("accepted build failed: %v", err)
	}
	acc := res.Report.Summary.Accepted
	if len(acc) != 1 || acc[0].RuleID != "mcp-yara" || acc[0].By != "release-admin@example.com" || acc[0].At.IsZero() || len(acc[0].Items) == 0 {
		t.Fatalf("accepted = %+v", acc)
	}
	for _, it := range res.Report.Summary.Items {
		if it.Kind == "mcp" && it.Verdict == VerdictClean && len(it.Accepted) > 0 {
			t.Fatalf("an item with an accepted finding reads clean: %+v", it)
		}
	}
	// The signed statement carries it, and verify shows it.
	v := NewVerifier(f.reg, f.policy(nil))
	got, err := v.Verify(context.Background(), f.m.host()+"/tmpl/claude@"+res.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if a := got.Statement.Predicate.Scan.Accepted; len(a) != 1 || a[0].Reason == "" {
		t.Fatalf("statement acceptances = %+v", a)
	}
}
