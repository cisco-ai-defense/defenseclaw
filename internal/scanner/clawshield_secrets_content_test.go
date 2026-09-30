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

package scanner

import (
	"strings"
	"testing"
)

func TestClawShieldSecretsScanContentMatchesInMemoryBytes(t *testing.T) {
	s := NewClawShieldSecretsScanner()
	key := "AKIA" + strings.Repeat("Q", 16)
	findings := s.ScanContent("config/app.ini", []byte("aws_access_key_id = "+key+"\n"))
	if len(findings) == 0 {
		t.Fatal("expected an AWS key finding")
	}
	f := findings[0]
	if f.RuleID != "CS-SEC-AWS-KEY" || f.Severity != SeverityCritical {
		t.Fatalf("finding = %s/%s, want CS-SEC-AWS-KEY/CRITICAL", f.RuleID, f.Severity)
	}
	if !strings.HasPrefix(f.Location, "config/app.ini") {
		t.Fatalf("location %q does not name the in-memory path", f.Location)
	}
	if strings.Contains(f.Description, key) {
		t.Fatal("description must carry a truncated value, not the full secret")
	}
	if got := s.ScanContent("README.md", []byte("nothing to see here\n")); len(got) != 0 {
		t.Fatalf("clean content produced %d findings", len(got))
	}
}
