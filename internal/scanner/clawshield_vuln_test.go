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

func TestCSVulnFindingTitlesAreReadable(t *testing.T) {
	findings := csVulnScanContent([]byte("value = eval(os.environ.get('X'))\n"), "helper.py")
	var eval *Finding
	for i := range findings {
		if findings[i].ID == "CS-VLN-XSS-EVAL" {
			eval = &findings[i]
		}
	}
	if eval == nil {
		t.Fatalf("eval() not reported: %+v", findings)
	}
	if eval.Title != "Dynamic code execution with eval()" {
		t.Fatalf("eval title = %q", eval.Title)
	}
	for _, rule := range csVulnRules {
		if title := csVulnTitle(rule); strings.Contains(title, rule.id) || strings.HasPrefix(title, "Vulnerability pattern") {
			t.Errorf("rule %s has no readable title: %q", rule.id, title)
		}
	}
}
