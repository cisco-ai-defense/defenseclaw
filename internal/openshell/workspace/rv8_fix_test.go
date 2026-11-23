//go:build !windows

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

package workspace

import (
	"strings"
	"testing"
)

// RV8-1 (GAP-0834): the agent wraps the whole file, past the few lines the
// near-line flag looks at. The change lands, and the file gets one note.
func TestRV8WholeFileWrapIsNoted(t *testing.T) {
	k := b1Key(0)
	up := "import os\nimport sys\nimport json\nA = 1\nB = 2\nTOKEN = \"" + k + "\"\nC = 3\nD = 4\nE = 5\nF = 6\nG = 7\n"
	agentUp := strings.Replace(up, k, "DC_SECRET_1", 1)
	agent := "x = \"\"\"\n" + agentUp + "\"\"\"\nsend(x)\n"
	e, fs := rv5Launch(t, "rv8w", map[string]string{"config.py": up}, "", PlaceholderToken)
	fs.write(remoteRepo+"/config.py", agent)
	pr, _ := rv6PullApply(t, e, fs, "rv8w")
	if got := s9aLocal(t, e, "config.py"); !strings.Contains(got, "send(x)") || !strings.Contains(got, k) {
		t.Fatalf("config.py = %q: want the agent's change with the person's value", got)
	}
	n := 0
	for _, f := range pr.Review.Flags {
		if f.Kind == RiskSecretContext && f.Path == "config.py" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d secret-context flags on config.py, want 1: %+v", n, pr.Review.Flags)
	}
	if !strings.Contains(strings.Join(pr.Review.Warnings, "\n"), "config.py holds your credential on line 6 and the agent changed this file") {
		t.Errorf("no file note: %q", pr.Review.Warnings)
	}
}
