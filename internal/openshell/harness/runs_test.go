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

package harness

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestParseRun(t *testing.T) {
	for in, want := range map[string]DetachedRun{
		"":                                            {State: sandboxapi.RunNone},
		"run_started=1790000000\nrun=running\n":       {State: sandboxapi.RunRunning, Started: 1790000000},
		"run_exit=3\nrun=exited\nrun_started=\n":      {State: sandboxapi.RunExited, Exit: "3"},
		"run=interrupted\nrun_started=17\n":           {State: sandboxapi.RunInterrupted, Started: 17},
		" run_exit=0 \n run=exited \n garbage \n":     {State: sandboxapi.RunExited, Exit: "0"},
		"run_exit=0\nrun=exited\nexited\nsynced\n":    {State: sandboxapi.RunExited, Exit: "0"},
		"run=bogus\n":                                 {State: sandboxapi.RunNone},
		"run=none\n":                                  {State: sandboxapi.RunNone},
		"state=running\nexit=0\n":                     {State: sandboxapi.RunNone},
		"run=interrupted\nrun_started=not-a-number\n": {State: sandboxapi.RunInterrupted},
	} {
		if got := ParseRun([]byte(in)); got != want {
			t.Errorf("ParseRun(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestLastLines(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"a\nb\nc\n", 2, "b\nc\n"},
		{"a\nb\nc", 2, "b\nc\n"},
		{"a\nb\n", 5, "a\nb\n"},
		{"\n\n", 1, ""},
		{"", 3, ""},
	} {
		if got := string(LastLines([]byte(c.in), c.n)); got != c.want {
			t.Errorf("LastLines(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}
