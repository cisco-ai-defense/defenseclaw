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

func rv9SecretFlags(pr *PullResult) int {
	n := 0
	for _, f := range pr.Review.Flags {
		if f.Kind == RiskSecretContext && f.Path == "config.py" {
			n++
		}
	}
	return n
}

// rv9Indent pulls the agent's edit of a config.py that holds the person's
// credential on line 1, far from the line the agent changes.
func rv9Indent(t *testing.T, name string, edit func(string) string) (string, *PullResult) {
	t.Helper()
	k := b1Key(0)
	up := "TOKEN = \"" + k + "\"\nA = 1\nB = 2\nC = 3\nD = 4\nE = 5\nif False:\n    pass\n    send(TOKEN)\n"
	agent := edit(strings.Replace(up, k, "DC_SECRET_1", 1))
	e, fs := rv5Launch(t, name, map[string]string{"config.py": up}, "", PlaceholderToken)
	fs.write(remoteRepo+"/config.py", agent)
	pr, _ := rv6PullApply(t, e, fs, name)
	return s9aLocal(t, e, "config.py"), pr
}

// RV9-2 (GAP-0868): the agent takes the indent off send(TOKEN), out of the
// if False: block, so it runs. The change lands with the file note.
func TestRV9IndentOnlyChangeIsNoted(t *testing.T) {
	got, pr := rv9Indent(t, "rv9i", func(s string) string { return strings.Replace(s, "    send(TOKEN)", "send(TOKEN)", 1) })
	if !strings.Contains(got, "\nsend(TOKEN)") {
		t.Fatalf("config.py = %q: want the agent's dedent", got)
	}
	if rv9SecretFlags(pr) != 1 || !strings.Contains(strings.Join(pr.Review.Warnings, "\n"), "config.py holds your credential on line 1 and the agent changed this file") {
		t.Errorf("no file note: flags %+v warnings %q", pr.Review.Flags, pr.Review.Warnings)
	}
}

// RV9-2: blank lines, trailing space and CRLF line ends stay quiet.
func TestRV9BlankAndTrailingSpaceStayQuiet(t *testing.T) {
	got, pr := rv9Indent(t, "rv9q", func(s string) string {
		s = strings.Replace(s, "if False:\n", "\nif False:  \n\n", 1)
		return strings.Replace(s, "    pass\n", "    pass\r\n", 1)
	})
	if !strings.Contains(got, "if False:  \n") {
		t.Fatalf("config.py = %q: want the agent's whitespace edit", got)
	}
	if n := rv9SecretFlags(pr); n != 0 || strings.Contains(strings.Join(pr.Review.Warnings, "\n"), "agent changed this file") {
		t.Errorf("whitespace-only edit got a note: flags %d warnings %q", n, pr.Review.Warnings)
	}
}
