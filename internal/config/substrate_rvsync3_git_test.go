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

package config

import (
	"strings"
	"testing"
)

// RV-SYNC3 F1 (GAP-0733), F2 (GAP-0734), F5: substrate.git.https_rewrite
// pairs that git would not apply as the launcher reads them are refused.
func TestRVSync3GitRewriteValidate(t *testing.T) {
	cases := []struct {
		name string
		r    SubstrateGitRewrite
		want string
	}{
		{"baked from with another to", SubstrateGitRewrite{From: "git@github.com:", To: "https://ghproxy.example/"}, "built into every actor image"},
		{"generic from cannot be set", SubstrateGitRewrite{From: "ssh://git@", To: "https://proxy.example/"}, "must end in : or /"},
		{"baked pair repeated", SubstrateGitRewrite{From: "git@github.com:", To: "https://github.com/"}, ""},
		{"longer than a baked from", SubstrateGitRewrite{From: "git@github.com:corp/", To: "https://ghproxy.example/corp/"}, ""},
		{"to with no slash", SubstrateGitRewrite{From: "git@ghe.example:", To: "https://ghe.example"}, "must end in /"},
		{"to path with no slash", SubstrateGitRewrite{From: "git@ghe.example:", To: "https://ghe.example/scm"}, "must end in /"},
		{"to with a port", SubstrateGitRewrite{From: "git@ghe.example:", To: "https://ghe.example:8443/"}, ""},
		{"upper-case scp host", SubstrateGitRewrite{From: "git@GHE.example:", To: "https://ghe.example/"}, "lower case"},
		{"upper-case ssh host", SubstrateGitRewrite{From: "ssh://git@Ghe.example/", To: "https://ghe.example/"}, "lower case"},
		{"upper-case scheme", SubstrateGitRewrite{From: "SSH://git@ghe.example/", To: "https://ghe.example/"}, "lower case"},
		{"upper-case path is kept", SubstrateGitRewrite{From: "git@ghe.example:Org/", To: "https://ghe.example/Org/"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := SubstrateConfig{Git: SubstrateGitConfig{HTTPSRewrite: []SubstrateGitRewrite{tc.r}}}
			msg := ""
			if err := s.Validate(); err != nil {
				msg = err.Error()
			}
			got := strings.Contains(msg, "git.https_rewrite")
			if tc.want == "" && got {
				t.Fatalf("refused: %s", msg)
			}
			if tc.want != "" && (!got || !strings.Contains(msg, tc.want)) {
				t.Fatalf("want a git.https_rewrite error with %q, got %q", tc.want, msg)
			}
		})
	}
}

// RV-SYNC3 F1 (GAP-0733): the launcher reads the map as git in the agent
// does: the baked rules stay when a list leaves them out, and win a tie.
func TestRVSync3RewriteGitURLBakedRulesWin(t *testing.T) {
	admin := []SubstrateGitRewrite{
		{From: "git@github.com:", To: "https://ghproxy.example/"},
		{From: "git@github.com:corp/", To: "https://ghproxy.example/corp/"},
		{From: "git@ghe.example:", To: "https://ghe.example/"},
		{From: "git@nos.example:", To: "https://nos.example"},
	}
	for raw, want := range map[string]string{
		"git@github.com:o/r.git":    "https://github.com/o/r.git",
		"git@github.com:corp/a.git": "https://ghproxy.example/corp/a.git",
		"git@gitlab.com:o/r.git":    "https://gitlab.com/o/r.git",
		"git@ghe.example:t/a.git":   "https://ghe.example/t/a.git",
		"ssh://git@h.example/o/r":   "https://h.example/o/r",
		"git@nos.example:o/r":       "",
	} {
		got, ok := RewriteGitURL(raw, admin)
		if !ok {
			got = ""
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", raw, got, want)
		}
	}
}
