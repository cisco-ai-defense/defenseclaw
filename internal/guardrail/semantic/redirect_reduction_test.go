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

package semantic

import "testing"

const parseStatusComplete = "defenseclaw.guardrail.semantic.v1." +
	"ParseStatus.PARSE_STATUS_COMPLETE"

func TestRedirectReductionSafe(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	const marker = `f.commands.exists(c, c.argv.exists(a, a == "dc-block-marker"))`
	tests := []struct {
		name       string
		expression string
		want       bool
	}{
		{"argv marker", marker, true},
		{
			"negation over argv",
			`f.commands.exists(c, c.program == "echo" && !c.argv.exists(a, a == "--dry-run"))`,
			true,
		},
		{
			"negation over one redirect's own field",
			`f.commands.exists(c, c.redirects.exists(r, !r.expands && r.fd == 1))`,
			true,
		},
		{
			"redirects inside an all() predicate",
			`f.commands.all(c, c.redirects.exists(r, r.fd == 1))`,
			true,
		},
		{
			"disjunction",
			marker + ` || f.commands.exists(c, c.redirects.exists(r, r.fd == 2))`,
			true,
		},
		{
			"no redirect anywhere",
			marker + ` && !f.commands.exists(c, c.redirects.exists(r, r.fd == 1))`,
			false,
		},
		{
			"every redirect under /tmp",
			`f.commands.exists(c, c.redirects.all(r, r.target.startsWith("/tmp/")))`,
			false,
		},
		{
			"redirect exists compared with false",
			`f.commands.exists(c, c.redirects.exists(r, r.fd == 1) == false)`,
			false,
		},
		{
			"redirect exists compared with not true",
			`f.commands.exists(c, c.redirects.exists(r, r.fd == 1) != true)`,
			false,
		},
		{"a command's argv_complete", `f.commands.exists(c, c.argv_complete)`, true},
		{
			"no path anywhere",
			marker + ` && !f.paths.exists(p, p.value.startsWith("/etc/"))`,
			false,
		},
		{"every path", `f.paths.all(p, p.absolute)`, false},
		{"no artifact", marker + ` && !f.artifacts.exists(a, a.value != "")`, false},
		{
			"no archive lineage",
			marker + ` && !f.archive_lineages.exists(l, l.identity != "")`,
			false,
		},
		{
			"authoritative lineage",
			`f.archive_lineages.exists(l, l.authoritative)`,
			false,
		},
		{
			"negation over child commands",
			`f.commands.exists(c, c.program == "sudo") && !f.commands.exists(c, c.program == "systemctl")`,
			true,
		},
		{"parse status", marker + ` && f.parse.status == ` + parseStatusComplete, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			program, code := compiler.Compile(test.expression)
			if code != CompileOK {
				t.Fatalf("Compile(%s) = %q", test.expression, code)
			}
			if got := program.RedirectReductionSafe(); got != test.want {
				t.Fatalf("RedirectReductionSafe(%s) = %t, want %t", test.expression, got, test.want)
			}
		})
	}
	var missing *Program
	if missing.RedirectReductionSafe() {
		t.Fatal("nil program is redirect-reduction safe")
	}
}
