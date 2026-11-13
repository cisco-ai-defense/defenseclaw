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

package testcorpus

import (
	"fmt"
	"math/rand"
	"strings"
)

// EmailCase is one email-detector sample (substrate-1:GAP-0149, GAP-0159).
// Every address is generated on reserved or invented domains, apart from the
// vendor no-reply addresses that agents put in their own instructions.
type EmailCase struct {
	Kind string
	Text string
	// Want is the expected highest email severity: "LOW" (one address,
	// alert-only), "MEDIUM" (a list of 5+ distinct addresses or a labeled
	// field: blocks in strict) or "" (no email finding at all).
	Want string
}

var firstNames = []string{"alice", "bob", "carol", "dmitri", "eva", "farid", "grace", "hiro", "ines", "jamal", "kai", "lena", "mateo", "nora", "omar", "priya"}
var lastNames = []string{"smith", "nguyen", "okafor", "garcia", "ivanova", "tanaka", "mueller", "dubois", "rossi", "kim", "haddad", "silva"}
var mailDomains = []string{"corp-mail.test", "example.com", "acme-widgets.example", "northwind.test", "contoso.example"}

func title(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

func person(r *rand.Rand) (name, address string) {
	f, l := firstNames[r.Intn(len(firstNames))], lastNames[r.Intn(len(lastNames))]
	return title(f) + " " + title(l), fmt.Sprintf("%s.%s%d@%s", f, l, r.Intn(1000), mailDomains[r.Intn(len(mailDomains))])
}

// trailer builds a commit trailer line ("<Kind>-by: <who>").
func trailer(kind, who string) string { return kind + "-by: " + who }

// vendorInstructions are agent-instruction shapes that carry one vendor
// no-reply address (the GAP-0149 false block in strict).
var vendorInstructions = []string{
	"When you create a commit, end the message with:\n\n" + trailer("Co-Authored", "Assistant <noreply@anthropic.com>") + "\n\nDo not push unless the user asks.",
	"# Git\n- Use the HEREDOC form for commit messages.\n- Add the trailer `" + trailer("Co-authored", "Codex <codex-noreply@openai.com>") + "`.\n- Never amend a pushed commit.",
	"Commits made by the bot use the identity github-actions <41898282+github-actions@users.noreply.github.com>.",
	"If the user asks for help, tell them to open an issue; replies come from notifications@github.com and cannot be answered.",
	"You are the editor's agent. Feedback about the product goes to hi@cursor.example. Use the tools below to edit files.",
	"Dependabot will open pull requests from support@dependabot.example; review them like any other change.",
}

// EmailBenign returns benign samples: one vendor or contact address, git
// history with many authors, locators and paths.
func EmailBenign(seed int64, n int) []EmailCase {
	r := rand.New(rand.NewSource(seed))
	var out []EmailCase
	for i := 0; i < n; i++ {
		out = append(out, EmailCase{Kind: "vendor-instructions", Text: vendorInstructions[i%len(vendorInstructions)], Want: "LOW"})
		_, a := person(r)
		out = append(out, EmailCase{Kind: "single-contact", Text: "If the build breaks, ping the maintainer at " + a + " before reverting.", Want: "LOW"})
		var log strings.Builder
		for k := 0; k < 8; k++ {
			name, addr := person(r)
			fmt.Fprintf(&log, "commit %s\nAuthor: %s <%s>\nDate:   Thu Nov 12 1%d:0%d:00 2026 +0000\n\n    fix: change %d\n\n", hexString(r, 40), name, addr, k%10, k%10, k)
		}
		out = append(out, EmailCase{Kind: "git-log-authors", Text: log.String(), Want: "LOW"})
		var trailers strings.Builder
		trailers.WriteString("feat: release notes\n\n")
		for k := 0; k < 6; k++ {
			name, addr := person(r)
			trailers.WriteString(trailer("Co-authored", name+" <"+addr+">") + "\n")
		}
		out = append(out, EmailCase{Kind: "git-trailers", Text: trailers.String(), Want: "LOW"})
		out = append(out, EmailCase{Kind: "git-remote", Text: "git clone git@github.com:acme/widgets.git && cd widgets", Want: ""})
		out = append(out, EmailCase{Kind: "home-path", Text: "ls /home/svc-build@corp.example/project/src", Want: ""})
		out = append(out, EmailCase{Kind: "no-email", Text: fmt.Sprintf("run make test in %s and report failures", hexString(r, 8)), Want: ""})
	}
	return out
}

// EmailPositive returns bulk lists and labeled fields.
func EmailPositive(seed int64, n int) []EmailCase {
	r := rand.New(rand.NewSource(seed))
	var out []EmailCase
	for i := 0; i < n; i++ {
		var csv strings.Builder
		csv.WriteString("id,name,contact,plan\n")
		for k := 1; k <= 50; k++ {
			name, addr := person(r)
			fmt.Fprintf(&csv, "%d,%s,%s,%s\n", k, name, addr, []string{"free", "pro", "team"}[r.Intn(3)])
		}
		out = append(out, EmailCase{Kind: "csv-50-rows", Text: "Here is the customer export, dedupe it:\n" + csv.String(), Want: "MEDIUM"})
		var list []string
		for len(list) < 10 {
			_, a := person(r)
			list = append(list, a)
		}
		out = append(out, EmailCase{Kind: "comma-list", Text: "send the invite to " + strings.Join(list, ", "), Want: "MEDIUM"})
		out = append(out, EmailCase{Kind: "semicolon-list", Text: "To: " + strings.Join(list[:6], "; "), Want: "MEDIUM"})
		var html strings.Builder
		for k := 0; k < 6; k++ {
			name, a := person(r)
			fmt.Fprintf(&html, "<li><a href=\"mailto:%s\">%s</a></li>\n", a, name)
		}
		out = append(out, EmailCase{Kind: "mailto-links", Text: "<ul>\n" + html.String() + "</ul>", Want: "MEDIUM"})
		_, a := person(r)
		out = append(out, EmailCase{Kind: "field-yaml", Text: "customer:\n  name: Jo\n  email: " + a + "\n", Want: "MEDIUM"})
		out = append(out, EmailCase{Kind: "field-json", Text: `{"id": 42, "email": "` + a + `", "plan": "pro"}`, Want: "MEDIUM"})
		out = append(out, EmailCase{Kind: "field-prose", Text: "Customer e-mail address: " + a + ", phone on file.", Want: "MEDIUM"})
	}
	return out
}
