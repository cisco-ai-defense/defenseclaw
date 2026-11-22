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

package reasons

import (
	"errors"
	"strconv"
	"strings"
)

// DocsPage is the docs page, relative to the repository root, that carries
// the generated table between the two sentinels.
const DocsPage = "docs-site/content/docs/substrate/secrets.mdx"

const (
	sentinelBegin = "{/* AUTOGEN-BEGIN: secret-reasons (go run ./internal/substrate/reasons/gen; do not edit) */}"
	sentinelEnd   = "{/* AUTOGEN-END: secret-reasons */}"
)

var whereWords = map[Where]string{API: "Answer", Render: "Left out of the agent's policy", Launcher: "Launcher"}

// DocsTable renders the table as Markdown, sentinels included.
func DocsTable() string {
	var b strings.Builder
	b.WriteString(sentinelBegin + "\n\n")
	b.WriteString("| Reason | Where | Meaning | What to do |\n|---|---|---|---|\n")
	for _, r := range Table {
		where := whereWords[r.Where]
		if r.HTTP != 0 {
			where += " " + strconv.Itoa(r.HTTP)
		}
		b.WriteString("| `" + r.Code + "` | " + where + " | " + cell(r.Words) + " | " + cell(r.Fix) + " |\n")
	}
	b.WriteString("\n| Status | Meaning |\n|---|---|\n")
	for _, s := range Statuses {
		b.WriteString("| `" + s.Status + "` | " + cell(s.Words) + " |\n")
	}
	b.WriteString("\n" + sentinelEnd)
	return b.String()
}

// cell escapes a table cell and puts a command in code font.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	if i := strings.Index(s, "defenseclaw"); i >= 0 && (i == 0 || s[i-1] == ' ') {
		return s[:i] + "`" + strings.TrimSuffix(s[i:], ".") + "`"
	}
	return s
}

// ErrNoSentinels is returned when a page has no generated block.
var ErrNoSentinels = errors.New("reasons: page has no AUTOGEN secret-reasons block")

// Splice returns page with its generated block replaced by DocsTable.
func Splice(page string) (string, error) {
	i := strings.Index(page, sentinelBegin)
	j := strings.Index(page, sentinelEnd)
	if i < 0 || j < i {
		return "", ErrNoSentinels
	}
	return page[:i] + DocsTable() + page[j+len(sentinelEnd):], nil
}
