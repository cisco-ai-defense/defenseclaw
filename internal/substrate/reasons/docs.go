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

// cell escapes a table cell and puts each command in code font. A command
// starts at "defenseclaw substrate" or "defenseclaw-gateway substrate" and
// ends at ", ", ")" or the end of the text (a final period stays prose), so
// the words after it are not in code font (RV4 F9).
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	var b strings.Builder
	for {
		i := commandStart(s)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		end := len(s)
		for _, stop := range []string{", ", ")"} {
			if j := strings.Index(s[i:], stop); j >= 0 && i+j < end {
				end = i + j
			}
		}
		cmd := s[i:end]
		tail := ""
		if end == len(s) && strings.HasSuffix(cmd, ".") {
			cmd, tail = strings.TrimSuffix(cmd, "."), "."
		}
		b.WriteString(s[:i] + "`" + cmd + "`" + tail)
		s = s[end:]
	}
}

// commandStart is the index of the first command in s, or -1.
func commandStart(s string) int {
	best := -1
	for _, p := range []string{"defenseclaw substrate ", "defenseclaw-gateway substrate "} {
		for off := 0; ; {
			j := strings.Index(s[off:], p)
			if j < 0 {
				break
			}
			if k := off + j; k == 0 || s[k-1] == ' ' || s[k-1] == '(' {
				if best < 0 || k < best {
					best = k
				}
				break
			}
			off += j + 1
		}
	}
	return best
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
