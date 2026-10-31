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

package gateway

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// longListingOwnerGroupRe matches the owner and group columns of one
// `ls -l` line ("drwxr-xr-x. 2 alice alice 6 Oct 31 01:15 ."). A hook
// tool result is often the JSON of the tool response, so a line also
// starts after an escaped line break or the opening quote of a string.
var longListingOwnerGroupRe = lazyregexp.New(`(?m)(?:^|\\[nr]|")[-bcdlpsD][-rwxsStTlL]{9}[.+@]?[ \t]+\d+[ \t]+(\S+)[ \t]+(\S+)[ \t]+`)

// accountPathSegmentEnd holds the bytes that may follow a path segment.
const accountPathSegmentEnd = "/\\ \t\r\n:\"\x27`,;)]}"

// filterAccountMetadataUsernames drops judge-reported Username entities
// that appear in the content only as local account metadata: a path
// segment right under a home root (/home/alice/proj, /Users/alice,
// C:\Users\alice) or the owner/group columns
// of an `ls -l` listing. The tool output of a coding agent carries the OS
// account name in nearly every listing and path, and the PII judge
// flagged it as a username (rel-1-0-6 GAP-0111). An entity that also
// appears anywhere else in the content (prose, a record, a form field)
// is kept, so a username shared as data still raises JUDGE-PII-USER.
//
// Returns the number of entities dropped (for logging).
func filterAccountMetadataUsernames(data map[string]interface{}, content string) int {
	if data == nil || content == "" {
		return 0
	}
	m, ok := data["Username"].(map[string]interface{})
	if !ok {
		return 0
	}
	if detected, _ := m["detection_result"].(bool); !detected {
		return 0
	}
	rawEntities, _ := m["entities"].([]interface{})
	if len(rawEntities) == 0 {
		return 0
	}
	var listing [][2]int
	for _, match := range longListingOwnerGroupRe.FindAllStringSubmatchIndex(content, -1) {
		listing = append(listing, [2]int{match[2], match[3]}, [2]int{match[4], match[5]})
	}
	lower := strings.ToLower(content)
	kept := make([]interface{}, 0, len(rawEntities))
	dropped := 0
	for _, e := range rawEntities {
		s, _ := e.(string)
		if s != "" && onlyAccountMetadata(lower, strings.ToLower(strings.TrimSpace(s)), listing) {
			dropped++
			if judgeLogTrace() {
				fmt.Fprintf(defaultLogWriter,
					"  [llm-judge] drop account-metadata username value=%s (path or listing column only)\n",
					redactEntity(s))
			}
			continue
		}
		kept = append(kept, e)
	}
	m["entities"] = kept
	if len(kept) == 0 {
		m["detection_result"] = false
	}
	return dropped
}

// onlyAccountMetadata reports whether needle occurs in haystack and every
// occurrence is a whole path segment or an `ls -l` owner/group column.
func onlyAccountMetadata(haystack, needle string, listing [][2]int) bool {
	if needle == "" || strings.ContainsAny(needle, " \t\r\n/\\") {
		return false
	}
	found := false
	for from := 0; ; {
		i := strings.Index(haystack[from:], needle)
		if i < 0 {
			return found
		}
		start := from + i
		end := start + len(needle)
		if !accountHomeSegmentAt(haystack, start, end) && !accountSpanIn(listing, start, end) {
			return false
		}
		found = true
		from = end
	}
}

// accountHomeSegmentAt reports whether s[start:end] is the path segment
// right under a home root (/home/x, /var/home/x, /Users/x, C:\Users\x, the
// latter also JSON-escaped). s is lower-cased. Any other path segment, such
// as a URL path (https://example.com/x), is not account metadata.
func accountHomeSegmentAt(s string, start, end int) bool {
	if end != len(s) && strings.IndexByte(accountPathSegmentEnd, s[end]) < 0 {
		return false
	}
	pre := strings.TrimRight(s[:start], "/\\")
	if n := start - len(pre); n == 0 || n > 2 {
		return false
	}
	for _, root := range []string{"home", "users"} {
		if !strings.HasSuffix(pre, root) {
			continue
		}
		if b := pre[:len(pre)-len(root)]; b == "" || strings.HasSuffix(b, "/") || strings.HasSuffix(b, "\\") {
			return true
		}
	}
	return false
}

func accountSpanIn(spans [][2]int, start, end int) bool {
	for _, span := range spans {
		if span[0] == start && span[1] == end {
			return true
		}
	}
	return false
}
