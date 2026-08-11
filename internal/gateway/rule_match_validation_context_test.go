// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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
	"regexp"
	"testing"
)

func TestFirstAcceptedRegexMatchPreservesFullTextContext(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{`\bTOKEN`, `^TOKEN`} {
		pattern := pattern
		t.Run(pattern, func(t *testing.T) {
			calls := 0
			match := firstAcceptedRegexMatch(
				regexp.MustCompile(pattern),
				"TOKENTOKEN",
				func(string) bool {
					calls++
					return calls > 1
				},
			)
			if match != nil {
				t.Fatalf("cursor restart manufactured match at %v", match)
			}
			if calls != 1 {
				t.Fatalf("validator calls=%d, want one original-context candidate", calls)
			}
		})
	}
}
